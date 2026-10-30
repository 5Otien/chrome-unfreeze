"""Reproduces the hang with real processes and checks that the analysis finds it.

A reads a socket whose other end is B. B waits on its child C. C is dead but D holds it with ptrace.
"""

import ctypes
import os
import signal
import socket
import time
import unittest

from chrome_unfreeze.analyze import wait_chain
from chrome_unfreeze.snapshot import read_proc, take_snapshot

PTRACE_SEIZE = 0x4206


def _ptrace_allowed() -> bool:
    try:
        with open("/proc/sys/kernel/yama/ptrace_scope") as f:
            return f.read().strip() == "0"
    except OSError:
        return True


def _wait_for(cond, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


@unittest.skipUnless(os.path.exists("/proc/self/syscall") and _ptrace_allowed(),
                     "needs Linux with ptrace allowed (yama ptrace_scope = 0)")
class LiveIncident(unittest.TestCase):
    def setUp(self):
        self.pids = []

    def tearDown(self):
        for pid in reversed(self.pids):
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except (ProcessLookupError, ChildProcessError):
                pass

    def fork(self, body):
        pid = os.fork()
        if pid == 0:
            try:
                body()
            finally:
                os._exit(0)
        self.pids.append(pid)
        return pid

    def test_chain_is_found(self):
        a_sock, b_sock = socket.socketpair()
        to_d_r, to_d_w = os.pipe()
        attached_r, attached_w = os.pipe()

        def b_body():
            a_sock.close()
            go_r, go_w = os.pipe()
            c = os.fork()
            if c == 0:  # C waits for the go signal, then exits
                os.read(go_r, 1)
                os._exit(0)
            os.write(to_d_w, str(c).encode().ljust(16))
            os.read(attached_r, 1)      # D is attached to C
            os.write(go_w, b"x")        # let C exit
            os.waitpid(c, 0)            # blocks because D never lets go of C

        def d_body():
            libc = ctypes.CDLL(None, use_errno=True)
            c = int(os.read(to_d_r, 16))
            if libc.ptrace(PTRACE_SEIZE, c, None, None) != 0:
                os._exit(1)
            os.write(attached_w, b"x")
            time.sleep(60)              # a tracer that never calls wait()

        b = self.fork(b_body)
        d = self.fork(d_body)
        b_sock.close()

        def a_body():
            a_sock.recv(1)              # blocks because B never answers

        a = self.fork(a_body)
        a_sock.close()

        def stuck():
            p = read_proc(b, with_fds=False)
            kids = [q for q in take_snapshot().procs.values() if q.ppid == b and q.state == "Z"]
            return p and p.syscall and p.syscall.name in ("wait4", "waitid") and kids
        self.assertTrue(_wait_for(stuck), "could not set up the hang")
        self.assertTrue(_wait_for(lambda: (read_proc(a, with_fds=False).syscall or 0)
                                  and read_proc(a, with_fds=False).syscall.name in ("read", "recvfrom", "recvmsg")))

        chain = [pid for pid, _ in wait_chain(take_snapshot(), a)]
        self.assertEqual(chain[0], b)
        self.assertEqual(chain[-1], d)
        self.assertEqual(len(chain), 3)


if __name__ == "__main__":
    unittest.main()
