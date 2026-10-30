"""Unit tests on a synthetic snapshot that mirrors the original incident."""

import unittest

from chrome_unfreeze.analyze import SAFE, diagnose, find_instances, impact, role, wait_chain
from chrome_unfreeze.snapshot import SYSCALL_NAMES, Proc, Snapshot, Syscall

NR = {name: nr for nr, name in SYSCALL_NAMES.items()}
CHROME = "/opt/google/chrome/chrome"


def proc(pid, ppid, argv, state="S", syscall=None, fds=None, tracer=0, nspid=None):
    return Proc(pid=pid, ppid=ppid, uid=1000, state=state, comm="chrome", argv=argv,
                syscall=syscall, fds=fds or {}, tracer=tracer, nspid=nspid or (pid,))


def incident() -> Snapshot:
    """Browser read()s the zygote socket, zygote wait4()s a zombie, crashpad holds the zombie."""
    procs = [
        proc(100, 1, [CHROME], syscall=Syscall(NR["read"], (10, 0, 128)), fds={10: "socket:[500]"}),
        proc(101, 1, ["/opt/google/chrome/chrome_crashpad_handler", "--monitor-self"],
             syscall=Syscall(NR["epoll_wait"], (3,))),
        proc(102, 100, [CHROME, "--type=zygote", "--no-zygote-sandbox", "--crashpad-handler-pid=101"],
             syscall=Syscall(NR["wait4"], (300,)), fds={3: "socket:[501]"}),
        proc(103, 100, [CHROME, "--type=zygote", "--crashpad-handler-pid=101"]),
        proc(104, 103, [CHROME, "--type=renderer", "--crashpad-handler-pid=101"]),
        proc(300, 102, [], state="Z", tracer=101),
    ]
    return Snapshot({p.pid: p for p in procs}, unix_peers={500: 501, 501: 500})


class Roles(unittest.TestCase):
    def test_roles(self):
        snap = incident()
        self.assertEqual(role(snap.procs[100]), "browser")
        self.assertEqual(role(snap.procs[101]), "crashpad")
        self.assertEqual(role(snap.procs[102]), "zygote")
        self.assertEqual(role(snap.procs[104]), "renderer")
        self.assertEqual(role(proc(1, 0, [CHROME, "--type=utility", "--utility-sub-type=network.mojom.NetworkService"])),
                         "utility:network")

    def test_crashpad_flag_is_not_a_crashpad(self):
        self.assertEqual(role(proc(1, 0, [CHROME, "--type=renderer", "--crashpad-handler-pid=9"])), "renderer")


class Incident(unittest.TestCase):
    def test_chain(self):
        chain = wait_chain(incident(), 100)
        self.assertEqual([pid for pid, _ in chain], [102, 300, 101])

    def test_diagnosis_recommends_crashpad(self):
        snap = incident()
        [inst] = find_instances(snap, uid=1000)
        self.assertEqual(inst.members[101], "crashpad")
        self.assertEqual(inst.members[300], "dead")
        d = diagnose(snap, inst, stuck=True)
        self.assertEqual(d.culprit, 101)
        self.assertEqual(impact("crashpad")[0], SAFE)
        self.assertTrue(any("GPU" in m for m in d.problems))

    def test_wait4_on_namespaced_pid(self):
        snap = incident()
        snap.procs[102].syscall = Syscall(NR["wait4"], (7,))
        snap.procs[300].nspid = (300, 7)
        self.assertEqual([pid for pid, _ in wait_chain(snap, 100)], [102, 300, 101])

    def test_never_recommends_zygote(self):
        snap = incident()
        snap.procs[300].tracer = 0  # untraced zombie: the chain stops at the zygote and zombie
        [inst] = find_instances(snap, uid=1000)
        self.assertIsNone(diagnose(snap, inst, stuck=True).culprit)


if __name__ == "__main__":
    unittest.main()
