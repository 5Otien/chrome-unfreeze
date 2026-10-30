"""Reads /proc into a snapshot of processes, their open fds and Unix socket peers."""

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field

_SYSCALLS = {
    "x86_64": {
        0: "read", 7: "poll", 23: "select", 35: "nanosleep", 45: "recvfrom",
        47: "recvmsg", 61: "wait4", 202: "futex", 230: "clock_nanosleep",
        232: "epoll_wait", 247: "waitid", 270: "pselect6", 271: "ppoll",
        281: "epoll_pwait", 441: "epoll_pwait2",
    },
    "aarch64": {
        22: "epoll_pwait", 63: "read", 73: "ppoll", 95: "waitid", 98: "futex",
        101: "nanosleep", 115: "clock_nanosleep", 207: "recvfrom",
        212: "recvmsg", 260: "wait4", 441: "epoll_pwait2",
    },
}
SYSCALL_NAMES = _SYSCALLS.get(platform.machine(), {})


@dataclass
class Syscall:
    nr: int
    args: tuple[int, ...]

    @property
    def name(self) -> str:
        return SYSCALL_NAMES.get(self.nr, f"syscall#{self.nr}")

    def arg_s32(self, i: int) -> int:
        """Argument i read as a signed 32 bit int (pid, fd)."""
        v = self.args[i] & 0xFFFFFFFF
        return v - (1 << 32) if v & 0x80000000 else v


@dataclass
class Proc:
    pid: int
    ppid: int
    uid: int
    state: str
    comm: str
    argv: list[str]
    rss_kb: int = 0
    swap_kb: int = 0
    tracer: int = 0
    nspid: tuple[int, ...] = ()
    threads: int = 1
    wchan: str = ""
    syscall: Syscall | None = None
    cpu_ticks: int = 0
    fds: dict[int, str] = field(default_factory=dict)


@dataclass
class Snapshot:
    procs: dict[int, Proc]
    unix_peers: dict[int, int] = field(default_factory=dict)  # inode to peer inode
    meminfo: dict[str, int] = field(default_factory=dict)     # in kB
    _owners: dict[str, list[int]] | None = None

    def children(self, pid: int) -> list[Proc]:
        return [p for p in self.procs.values() if p.ppid == pid]

    def owners(self, link: str) -> list[int]:
        """Pids holding `link` open, for example 'socket:[123]'."""
        if self._owners is None:
            self._owners = {}
            for p in self.procs.values():
                for target in set(p.fds.values()):
                    self._owners.setdefault(target, []).append(p.pid)
        return sorted(self._owners.get(link, []))


def _read(path: str) -> str | None:
    try:
        with open(path, "rb") as f:
            return f.read().decode(errors="replace")
    except OSError:
        return None


def _parse_syscall(text: str | None) -> Syscall | None:
    if not text:
        return None
    parts = text.split()
    if not parts or parts[0] in ("running", "-1"):
        return None
    try:
        return Syscall(int(parts[0]), tuple(int(a, 16) for a in parts[1:7]))
    except ValueError:
        return None


def read_proc(pid: int, with_fds: bool = True) -> Proc | None:
    base = f"/proc/{pid}"
    status = _read(f"{base}/status")
    if status is None:
        return None
    fields = {}
    for line in status.splitlines():
        key, _, value = line.partition(":")
        fields[key] = value.strip()

    def kb(key):
        return int(fields.get(key, "0 kB").split()[0])

    argv = [a for a in (_read(f"{base}/cmdline") or "").split("\0") if a]
    if len(argv) == 1 and " --" in argv[0]:
        # Chrome rewrites its child process titles into one space separated string
        argv = argv[0].split(" ")
    stat = _read(f"{base}/stat") or ""
    after = stat.rpartition(")")[2].split()
    cpu = int(after[11]) + int(after[12]) if len(after) > 12 else 0

    proc = Proc(
        pid=pid,
        ppid=int(fields.get("PPid", 0)),
        uid=int(fields.get("Uid", "0").split()[0]),
        state=fields.get("State", "?")[:1],
        comm=fields.get("Name", ""),
        argv=argv,
        rss_kb=kb("VmRSS"),
        swap_kb=kb("VmSwap"),
        tracer=int(fields.get("TracerPid", 0)),
        nspid=tuple(int(x) for x in fields.get("NSpid", str(pid)).split()),
        threads=int(fields.get("Threads", 1)),
        wchan=(_read(f"{base}/wchan") or "").strip(),
        syscall=_parse_syscall(_read(f"{base}/syscall")),
        cpu_ticks=cpu,
    )
    if with_fds:
        try:
            for fd in os.listdir(f"{base}/fd"):
                try:
                    proc.fds[int(fd)] = os.readlink(f"{base}/fd/{fd}")
                except OSError:
                    pass
        except OSError:
            pass
    return proc


def read_unix_peers() -> dict[int, int]:
    """Maps each Unix socket inode to its peer inode, using `ss`."""
    if not shutil.which("ss"):
        return {}
    try:
        out = subprocess.run(["ss", "-xaH"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    peers = {}
    for line in out.splitlines():
        cols = line.split()
        # Netid State Recv-Q Send-Q Local Port Peer Port
        if len(cols) >= 8 and cols[5].isdigit() and cols[7].isdigit():
            local, peer = int(cols[5]), int(cols[7])
            if peer:
                peers[local] = peer
                peers.setdefault(peer, local)
    return peers


def read_meminfo() -> dict[str, int]:
    info = {}
    for line in (_read("/proc/meminfo") or "").splitlines():
        key, _, value = line.partition(":")
        if value.split():
            info[key] = int(value.split()[0])
    return info


def take_snapshot() -> Snapshot:
    uid = os.getuid()
    procs = {}
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            pid = int(entry)
            p = read_proc(pid, with_fds=False)
            if p is None:
                continue
            if p.uid == uid or uid == 0:
                p = read_proc(pid) or p
            procs[pid] = p
    return Snapshot(procs, read_unix_peers(), read_meminfo())
