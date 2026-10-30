"""Chrome process roles, the wait chain, and what stopping each process costs."""

import os
from dataclasses import dataclass, field

from .snapshot import Proc, Snapshot

BROWSER_BINARIES = {"chrome", "chromium", "chromium-browser", "brave", "msedge"}

SAFE, CAUTION, DANGER = "safe", "caution", "danger"

# Syscalls where a thread sits waiting on another process.
BLOCKING_WAITS = {"read", "recvfrom", "recvmsg", "wait4", "waitid"}


def arg_value(argv: list[str], name: str) -> str | None:
    prefix = name + "="
    for a in argv:
        if a.startswith(prefix):
            return a[len(prefix):]
    return None


def role(p: Proc) -> str | None:
    if not p.argv:  # zombies and kernel threads have no command line
        return None
    exe = os.path.basename(p.argv[0])
    if "crashpad" in exe:
        return "crashpad"
    kind = arg_value(p.argv, "--type")
    if kind is None:
        return "browser" if exe in BROWSER_BINARIES else None
    if kind == "utility":
        sub = arg_value(p.argv, "--utility-sub-type") or ""
        return "utility:" + sub.split(".")[0]
    if kind == "renderer" and "--extension-process" in p.argv:
        return "extension"
    return kind


def impact(r: str | None) -> tuple[str, str]:
    """Risk level and the practical consequence of stopping a process with this role."""
    if r == "crashpad":
        return SAFE, "no tabs affected, crash reporting is off until Chrome restarts"
    if r == "gpu-process":
        return SAFE, "Chrome restarts it, the screen flickers and videos or WebGL reload"
    if r == "utility:network":
        return CAUTION, "Chrome restarts it, but downloads and requests in flight are cut"
    if r and r.startswith("utility:"):
        return SAFE, "helper service, started again when needed"
    if r == "extension":
        return CAUTION, "the extension crashes and has to be reloaded"
    if r == "renderer":
        return CAUTION, "its tabs show \"Aw, Snap!\" and need a reload, unsent form input is lost"
    if r == "zygote":
        return DANGER, "no new tabs can open and Chrome will likely crash"
    if r == "browser":
        return DANGER, "closes all of Chrome, tabs come back when you restart it"
    if r == "dead":
        return SAFE, "already dead, nothing to lose"
    return CAUTION, "unknown process type"


@dataclass
class Instance:
    browser: Proc
    members: dict[int, str] = field(default_factory=dict)  # pid to role


def find_instances(snap: Snapshot, uid: int | None = None) -> list[Instance]:
    instances = []
    for p in sorted(snap.procs.values(), key=lambda p: p.pid):
        if role(p) != "browser" or (uid is not None and p.uid != uid):
            continue
        inst = Instance(p, {p.pid: "browser"})
        todo = [p.pid]
        while todo:
            for child in snap.children(todo.pop()):
                if child.pid not in inst.members:
                    inst.members[child.pid] = "dead" if child.state == "Z" else (role(child) or child.comm)
                    todo.append(child.pid)
        for pid in list(inst.members):
            ref = arg_value(snap.procs[pid].argv, "--crashpad-handler-pid")
            if ref and ref.isdigit() and int(ref) in snap.procs:
                for c in [snap.procs[int(ref)], *snap.children(int(ref))]:
                    inst.members.setdefault(c.pid, "crashpad")
        instances.append(inst)
    return instances


def waits_on(snap: Snapshot, p: Proc) -> tuple[int, str] | None:
    """The pid that `p` is waiting on and why, or None if there is no one to point at."""
    if p.state == "Z":
        if p.tracer:
            return p.tracer, f"dead, but held by ptrace (TracerPid={p.tracer}), so its parent cannot reap it"
        return None

    sc = p.syscall
    if sc is None or sc.name not in BLOCKING_WAITS:
        return None

    if sc.name in ("wait4", "waitid"):
        if sc.name == "waitid":
            target = sc.arg_s32(1) if sc.args[0] == 1 else -1  # P_PID == 1
        else:
            target = sc.arg_s32(0)
        kids = snap.children(p.pid)
        if target > 0:
            # the pid may be the one seen from inside the sandbox pid namespace (NSpid)
            for c in kids:
                if target == c.pid or target in c.nspid:
                    return c.pid, f"{sc.name}() waiting for its child {c.pid} to exit"
            return None
        for c in kids:
            if c.state == "Z" and c.tracer:
                return c.pid, f"{sc.name}() waiting for a child ({c.pid}) to exit"
        return None

    fd = sc.arg_s32(0)
    link = p.fds.get(fd)
    if link is None:
        return None
    target = link
    if link.startswith("socket:["):
        peer = snap.unix_peers.get(int(link[8:-1]))
        if peer is None:
            return None
        target = f"socket:[{peer}]"
    others = [o for o in snap.owners(target) if o != p.pid]
    if not others:
        return None
    return others[0], f"{sc.name}() stuck on fd {fd} ({link}), waiting for a reply from {others[0]}"


def wait_chain(snap: Snapshot, pid: int, limit: int = 12) -> list[tuple[int, str]]:
    """[(pid, reason)] for each process that `pid` depends on, ending with the blocker."""
    chain, seen = [], {pid}
    current = snap.procs.get(pid)
    while current and len(chain) < limit:
        nxt = waits_on(snap, current)
        if nxt is None or nxt[0] in seen:
            break
        chain.append(nxt)
        seen.add(nxt[0])
        current = snap.procs.get(nxt[0])
    return chain


@dataclass
class Diagnosis:
    instance: Instance
    stuck: bool
    chain: list[tuple[int, str]]
    problems: list[str]
    culprit: int | None


def diagnose(snap: Snapshot, inst: Instance, stuck: bool) -> Diagnosis:
    procs = snap.procs
    problems = []
    chain = wait_chain(snap, inst.browser.pid) if stuck else []

    for pid, r in inst.members.items():
        p = procs[pid]
        if p.state == "Z" and p.tracer:
            tr = procs.get(p.tracer)
            name = role(tr) if tr else None
            problems.append(f"Dead process {pid} is held by {p.tracer} ({name or 'unknown'}).")
        elif p.state == "D":
            problems.append(f"{pid} ({r}) is stuck waiting on the disk (state D).")
    if not any(r == "gpu-process" for r in inst.members.values()):
        problems.append("No GPU process. It probably crashed and Chrome could not start a new one.")
    if inst.browser.state == "D":
        problems.append("The main process is waiting on the disk, usually because RAM is short and the system is swapping.")

    mem = snap.meminfo
    if mem.get("MemTotal") and mem.get("MemAvailable", 0) < 0.10 * mem["MemTotal"]:
        problems.append(f"RAM almost full: {mem['MemAvailable'] // 1024} MB available.")
    if mem.get("SwapTotal") and mem.get("SwapFree", 0) < 0.10 * mem["SwapTotal"]:
        problems.append(f"Swap almost full: {mem['SwapFree'] // 1024} MB free.")

    culprit = None
    if chain:
        last = chain[-1][0]
        if last in procs and procs[last].state != "Z" and impact(inst.members.get(last) or role(procs.get(last)))[0] == SAFE:
            culprit = last
    if culprit is None:
        for pid in inst.members:
            p = procs[pid]
            if p.state == "Z" and p.tracer and inst.members.get(p.tracer) == "crashpad":
                culprit = p.tracer
                break
    return Diagnosis(inst, stuck, chain, problems, culprit)
