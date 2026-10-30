"""Command line interface: diagnose, then pick which process to stop."""

import argparse
import json
import os
import sys
import time

from .actions import DENIED, DONE, RESISTING, terminate
from .analyze import (BLOCKING_WAITS, CAUTION, DANGER, SAFE, Diagnosis,
                      diagnose, find_instances, impact, role)
from .snapshot import read_proc, take_snapshot

COLORS = {SAFE: "32", CAUTION: "33", DANGER: "31", "bold": "1", "dim": "2"}
_tty = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def c(text: str, color: str) -> str:
    return f"\033[{COLORS[color]}m{text}\033[0m" if _tty else text


def is_stuck(pid: int, delay: float = 1.0) -> bool:
    """True if the main thread stays in the same blocking wait for `delay` seconds."""
    a = read_proc(pid, with_fds=False)
    time.sleep(delay)
    b = read_proc(pid, with_fds=False)
    if a is None or b is None:
        return False
    if a.state == "D" and b.state == "D":
        return True
    return (a.syscall is not None and b.syscall is not None
            and a.syscall.name in BLOCKING_WAITS and a.syscall == b.syscall)


def describe(pid: int, snap, members) -> str:
    p = snap.procs.get(pid)
    if p is None:
        return f"{pid} (gone)"
    r = members.get(pid) or role(p) or p.comm
    return f"{pid} {c(r, 'bold')}" + (" " + c("[dead]", "dim") if p.state == "Z" else "")


def print_diagnosis(d: Diagnosis, snap) -> list[int]:
    inst, members = d.instance, d.instance.members
    b = inst.browser
    status = c("FROZEN", DANGER) if d.stuck else c("responding", SAFE)
    print(f"\n{c('Chrome', 'bold')} pid {b.pid}: {status}  "
          f"({len(members)} processes, {sum(snap.procs[p].rss_kb for p in members) // 1024} MB of RAM)")

    if d.stuck:
        print(f"\n{c('Wait chain', 'bold')}")
        print(f"  {describe(b.pid, snap, members)}")
        for depth, (pid, why) in enumerate(d.chain, 1):
            print(f"  {'   ' * (depth - 1)}└─ {c(why, 'dim')}")
            print(f"  {'   ' * depth}{describe(pid, snap, members)}")
        if not d.chain:
            print("  (can't follow the chain any further, see problems below)")

    if d.problems:
        print(f"\n{c('Problems found', 'bold')}")
        for msg in d.problems:
            print(f"  • {msg}")

    order = ["crashpad", "gpu-process", "dead"]
    rows = sorted(members, key=lambda pid: (
        0 if pid == d.culprit else 1,
        order.index(members[pid]) if members[pid] in order else len(order),
        members[pid] == "browser",
        -snap.procs[pid].rss_kb,
    ))
    print(f"\n{c('Processes', 'bold')}  (# is the number to type)")
    print(f"  {'#':>3} {'PID':>8}  {'role':<22} {'state':<4} {'RAM':>7} {'swap':>7}  impact")
    for i, pid in enumerate(rows, 1):
        p, r = snap.procs[pid], members[pid]
        level, text = impact(r)
        mark = c(" <- recommended", SAFE) if pid == d.culprit else ""
        print(f"  {i:>3} {pid:>8}  {r:<22} {p.state:<4} {p.rss_kb // 1024:>5}MB {p.swap_kb // 1024:>5}MB  "
              f"{c(level, level)}: {text}{mark}")
    return rows


def stop(pid: int) -> None:
    result = terminate(pid)
    if result == RESISTING and input(f"{pid} ignored SIGTERM. Force it with SIGKILL? [y/N] ").strip().lower() in ("y", "yes"):
        result = terminate(pid, force=True)
    if result == DONE:
        print(c(f"{pid} stopped.", SAFE))
    elif result == DENIED:
        print(c(f"Permission denied for {pid}. Does it belong to another user?", DANGER))
    else:
        print(f"{pid} is still running.")


def confirm(pid: int, r: str) -> bool:
    level, text = impact(r)
    print(f"\nStop {pid} ({r}): {c(level, level)}, {text}.")
    if level == DANGER:
        return input("Type \"yes\" to confirm: ").strip().lower() == "yes"
    return input("Go ahead? [Y/n] ").strip().lower() in ("", "y", "yes")


def to_json(d: Diagnosis, snap) -> dict:
    return {
        "browser_pid": d.instance.browser.pid,
        "stuck": d.stuck,
        "chain": [{"pid": pid, "role": d.instance.members.get(pid), "reason": why} for pid, why in d.chain],
        "problems": d.problems,
        "recommended_pid": d.culprit,
        "processes": [
            {"pid": pid, "role": r, "state": snap.procs[pid].state, "rss_kb": snap.procs[pid].rss_kb,
             "swap_kb": snap.procs[pid].swap_kb, "risk": impact(r)[0], "impact": impact(r)[1]}
            for pid, r in d.instance.members.items()
        ],
    }


def run_once(args) -> list[tuple[Diagnosis, object]]:
    snap = take_snapshot()
    instances = find_instances(snap, uid=None if os.getuid() == 0 else os.getuid())
    if args.pid:
        instances = [i for i in instances if i.browser.pid == args.pid]
    results = []
    for inst in instances:
        results.append((diagnose(snap, inst, is_stuck(inst.browser.pid)), snap))
    return results


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="chrome-unfreeze",
        description="Find what is blocking a hung Chrome and stop only that process, so you keep your tabs.")
    ap.add_argument("command", nargs="?", default="interactive", choices=["interactive", "diag", "fix", "gui"],
                    help="interactive (default): diagnose, then pick a process. diag: read only. "
                         "fix: only apply the recommended safe action. gui: open the window")
    ap.add_argument("--pid", type=int, help="pid of the main Chrome process to look at")
    ap.add_argument("--json", action="store_true", help="print JSON (with diag)")
    ap.add_argument("-y", "--yes", action="store_true", help="don't ask before stopping (with fix)")
    args = ap.parse_args(argv)

    if args.command == "gui":
        from .gui import run
        return run()

    results = run_once(args)
    if not results:
        print("No Chrome found for this user.", file=sys.stderr)
        return 1

    if args.command == "diag":
        if args.json:
            print(json.dumps([to_json(d, s) for d, s in results], ensure_ascii=False, indent=2))
        else:
            for d, s in results:
                print_diagnosis(d, s)
        return 2 if any(d.stuck for d, _ in results) else 0

    if args.command == "fix":
        code = 0
        for d, s in results:
            print_diagnosis(d, s)
            if d.culprit is None:
                print("\nNo safe action to recommend.")
                code = 2 if d.stuck else code
            elif args.yes or confirm(d.culprit, d.instance.members[d.culprit]):
                stop(d.culprit)
        return code

    while True:
        rows_by_instance = [(d, s, print_diagnosis(d, s)) for d, s in results]
        d, s, rows = rows_by_instance[0]
        if len(rows_by_instance) > 1:
            print(c(f"\n{len(results)} Chrome instances found. Only the first one (pid {d.instance.browser.pid}) "
                    "is interactive. Use --pid to pick another.", "dim"))
        hint = "Enter = recommended, " if d.culprit else ""
        choice = input(f"\nNumber to stop ({hint}r = refresh, q = quit): ").strip().lower()
        if choice == "q":
            return 0
        if choice == "r":
            results = run_once(args)
            continue
        if choice == "" and d.culprit:
            pid = d.culprit
        elif choice.isdigit() and 1 <= int(choice) <= len(rows):
            pid = rows[int(choice) - 1]
        else:
            print("Not a valid choice.")
            continue
        if confirm(pid, d.instance.members[pid]):
            stop(pid)
            time.sleep(2)
        results = run_once(args)
        if not results:
            print("Chrome is no longer running.")
            return 0


if __name__ == "__main__":
    sys.exit(main())
