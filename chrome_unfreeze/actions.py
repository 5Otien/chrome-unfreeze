"""Stops a process: SIGTERM first, SIGKILL only when asked for."""

import os
import signal
import time

from .snapshot import read_proc

DONE, DENIED, RESISTING = "done", "denied", "resisting"


def terminate(pid: int, force: bool = False, timeout: float = 3.0) -> str:
    try:
        os.kill(pid, signal.SIGKILL if force else signal.SIGTERM)
    except ProcessLookupError:
        return DONE
    except PermissionError:
        return DENIED
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        p = read_proc(pid, with_fds=False)
        if p is None or p.state == "Z":
            return DONE
        time.sleep(0.1)
    return RESISTING
