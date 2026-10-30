# Chrome Unfreeze

Unfreeze a hung Google Chrome on Linux without losing your tabs.

When Chrome keeps showing "Google Chrome is not responding", the usual move is to click Force Quit and lose everything. Often, though, one small process is blocking all the others. Chrome Unfreeze reads `/proc` to find out which one, tells you what stopping it will cost, and lets you stop only that one.

There is a GTK 4 / libadwaita window (it follows your light or dark theme) and a terminal command.

## Install

You need Linux and Python 3.10 or newer. The window also needs GTK 4 and libadwaita 1.6 or newer, which any recent GNOME desktop already has. On Debian or Ubuntu you can get them with `sudo apt install python3-gi gir1.2-adw-1`.

```bash
git clone https://github.com/5Otien/chrome-unfreeze
cd chrome-unfreeze
./install.sh
```

This puts a single executable file in `~/.local/bin/chrome-unfreeze` and adds a Chrome Unfreeze launcher to your applications menu. No sudo needed. Run `./install.sh --remove` to uninstall.

If you only want the executable, `./build.sh` writes it to `dist/chrome-unfreeze` and installs nothing.

## Usage

### The window

Open Chrome Unfreeze from the applications menu, or run `chrome-unfreeze gui`.

If Chrome is fine, you get its processes sorted into three groups (safe, careful, dangerous), with a line under each one saying what stopping it would do.

If Chrome is frozen, the window shows the wait chain and the process at the end of it. If that process is safe to stop, the Unfreeze Chrome button stops it in one click.

The view refreshes every 5 seconds. Press `Ctrl+R` to refresh by hand.

### The terminal

| Command | What it does |
|---|---|
| `chrome-unfreeze` | Diagnose, then pick a process to stop from a menu |
| `chrome-unfreeze diag` | Diagnose only, touch nothing (exits with 2 if Chrome is frozen) |
| `chrome-unfreeze diag --json` | Same, as JSON |
| `chrome-unfreeze fix` | Apply the recommended safe action after asking (`-y` skips the question) |
| `chrome-unfreeze gui` | Open the window |
| `--pid N` | Look at one specific Chrome instance |

## What stopping each process costs

| Process | Risk | Consequence |
|---|---|---|
| Crash handler (`crashpad`) | safe | No tabs affected, crash reports are off until the next restart |
| GPU process | safe | Chrome restarts it, the screen flickers and videos or WebGL reload |
| Helper services (audio, storage...) | safe | Started again when needed |
| Network service | caution | Chrome restarts it, but downloads and requests in flight are cut |
| Extension | caution | The extension crashes and has to be reloaded |
| Tabs (`renderer`) | caution | Its tabs show "Aw, Snap!" and need a reload, unsent form input is lost |
| Zygote | danger | No new tabs can open and Chrome will likely crash |
| Browser | danger | Closes all of Chrome, tabs come back when you restart it |

The tool only ever recommends stopping a safe process. Anything marked caution or danger asks you first.

## How it works

A frozen program is almost always waiting on something. Chrome Unfreeze follows that wait from one process to the next, the way you would by hand with `/proc` and `ss`.

First it checks what the process is waiting on. `/proc/<pid>/syscall` gives the system call in progress and its arguments, for example a `read` on fd 10 or a `wait4` on pid 3440968.

Then it finds who is on the other end. For a `read` or `recvmsg` on a socket, `/proc/<pid>/fd/<n>` gives the socket inode, `ss -x` gives the inode of its peer, and a pass over `/proc/*/fd` finds the process holding that peer. For `wait4` or `waitid`, it is the child being waited on, matched through `NSpid` because Chrome's sandbox has its own pid numbers. For a dead (zombie) process that never goes away, `TracerPid` shows which process has it attached with `ptrace` and is keeping it from being reaped.

It repeats this until it reaches a process that isn't waiting on anyone. That's the blocker.

Chrome only counts as frozen if its main thread stays in the same blocking wait for a full second, so a busy but healthy Chrome isn't flagged. The tool also reports indirect causes: a missing GPU process, processes stuck on the disk (state `D`), and low RAM or swap.

### The bug that started this

```
Browser  --read()-->  Zygote  --wait4()-->  dead GPU process  <--ptrace--  crashpad
```

Chrome's GPU process had crashed. The crash handler attached to the dead process to write a report and never detached. The zygote was waiting to reap that dead process, and the browser was waiting on the zygote before it could start a new GPU process. Killing crashpad was enough to unblock everything, and no tab was closed.

## Limits

Linux only, on x86_64 and aarch64. It recognizes Chrome, Chromium, Brave and Edge.

It only looks at your own processes unless you run it as root.

`/proc` cannot tell which tabs a renderer process is hosting. If Chrome still responds a little, its own task manager (`Shift+Esc`) shows that mapping.

## Development

```bash
python3 -m chrome_unfreeze          # run from source
python3 -m unittest discover -s tests -v
```

`tests/test_live.py` reproduces the hang with real processes (a read on a socket, then a `wait4`, then a zombie held by `ptrace`) and checks that the whole chain is found. It's skipped when ptrace is restricted (`kernel.yama.ptrace_scope` other than 0).

## License

MIT
