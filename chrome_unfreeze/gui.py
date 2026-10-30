"""GTK 4 and libadwaita window."""

import os
import sys
import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk  # noqa: E402

from .actions import DENIED, DONE, RESISTING, terminate  # noqa: E402
from .analyze import CAUTION, DANGER, SAFE, diagnose, find_instances, impact  # noqa: E402
from .cli import is_stuck  # noqa: E402
from .snapshot import take_snapshot  # noqa: E402

APP_ID = "io.github.otien.ChromeUnfreeze"
REFRESH_SECONDS = 5

ROLE_LABELS = {
    "browser": "Browser",
    "crashpad": "Crash handler",
    "gpu-process": "GPU process",
    "renderer": "Tabs",
    "extension": "Extension",
    "zygote": "Zygote",
    "dead": "Dead process",
    "utility:network": "Network service",
    "utility:storage": "Storage service",
    "utility:audio": "Audio service",
    "utility:video_capture": "Video capture",
}

GROUPS = [
    (SAFE, "Safe", "Chrome restarts these by itself. No tabs are lost."),
    (CAUTION, "Careful", "A tab or an extension will need a reload."),
    (DANGER, "Dangerous", "Can bring down all of Chrome."),
]


def label(r: str) -> str:
    if r in ROLE_LABELS:
        return ROLE_LABELS[r]
    if r.startswith("utility:"):
        return r.split(":", 1)[1].replace("_", " ").capitalize() + " service"
    return r


def mb(kb: int) -> str:
    return f"{kb / 1024 / 1024:.1f} GB" if kb >= 1024 * 1024 else f"{kb // 1024} MB"


def collect():
    """Called from a worker thread, since is_stuck() sleeps for a second."""
    snap = take_snapshot()
    results = []
    for inst in find_instances(snap, uid=None if os.getuid() == 0 else os.getuid()):
        results.append((diagnose(snap, inst, is_stuck(inst.browser.pid)), snap))
    return results


class Window(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="Chrome Unfreeze", default_width=760, default_height=820)
        self.results = []
        self.selected = 0
        self.busy = False
        self.dialog_open = False

        self.toasts = Adw.ToastOverlay()
        view = Adw.ToolbarView()
        header = Adw.HeaderBar()

        self.refresh_button = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="Refresh (Ctrl+R)")
        self.refresh_button.connect("clicked", lambda *_: self.refresh())
        header.pack_start(self.refresh_button)
        self.spinner = Adw.Spinner(visible=False)
        header.pack_start(self.spinner)

        self.instance_picker = Gtk.DropDown(visible=False, tooltip_text="Chrome instance")
        self.instance_picker.connect("notify::selected", self.on_instance_changed)
        header.pack_end(self.instance_picker)

        view.add_top_bar(header)

        self.scroller = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True)
        self.clamp = Adw.Clamp(maximum_size=720, tightening_threshold=560)
        self.scroller.set_child(self.clamp)
        self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)
        self.stack.add_named(Adw.StatusPage(title="Looking at Chrome…", child=Adw.Spinner(height_request=32)), "loading")
        self.stack.add_named(Adw.StatusPage(icon_name="web-browser-symbolic", title="Chrome is not running",
                                            description="No Chrome instance found for your user."),
                             "empty")
        self.stack.add_named(self.scroller, "main")
        view.set_content(self.stack)
        self.toasts.set_child(view)
        self.set_content(self.toasts)

        shortcut = Gtk.ShortcutController()
        shortcut.add_shortcut(Gtk.Shortcut(trigger=Gtk.ShortcutTrigger.parse_string("<Control>r"),
                                           action=Gtk.CallbackAction.new(lambda *_: self.refresh() or True)))
        self.add_controller(shortcut)

        self.refresh()
        GLib.timeout_add_seconds(REFRESH_SECONDS, self.auto_refresh)

    def auto_refresh(self):
        if not self.dialog_open and self.is_visible():
            self.refresh()
        return GLib.SOURCE_CONTINUE

    def refresh(self):
        if self.busy:
            return
        self.busy = True
        self.spinner.set_visible(True)
        self.refresh_button.set_sensitive(False)

        def work():
            try:
                results = collect()
            except Exception as exc:  # report it instead of letting the thread die silently
                GLib.idle_add(self.on_error, exc)
                return
            GLib.idle_add(self.on_results, results)

        threading.Thread(target=work, daemon=True).start()

    def on_error(self, exc):
        self.busy = False
        self.spinner.set_visible(False)
        self.refresh_button.set_sensitive(True)
        self.toast(f"Analysis failed: {exc}")

    def on_results(self, results):
        self.busy = False
        self.spinner.set_visible(False)
        self.refresh_button.set_sensitive(True)
        previous = self.current_pid()
        self.results = results

        names = [f"Chrome {d.instance.browser.pid}" for d, _ in results]
        self.instance_picker.set_visible(len(results) > 1)
        self.instance_picker.handler_block_by_func(self.on_instance_changed)
        self.instance_picker.set_model(Gtk.StringList.new(names))
        pids = [d.instance.browser.pid for d, _ in results]
        self.selected = pids.index(previous) if previous in pids else 0
        self.instance_picker.set_selected(self.selected)
        self.instance_picker.handler_unblock_by_func(self.on_instance_changed)

        self.render()

    def current_pid(self):
        if 0 <= self.selected < len(self.results):
            return self.results[self.selected][0].instance.browser.pid
        return None

    def on_instance_changed(self, picker, _pspec):
        self.selected = picker.get_selected()
        self.render()

    def render(self):
        if not self.results:
            self.stack.set_visible_child_name("empty")
            return
        adj = self.scroller.get_vadjustment()
        scroll = adj.get_value()

        d, snap = self.results[self.selected]
        members = d.instance.members
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24,
                       margin_top=24, margin_bottom=32, margin_start=12, margin_end=12)

        page.append(self.status_block(d, snap))

        if d.stuck and d.chain:
            group = Adw.PreferencesGroup(title="Wait chain",
                                         description="Each process is waiting on the next one. The last one is the blocker.")
            pids = [d.instance.browser.pid] + [pid for pid, _ in d.chain]
            waits = [why for _, why in d.chain] + ["Not waiting on anyone. This is the blocker."]
            for i, (pid, why) in enumerate(zip(pids, waits)):
                p = snap.procs.get(pid)
                r = members.get(pid, "?")
                row = Adw.ActionRow(title=f"{label(r)}  <span alpha='55%'>{pid}</span>", subtitle=why,
                                    subtitle_lines=3, use_markup=True)
                step = Gtk.Label(label=str(i + 1), width_chars=2, valign=Gtk.Align.CENTER)
                step.add_css_class("dim-label" if i < len(pids) - 1 else "error")
                step.add_css_class("numeric")
                row.add_prefix(step)
                if p is not None and p.state == "Z":
                    row.add_suffix(self.tag("dead"))
                group.add(row)
            page.append(group)

        if d.problems:
            group = Adw.PreferencesGroup(title="Problems found")
            for msg in d.problems:
                row = Adw.ActionRow(title=msg, title_lines=0)
                icon = Gtk.Image(icon_name="dialog-warning-symbolic")
                icon.add_css_class("warning")
                row.add_prefix(icon)
                group.add(row)
            page.append(group)

        for level, title, description in GROUPS:
            pids = [pid for pid, r in members.items()
                    if impact(r)[0] == level and snap.procs[pid].state != "Z"]
            if not pids:
                continue
            pids.sort(key=lambda pid: (pid != d.culprit, -snap.procs[pid].rss_kb))
            group = Adw.PreferencesGroup(title=title, description=description)
            for pid in pids:
                group.add(self.process_row(pid, members[pid], snap, level, pid == d.culprit))
            page.append(group)

        self.clamp.set_child(page)
        self.stack.set_visible_child_name("main")
        GLib.idle_add(adj.set_value, scroll)

    def status_block(self, d, snap):
        members = d.instance.members
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, halign=Gtk.Align.CENTER)
        icon = Gtk.Image(icon_name="dialog-warning-symbolic" if d.stuck else "object-select-symbolic",
                         pixel_size=64, margin_bottom=12)
        icon.add_css_class("error" if d.stuck else "success")
        box.append(icon)

        title = Gtk.Label(label="Chrome is frozen" if d.stuck else "Chrome is responding", wrap=True,
                          justify=Gtk.Justification.CENTER)
        title.add_css_class("title-1")
        box.append(title)

        total = sum(snap.procs[p].rss_kb for p in members)
        sub = Gtk.Label(label=f"pid {d.instance.browser.pid} · {len(members)} processes · {mb(total)} of RAM")
        sub.add_css_class("dim-label")
        box.append(sub)

        if d.culprit is not None:
            r = members[d.culprit]
            hint = Gtk.Label(
                label=f"The {label(r).lower()} ({d.culprit}) is blocking it. Stopping it is safe: "
                      f"{impact(r)[1]}.",
                wrap=True, justify=Gtk.Justification.CENTER, max_width_chars=60, margin_top=12)
            box.append(hint)
            button = Gtk.Button(label="Unfreeze Chrome", halign=Gtk.Align.CENTER, margin_top=12)
            button.add_css_class("pill")
            button.add_css_class("suggested-action")
            button.connect("clicked", lambda *_: self.kill(d.culprit, r, confirm=False))
            box.append(button)
        elif d.stuck:
            hint = Gtk.Label(label="The blocker isn't safe to stop. "
                                   "Check the risks below before you pick a process.",
                             wrap=True, justify=Gtk.Justification.CENTER, max_width_chars=60, margin_top=12)
            hint.add_css_class("dim-label")
            box.append(hint)
        return box

    def tag(self, text, css="dim-label"):
        lbl = Gtk.Label(label=text, valign=Gtk.Align.CENTER)
        lbl.add_css_class("caption")
        lbl.add_css_class(css)
        return lbl

    def process_row(self, pid, r, snap, level, recommended):
        p = snap.procs[pid]
        row = Adw.ActionRow(title=f"{label(r)}  <span alpha='55%'>{pid}</span>", use_markup=True,
                            subtitle=impact(r)[1], subtitle_lines=2)
        if recommended:
            row.add_suffix(self.tag("recommended", "accent"))
        if p.state == "D":
            row.add_suffix(self.tag("waiting on disk", "warning"))
        mem = self.tag(mb(p.rss_kb))
        mem.add_css_class("numeric")
        mem.set_width_chars(7)
        mem.set_xalign(1)
        row.add_suffix(mem)

        button = Gtk.Button(label="Stop", valign=Gtk.Align.CENTER)
        if level == DANGER:
            button.add_css_class("destructive-action")
        else:
            button.add_css_class("flat")
        button.connect("clicked", lambda *_: self.kill(pid, r, confirm=True))
        row.add_suffix(button)
        return row

    def kill(self, pid, r, confirm=True):
        level, text = impact(r)
        if not confirm and level == SAFE:
            self.do_kill(pid, r)
            return
        dialog = Adw.AlertDialog(heading=f"Stop {label(r)} ({pid})?", body=text[0].upper() + text[1:] + ".")
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("kill", "Stop")
        dialog.set_response_appearance(
            "kill", Adw.ResponseAppearance.SUGGESTED if level == SAFE else Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("kill" if level == SAFE else "cancel")
        dialog.set_close_response("cancel")
        self.dialog_open = True

        def on_response(_dialog, response):
            self.dialog_open = False
            if response == "kill":
                self.do_kill(pid, r)

        dialog.connect("response", on_response)
        dialog.present(self)

    def do_kill(self, pid, r, force=False):
        def work():
            result = terminate(pid, force=force)
            GLib.idle_add(self.after_kill, pid, r, result)

        threading.Thread(target=work, daemon=True).start()

    def after_kill(self, pid, r, result):
        if result == DONE:
            self.toast(f"{label(r)} ({pid}) stopped")
            GLib.timeout_add(1500, lambda: self.refresh() and False)
        elif result == DENIED:
            self.toast(f"Permission denied for {pid}")
        elif result == RESISTING:
            dialog = Adw.AlertDialog(heading="Process did not stop",
                                     body=f"{label(r)} ({pid}) ignored the request to stop. "
                                          "Forcing it kills it immediately, with no chance to clean up.")
            dialog.add_response("cancel", "Leave it")
            dialog.add_response("force", "Force stop")
            dialog.set_response_appearance("force", Adw.ResponseAppearance.DESTRUCTIVE)
            dialog.set_close_response("cancel")
            self.dialog_open = True

            def on_response(_dialog, response):
                self.dialog_open = False
                if response == "force":
                    self.do_kill(pid, r, force=True)

            dialog.connect("response", on_response)
            dialog.present(self)

    def toast(self, text):
        self.toasts.add_toast(Adw.Toast(title=text, timeout=4))


class App(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID)

    def do_activate(self):
        win = self.get_active_window() or Window(self)
        win.present()


def run() -> int:
    GLib.set_application_name("Chrome Unfreeze")
    return App().run([sys.argv[0]])
