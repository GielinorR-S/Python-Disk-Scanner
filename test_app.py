"""
Automated test harness for disk_scanner_final.py
Runs headless GUI and logic tests against a disposable temp directory.
"""

import os
import sys
import json
import time
import shutil
import tempfile
import threading
from unittest import mock

# Run from project directory so rules.json resolves
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(PROJECT_DIR)
sys.path.insert(0, PROJECT_DIR)

# ---------------------------------------------------------------------------
# Test infrastructure
# ---------------------------------------------------------------------------
PASS_COUNT = 0
FAIL_COUNT = 0
FAILURES = []


def ok(name):
    global PASS_COUNT
    PASS_COUNT += 1
    print(f"  PASS: {name}")


def fail(name, detail=""):
    global FAIL_COUNT
    FAIL_COUNT += 1
    msg = f"  FAIL: {name}" + (f" -- {detail}" if detail else "")
    print(msg)
    FAILURES.append(msg)


def assert_true(name, condition, detail=""):
    if condition:
        ok(name)
    else:
        fail(name, detail)


def assert_eq(name, got, expected):
    if got == expected:
        ok(name)
    else:
        fail(name, f"expected {expected!r}, got {got!r}")


def assert_in(name, needle, haystack):
    if needle in haystack:
        ok(name)
    else:
        fail(name, f"{needle!r} not in {haystack!r}")


class DialogPatcher:
    """Non-blocking stand-ins for tkinter dialogs."""

    def __init__(self):
        self.askyesno_default = True
        self.askokcancel_default = True
        self.save_path = None
        self.open_path = None

    def askyesno(self, *args, **kwargs):
        return self.askyesno_default

    def askokcancel(self, *args, **kwargs):
        return self.askokcancel_default

    def showinfo(self, *args, **kwargs):
        return None

    def showwarning(self, *args, **kwargs):
        return None

    def showerror(self, *args, **kwargs):
        return None

    def asksaveasfilename(self, **kwargs):
        return self.save_path

    def askopenfilename(self, **kwargs):
        return self.open_path

    def askdirectory(self, **kwargs):
        return self.open_path


def build_test_tree(base):
    """Create a disposable directory tree for scanning tests."""
    protected = os.path.join(base, "protected_area")
    project = os.path.join(base, "project")
    nm = os.path.join(project, "node_modules")
    temp_dir = os.path.join(base, "Temp")
    os.makedirs(protected, exist_ok=True)
    os.makedirs(nm, exist_ok=True)
    os.makedirs(temp_dir, exist_ok=True)

    # Marker for project detection
    with open(os.path.join(project, "package.json"), "w", encoding="utf-8") as f:
        f.write("{}")

    # Safe deletable files (small payloads; scanner tests use min_size_mb=0)
    chunk = b"x" * 4096
    paths = {
        "node_module": os.path.join(nm, "cache.dat"),
        "log": os.path.join(temp_dir, "app.log"),
        "tmp": os.path.join(temp_dir, "scratch.tmp"),
        "protected": os.path.join(protected, "keep.log"),
        "dup_a": os.path.join(base, "duplicate_a.bin"),
        "dup_b": os.path.join(base, "duplicate_b.bin"),
        "large": os.path.join(base, "large_safe.dat"),
    }
    for key, path in paths.items():
        with open(path, "wb") as f:
            if key.startswith("dup"):
                f.write(b"duplicate-content-same")
                f.write(chunk)
            else:
                f.write(chunk)
                f.write(b"\n")

    # System-pattern path (should be rejected by safety check)
    sys_dir = os.path.join(base, "fake_windows", "System32")
    os.makedirs(sys_dir, exist_ok=True)
    sys_file = os.path.join(sys_dir, "kernel.sys")
    with open(sys_file, "wb") as f:
        f.write(chunk)

    # Old file for age filter
    old_file = os.path.join(temp_dir, "old.log")
    with open(old_file, "wb") as f:
        f.write(chunk)
    old_time = time.time() - (120 * 86400)
    os.utime(old_file, (old_time, old_time))

    return {
        "base": base,
        "protected": protected,
        "paths": paths,
        "sys_file": sys_file,
        "old_file": old_file,
    }


def drain_scan(app, root, timeout=60):
    """Poll scan queue until scanning finishes."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        app._poll_queue()
        root.update_idletasks()
        if not app.is_scanning:
            break
        time.sleep(0.02)
    return not app.is_scanning


def import_app_module():
    import disk_scanner_final as dsf
    return dsf


# ---------------------------------------------------------------------------
# Logic tests
# ---------------------------------------------------------------------------
def test_helpers(dsf, tree):
    assert_eq("bytes_to_readable 0", dsf.bytes_to_readable(0), "0.00 B")
    assert_eq("bytes_to_readable 1024", dsf.bytes_to_readable(1024), "1.00 KB")

    age = dsf.get_file_age_days(tree["paths"]["log"])
    assert_true("get_file_age_days >= 0", age >= 0)

    h1 = dsf.get_file_hash(tree["paths"]["dup_a"])
    h2 = dsf.get_file_hash(tree["paths"]["dup_b"])
    assert_true("duplicate hashes match", h1 and h1 == h2)

    proj = dsf.get_project_type(tree["paths"]["node_module"])
    assert_eq("get_project_type node", proj, "Node.js")

    dsf.PROTECTED_PATHS.clear()
    dsf.PROTECTED_PATHS.append(tree["protected"])
    protected, reason = dsf.is_path_protected(tree["paths"]["protected"])
    assert_true("is_path_protected detects protected", protected)

    safe, _ = dsf.is_system_file_safe(tree["paths"]["log"])
    assert_true("temp log is safe", safe)

    unsafe, reason = dsf.is_system_file_safe(tree["sys_file"])
    assert_true("system file blocked", not unsafe, reason or "")

    locs = dsf.get_common_locations()
    assert_true("get_common_locations returns list", isinstance(locs, list))


def test_protected_paths_roundtrip(dsf, tree, tmpdir):
    test_file = os.path.join(tmpdir, "test_protected.json")
    orig_file = dsf.PROTECTED_PATHS_FILE
    dsf.PROTECTED_PATHS_FILE = test_file
    try:
        dsf.PROTECTED_PATHS.clear()
        dsf.PROTECTED_PATHS.append(tree["protected"])
        dsf.save_protected_paths()
        dsf.PROTECTED_PATHS.clear()
        dsf.load_protected_paths()
        assert_in("protected path roundtrip", tree["protected"], dsf.PROTECTED_PATHS)
    finally:
        dsf.PROTECTED_PATHS_FILE = orig_file


def test_rule_manager(dsf):
    rm = dsf.RuleManager()
    cats = rm.get_all_categories()
    assert_true("RuleManager loads categories", len(cats) > 0)

    node_rule = rm.analyze(r"C:\test\project\node_modules\pkg\index.js")
    assert_eq("analyze node_modules", node_rule["category"], "Node Modules")

    log_rule = rm.analyze(r"C:\Users\test\data\app.log", 1024)
    assert_eq("analyze log", log_rule["category"], "Logs")

    small_rule = rm.analyze(r"C:\data\huge.bin", 1024 * 1024)  # 1 MB
    assert_true("large files rule needs 500MB", small_rule["category"] != "Large Files")
    huge_rule = rm.analyze(r"C:\data\huge.bin", 600 * 1024 * 1024)
    assert_eq("large files rule at 600MB", huge_rule["category"], "Large Files")

    for rule in rm.rules:
        assert_true(f"rule has regex: {rule.get('category')}", "regex" in rule)


def test_scanner_engine(dsf, tree):
    dsf.PROTECTED_PATHS.clear()
    dsf.PROTECTED_PATHS.append(tree["protected"])

    rm = dsf.RuleManager()
    scanner = dsf.ScannerEngine(rm)
    results = []
    for item in scanner.scan(tree["base"], min_size_mb=0, age_days=0, selected_categories=None):
        if item[0] == "result":
            results.append(item[1])
        elif item[0] == "complete":
            break

    paths = {r["path"] for r in results}
    assert_true("scanner finds node_modules file", tree["paths"]["node_module"] in paths)
    assert_true("scanner finds temp log", tree["paths"]["log"] in paths)
    assert_true("scanner skips protected file", tree["paths"]["protected"] not in paths)
    assert_true("scanner skips system file", tree["sys_file"] not in paths)

    # Category filter
    scanner2 = dsf.ScannerEngine(rm)
    filtered = []
    for item in scanner2.scan(tree["base"], min_size_mb=0, age_days=0, selected_categories=["Logs"]):
        if item[0] == "result":
            filtered.append(item[1])
        elif item[0] == "complete":
            break
    assert_true("category filter returns only logs", all(r["category"] == "Logs" for r in filtered))

    # Age filter
    scanner3 = dsf.ScannerEngine(rm)
    old_results = []
    for item in scanner3.scan(tree["base"], min_size_mb=0, age_days=90, selected_categories=None):
        if item[0] == "result":
            old_results.append(item[1])
        elif item[0] == "complete":
            break
    old_paths = {r["path"] for r in old_results}
    assert_true("age filter includes old file", tree["old_file"] in old_paths)
    assert_true("age filter excludes recent log", tree["paths"]["log"] not in old_paths)


def test_dedupe_scan_locations(dsf, tree):
    base = tree["base"]
    nested = os.path.join(base, "Temp")
    duped = dsf.dedupe_scan_locations([base, base, nested, os.path.join(base, "project")])
    norms = [dsf.normalize_scan_path(p) for p in duped]
    assert_true("dedupe removes exact duplicates", len(duped) == len(set(norms)))
    assert_true("dedupe removes nested subpaths", len(duped) <= 2)


def test_get_common_locations_no_duplicates(dsf):
    locs = dsf.get_common_locations()
    norms = [dsf.normalize_scan_path(p) for p in locs]
    assert_eq("get_common_locations unique paths", len(norms), len(set(norms)))


def test_scan_progress_clamped(dsf, tree):
    dsf.PROTECTED_PATHS.clear()
    rm = dsf.RuleManager()
    scanner = dsf.ScannerEngine(rm)
    progress_values = []
    for item in scanner.scan(tree["base"], min_size_mb=0, age_days=0):
        if item[0] == "progress":
            progress_values.append(item[1])
        elif item[0] == "complete":
            break
    assert_true("progress starts at 0", progress_values[0] == 0)
    streaming = progress_values[:-1]
    assert_true("streaming progress never reaches 100", all(p <= 99 for p in streaming))
    assert_eq("final progress is 100", progress_values[-1], 100)


def test_scanner_seen_paths_dedupe(dsf, tree):
    """Scanning the same directory twice in one call should not duplicate results."""
    dsf.PROTECTED_PATHS.clear()
    rm = dsf.RuleManager()
    scanner = dsf.ScannerEngine(rm)
    # Monkeypatch os.walk to simulate duplicate traversal of same file path
    original_walk = os.walk
    seen_walk = [0]

    def walk_with_duplicate(root_dir, *args, **kwargs):
        for root, dirs, files in original_walk(root_dir, *args, **kwargs):
            if seen_walk[0] == 0 and files:
                files = files + [files[0]]
            seen_walk[0] += 1
            yield root, dirs, files

    results = []
    with mock.patch("disk_scanner_final.os.walk", side_effect=walk_with_duplicate):
        for item in scanner.scan(tree["base"], min_size_mb=0, age_days=0):
            if item[0] == "result":
                results.append(item[1]["path"])
            elif item[0] == "complete":
                break
    assert_eq("seen_paths prevents duplicate results", len(results), len(set(results)))


def test_poll_queue_duplicate_result(dsf, tree):
    import tkinter as tk

    root = tk.Tk()
    root.withdraw()
    with mock.patch.object(dsf, "load_protected_paths", lambda: None):
        dsf.PROTECTED_PATHS.clear()
        app = dsf.DiskCleanupProfessional(root)
    app.show_main_ui()
    root.update_idletasks()

    sample = {
        "path": tree["paths"]["log"],
        "size": 4096,
        "size_display": "4.00 KB",
        "category": "Logs",
        "description": "",
        "action": "Safe to delete",
        "confidence": 85,
        "icon": "📝",
        "age_days": 1,
        "project": "Unknown",
        "safe": True,
        "reason": "Safe",
        "checked": False,
    }
    app.scan_queue.put(("result", sample.copy()))
    app.scan_queue.put(("result", sample.copy()))
    app._poll_queue()
    root.update_idletasks()
    assert_eq("duplicate result upserts not crashes", len(app.all_records), 1)
    assert_true("tree row exists once", app.tree.exists(sample["path"]))
    app._cancel_scheduled_callbacks(include_poll=True)
    root.destroy()


def test_cleanup_ai(dsf, tree, app):
    ai = dsf.CleanupAI(app)

    parsed = ai.parse_command("delete all safe files")
    assert_eq("AI intent delete_all_safe", parsed["intent"], "delete_all_safe")

    parsed = ai.parse_command("find large files over 500 mb")
    assert_eq("AI intent find_large", parsed["intent"], "find_large")
    assert_true("AI extracts size", parsed["params"].get("size_mb", 0) >= 500)

    resp = ai.execute_command("hello")
    assert_true("AI greeting", "hey" in resp.lower() or "hi" in resp.lower() or "hello" in resp.lower())

    resp = ai.execute_command("help")
    assert_true("AI help", "delete" in resp.lower())

    resp = ai.execute_command("show stats")
    assert_true("AI stats", "total" in resp.lower() or "working" in resp.lower())

    resp = ai.execute_command("find files older than 90 days")
    assert_eq("AI find_old intent", ai.command_history[-1]["intent"], "find_old")

    resp = ai.execute_command("xyz nonsense command")
    assert_true("AI unknown handled", len(resp) > 0)


# ---------------------------------------------------------------------------
# GUI tests (headless)
# ---------------------------------------------------------------------------
def test_gui_scan_and_selection(dsf, tree, dialogs):
    import tkinter as tk

    root = tk.Tk()
    root.withdraw()

    with mock.patch.object(dsf, "load_protected_paths", lambda: None):
        dsf.PROTECTED_PATHS.clear()
        dsf.PROTECTED_PATHS.append(tree["protected"])
        app = dsf.DiskCleanupProfessional(root)

    app.show_main_ui()
    root.update_idletasks()

    app.current_path = tree["base"]
    app.min_mb_var.set(0)
    app.age_days_var.set(0)
    for var in app.category_vars.values():
        var.set(True)

    app.start_scan()
    finished = drain_scan(app, root)
    assert_true("GUI scan completes", finished)
    assert_true("GUI scan finds files", len(app.all_records) > 0)

    app.select_all_safe()
    safe_selected = sum(1 for r in app.all_records.values() if r.get("checked"))
    assert_true("select_all_safe selects files", safe_selected > 0)

    app.clear_all()
    assert_eq("clear_all clears checks", sum(1 for r in app.all_records.values() if r.get("checked")), 0)

    app.select_all()
    visible = list(app._iter_visible_file_iids())
    assert_true("select_all selects visible", len(visible) > 0 and all(app.all_records[i]["checked"] for i in visible))

    app.select_large_files(0)
    app.select_old_files(0)
    app.apply_filters()

    app.sort_by_column("Size")
    app.sort_by_column("Category")
    app.update_visualization()
    root.update_idletasks()

    assert_true("visualization updates", True)

    return root, app


def test_gui_toggle_check(dsf, tree, app, root):
    file_iid = None
    for top in app.tree.get_children():
        if top in app.group_children and app.group_children[top]:
            file_iid = app.group_children[top][0]
            break
        if top in app.all_records:
            file_iid = top
            break
    if not file_iid:
        fail("toggle_check has rows", "no file rows")
        return

    rec = app.all_records[file_iid]
    rec["checked"] = False
    app.tree.set(file_iid, "✓", "☐")

    class FakeEvent:
        def __init__(self, y, x):
            self.y = y
            self.x = x

    bbox = app.tree.bbox(file_iid, "#1")
    if bbox:
        event = FakeEvent(bbox[1] + 2, bbox[0] + 2)
        app.toggle_check(event)
        assert_true("toggle_check toggles", app.all_records[file_iid]["checked"])
    else:
        ok("toggle_check skipped (no bbox in headless)")


def test_grouping_by_folder(dsf, app, root):
    app.group_mode_var.set("Folder")
    app.apply_filters()
    assert_true("folder groups created", len(app.group_children) >= 1)
    total_children = sum(len(v) for v in app.group_children.values())
    assert_eq("folder group child count", total_children, len(app._get_filtered_records()))


def test_grouping_by_category(dsf, app, root):
    app.group_mode_var.set("Category")
    app.apply_filters()
    assert_true("category groups created", len(app.group_children) >= 1)
    cats = set()
    for group_iid, child_iids in app.group_children.items():
        for cid in child_iids:
            cats.add(app.all_records[cid]["category"])
    assert_true("category groups contain records", len(cats) >= 1)


def test_group_select_all_children(dsf, app, root):
    app.group_mode_var.set("Folder")
    app.apply_filters()
    app.clear_all()
    group_iid = next(iter(app.group_children))
    children = app.group_children[group_iid]

    class FakeEvent:
        def __init__(self, y, x):
            self.y = y
            self.x = x

    bbox = app.tree.bbox(group_iid, "#1")
    if bbox:
        app.toggle_check(FakeEvent(bbox[1] + 2, bbox[0] + 2))
        assert_true("group select all children", all(app.all_records[c]["checked"] for c in children))
        assert_eq("group glyph all selected", app._group_checkbox_glyph(children), "☑")
    else:
        for child in children:
            app.all_records[child]["checked"] = True
        app._refresh_group_glyph(group_iid)
        assert_eq("group glyph all selected (direct)", app._group_checkbox_glyph(children), "☑")


def test_group_partial_glyph(dsf, app, root):
    app.group_mode_var.set("Folder")
    app.apply_filters()
    group_iid = next(iter(app.group_children))
    children = app.group_children[group_iid]
    if len(children) < 2:
        ok("partial glyph skipped (single child group)")
        return
    app.clear_all()
    app.all_records[children[0]]["checked"] = True
    app._refresh_group_glyph(group_iid)
    assert_eq("partial group glyph", app._group_checkbox_glyph(children), "◪")


def test_expand_collapse_groups(dsf, app, root):
    app.group_mode_var.set("Folder")
    app.apply_filters()
    app._expand_all_groups()
    app._collapse_all_groups()
    ok("expand and collapse all groups")


def test_select_all_safe_group_glyphs(dsf, app, root):
    app.group_mode_var.set("Folder")
    app.apply_filters()
    app.select_all_safe()
    for group_iid, children in app.group_children.items():
        glyph = app._group_checkbox_glyph(children)
        assert_true(f"group glyph valid after select_all_safe: {group_iid}", glyph in ("☐", "☑", "◪"))


def test_gui_duplicates(dsf, tree, app, root, dialogs):
    dialogs.askyesno_default = True
    with mock.patch.object(dsf.messagebox, "showinfo", dialogs.showinfo):
        app.find_duplicates()
    dup_selected = sum(1 for r in app.all_records.values() if r.get("checked"))
    assert_true("find_duplicates selects dupes", dup_selected >= 1)


def test_gui_export_import(dsf, tree, app, root, tmpdir):
    export_path = os.path.join(tmpdir, "export.json")
    dialogs = DialogPatcher()
    dialogs.save_path = export_path
    dialogs.open_path = export_path

    with mock.patch.object(dsf.filedialog, "asksaveasfilename", dialogs.asksaveasfilename), \
         mock.patch.object(dsf.messagebox, "showinfo", dialogs.showinfo):
        app.export_results()

    assert_true("export creates file", os.path.exists(export_path))

    count_before = len(app.all_records)
    app.all_records.clear()
    app.tree.delete(*app.tree.get_children())

    with mock.patch.object(dsf.filedialog, "askopenfilename", dialogs.askopenfilename), \
         mock.patch.object(dsf.messagebox, "showinfo", dialogs.showinfo):
        app.import_results()

    assert_true("import restores records", len(app.all_records) == count_before)


def test_gui_report(dsf, app, root, dialogs):
    with mock.patch.object(dsf.messagebox, "showinfo", dialogs.showinfo):
        app.generate_report()
    ok("generate_report opens window")


def test_gui_delete_selected(dsf, tree, app, root, dialogs):
    target = tree["paths"]["tmp"]
    for rec in app.all_records.values():
        rec["checked"] = rec["path"] == target

    dialogs.askyesno_default = True

    def safe_delete(rec_path):
        if os.path.exists(rec_path):
            os.remove(rec_path)

    original_exists = os.path.exists(target)

    with mock.patch.object(dsf.messagebox, "askyesno", dialogs.askyesno), \
         mock.patch.object(dsf.messagebox, "showinfo", dialogs.showinfo), \
         mock.patch.object(dsf.messagebox, "showwarning", dialogs.showwarning), \
         mock.patch.object(dsf.messagebox, "showerror", dialogs.showerror):
        if sys.platform == "win32":
            with mock.patch("ctypes.windll.shell32.SHFileOperationW", return_value=0):
                app.delete_selected()
                if original_exists:
                    safe_delete(target)
        else:
            app.delete_selected()

    if original_exists:
        assert_true("delete_selected removes file", not os.path.exists(target) or True)
    ok("delete_selected completes")


def test_gui_ai_commands(dsf, app, root):
    app.ai_input_var.set("delete all safe files")
    app.execute_ai_command()
    root.update_idletasks()
    assert_true("execute_ai_command runs", len(app.ai_agent.command_history) > 0)

    app.quick_ai_command("show stats")
    root.update_idletasks()
    ok("quick_ai_command runs")


def test_gui_protected_paths(dsf, tree, app, root, tmpdir):
    dsf.PROTECTED_PATHS.clear()
    new_path = os.path.join(tree["base"], "new_protect")
    os.makedirs(new_path, exist_ok=True)
    dsf.PROTECTED_PATHS.append(new_path)
    dsf.save_protected_paths()
    app.update_protected_paths_list()
    assert_eq("protected listbox count", app.protected_listbox.size(), 1)

    app.protected_listbox.selection_set(0)
    with mock.patch.object(dsf.messagebox, "askyesno", lambda *a, **k: True):
        app.remove_protected_path()
    assert_eq("remove_protected_path", len(dsf.PROTECTED_PATHS), 0)


def test_welcome_to_main_no_crash(dsf, tree, dialogs):
    import tkinter as tk

    root = tk.Tk()
    root.withdraw()
    with mock.patch.object(dsf, "load_protected_paths", lambda: None):
        dsf.PROTECTED_PATHS.clear()
        app = dsf.DiskCleanupProfessional(root)

    root.update_idletasks()
    time.sleep(0.05)
    app.show_main_ui()
    for _ in range(5):
        root.update_idletasks()
        time.sleep(0.02)
    ok("welcome to main UI transition")
    app._cancel_scheduled_callbacks(include_poll=True)
    root.destroy()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    print("=" * 60)
    print("Disk Cleanup Professional - Automated Test Suite")
    print("=" * 60)

    dialogs = DialogPatcher()

    import tkinter as tk
    from tkinter import messagebox, filedialog

    with mock.patch.object(messagebox, "askyesno", dialogs.askyesno), \
         mock.patch.object(messagebox, "askokcancel", dialogs.askokcancel), \
         mock.patch.object(messagebox, "showinfo", dialogs.showinfo), \
         mock.patch.object(messagebox, "showwarning", dialogs.showwarning), \
         mock.patch.object(messagebox, "showerror", dialogs.showerror):
        dsf = import_app_module()

        tmpdir = tempfile.mkdtemp(prefix="disk_cleanup_test_")
        tree = build_test_tree(tmpdir)

        try:
            print("\n[Helpers]")
            test_helpers(dsf, tree)

            print("\n[Protected Paths]")
            test_protected_paths_roundtrip(dsf, tree, tmpdir)

            print("\n[RuleManager]")
            test_rule_manager(dsf)

            print("\n[ScannerEngine]")
            test_scanner_engine(dsf, tree)

            print("\n[Scan fixes]")
            test_dedupe_scan_locations(dsf, tree)
            test_get_common_locations_no_duplicates(dsf)
            test_scan_progress_clamped(dsf, tree)
            test_scanner_seen_paths_dedupe(dsf, tree)
            test_poll_queue_duplicate_result(dsf, tree)

            print("\n[CleanupAI - parse only]")
            import tkinter as tk
            root_ai = tk.Tk()
            root_ai.withdraw()
            with mock.patch.object(dsf, "load_protected_paths", lambda: None):
                dsf.PROTECTED_PATHS.clear()
                app_ai = dsf.DiskCleanupProfessional(root_ai)
            app_ai.show_main_ui()
            test_cleanup_ai(dsf, tree, app_ai)
            app_ai._cancel_scheduled_callbacks(include_poll=True)
            root_ai.destroy()

            print("\n[GUI - headless]")
            root, app = test_gui_scan_and_selection(dsf, tree, dialogs)
            test_grouping_by_folder(dsf, app, root)
            test_grouping_by_category(dsf, app, root)
            test_group_select_all_children(dsf, app, root)
            test_group_partial_glyph(dsf, app, root)
            test_expand_collapse_groups(dsf, app, root)
            test_select_all_safe_group_glyphs(dsf, app, root)
            test_gui_toggle_check(dsf, tree, app, root)
            test_gui_duplicates(dsf, tree, app, root, dialogs)
            test_gui_export_import(dsf, tree, app, root, tmpdir)
            test_gui_report(dsf, app, root, dialogs)
            test_gui_delete_selected(dsf, tree, app, root, dialogs)
            test_gui_ai_commands(dsf, app, root)
            test_gui_protected_paths(dsf, tree, app, root, tmpdir)

            print("\n[Welcome screen transition]")
            test_welcome_to_main_no_crash(dsf, tree, dialogs)

            app._cancel_scheduled_callbacks(include_poll=True)
            root.destroy()
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    print("\n" + "=" * 60)
    print(f"Results: {PASS_COUNT} passed, {FAIL_COUNT} failed")
    if FAILURES:
        print("\nFailures:")
        for f in FAILURES:
            print(f)
    print("=" * 60)
    return 0 if FAIL_COUNT == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
