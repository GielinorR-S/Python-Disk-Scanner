import os
import sys
import re
import json
import queue
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# =========================
# Config
# =========================
DEFAULT_MIN_MB = 1
RULES_FILE = "rules.json"

PROJECT_MARKERS = {
    "Node.js": ["package.json"],
    "Python": ["pyproject.toml", "requirements.txt"],
    ".NET": [".sln", ".csproj"],
    "Java": ["pom.xml", "build.gradle"],
}

# =========================
# Helpers
# =========================
def bytes_to_readable(n):
    if n >= 1024**3:
        return f"{n / (1024**3):.2f} GB"
    if n >= 1024**2:
        return f"{n / (1024**2):.2f} MB"
    return f"{n / 1024:.0f} KB"

# =========================
# Load Rules
# =========================
def load_rules():
    rules = []
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            for r in json.load(f):
                r["regex"] = re.compile(r["match"], re.IGNORECASE)
                rules.append(r)
    return rules

RULES = load_rules()

def analyze(path):
    p = path.lower()
    for r in RULES:
        if r["regex"].search(p):
            return r
    return {
        "category": "Unknown",
        "relevance": "Unknown",
        "description": "Unclassified file",
        "action": "Review before deleting",
        "confidence": 30
    }

# =========================
# Project Detection
# =========================
_project_cache = {}

def detect_project(path):
    folder = os.path.dirname(path)
    if folder in _project_cache:
        return _project_cache[folder]

    cur = folder
    while True:
        for name, markers in PROJECT_MARKERS.items():
            for m in markers:
                if os.path.exists(os.path.join(cur, m)):
                    proj = f"{os.path.basename(cur)} ({name})"
                    _project_cache[folder] = proj
                    return proj
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent

    _project_cache[folder] = "Unknown / System"
    return "Unknown / System"

# =========================
# Windows Recycle Bin Delete
# =========================
def recycle_delete(path):
    if sys.platform != "win32":
        os.remove(path)
        return
    import ctypes
    from ctypes import wintypes

    FO_DELETE = 3
    FOF_ALLOWUNDO = 0x40

    class SHFILEOPSTRUCTW(ctypes.Structure):
        _fields_ = [
            ("hwnd", wintypes.HWND),
            ("wFunc", wintypes.UINT),
            ("pFrom", wintypes.LPCWSTR),
            ("pTo", wintypes.LPCWSTR),
            ("fFlags", wintypes.UINT),
            ("fAnyOperationsAborted", wintypes.BOOL),
            ("hNameMappings", wintypes.LPVOID),
            ("lpszProgressTitle", wintypes.LPCWSTR),
        ]

    op = SHFILEOPSTRUCTW()
    op.wFunc = FO_DELETE
    op.pFrom = path + "\0\0"
    op.fFlags = FOF_ALLOWUNDO
    ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))

# =========================
# App
# =========================
class DiskCleanupApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Intelligent Disk Cleanup")
        self.root.geometry("1600x860")

        self.records = {}
        self.queue = queue.Queue()
        self.search_var = tk.StringVar()
        self.min_mb_var = tk.IntVar(value=DEFAULT_MIN_MB)

        self._build_styles()
        self._build_ui()
        self._poll_queue()

    def _build_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("Sub.TLabel", font=("Segoe UI", 10))
        style.configure("Toolbar.TFrame", padding=8)
        style.configure("Status.TLabel", font=("Segoe UI", 10))

    def _build_ui(self):
        # Header
        header = ttk.Frame(self.root, padding=12)
        header.pack(fill=tk.X)

        ttk.Label(header, text="Intelligent Disk Cleanup", style="Header.TLabel").pack(anchor="w")
        ttk.Label(header, text="Project-aware • Offline-first • Safe cleanup", style="Sub.TLabel").pack(anchor="w")

        # Toolbar
        toolbar = ttk.Frame(self.root, style="Toolbar.TFrame")
        toolbar.pack(fill=tk.X)

        ttk.Button(toolbar, text="Scan Folder / Drive", command=self.start_scan).pack(side=tk.LEFT)
        ttk.Label(toolbar, text="Min size (MB):").pack(side=tk.LEFT, padx=(12, 4))
        ttk.Spinbox(toolbar, from_=1, to=102400, width=6, textvariable=self.min_mb_var).pack(side=tk.LEFT)

        ttk.Label(toolbar, text="Search:").pack(side=tk.LEFT, padx=(12, 4))
        ttk.Entry(toolbar, textvariable=self.search_var, width=28).pack(side=tk.LEFT)
        self.search_var.trace_add("write", lambda *_: self.apply_filters())

        ttk.Button(toolbar, text="Delete Selected", command=self.delete_selected).pack(side=tk.RIGHT)

        # Table
        columns = ("✔", "Size", "Project", "Category", "Action", "Path")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", selectmode="none")

        widths = [50, 100, 240, 160, 200, 600]
        for col, w in zip(columns, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor=tk.CENTER if col == "✔" else tk.W)

        vsb = ttk.Scrollbar(self.root, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(self.root, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

        self.tree.bind("<Button-1>", self.toggle_check)

        # Status bar
        status = ttk.Frame(self.root, padding=8)
        status.pack(fill=tk.X)

        self.status_label = ttk.Label(status, text="Ready.", style="Status.TLabel")
        self.status_label.pack(side=tk.LEFT)

        self.summary_label = ttk.Label(status, text="Selected: 0 files | 0.00 GB", style="Status.TLabel")
        self.summary_label.pack(side=tk.RIGHT)

    # =========================
    # Logic
    # =========================
    def start_scan(self):
        folder = filedialog.askdirectory()
        if not folder:
            return

        self.tree.delete(*self.tree.get_children())
        self.records.clear()
        self.status_label.config(text="Scanning...")

        min_bytes = self.min_mb_var.get() * 1024 * 1024
        threading.Thread(target=self._scan_worker, args=(folder, min_bytes), daemon=True).start()

    def _scan_worker(self, root_dir, min_bytes):
        for root, _, files in os.walk(root_dir):
            for f in files:
                try:
                    path = os.path.join(root, f)
                    size = os.path.getsize(path)
                    if size < min_bytes:
                        continue
                    meta = analyze(path)
                    rec = {
                        "path": path,
                        "size": size,
                        "project": detect_project(path),
                        "category": meta["category"],
                        "action": meta["action"],
                        "checked": False,
                    }
                    self.queue.put(rec)
                except Exception:
                    continue
        self.queue.put(None)

    def _poll_queue(self):
        try:
            while True:
                rec = self.queue.get_nowait()
                if rec is None:
                    self.status_label.config(text="Scan complete.")
                    break
                iid = rec["path"]
                self.records[iid] = rec
                self.tree.insert(
                    "", "end", iid=iid,
                    values=("☐", bytes_to_readable(rec["size"]), rec["project"], rec["category"], rec["action"], rec["path"])
                )
        except queue.Empty:
            pass
        self.root.after(50, self._poll_queue)

    def toggle_check(self, event):
        row = self.tree.identify_row(event.y)
        col = self.tree.identify_column(event.x)
        if not row or col != "#1":
            return
        rec = self.records[row]
        rec["checked"] = not rec["checked"]
        self.tree.set(row, "✔", "☑" if rec["checked"] else "☐")
        self.update_summary()

    def update_summary(self):
        total = sum(r["size"] for r in self.records.values() if r["checked"])
        count = sum(1 for r in self.records.values() if r["checked"])
        self.summary_label.config(text=f"Selected: {count} files | {bytes_to_readable(total)}")

    def apply_filters(self):
        q = self.search_var.get().lower()
        self.tree.delete(*self.tree.get_children())
        for iid, r in self.records.items():
            if q and q not in r["path"].lower():
                continue
            self.tree.insert(
                "", "end", iid=iid,
                values=("☑" if r["checked"] else "☐", bytes_to_readable(r["size"]), r["project"], r["category"], r["action"], r["path"])
            )

    def delete_selected(self):
        targets = [r for r in self.records.values() if r["checked"]]
        if not targets:
            messagebox.showinfo("Nothing selected", "No files selected.")
            return

        total = sum(r["size"] for r in targets)
        if not messagebox.askyesno("Confirm deletion", f"Delete {len(targets)} files\nFree {bytes_to_readable(total)}?"):
            return

        for iid, r in list(self.records.items()):
            if r["checked"]:
                recycle_delete(r["path"])
                self.tree.delete(iid)
                del self.records[iid]

        self.update_summary()

# =========================
# Run
# =========================
if __name__ == "__main__":
    root = tk.Tk()
    DiskCleanupApp(root)
    root.mainloop()
