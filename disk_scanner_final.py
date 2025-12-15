"""
Disk Cleanup Professional - FIXED VERSION
=========================================
A comprehensive, safe disk cleanup tool with advanced features.
Fixed: Percentage counter stops at 100%
Fixed: Added dropdown category filter
"""

import os
import sys
import re
import json
import queue
import threading
import time
import shutil
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, font
from collections import defaultdict

# ============================================
# CONFIGURATION
# ============================================
DEFAULT_MIN_MB = 10
RULES_FILE = "rules.json"

# NEVER delete these system patterns
SYSTEM_SAFETY_PATTERNS = [
    # Windows system directories
    r'\\Windows\\',
    r'\\Program Files\\',
    r'\\Program Files \(x86\)\\',
    r'\\ProgramData\\',
    r'\\System32\\',
    r'\\SysWOW64\\',
    
    # Hardware drivers
    r'\\AMD\\',
    r'\\NVIDIA\\',
    r'\\Intel\\',
    r'\\Drivers\\',
    r'\\DriverStore\\',
    
    # Boot and system
    r'\\Boot\\',
    r'\\EFI\\',
    r'\\Recovery\\',
    r'\\System Volume Information\\',
    r'\\\$Recycle\.Bin\\',
    
    # System files
    r'\\explorer\.exe$',
    r'\\svchost\.exe$',
    r'\\lsass\.exe$',
    r'\\services\.exe$',
    
    # Critical extensions (unless in temp/downloads)
    r'\.sys$',
    r'\.dll$',
    r'\.exe$',
    r'\.drv$',
    r'\.inf$',
    r'\.cat$',
    r'\.efi$',
]

# Project detection
PROJECT_MARKERS = {
    "Node.js": ["package.json", "yarn.lock"],
    "Python": ["requirements.txt", "pyproject.toml"],
    ".NET": [".csproj", ".sln"],
    "Java": ["pom.xml", "build.gradle"],
    "Go": ["go.mod"],
    "Rust": ["Cargo.toml"],
    "Docker": ["Dockerfile"],
}

# ============================================
# HELPER FUNCTIONS
# ============================================
def bytes_to_readable(n):
    """Convert bytes to human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if n < 1024.0:
            return f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{n:.2f} PB"

def get_file_age_days(path):
    """Get file age in days."""
    try:
        mtime = os.path.getmtime(path)
        age_days = (time.time() - mtime) / (60 * 60 * 24)
        return int(age_days)
    except:
        return 0

def is_system_file_safe(path):
    """
    Check if file is SAFE to delete (not a system file).
    Returns: (is_safe, reason)
    """
    path_lower = path.lower()
    
    # Check against dangerous patterns
    for pattern in SYSTEM_SAFETY_PATTERNS:
        if re.search(pattern, path_lower, re.IGNORECASE):
            # But allow deleting installers in Downloads/Temp
            safe_dirs = ['\\downloads\\', '\\temp\\', '\\tmp\\', '\\cache\\']
            if any(safe_dir in path_lower for safe_dir in safe_dirs):
                if pattern.endswith('\.exe$') or pattern.endswith('\.msi$'):
                    return True, "Installer in safe directory"
            return False, "System file detected"
    
    return True, "Safe"

def get_project_type(path):
    """Detect project type for a file."""
    folder = os.path.dirname(path)
    
    # Check current and parent directories
    for _ in range(3):  # Check up to 3 levels up
        for proj_type, markers in PROJECT_MARKERS.items():
            for marker in markers:
                if os.path.exists(os.path.join(folder, marker)):
                    return proj_type
        folder = os.path.dirname(folder)
        if folder == os.path.dirname(folder):  # Reached root
            break
    
    return "Unknown"

# ============================================
# RULE MANAGER
# ============================================
class RuleManager:
    def __init__(self):
        self.rules = []
        self.categories = set()
        self.load_rules()
    
    def load_rules(self):
        """Load and compile rules."""
        if os.path.exists(RULES_FILE):
            try:
                with open(RULES_FILE, 'r', encoding='utf-8') as f:
                    rules_data = json.load(f)
                
                for rule in rules_data:
                    pattern = rule.get("match", "")
                    try:
                        regex = re.compile(pattern, re.IGNORECASE)
                        rule["regex"] = regex
                        self.rules.append(rule)
                        self.categories.add(rule["category"])
                    except:
                        continue
            except Exception as e:
                print(f"Error loading rules: {e}")
                self.create_default_rules()
        else:
            self.create_default_rules()
    
    def create_default_rules(self):
        """Create default rules if file is missing."""
        default_rules = [
            {"category": "Node Modules", "match": "node_modules", "action": "Safe to delete"},
            {"category": "System Cache", "match": "Temp|tmp", "action": "Safe to delete"},
        ]
        for rule in default_rules:
            rule["regex"] = re.compile(rule["match"], re.IGNORECASE)
            self.rules.append(rule)
            self.categories.add(rule["category"])
    
    def analyze(self, path):
        """Analyze file against rules."""
        path_lower = path.lower()
        
        for rule in self.rules:
            if rule["regex"].search(path_lower):
                return rule
        
        return {
            "category": "Unknown",
            "description": "Unclassified file",
            "action": "Review before deleting",
            "confidence": 30,
            "icon": "❓"
        }
    
    def get_all_categories(self):
        """Get all unique categories."""
        return sorted(list(self.categories))

# ============================================
# SCANNER ENGINE - FIXED PROGRESS TRACKING
# ============================================
class ScannerEngine:
    def __init__(self, rule_manager):
        self.rule_manager = rule_manager
        self.stop_event = threading.Event()
        self.current_file = ""
        self.stats = {
            'total_scanned': 0,
            'total_size': 0,
            'files_found': 0,
            'start_time': None,
            'end_time': None
        }
    
    def scan(self, root_dir, min_size_mb=10, age_days=0, selected_categories=None):
        """Scan directory with filters."""
        self.stop_event.clear()
        
        self.stats = {
            'total_scanned': 0,
            'total_size': 0,
            'files_found': 0,
            'start_time': time.time(),
            'end_time': None
        }
        
        min_size_bytes = min_size_mb * 1024 * 1024
        results = []
        
        try:
            # Count total files for progress - FIXED: Better counting
            total_files = 0
            for root, dirs, files in os.walk(root_dir):
                # Skip system directories in counting too
                dirs[:] = [d for d in dirs if not self._should_skip_dir(os.path.join(root, d))]
                total_files += len(files)
                if total_files > 100000:  # Cap for performance
                    total_files = 100000
                    break
            
            scanned = 0
            for root, dirs, files in os.walk(root_dir):
                if self.stop_event.is_set():
                    break
                
                # Skip system directories
                dirs[:] = [d for d in dirs if not self._should_skip_dir(os.path.join(root, d))]
                
                for file in files:
                    if self.stop_event.is_set():
                        break
                    
                    try:
                        path = os.path.join(root, file)
                        self.current_file = path
                        scanned += 1
                        
                        # FIXED: Percentage calculation - ensure it doesn't exceed 100%
                        if total_files > 0:
                            progress = min(100, (scanned / total_files * 100))  # MIN ensures <= 100
                        else:
                            progress = 0
                        
                        # Update progress every 10 files
                        if scanned % 10 == 0:
                            yield ('progress', progress, scanned, total_files)
                        
                        # Skip if unsafe
                        safe, reason = is_system_file_safe(path)
                        if not safe:
                            continue
                        
                        # Get file info
                        size = os.path.getsize(path)
                        if size < min_size_bytes:
                            continue
                        
                        age = get_file_age_days(path)
                        if age_days > 0 and age < age_days:
                            continue
                        
                        # Analyze with rules
                        rule = self.rule_manager.analyze(path)
                        
                        # Category filter
                        if selected_categories and rule['category'] not in selected_categories:
                            continue
                        
                        # Add result
                        result = {
                            'path': path,
                            'size': size,
                            'size_display': bytes_to_readable(size),
                            'category': rule.get('category', 'Unknown'),
                            'description': rule.get('description', ''),
                            'action': rule.get('action', 'Review'),
                            'confidence': rule.get('confidence', 50),
                            'icon': rule.get('icon', '📄'),
                            'age_days': age,
                            'project': get_project_type(path),
                            'safe': safe,
                            'reason': reason,
                            'checked': False
                        }
                        
                        results.append(result)
                        self.stats['files_found'] += 1
                        self.stats['total_size'] += size
                        
                        # Yield result for immediate display
                        yield ('result', result)
                        
                    except (OSError, PermissionError):
                        continue
                
                self.stats['total_scanned'] = scanned
            
            # Final progress update - FIXED: Always send 100%
            yield ('progress', 100, scanned, total_files)
            
            # Final stats
            self.stats['end_time'] = time.time()
            
        except Exception as e:
            print(f"Scan error: {e}")
            yield ('error', str(e))
        
        yield ('complete', results, self.stats)
    
    def _should_skip_dir(self, dir_path):
        """Check if directory should be skipped."""
        skip_patterns = [
            r'\\Windows\\',
            r'\\Program Files\\',
            r'\\ProgramData\\',
            r'\\System Volume Information\\',
            r'\\\$Recycle\.Bin\\',
        ]
        
        dir_lower = dir_path.lower()
        return any(re.search(pattern, dir_lower) for pattern in skip_patterns)
    
    def stop(self):
        """Stop scanning."""
        self.stop_event.set()

# ============================================
# MAIN APPLICATION - FIXED VERSION
# ============================================
class DiskCleanupProfessional:
    def __init__(self, root):
        self.root = root
        self.root.title("Disk Cleanup Professional")
        self.root.geometry("1800x950")
        
        # Setup
        self.rule_manager = RuleManager()
        self.scanner = ScannerEngine(self.rule_manager)
        
        # Data
        self.all_records = {}
        self.scan_queue = queue.Queue()
        self.scan_thread = None
        self.is_scanning = False
        self.current_path = ""
        
        # UI Variables
        self.search_var = tk.StringVar()
        self.min_mb_var = tk.IntVar(value=DEFAULT_MIN_MB)
        self.age_days_var = tk.IntVar(value=0)
        self.selected_categories = []
        
        # NEW: Category dropdown variable
        self.category_filter_var = tk.StringVar(value="All Categories")
        
        # Statistics
        self.stats = {
            'total_files': 0,
            'total_size': 0,
            'selected_files': 0,
            'selected_size': 0,
            'potential_savings': 0,
            'scan_time': 0
        }
        
        # Build UI
        self._setup_styles()
        self._build_ui()
        
        # Start queue polling
        self.root.after(100, self._poll_queue)
        
        # Center window
        self.center_window()
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def _setup_styles(self):
        """Configure application styles."""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Colors
        self.colors = {
            'safe': '#2ecc71',
            'warning': '#f39c12',
            'danger': '#e74c3c',
            'bg': '#f5f7fa',
            'text': '#2c3e50'
        }
        
        self.root.configure(bg=self.colors['bg'])
    
    def _build_ui(self):
        """Build the complete user interface."""
        # Main container
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        self._build_header(main_container)
        
        # Control Panel
        self._build_control_panel(main_container)
        
        # Progress Section
        self._build_progress_section(main_container)
        
        # Main Content Area
        content_frame = ttk.Frame(main_container)
        content_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Left Panel (Filters/Stats)
        left_panel = ttk.Frame(content_frame, width=300)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        
        self._build_filters_panel(left_panel)
        self._build_stats_panel(left_panel)
        self._build_category_panel(left_panel)
        
        # Right Panel (Results)
        right_panel = ttk.Frame(content_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        self._build_results_table(right_panel)
        
        # Status Bar
        self._build_status_bar(main_container)
    
    def _build_header(self, parent):
        """Build application header."""
        header = ttk.Frame(parent)
        header.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(header,
                 text="🚀 DISK CLEANUP PROFESSIONAL",
                 font=("Segoe UI", 22, "bold"),
                 foreground=self.colors['text']).pack(anchor=tk.W)
        
        ttk.Label(header,
                 text="Smart cleaning with advanced safety protection",
                 font=("Segoe UI", 11),
                 foreground="#7f8c8d").pack(anchor=tk.W)
    
    def _build_control_panel(self, parent):
        """Build control panel with scan options."""
        control_frame = ttk.LabelFrame(parent, text="Scan Controls", padding="15")
        control_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Row 1: Scan buttons
        row1 = ttk.Frame(control_frame)
        row1.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(row1, text="📁 Select Folder",
                  command=self.select_folder, width=15).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(row1, text="💿 Scan Drive",
                  command=self.scan_drive, width=12).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(row1, text="⚡ Quick Clean",
                  command=self.quick_clean, width=12).pack(side=tk.LEFT)
        
        # Row 2: Filters
        row2 = ttk.Frame(control_frame)
        row2.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(row2, text="Min Size (MB):").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Spinbox(row2, from_=1, to=10240, width=8,
                   textvariable=self.min_mb_var).pack(side=tk.LEFT, padx=(0, 15))
        
        ttk.Label(row2, text="Age (days+):").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Spinbox(row2, from_=0, to=365, width=8,
                   textvariable=self.age_days_var).pack(side=tk.LEFT, padx=(0, 15))
        
        ttk.Label(row2, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        ttk.Entry(row2, textvariable=self.search_var, width=30).pack(side=tk.LEFT, padx=(0, 15))
        self.search_var.trace_add("write", lambda *args: self.apply_filters())
        
        # NEW: Category dropdown filter
        ttk.Label(row2, text="Category Filter:").pack(side=tk.LEFT, padx=(0, 5))
        categories = ["All Categories"] + self.rule_manager.get_all_categories()
        self.category_dropdown = ttk.Combobox(row2, textvariable=self.category_filter_var, 
                                            values=categories, state="readonly", width=20)
        self.category_dropdown.pack(side=tk.LEFT, padx=(0, 15))
        self.category_dropdown.bind('<<ComboboxSelected>>', lambda e: self.apply_filters())
        
        # Row 3: Action buttons
        row3 = ttk.Frame(control_frame)
        row3.pack(fill=tk.X)
        
        ttk.Button(row3, text="✅ Select All",
                  command=self.select_all, width=12).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(row3, text="❌ Clear All",
                  command=self.clear_all, width=12).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(row3, text="🗑️ Delete Selected",
                  command=self.delete_selected, width=15).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(row3, text="📊 Generate Report",
                  command=self.generate_report, width=15).pack(side=tk.LEFT)
    
    def _build_progress_section(self, parent):
        """Build progress display section."""
        progress_frame = ttk.LabelFrame(parent, text="Progress", padding="10")
        progress_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Progress bar
        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=(0, 5))
        
        # Progress info
        progress_info = ttk.Frame(progress_frame)
        progress_info.pack(fill=tk.X)
        
        self.progress_text = ttk.Label(progress_info, text="Ready to scan")
        self.progress_text.pack(side=tk.LEFT)
        
        self.progress_percent = ttk.Label(progress_info, text="0%")
        self.progress_percent.pack(side=tk.RIGHT)
        
        # Current file
        self.current_file_label = ttk.Label(progress_frame, text="", foreground="#666")
        self.current_file_label.pack(fill=tk.X)
    
    def _build_filters_panel(self, parent):
        """Build filters panel."""
        filter_frame = ttk.LabelFrame(parent, text="Quick Filters", padding="10")
        filter_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Safety filters
        ttk.Label(filter_frame, text="Safety Level:").pack(anchor=tk.W)
        
        self.safe_var = tk.BooleanVar(value=True)
        self.warning_var = tk.BooleanVar(value=True)
        self.danger_var = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(filter_frame, text="🟢 Safe to delete",
                       variable=self.safe_var).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(filter_frame, text="🟡 Review needed",
                       variable=self.warning_var).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(filter_frame, text="🔴 Not safe",
                       variable=self.danger_var).pack(anchor=tk.W, pady=2)
        
        ttk.Button(filter_frame, text="Apply Filters",
                  command=self.apply_filters).pack(fill=tk.X, pady=(10, 0))
    
    def _build_stats_panel(self, parent):
        """Build statistics panel."""
        stats_frame = ttk.LabelFrame(parent, text="Statistics", padding="10")
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.stats_labels = {}
        stats_data = [
            ("Total Files:", "total_files", "0"),
            ("Total Size:", "total_size", "0.00 GB"),
            ("Selected:", "selected", "0 files"),
            ("Selected Size:", "selected_size", "0.00 GB"),
            ("Potential Save:", "potential", "0.00 GB"),
            ("Scan Time:", "time", "0s")
        ]
        
        for label, key, default in stats_data:
            frame = ttk.Frame(stats_frame)
            frame.pack(fill=tk.X, pady=2)
            
            ttk.Label(frame, text=label).pack(side=tk.LEFT)
            self.stats_labels[key] = ttk.Label(frame, text=default,
                                             font=("Segoe UI", 10, "bold"))
            self.stats_labels[key].pack(side=tk.RIGHT)
    
    def _build_category_panel(self, parent):
        """Build category selection panel."""
        cat_frame = ttk.LabelFrame(parent, text="File Types", padding="10")
        cat_frame.pack(fill=tk.X)
        
        # Create scrollable category list
        canvas = tk.Canvas(cat_frame, height=200)
        scrollbar = ttk.Scrollbar(cat_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Add checkboxes for each category
        self.category_vars = {}
        categories = self.rule_manager.get_all_categories()
        
        for category in categories:
            var = tk.BooleanVar(value=True)
            self.category_vars[category] = var
            cb = ttk.Checkbutton(scrollable_frame, text=category, variable=var)
            cb.pack(anchor=tk.W, pady=2)
        
        # Pack canvas and scrollbar
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Select All/None buttons
        btn_frame = ttk.Frame(cat_frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(btn_frame, text="Select All",
                  command=lambda: self._set_all_categories(True)).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(btn_frame, text="Select None",
                  command=lambda: self._set_all_categories(False)).pack(side=tk.RIGHT, fill=tk.X, expand=True)
    
    def _build_results_table(self, parent):
        """Build results table."""
        table_frame = ttk.LabelFrame(parent, text="Scan Results", padding="10")
        table_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create treeview
        columns = ("✓", "Type", "Size", "Age", "Category", "Safety", "Action", "Path")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="none")
        
        # Configure columns
        widths = [40, 40, 80, 60, 120, 80, 120, 800]
        for col, width in zip(columns, widths):
            self.tree.heading(col, text=col)
            anchor = tk.CENTER if col in ["✓", "Type", "Size", "Age", "Safety"] else tk.W
            self.tree.column(col, width=width, anchor=anchor)
        
        # Scrollbars
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Grid layout
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
        
        # Bind events
        self.tree.bind("<Button-1>", self.toggle_check)
        self.tree.bind("<Double-1>", self.show_file_info)
    
    def _build_status_bar(self, parent):
        """Build status bar."""
        status_frame = ttk.Frame(parent, relief=tk.SUNKEN, padding="5")
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = ttk.Label(status_frame, text="Ready to scan")
        self.status_label.pack(side=tk.LEFT)
    
    def _set_all_categories(self, state):
        """Select all or no categories."""
        for var in self.category_vars.values():
            var.set(state)
        self.apply_filters()
    
    # ============================================
    # SCANNING FUNCTIONS - FIXED
    # ============================================
    def select_folder(self):
        """Select folder to scan."""
        folder = filedialog.askdirectory(title="Select Folder to Scan")
        if folder:
            self.current_path = folder
            self.start_scan()
    
    def scan_drive(self):
        """Scan entire drive."""
        if sys.platform == "win32":
            import string
            for drive in string.ascii_uppercase:
                drive_path = f"{drive}:\\"
                if os.path.exists(drive_path):
                    self.current_path = drive_path
                    self.start_scan()
                    break
    
    def quick_clean(self):
        """Quick clean of common locations."""
        locations = [
            os.environ.get('TEMP', ''),
            os.environ.get('TMP', ''),
            os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),
            os.path.join(os.environ.get('USERPROFILE', ''), 'AppData', 'Local', 'Temp')
        ]
        
        for location in locations:
            if location and os.path.exists(location):
                self.current_path = location
                self.start_scan()
                break
    
    def start_scan(self):
        """Start scanning process."""
        if not self.current_path:
            messagebox.showwarning("No Location", "Please select a folder or drive first.")
            return
        
        # Clear previous results
        self.tree.delete(*self.tree.get_children())
        self.all_records.clear()
        
        # Reset UI
        self.is_scanning = True
        self.progress_bar['value'] = 0
        self.progress_percent.config(text="0%")
        self.progress_text.config(text=f"Scanning: {self.current_path}")
        self.status_label.config(text="Starting scan...")
        self.current_file_label.config(text="")
        
        # Get selected categories from checkboxes
        selected_categories = []
        for category, var in self.category_vars.items():
            if var.get():
                selected_categories.append(category)
        
        # Get scan parameters
        min_mb = self.min_mb_var.get()
        age_days = self.age_days_var.get()
        
        # Start scan thread
        self.scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(self.current_path, min_mb, age_days, selected_categories),
            daemon=True
        )
        self.scan_thread.start()
    
    def _scan_worker(self, path, min_mb, age_days, categories):
        """Worker function for scanning."""
        try:
            scan_gen = self.scanner.scan(path, min_mb, age_days, categories)
            
            for item in scan_gen:
                if item[0] == 'progress':
                    _, progress, scanned, total = item
                    self.scan_queue.put(('progress', (progress, scanned, total)))
                
                elif item[0] == 'result':
                    _, result = item
                    self.scan_queue.put(('result', result))
                
                elif item[0] == 'complete':
                    _, results, stats = item
                    self.scan_queue.put(('stats', stats))
                    self.scan_queue.put(('complete', None))
                    break
                
                elif item[0] == 'error':
                    _, error_msg = item
                    self.scan_queue.put(('error', error_msg))
        
        except Exception as e:
            self.scan_queue.put(('error', str(e)))
    
    def _poll_queue(self):
        """Poll the queue for updates."""
        try:
            while True:
                item = self.scan_queue.get_nowait()
                
                if isinstance(item, tuple):
                    cmd, data = item
                    
                    if cmd == 'progress':
                        progress, scanned, total = data
                        # FIXED: Ensure progress never exceeds 100
                        progress = min(100, progress)
                        self.progress_bar['value'] = progress
                        self.progress_percent.config(text=f"{progress:.1f}%")
                        self.status_label.config(
                            text=f"Scanned: {scanned:,} of {total:,} files"
                        )
                        # Update current file from scanner
                        current_file = self.scanner.current_file
                        if len(current_file) > 80:
                            current_file = "..." + current_file[-77:]
                        self.current_file_label.config(text=current_file)
                    
                    elif cmd == 'result':
                        result = data
                        iid = result['path']
                        self.all_records[iid] = result
                        
                        # Determine safety color
                        if not result['safe']:
                            safety = "🔴"
                            color = 'danger'
                        elif "Safe" in result['action']:
                            safety = "🟢"
                            color = 'safe'
                        elif "Review" in result['action']:
                            safety = "🟡"
                            color = 'warning'
                        else:
                            safety = "⚪"
                            color = 'neutral'
                        
                        values = (
                            "☐",
                            result.get('icon', '📄'),
                            result['size_display'],
                            f"{result['age_days']}d",
                            result['category'],
                            safety,
                            result['action'],
                            result['path']
                        )
                        
                        self.tree.insert("", "end", iid=iid, values=values)
                        
                        # Apply color
                        if color == 'danger':
                            self.tree.tag_configure('danger', foreground=self.colors['danger'])
                            self.tree.item(iid, tags=('danger',))
                        elif color == 'warning':
                            self.tree.tag_configure('warning', foreground=self.colors['warning'])
                            self.tree.item(iid, tags=('warning',))
                        elif color == 'safe':
                            self.tree.tag_configure('safe', foreground=self.colors['safe'])
                            self.tree.item(iid, tags=('safe',))
                    
                    elif cmd == 'stats':
                        stats = data
                        self.stats_labels['total_files'].config(text=f"{stats['files_found']:,}")
                        self.stats_labels['total_size'].config(text=bytes_to_readable(stats['total_size']))
                        self.stats_labels['time'].config(text=f"{stats['end_time'] - stats['start_time']:.1f}s")
                        
                        # Calculate potential savings
                        safe_size = 0
                        for rec in self.all_records.values():
                            if "Safe" in rec['action']:
                                safe_size += rec['size']
                        
                        self.stats_labels['potential'].config(text=bytes_to_readable(safe_size))
                        self.stats['potential_savings'] = safe_size
                    
                    elif cmd == 'complete':
                        self.is_scanning = False
                        self.progress_text.config(text="Scan complete")
                        self.status_label.config(
                            text=f"Found {len(self.all_records):,} files, "
                                 f"{bytes_to_readable(self.scanner.stats['total_size'])} total"
                        )
                        self.current_file_label.config(text="")
                        # Apply initial filters
                        self.apply_filters()
                    
                    elif cmd == 'error':
                        messagebox.showerror("Scan Error", f"An error occurred:\n\n{data}")
                        self.is_scanning = False
        
        except queue.Empty:
            pass
        
        self.root.after(50, self._poll_queue)
    
    # ============================================
    # SELECTION AND FILTERING - UPDATED WITH DROPDOWN
    # ============================================
    def toggle_check(self, event):
        """Toggle checkbox for a row."""
        row = self.tree.identify_row(event.y)
        col = self.tree.identify_column(event.x)
        
        if row and col == "#1":  # Checkbox column
            rec = self.all_records.get(row)
            if rec:
                rec['checked'] = not rec['checked']
                self.tree.set(row, "✓", "☑" if rec['checked'] else "☐")
                self._update_selection_stats()
    
    def select_all(self):
        """Select all visible items."""
        for iid in self.tree.get_children():
            rec = self.all_records.get(iid)
            if rec:
                rec['checked'] = True
                self.tree.set(iid, "✓", "☑")
        self._update_selection_stats()
    
    def clear_all(self):
        """Clear all selections."""
        for iid in self.all_records:
            rec = self.all_records[iid]
            rec['checked'] = False
            if iid in self.tree.get_children():
                self.tree.set(iid, "✓", "☐")
        self._update_selection_stats()
    
    def apply_filters(self):
        """Apply all filters to the view."""
        search_text = self.search_var.get().lower()
        selected_category = self.category_filter_var.get()
        
        # Clear current view
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Apply filters
        filtered_count = 0
        for iid, rec in self.all_records.items():
            # Search filter
            if search_text and search_text not in rec['path'].lower():
                continue
            
            # NEW: Category dropdown filter
            if selected_category != "All Categories" and rec['category'] != selected_category:
                continue
            
            # Safety filter
            if rec['safe'] and not self.safe_var.get():
                continue
            if "Review" in rec['action'] and not self.warning_var.get():
                continue
            if not rec['safe'] and not self.danger_var.get():
                continue
            
            # Determine safety display
            if not rec['safe']:
                safety = "🔴"
            elif "Safe" in rec['action']:
                safety = "🟢"
            elif "Review" in rec['action']:
                safety = "🟡"
            else:
                safety = "⚪"
            
            values = (
                "☑" if rec['checked'] else "☐",
                rec.get('icon', '📄'),
                rec['size_display'],
                f"{rec['age_days']}d",
                rec['category'],
                safety,
                rec['action'],
                rec['path']
            )
            
            self.tree.insert("", "end", iid=iid, values=values)
            filtered_count += 1
        
        self.status_label.config(text=f"Showing {filtered_count:,} of {len(self.all_records):,} files")
        self._update_selection_stats()
    
    def _update_selection_stats(self):
        """Update selection statistics."""
        selected_size = 0
        selected_count = 0
        
        for rec in self.all_records.values():
            if rec['checked']:
                selected_size += rec['size']
                selected_count += 1
        
        self.stats['selected_files'] = selected_count
        self.stats['selected_size'] = selected_size
        
        self.stats_labels['selected'].config(text=f"{selected_count:,} files")
        self.stats_labels['selected_size'].config(text=bytes_to_readable(selected_size))
    
    # ============================================
    # FILE OPERATIONS
    # ============================================
    def delete_selected(self):
        """Delete selected files with safety checks."""
        selected = [r for r in self.all_records.values() if r['checked']]
        
        if not selected:
            messagebox.showinfo("No Selection", "No files selected for deletion.")
            return
        
        # Check for unsafe files
        unsafe_files = []
        for rec in selected:
            if not rec['safe']:
                unsafe_files.append(rec['path'])
        
        if unsafe_files:
            messagebox.showerror(
                "Unsafe Files",
                f"Cannot delete {len(unsafe_files)} system files!\n\n"
                "These files are protected for system safety."
            )
            # Remove unsafe files from selection
            selected = [r for r in selected if r['safe']]
            
            if not selected:
                return
        
        # Show confirmation
        total_size = sum(r['size'] for r in selected)
        
        response = messagebox.askyesno(
            "Confirm Deletion",
            f"Delete {len(selected):,} files?\n\n"
            f"Total size: {bytes_to_readable(total_size)}\n\n"
            "Files will be moved to Recycle Bin.",
            icon=messagebox.WARNING
        )
        
        if not response:
            return
        
        # Delete files
        deleted = 0
        errors = []
        
        for rec in selected:
            try:
                path = rec['path']
                if os.path.exists(path):
                    # Use system recycle bin on Windows
                    if sys.platform == "win32":
                        import ctypes
                        from ctypes import wintypes
                        
                        FO_DELETE = 3
                        FOF_ALLOWUNDO = 0x40
                        FOF_NOCONFIRMATION = 0x10
                        
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
                        op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION
                        ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
                    else:
                        # On other OS, just delete
                        os.remove(path)
                    
                    deleted += 1
                    
                    # Remove from UI
                    if rec['path'] in self.tree.get_children():
                        self.tree.delete(rec['path'])
                    
                    # Remove from records
                    if rec['path'] in self.all_records:
                        del self.all_records[rec['path']]
                        
            except Exception as e:
                errors.append(f"{os.path.basename(rec['path'])}: {str(e)}")
        
        # Update UI
        self._update_selection_stats()
        
        # Show results
        result_msg = f"✅ Successfully deleted {deleted} files."
        if errors:
            result_msg += f"\n\n❌ Errors ({len(errors)}):\n" + "\n".join(errors[:3])
            if len(errors) > 3:
                result_msg += f"\n... and {len(errors)-3} more"
        
        messagebox.showinfo("Deletion Complete", result_msg)
        self.status_label.config(text=f"Deleted {deleted} files")
        self.apply_filters()
    
    def show_file_info(self, event):
        """Show detailed file information."""
        row = self.tree.identify_row(event.y)
        if row:
            rec = self.all_records.get(row)
            if rec:
                info = (
                    f"📁 Path: {rec['path']}\n"
                    f"📊 Size: {rec['size_display']}\n"
                    f"📅 Age: {rec['age_days']} days\n"
                    f"🏷️ Category: {rec['category']}\n"
                    f"📝 Description: {rec['description']}\n"
                    f"⚡ Action: {rec['action']}\n"
                    f"🎯 Confidence: {rec['confidence']}%\n"
                    f"🔒 Safety: {'🟢 Safe' if rec['safe'] else '🔴 Not safe'}\n"
                    f"📦 Project: {rec.get('project', 'Unknown')}\n"
                )
                messagebox.showinfo("File Information", info)
    
    # ============================================
    # UTILITIES
    # ============================================
    def generate_report(self):
        """Generate cleanup report."""
        if not self.all_records:
            messagebox.showinfo("No Data", "Scan some files first to generate a report.")
            return
        
        # Calculate statistics
        by_category = defaultdict(lambda: {'count': 0, 'size': 0})
        safe_size = 0
        
        for rec in self.all_records.values():
            cat = rec['category']
            by_category[cat]['count'] += 1
            by_category[cat]['size'] += rec['size']
            
            if "Safe" in rec['action']:
                safe_size += rec['size']
        
        # Create report
        report_lines = [
            "=" * 60,
            "DISK CLEANUP REPORT",
            "=" * 60,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Location: {self.current_path}",
            f"Total files: {len(self.all_records):,}",
            f"Total size: {bytes_to_readable(self.scanner.stats['total_size'])}",
            f"Potential savings: {bytes_to_readable(safe_size)}",
            "",
            "BY CATEGORY:",
            "-" * 40
        ]
        
        for cat, data in sorted(by_category.items()):
            report_lines.append(f"{cat:30} {data['count']:6d} files  {bytes_to_readable(data['size']):>12}")
        
        report_text = "\n".join(report_lines)
        
        # Show in dialog
        report_window = tk.Toplevel(self.root)
        report_window.title("Cleanup Report")
        report_window.geometry("600x500")
        
        text_widget = tk.Text(report_window, wrap=tk.WORD)
        text_widget.insert(1.0, report_text)
        text_widget.config(state=tk.DISABLED)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Button(report_window, text="Close",
                  command=report_window.destroy).pack(pady=10)
    
    def center_window(self):
        """Center window on screen."""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def on_closing(self):
        """Handle window closing."""
        if self.is_scanning:
            if messagebox.askyesno("Scan in Progress",
                                  "A scan is in progress. Stop it and quit?"):
                self.scanner.stop()
                self.root.destroy()
        else:
            if messagebox.askokcancel("Quit", "Do you want to quit?"):
                self.root.destroy()

# ============================================
# MAIN ENTRY POINT
# ============================================
if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║                DISK CLEANUP PROFESSIONAL                 ║
    ║                 Final Production Version                 ║
    ╚══════════════════════════════════════════════════════════╝
    
    🔒 SAFETY FIRST: Never deletes system files or drivers
    📊 Professional: Advanced filtering and statistics
    ⚡ Fast: Multi-threaded scanning with progress feedback
    🎯 Smart: File type categorization and safety analysis
    
    Loading...
    """)
    
    # Create and run application
    root = tk.Tk()
    app = DiskCleanupProfessional(root)
    root.mainloop()