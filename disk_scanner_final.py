"""
Disk Cleanup Professional - ENHANCED VERSION
===========================================
A comprehensive, safe disk cleanup tool with advanced features.
- One-Click Cleanup for instant space freeing
- Smart Scan to find biggest space wasters
- Welcome screen for easy start
- Enhanced batch selection
- Disk space visualization
- Duplicate file detection
- Export/Import functionality
"""

import os
import sys
import re
import json
import queue
import threading
import time
import shutil
import hashlib
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, font
from collections import defaultdict

# ============================================
# CONFIGURATION
# ============================================
DEFAULT_MIN_MB = 10
RULES_FILE = "rules.json"
PROTECTED_PATHS_FILE = "protected_paths.json"

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

# Global protected paths (loaded from file)
PROTECTED_PATHS = []

def load_protected_paths():
    """Load protected paths from file."""
    global PROTECTED_PATHS
    PROTECTED_PATHS = []
    
    if os.path.exists(PROTECTED_PATHS_FILE):
        try:
            with open(PROTECTED_PATHS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                PROTECTED_PATHS = data.get('paths', [])
        except:
            pass
    
    # Auto-detect common protected locations
    userprofile = os.environ.get('USERPROFILE', '')
    desktop = os.path.join(userprofile, 'Desktop') if userprofile else ''
    
    # Auto-add Portfolio and OneDrive if they exist
    auto_protect = []
    if desktop:
        # Look for Portfolio folders
        for item in os.listdir(desktop) if os.path.exists(desktop) else []:
            item_path = os.path.join(desktop, item)
            if os.path.isdir(item_path) and 'portfolio' in item.lower():
                auto_protect.append(item_path)
        
        # Look for OneDrive
        onedrive_paths = [
            os.path.join(userprofile, 'OneDrive'),
            os.path.join(userprofile, 'OneDrive - Personal'),
            os.path.join(userprofile, 'OneDrive - Work'),
        ]
        for path in onedrive_paths:
            if os.path.exists(path) and path not in PROTECTED_PATHS:
                auto_protect.append(path)
    
    # Add auto-detected paths
    for path in auto_protect:
        if path not in PROTECTED_PATHS:
            PROTECTED_PATHS.append(path)
    
    # Save updated list
    save_protected_paths()

def save_protected_paths():
    """Save protected paths to file."""
    try:
        with open(PROTECTED_PATHS_FILE, 'w', encoding='utf-8') as f:
            json.dump({'paths': PROTECTED_PATHS}, f, indent=2)
    except:
        pass

def is_path_protected(path):
    """Check if path is in protected list."""
    path_normalized = os.path.normpath(path).lower()
    
    for protected in PROTECTED_PATHS:
        protected_normalized = os.path.normpath(protected).lower()
        # Check if path is within protected directory
        if path_normalized.startswith(protected_normalized):
            return True, f"Protected: {protected}"
    
    return False, None

def is_system_file_safe(path):
    """
    Check if file is SAFE to delete (not a system file or protected).
    Returns: (is_safe, reason)
    """
    path_lower = path.lower()
    
    # Check if path is protected (Portfolio, OneDrive, etc.)
    is_protected, protect_reason = is_path_protected(path)
    if is_protected:
        return False, protect_reason
    
    # Check against dangerous patterns
    for pattern in SYSTEM_SAFETY_PATTERNS:
        if re.search(pattern, path_lower, re.IGNORECASE):
            # But allow deleting installers in Downloads/Temp
            safe_dirs = ['\\downloads\\', '\\temp\\', '\\tmp\\', '\\cache\\']
            if any(safe_dir in path_lower for safe_dir in safe_dirs):
                if pattern.endswith(r'\.exe$') or pattern.endswith(r'\.msi$'):
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

def get_file_hash(path, chunk_size=8192):
    """Calculate MD5 hash of a file."""
    try:
        hash_md5 = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except:
        return None

def normalize_scan_path(path):
    """Normalize a path for deduplication comparisons."""
    try:
        return os.path.normcase(os.path.realpath(path))
    except OSError:
        return os.path.normcase(os.path.normpath(path))


def dedupe_scan_locations(locations):
    """Remove duplicate and nested/overlapping scan roots."""
    entries = []
    for loc in locations:
        if not loc or not os.path.exists(loc):
            continue
        try:
            real = os.path.realpath(loc)
            norm = os.path.normcase(real)
        except OSError:
            continue
        entries.append((loc, norm))

    entries.sort(key=lambda item: len(item[1]))
    result = []
    kept_norms = []
    sep = os.sep
    for loc, norm in entries:
        is_nested = False
        for kept in kept_norms:
            if norm == kept or norm.startswith(kept + sep):
                is_nested = True
                break
        if is_nested:
            continue
        kept_norms.append(norm)
        result.append(loc)
    return result


def get_common_locations():
    """Get list of common Windows cleanup locations."""
    raw_locations = []
    userprofile = os.environ.get('USERPROFILE', '')
    
    if sys.platform == "win32":
        # System temp
        if os.environ.get('TEMP'):
            raw_locations.append(os.environ.get('TEMP'))
        if os.environ.get('TMP'):
            raw_locations.append(os.environ.get('TMP'))
        
        # User temp
        if userprofile:
            raw_locations.extend([
                os.path.join(userprofile, 'AppData', 'Local', 'Temp'),
                os.path.join(userprofile, 'AppData', 'Local', 'Microsoft', 'Windows', 'INetCache'),
                os.path.join(userprofile, 'AppData', 'Local', 'Microsoft', 'Windows', 'Temporary Internet Files'),
                os.path.join(userprofile, 'Downloads'),
            ])
            
            # Browser caches
            for browser in ['Chrome', 'Firefox', 'Edge', 'Opera']:
                cache_paths = [
                    os.path.join(userprofile, 'AppData', 'Local', browser, 'User Data', 'Default', 'Cache'),
                    os.path.join(userprofile, 'AppData', 'Local', browser, 'Cache'),
                ]
                for cache_path in cache_paths:
                    if os.path.exists(cache_path):
                        raw_locations.append(cache_path)
                        break
    
    return dedupe_scan_locations(raw_locations)

# ============================================
# AI AGENT - Natural Language Command Processor
# ============================================
class CleanupAI:
    """AI agent that understands natural language cleanup commands."""
    
    def __init__(self, app_instance):
        self.app = app_instance
        self.command_history = []
        self.conversation_context = []
        self.user_name = "there"  # Will try to detect from system
        self.personality_traits = {
            'helpful': True,
            'cautious': True,
            'encouraging': True,
            'friendly': True
        }
        self._detect_user_name()
    
    def _detect_user_name(self):
        """Try to detect user name from system."""
        try:
            username = os.environ.get('USERNAME', '')
            if username:
                self.user_name = username.split()[0] if ' ' in username else username
        except:
            pass
        
    def parse_command(self, command):
        """Parse natural language command and return action."""
        command_lower = command.lower().strip()
        
        # Extract intent
        intent = self._extract_intent(command_lower)
        
        # Extract parameters
        params = self._extract_parameters(command_lower, intent)
        
        return {
            'intent': intent,
            'params': params,
            'original': command
        }
    
    def _extract_intent(self, command):
        """Extract the main intent from command."""
        # Delete/Remove/Clean commands
        if any(word in command for word in ['delete', 'remove', 'clean', 'clear', 'free']):
            if any(word in command for word in ['all', 'everything']):
                return 'delete_all_safe'
            elif any(word in command for word in ['node', 'node_modules', 'npm']):
                return 'delete_category'
            elif any(word in command for word in ['temp', 'temporary', 'cache']):
                return 'delete_category'
            elif any(word in command for word in ['log', 'logs']):
                return 'delete_category'
            elif any(word in command for word in ['duplicate', 'duplicates']):
                return 'delete_duplicates'
            elif any(word in command for word in ['old', 'older']):
                return 'delete_old'
            elif any(word in command for word in ['large', 'big', 'huge']):
                return 'delete_large'
            else:
                return 'delete_selected'
        
        # Stats/Info commands (before show/find - "show stats" must not match find_files)
        if any(word in command for word in ['stats', 'statistics', 'summary', 'how much']):
            return 'show_stats'
        
        # Scan commands (before generic search)
        if 'search for' in command:
            return 'scan_location'
        if 'scan' in command:
            return 'scan_location'
        
        # Find/Search/Show commands
        if any(word in command for word in ['find', 'search', 'show', 'list', 'display']):
            if any(word in command for word in ['duplicate', 'duplicates']):
                return 'find_duplicates'
            elif any(word in command for word in ['large', 'big', 'huge']):
                return 'find_large'
            elif any(word in command for word in ['old', 'older']):
                return 'find_old'
            else:
                return 'find_files'
        
        # Protect/Exclude commands
        if any(word in command for word in ['protect', 'exclude', 'ignore', 'never delete', 'keep']):
            return 'protect_path'
        
        # Help/Info commands
        if any(word in command for word in ['help', 'what can', 'how do', 'how to', 'commands']):
            return 'show_help'
        
        return 'unknown'
    
    def _extract_parameters(self, command, intent):
        """Extract parameters from command."""
        params = {}
        
        # Extract size (MB, GB)
        size_match = re.search(r'(\d+)\s*(mb|gb|megabytes?|gigabytes?)', command)
        if size_match:
            value = int(size_match.group(1))
            unit = size_match.group(2).lower()
            if 'gb' in unit or 'gigabyte' in unit:
                params['size_mb'] = value * 1024
            else:
                params['size_mb'] = value
        
        # Extract age (days, weeks, months, years)
        age_match = re.search(r'(\d+)\s*(day|week|month|year|d|w|m|y)s?', command)
        if age_match:
            value = int(age_match.group(1))
            unit = age_match.group(2).lower()
            if 'week' in unit or unit == 'w':
                params['age_days'] = value * 7
            elif 'month' in unit or unit == 'm':
                params['age_days'] = value * 30
            elif 'year' in unit or unit == 'y':
                params['age_days'] = value * 365
            else:
                params['age_days'] = value
        
        # Extract category
        categories = {
            'node_modules': 'Node Modules',
            'node': 'Node Modules',
            'npm': 'Node Modules',
            'python': 'Python Envs',
            'venv': 'Python Envs',
            'temp': 'System Cache',
            'cache': 'System Cache',
            'log': 'Logs',
            'logs': 'Logs',
            'build': 'Build Output',
            'dist': 'Build Output',
        }
        for key, category in categories.items():
            if key in command:
                params['category'] = category
                break
        
        # Extract path (if mentioned)
        path_patterns = [
            r'in\s+([a-z]:\\[^\s]+)',
            r'from\s+([a-z]:\\[^\s]+)',
            r'at\s+([a-z]:\\[^\s]+)',
        ]
        for pattern in path_patterns:
            match = re.search(pattern, command, re.IGNORECASE)
            if match:
                params['path'] = match.group(1)
                break
        
        return params
    
    def _get_greeting(self):
        """Get a friendly greeting."""
        greetings = [
            "Hey! 👋 Ready to free up some space?",
            "Hi there! What can I help you clean up today?",
            "Hello! Let's get that disk space back! 💪",
            "Hey! I'm here to help you clean up safely. What do you need?",
        ]
        return greetings[len(self.command_history) % len(greetings)]
    
    def _get_encouragement(self, action_type, count=0, size=0):
        """Get encouraging response based on action."""
        if action_type == 'delete' and count > 0:
            encouragements = [
                f"Nice! 🎉 I've selected {count:,} files for you. That's {bytes_to_readable(size)} of space you can free up!",
                f"Great choice! ✅ Found {count:,} files ready to go. You'll free up {bytes_to_readable(size)}!",
                f"Awesome! 🚀 {count:,} files selected. That's {bytes_to_readable(size)} coming back to you!",
            ]
            return encouragements[count % len(encouragements)]
        return ""
    
    def _get_contextual_response(self, intent, params, result_data=None):
        """Get contextual, human-like response."""
        # Check if this is first command
        if len(self.command_history) == 0:
            return self._get_greeting()
        
        # Build natural response
        responses = []
        
        if intent == 'delete_all_safe':
            count = result_data.get('count', 0) if result_data else 0
            size = result_data.get('size', 0) if result_data else 0
            if count > 0:
                responses.append(f"Perfect! I've selected {count:,} safe files for you.")
                responses.append(f"That's {bytes_to_readable(size)} of space you can free up! 🎉")
                responses.append("Just review them and click 'Delete Selected' when you're ready.")
            else:
                responses.append("Hmm, I couldn't find any safe files to select right now.")
                responses.append("Try running a scan first, or check your filters!")
        
        elif intent == 'delete_category':
            category = params.get('category', 'files')
            count = result_data.get('count', 0) if result_data else 0
            if count > 0:
                responses.append(f"Got it! I've selected {count:,} {category} files.")
                responses.append("These are safe to delete - they can usually be regenerated.")
            else:
                responses.append(f"I couldn't find any {category} files to delete.")
                responses.append("Maybe they're already gone, or try scanning first?")
        
        elif intent == 'find_large':
            size_mb = params.get('size_mb', 100)
            count = result_data.get('count', 0) if result_data else 0
            selected = result_data.get('selected', 0) if result_data else 0
            responses.append(f"Found {count:,} files larger than {size_mb}MB!")
            if selected > 0:
                responses.append(f"I've selected {selected:,} safe ones for you. The big space hogs! 💾")
            else:
                responses.append("Take a look - some of these might be important, so review carefully.")
        
        elif intent == 'protect_path':
            path = params.get('path', '')
            if path:
                responses.append(f"🛡️ Done! I've protected that path for you.")
                responses.append("Nothing in there will ever be deleted, no matter what you ask me to do.")
                responses.append("Your files are safe! ✨")
            else:
                responses.append("I couldn't find that path to protect.")
                responses.append("Try using the 'Search & Protect' button, or give me a full path!")
        
        elif intent == 'show_stats':
            responses.append("Here's what we're working with:")
            if result_data:
                responses.append(f"• Total files: {result_data.get('total', 0):,}")
                responses.append(f"• Total size: {bytes_to_readable(result_data.get('total_size', 0))}")
                responses.append(f"• Selected: {result_data.get('selected', 0):,} files")
                responses.append(f"• Potential savings: {bytes_to_readable(result_data.get('selected_size', 0))}")
        
        elif intent == 'show_help':
            responses.append("Sure thing! Here's what I can do for you:")
            responses.append("")
            responses.append("🗑️ DELETE/REMOVE:")
            responses.append("• 'delete all safe files' - Selects everything safe to delete")
            responses.append("• 'remove all node_modules' - Gets rid of Node.js dependencies")
            responses.append("• 'clean temp files older than 30 days' - Old temp files")
            responses.append("• 'delete files larger than 500MB' - Big files")
            responses.append("")
            responses.append("🔍 FIND/SEARCH:")
            responses.append("• 'find large files' - Shows you the space hogs")
            responses.append("• 'show files older than 90 days' - Old files")
            responses.append("• 'find duplicates' - Finds duplicate files")
            responses.append("")
            responses.append("🛡️ PROTECT:")
            responses.append("• 'protect my portfolio' - Keeps it safe forever")
            responses.append("• 'never delete OneDrive' - Protects OneDrive")
            responses.append("")
            responses.append("Just talk to me naturally - I'll figure it out! 😊")
        
        elif intent == 'unknown':
            responses.append("Hmm, I'm not quite sure what you mean by that. 🤔")
            responses.append("Try something like:")
            responses.append("• 'delete all safe files'")
            responses.append("• 'find large files'")
            responses.append("• 'help' for more options")
            responses.append("")
            responses.append("I'm still learning, but I'm getting smarter! 💪")
        
        return "\n".join(responses) if responses else "Done! ✅"
    
    def execute_command(self, command):
        """Execute a natural language command."""
        # Check for greetings
        command_lower = command.lower().strip()
        if any(word in command_lower for word in ['hi', 'hello', 'hey', 'sup']):
            return self._get_greeting() + "\n\nWhat would you like me to help you with today?"
        
        # Check for thanks
        if any(word in command_lower for word in ['thanks', 'thank you', 'ty', 'appreciate']):
            thanks_responses = [
                "You're welcome! Happy to help! 😊",
                "Anytime! That's what I'm here for! ✨",
                "No problem! Let me know if you need anything else! 🎉",
            ]
            return thanks_responses[len(self.command_history) % len(thanks_responses)]
        
        parsed = self.parse_command(command)
        self.command_history.append(parsed)
        self.conversation_context.append({'command': command, 'intent': parsed['intent']})
        
        intent = parsed['intent']
        params = parsed['params']
        
        response = ""
        result_data = {}
        
        try:
            if intent == 'delete_all_safe':
                self.app.select_all_safe()
                count = sum(1 for r in self.app.all_records.values() if r.get('checked', False))
                size = sum(r['size'] for r in self.app.all_records.values() if r.get('checked', False))
                result_data = {'count': count, 'size': size}
                response = self._get_contextual_response(intent, params, result_data)
            
            elif intent == 'delete_category':
                category = params.get('category', 'Node Modules')
                count = 0
                size = 0
                for rec in self.app.all_records.values():
                    if rec['category'] == category and rec['safe']:
                        rec['checked'] = True
                        count += 1
                        size += rec['size']
                        if rec['path'] in self.app.tree.get_children():
                            self.app.tree.set(rec['path'], "✓", "☑")
                self.app._update_selection_stats()
                result_data = {'count': count, 'size': size, 'category': category}
                response = self._get_contextual_response(intent, params, result_data)
            
            elif intent == 'delete_old':
                age_days = params.get('age_days', 90)
                self.app.select_old_files(age_days)
                count = sum(1 for r in self.app.all_records.values() if r.get('checked', False))
                response = f"✅ Selected {count:,} files older than {age_days} days."
            
            elif intent == 'delete_large':
                size_mb = params.get('size_mb', 100)
                self.app.select_large_files(size_mb)
                count = sum(1 for r in self.app.all_records.values() if r.get('checked', False))
                response = f"✅ Selected {count:,} files larger than {size_mb}MB."
            
            elif intent == 'delete_duplicates':
                self.app.find_duplicates()
                response = "✅ Finding duplicates... Check the duplicate window for details."
            
            elif intent == 'find_duplicates':
                self.app.find_duplicates()
                response = "🔍 Searching for duplicate files..."
            
            elif intent == 'find_large':
                size_mb = params.get('size_mb', 100)
                # Select large files to highlight them
                self.app.select_large_files(size_mb)
                count = sum(1 for r in self.app.all_records.values() if r['size'] >= size_mb * 1024 * 1024)
                selected = sum(1 for r in self.app.all_records.values() if r.get('checked', False))
                result_data = {'count': count, 'selected': selected, 'size_mb': size_mb}
                response = self._get_contextual_response(intent, params, result_data)
            
            elif intent == 'find_old':
                age_days = params.get('age_days', 90)
                # Filter results
                old_files = [r for r in self.app.all_records.values() if r['age_days'] >= age_days]
                response = f"🔍 Found {len(old_files):,} files older than {age_days} days."
            
            elif intent == 'protect_path':
                # Extract path from command
                path = params.get('path', '')
                if not path:
                    # Try to extract from command
                    path_match = re.search(r'["\']([^"\']+)["\']', command)
                    if path_match:
                        path = path_match.group(1)
                    # Try common patterns
                    elif 'portfolio' in command_lower:
                        # Try to find portfolio
                        desktop = os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop')
                        if os.path.exists(desktop):
                            for item in os.listdir(desktop):
                                if 'portfolio' in item.lower():
                                    path = os.path.join(desktop, item)
                                    break
                    elif 'onedrive' in command_lower:
                        userprofile = os.environ.get('USERPROFILE', '')
                        onedrive_paths = [
                            os.path.join(userprofile, 'OneDrive'),
                            os.path.join(userprofile, 'OneDrive - Personal'),
                            os.path.join(userprofile, 'OneDrive - Work'),
                        ]
                        for op in onedrive_paths:
                            if os.path.exists(op):
                                path = op
                                break
                
                if path and os.path.exists(path):
                    if path not in PROTECTED_PATHS:
                        PROTECTED_PATHS.append(path)
                        save_protected_paths()
                        self.app.update_protected_paths_list()
                        result_data = {'path': path, 'success': True}
                        response = self._get_contextual_response(intent, params, result_data)
                    else:
                        response = f"🛡️ That path is already protected! Your files there are safe. ✨"
                else:
                    response = "Hmm, I couldn't find that path to protect. 😕\n\nTry:\n• Using the 'Search & Protect' button\n• Or give me the full path like 'C:\\Users\\...\\Portfolio'\n• Or say 'protect my portfolio' and I'll try to find it!"
            
            elif intent == 'scan_location':
                path = params.get('path', '')
                if path and os.path.exists(path):
                    self.app.current_path = path
                    self.app.start_scan()
                    response = f"🔍 Scanning: {path}"
                else:
                    response = "❌ Invalid path. Please provide a valid directory path."
            
            elif intent == 'show_stats':
                total = len(self.app.all_records)
                total_size = sum(r['size'] for r in self.app.all_records.values())
                selected = sum(1 for r in self.app.all_records.values() if r.get('checked', False))
                selected_size = sum(r['size'] for r in self.app.all_records.values() if r.get('checked', False))
                result_data = {'total': total, 'total_size': total_size, 'selected': selected, 'selected_size': selected_size}
                response = self._get_contextual_response(intent, params, result_data)
            
            elif intent == 'show_help':
                result_data = {}
                response = self._get_contextual_response(intent, params, result_data)
            
            elif intent == 'unknown':
                result_data = {}
                response = self._get_contextual_response(intent, params, result_data)
            
            else:
                response = f"✅ Command executed: {intent}"
        
        except Exception as e:
            response = f"Oops! 😅 Something went wrong: {str(e)}\n\nDon't worry, nothing was deleted. Try again or let me know if you need help!"
        
        # Add follow-up suggestions based on context
        if intent in ['delete_all_safe', 'delete_category', 'delete_large', 'delete_old']:
            if result_data.get('count', 0) > 0:
                response += "\n\n💡 Tip: Review the selected files, then click 'Delete Selected' when ready!"
        
        return response

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
    
    def analyze(self, path, file_size_bytes=None):
        """Analyze file against rules (first match wins; optional size gates)."""
        path_lower = path.lower()
        
        for rule in self.rules:
            min_mb = rule.get("min_size_mb")
            if min_mb is not None:
                if file_size_bytes is None:
                    continue
                if file_size_bytes < min_mb * 1024 * 1024:
                    continue
            
            if rule["regex"].search(path_lower):
                return rule
        
        return {
            "category": "Other Files",
            "description": "Unclassified file — review before deleting",
            "action": "Review before deleting",
            "confidence": 30,
            "icon": "📄"
        }
    
    def get_all_categories(self):
        """Get all unique categories."""
        return sorted(list(self.categories))

# ============================================
# SCANNER ENGINE - FIXED PROGRESS TRACKING
# ============================================
SCAN_FILE_COUNT_CAP = 100000
SCAN_PROGRESS_FILE_INTERVAL = 10
SCAN_PROGRESS_TIME_INTERVAL = 0.15


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
    
    def _is_reparse_point(self, path):
        """Skip junctions/symlinks to avoid loops and ballooning walks."""
        try:
            if os.path.islink(path):
                return True
            if hasattr(os.path, 'isjunction') and os.path.isjunction(path):
                return True
        except OSError:
            return True
        return False
    
    def _should_skip_dir(self, dir_path):
        """Check if directory should be skipped."""
        if self._is_reparse_point(dir_path):
            return True

        skip_patterns = [
            r'\\Windows\\',
            r'\\Program Files\\',
            r'\\ProgramData\\',
            r'\\System Volume Information\\',
            r'\\\$Recycle\.Bin\\',
        ]
        
        dir_lower = dir_path.lower()
        return any(re.search(pattern, dir_lower) for pattern in skip_patterns)
    
    def _filter_walk_dirs(self, root, dirs):
        """Apply consistent directory filtering for count and scan walks."""
        dirs[:] = [
            d for d in dirs
            if not self._should_skip_dir(os.path.join(root, d))
        ]
    
    def _count_files(self, root_dir):
        """Pre-count files using the same skip rules as the scan walk."""
        total_files = 0
        count_capped = False
        for root, dirs, files in os.walk(root_dir):
            self._filter_walk_dirs(root, dirs)
            total_files += len(files)
            if total_files >= SCAN_FILE_COUNT_CAP:
                total_files = SCAN_FILE_COUNT_CAP
                count_capped = True
                break
        return total_files, count_capped
    
    def _compute_progress(self, scanned, total_files, count_capped):
        """Compute streaming progress; hold at 99% until scan truly completes."""
        if total_files <= 0:
            return 0
        if count_capped or scanned > total_files:
            return 99
        return min(99, (scanned / total_files) * 100)
    
    def _should_emit_progress(self, scanned, last_progress_time):
        """Emit progress on an interval so the UI stays responsive."""
        if scanned == 0:
            return True
        if scanned % SCAN_PROGRESS_FILE_INTERVAL == 0:
            return True
        return (time.time() - last_progress_time) >= SCAN_PROGRESS_TIME_INTERVAL
    
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
        seen_paths = set()
        
        try:
            total_files, count_capped = self._count_files(root_dir)
            scanned = 0
            last_progress_time = 0.0
            yield ('progress', 0, scanned, total_files)
            
            for root, dirs, files in os.walk(root_dir):
                if self.stop_event.is_set():
                    break
                
                self._filter_walk_dirs(root, dirs)
                
                for file in files:
                    if self.stop_event.is_set():
                        break
                    
                    try:
                        path = os.path.join(root, file)
                        norm_path = normalize_scan_path(path)
                        self.current_file = path
                        scanned += 1
                        
                        if self._should_emit_progress(scanned, last_progress_time):
                            progress = self._compute_progress(scanned, total_files, count_capped)
                            yield ('progress', progress, scanned, total_files)
                            last_progress_time = time.time()
                        
                        if norm_path in seen_paths:
                            continue
                        seen_paths.add(norm_path)
                        
                        # Skip if unsafe or protected
                        safe, reason = is_system_file_safe(path)
                        if not safe:
                            continue
                        
                        # Double-check protected paths (extra safety)
                        is_protected, protect_reason = is_path_protected(path)
                        if is_protected:
                            continue  # Skip protected files entirely
                        
                        # Get file info
                        size = os.path.getsize(path)
                        if size < min_size_bytes:
                            continue
                        
                        age = get_file_age_days(path)
                        if age_days > 0 and age < age_days:
                            continue
                        
                        # Analyze with rules (size-aware for Large Files, etc.)
                        rule = self.rule_manager.analyze(path, size)
                        
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
            
            # Final progress update - only reach 100% when scan is complete
            yield ('progress', 100, scanned, total_files)
            
            # Final stats
            self.stats['end_time'] = time.time()
            
        except Exception as e:
            print(f"Scan error: {e}")
            yield ('error', str(e))
        
        yield ('complete', results, self.stats)
    
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
        self.ai_agent = CleanupAI(self)
        
        # Load protected paths
        load_protected_paths()
        
        # Data
        self.all_records = {}
        self.scan_queue = queue.Queue()
        self.scan_thread = None
        self.is_scanning = False
        self.current_path = ""
        self.advanced_mode = False
        self.duplicate_groups = {}
        
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
        
        # Show welcome screen first
        self.show_welcome_screen()
        
        # Start queue polling
        self._poll_queue_id = None
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
    
    def _cancel_scheduled_callbacks(self, include_poll=False):
        """Cancel pending after() callbacks when switching views."""
        attrs = ['_welcome_anim_id', '_tip_rotate_id']
        if include_poll:
            attrs.append('_poll_queue_id')
        for attr in attrs:
            callback_id = getattr(self, attr, None)
            if callback_id is not None:
                try:
                    self.root.after_cancel(callback_id)
                except (tk.TclError, ValueError):
                    pass
                setattr(self, attr, None)
    
    def show_welcome_screen(self):
        """Show welcome screen with quick start options."""
        self._cancel_scheduled_callbacks()
        # Clear existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()
        
        welcome_frame = ttk.Frame(self.root)
        welcome_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(welcome_frame, 
                               text="🚀 Disk Cleanup Professional",
                               font=("Segoe UI", 32, "bold"))
        title_label.pack(pady=(50, 10))
        
        subtitle_label = ttk.Label(welcome_frame,
                                  text="Free up disk space quickly and safely",
                                  font=("Segoe UI", 14))
        subtitle_label.pack(pady=(0, 50))
        
        # Quick action buttons
        button_frame = ttk.Frame(welcome_frame)
        button_frame.pack(pady=20)
        
        # One-Click Cleanup button (large and prominent)
        one_click_btn = tk.Button(button_frame,
                                  text="⚡ ONE-CLICK CLEANUP\n\nScans common locations\nAuto-selects safe files\nFree up space instantly",
                                  font=("Segoe UI", 14, "bold"),
                                  bg="#2ecc71",
                                  fg="white",
                                  relief=tk.RAISED,
                                  bd=5,
                                  width=25,
                                  height=6,
                                  cursor="hand2",
                                  command=self.one_click_cleanup)
        one_click_btn.pack(side=tk.LEFT, padx=20, pady=10)
        
        # Smart Scan button
        smart_scan_btn = tk.Button(button_frame,
                                 text="🧠 SMART SCAN\n\nFinds biggest space wasters\nScans entire user profile\nHighlights top files",
                                 font=("Segoe UI", 14, "bold"),
                                 bg="#3498db",
                                 fg="white",
                                 relief=tk.RAISED,
                                 bd=5,
                                 width=25,
                                 height=6,
                                 cursor="hand2",
                                 command=self.smart_scan)
        smart_scan_btn.pack(side=tk.LEFT, padx=20, pady=10)
        
        # Custom Scan button
        custom_scan_btn = tk.Button(button_frame,
                                   text="⚙️ CUSTOM SCAN\n\nFull control over scanning\nAdvanced filters\nManual selection",
                                   font=("Segoe UI", 14, "bold"),
                                   bg="#95a5a6",
                                   fg="white",
                                   relief=tk.RAISED,
                                   bd=5,
                                   width=25,
                                   height=6,
                                   cursor="hand2",
                                   command=self.show_main_ui)
        custom_scan_btn.pack(side=tk.LEFT, padx=20, pady=10)
        
        # AI Agent button (prominent and animated)
        ai_frame = ttk.Frame(welcome_frame)
        ai_frame.pack(pady=20)
        
        ai_btn = tk.Button(ai_frame,
                          text="🤖 TALK TO AI AGENT\n\nJust tell me what to do!\n'delete all safe files'\n'find large files'\n'protect my portfolio'",
                          font=("Segoe UI", 12, "bold"),
                          bg="#9b59b6",
                          fg="white",
                          relief=tk.RAISED,
                          bd=5,
                          width=35,
                          height=5,
                          cursor="hand2",
                          command=self.show_main_ui,
                          activebackground="#8e44ad",
                          activeforeground="white")
        ai_btn.pack()
        
        # Add subtle animation hint
        def animate_ai_button():
            try:
                if not ai_btn.winfo_exists():
                    return
                current_bg = ai_btn.cget('bg')
                if current_bg == "#9b59b6":
                    ai_btn.config(bg="#8e44ad")
                else:
                    ai_btn.config(bg="#9b59b6")
                self._welcome_anim_id = self.root.after(1500, animate_ai_button)
            except tk.TclError:
                return
        
        self._welcome_anim_id = self.root.after(1000, animate_ai_button)
        
        # Info text with better formatting
        info_frame = ttk.Frame(welcome_frame)
        info_frame.pack(pady=(20, 0))
        
        info_label = ttk.Label(info_frame,
                              text="🔒 All operations are safe",
                              font=("Segoe UI", 11, "bold"),
                              foreground="#2ecc71")
        info_label.pack()
        
        info_label2 = ttk.Label(info_frame,
                               text="System files and protected paths (Portfolio, OneDrive) are never deleted",
                               font=("Segoe UI", 9),
                               foreground="#7f8c8d")
        info_label2.pack()
    
    def show_main_ui(self):
        """Show the main application UI."""
        self._cancel_scheduled_callbacks()
        # Clear existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()
        
        self.advanced_mode = True
        self._build_ui()
    
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
        
        self._build_ai_panel(left_panel)
        self._build_protected_paths_panel(left_panel)
        self._build_filters_panel(left_panel)
        self._build_stats_panel(left_panel)
        self._build_visualization_panel(left_panel)
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
        
        left_header = ttk.Frame(header)
        left_header.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        ttk.Label(left_header,
                 text="🚀 DISK CLEANUP PROFESSIONAL",
                 font=("Segoe UI", 22, "bold"),
                 foreground=self.colors['text']).pack(anchor=tk.W)
        
        ttk.Label(left_header,
                 text="Smart cleaning with advanced safety protection",
                 font=("Segoe UI", 11),
                 foreground="#7f8c8d").pack(anchor=tk.W)
        
        # Back to welcome button
        ttk.Button(header, text="🏠 Welcome Screen",
                  command=self.show_welcome_screen, width=15).pack(side=tk.RIGHT, padx=(10, 0))
    
    def _build_control_panel(self, parent):
        """Build control panel with scan options."""
        control_frame = ttk.LabelFrame(parent, text="Scan Controls", padding="15")
        control_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Row 1: Quick action buttons (prominent)
        row1 = ttk.Frame(control_frame)
        row1.pack(fill=tk.X, pady=(0, 10))
        
        one_click_btn = tk.Button(row1, text="⚡ ONE-CLICK CLEANUP",
                                  command=self.one_click_cleanup,
                                  bg="#2ecc71", fg="white",
                                  font=("Segoe UI", 11, "bold"),
                                  width=18, height=2)
        one_click_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        smart_scan_btn = tk.Button(row1, text="🧠 SMART SCAN",
                                   command=self.smart_scan,
                                   bg="#3498db", fg="white",
                                   font=("Segoe UI", 11, "bold"),
                                   width=18, height=2)
        smart_scan_btn.pack(side=tk.LEFT, padx=(0, 10))
        
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
        
        # Row 3: Smart selection buttons
        row3 = ttk.Frame(control_frame)
        row3.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(row3, text="✅ Select All Safe",
                  command=self.select_all_safe, width=15).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(row3, text="📦 Select Large (>100MB)",
                  command=lambda: self.select_large_files(100), width=18).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(row3, text="📅 Select Old (>90 days)",
                  command=lambda: self.select_old_files(90), width=18).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(row3, text="🔍 Find Duplicates",
                  command=self.find_duplicates, width=15).pack(side=tk.LEFT, padx=(0, 10))
        
        # Row 4: Action buttons
        row4 = ttk.Frame(control_frame)
        row4.pack(fill=tk.X)
        
        ttk.Button(row4, text="✅ Select All",
                  command=self.select_all, width=12).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(row4, text="❌ Clear All",
                  command=self.clear_all, width=12).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(row4, text="🗑️ Delete Selected",
                  command=self.delete_selected, width=15).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(row4, text="📊 Generate Report",
                  command=self.generate_report, width=15).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(row4, text="💾 Export Results",
                  command=self.export_results, width=15).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(row4, text="📥 Import Results",
                  command=self.import_results, width=15).pack(side=tk.LEFT)
    
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
    
    def _build_ai_panel(self, parent):
        """Build AI agent chat panel."""
        ai_frame = ttk.LabelFrame(parent, text="🤖 AI Agent - Just Tell Me What To Do", padding="10")
        ai_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Chat display
        chat_container = ttk.Frame(ai_frame)
        chat_container.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Scrollable text widget for chat
        scrollbar = ttk.Scrollbar(chat_container)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.ai_chat_text = tk.Text(chat_container, height=8, wrap=tk.WORD, 
                                    font=("Segoe UI", 9),
                                    yscrollcommand=scrollbar.set)
        self.ai_chat_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.ai_chat_text.yview)
        
        # Welcome message with personality
        welcome_msgs = [
            "👋 Hey! I'm your cleanup assistant. Just tell me what you need!\n\nTry:\n• 'delete all safe files'\n• 'find large files'\n• 'protect my portfolio'\n• 'help' for more\n\nI'm here to help! 😊\n",
            "🤖 Hi there! Ready to free up some space?\n\nI can help you:\n• Find and delete safe files\n• Protect important folders\n• Find duplicates and large files\n\nJust talk to me naturally! 💬\n",
            "✨ Hello! I'm your smart cleanup buddy.\n\nSay things like:\n• 'delete all safe files'\n• 'find large files'\n• 'protect my portfolio'\n• Type 'help' to see everything I can do!\n\nLet's get started! 🚀\n",
        ]
        welcome_msg = welcome_msgs[hash(str(time.time())) % len(welcome_msgs)]
        self.ai_chat_text.insert(1.0, welcome_msg)
        self.ai_chat_text.config(state=tk.DISABLED)
        
        # Input frame
        input_frame = ttk.Frame(ai_frame)
        input_frame.pack(fill=tk.X)
        
        self.ai_input_var = tk.StringVar()
        ai_entry = ttk.Entry(input_frame, textvariable=self.ai_input_var, font=("Segoe UI", 10))
        ai_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ai_entry.bind('<Return>', lambda e: self.execute_ai_command())
        
        ttk.Button(input_frame, text="Send", command=self.execute_ai_command, width=8).pack(side=tk.RIGHT)
        
        # Quick commands
        quick_frame = ttk.Frame(ai_frame)
        quick_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Label(quick_frame, text="Quick:", font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=(0, 5))
        
        quick_commands = [
            ("Safe", "delete all safe files"),
            ("Large", "find large files"),
            ("Old", "find files older than 90 days"),
            ("Stats", "show stats"),
        ]
        
        for label, cmd in quick_commands:
            btn = ttk.Button(quick_frame, text=label, width=8,
                           command=lambda c=cmd: self.quick_ai_command(c))
            btn.pack(side=tk.LEFT, padx=2)
    
    def execute_ai_command(self):
        """Execute AI command from input."""
        command = self.ai_input_var.get().strip()
        if not command:
            return
        
        # Clear input
        self.ai_input_var.set("")
        
        # Enable text widget and add user message
        self.ai_chat_text.config(state=tk.NORMAL)
        self.ai_chat_text.insert(tk.END, f"\n👤 You: {command}\n")
        self.ai_chat_text.see(tk.END)
        self.ai_chat_text.update()
        
        # Show thinking indicator
        self.ai_chat_text.insert(tk.END, "🤖 AI: ")
        self.ai_chat_text.see(tk.END)
        self.ai_chat_text.update()
        
        # Small delay for natural feel
        self.root.update()
        time.sleep(0.1)
        
        # Execute command
        try:
            response = self.ai_agent.execute_command(command)
        except Exception as e:
            response = f"Oops! 😅 Something went wrong: {str(e)}\n\nDon't worry, nothing was deleted. Try again!"
        
        # Remove "thinking" and add actual response
        self.ai_chat_text.delete("end-1l", tk.END)
        self.ai_chat_text.insert(tk.END, f"🤖 AI: {response}\n")
        self.ai_chat_text.see(tk.END)
        self.ai_chat_text.config(state=tk.DISABLED)
        
        # Update UI if needed
        self.apply_filters()
        self.update_visualization()
        
        # Playful success sound effect (visual)
        if "selected" in response.lower() or "found" in response.lower():
            # Flash the chat briefly
            original_bg = self.ai_chat_text.cget('bg')
            self.ai_chat_text.config(bg='#e8f5e9')
            self.root.after(200, lambda: self.ai_chat_text.config(bg=original_bg))
    
    def quick_ai_command(self, command):
        """Execute a quick AI command."""
        self.ai_input_var.set(command)
        self.execute_ai_command()
    
    def _build_protected_paths_panel(self, parent):
        """Build protected paths management panel."""
        protect_frame = ttk.LabelFrame(parent, text="🛡️ Protected Paths", padding="10")
        protect_frame.pack(fill=tk.X, pady=(0, 10))
        
        # List of protected paths
        list_frame = ttk.Frame(protect_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.protected_listbox = tk.Listbox(list_frame, height=4, font=("Segoe UI", 8),
                                            yscrollcommand=scrollbar.set)
        self.protected_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.protected_listbox.yview)
        
        # Update list
        self.update_protected_paths_list()
        
        # Buttons
        btn_frame = ttk.Frame(protect_frame)
        btn_frame.pack(fill=tk.X)
        
        ttk.Button(btn_frame, text="➕ Add Path",
                  command=self.add_protected_path, width=12).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="🔍 Search & Protect",
                  command=self.search_and_protect, width=15).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="➖ Remove",
                  command=self.remove_protected_path, width=12).pack(side=tk.LEFT)
    
    def update_protected_paths_list(self):
        """Update the protected paths listbox."""
        self.protected_listbox.delete(0, tk.END)
        for path in PROTECTED_PATHS:
            # Show shortened path
            display_path = path
            if len(display_path) > 40:
                display_path = "..." + display_path[-37:]
            self.protected_listbox.insert(tk.END, display_path)
    
    def add_protected_path(self):
        """Add a protected path."""
        path = filedialog.askdirectory(title="Select Directory to Protect")
        if path:
            if path not in PROTECTED_PATHS:
                PROTECTED_PATHS.append(path)
                save_protected_paths()
                self.update_protected_paths_list()
                messagebox.showinfo("Path Protected", f"🛡️ Protected: {path}\n\nFiles in this location will never be deleted.")
            else:
                messagebox.showinfo("Already Protected", f"This path is already protected.")
    
    def remove_protected_path(self):
        """Remove a protected path."""
        selection = self.protected_listbox.curselection()
        if not selection:
            messagebox.showinfo("No Selection", "Please select a path to remove.")
            return
        
        index = selection[0]
        path = PROTECTED_PATHS[index]
        
        response = messagebox.askyesno("Remove Protection", 
                                      f"Remove protection from:\n{path}?")
        if response:
            PROTECTED_PATHS.pop(index)
            save_protected_paths()
            self.update_protected_paths_list()
    
    def search_and_protect(self):
        """Search for files/folders and protect them."""
        search_window = tk.Toplevel(self.root)
        search_window.title("Search & Protect")
        search_window.geometry("600x400")
        
        # Search input
        search_frame = ttk.Frame(search_window, padding="10")
        search_frame.pack(fill=tk.X)
        
        ttk.Label(search_frame, text="Search for:", font=("Segoe UI", 10, "bold")).pack(anchor=tk.W)
        
        search_input_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=search_input_var, width=50, font=("Segoe UI", 10))
        search_entry.pack(fill=tk.X, pady=(5, 0))
        search_entry.bind('<Return>', lambda e: self._perform_search(search_input_var.get(), results_listbox))
        
        ttk.Label(search_frame, text="Examples: 'portfolio', 'onedrive', 'my projects'", 
                 font=("Segoe UI", 8), foreground="#666").pack(anchor=tk.W, pady=(2, 0))
        
        # Results
        results_frame = ttk.LabelFrame(search_window, text="Search Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        results_scrollbar = ttk.Scrollbar(results_frame)
        results_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        results_listbox = tk.Listbox(results_frame, font=("Segoe UI", 9),
                                     yscrollcommand=results_scrollbar.set)
        results_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        results_scrollbar.config(command=results_listbox.yview)
        
        # Buttons
        btn_frame = ttk.Frame(search_window, padding="10")
        btn_frame.pack(fill=tk.X)
        
        ttk.Button(btn_frame, text="🔍 Search",
                  command=lambda: self._perform_search(search_input_var.get(), results_listbox)).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="🛡️ Protect Selected",
                  command=lambda: self._protect_selected_from_search(results_listbox, search_window)).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_frame, text="Close",
                  command=search_window.destroy).pack(side=tk.RIGHT)
        
        # Store search results
        self.search_results = []
    
    def _perform_search(self, search_term, listbox):
        """Perform search for files/folders matching search term."""
        if not search_term:
            messagebox.showinfo("No Search Term", "Please enter a search term.")
            return
        
        listbox.delete(0, tk.END)
        self.search_results = []
        
        search_term_lower = search_term.lower()
        userprofile = os.environ.get('USERPROFILE', '')
        
        # Search in common locations
        search_locations = [
            userprofile,
            os.path.join(userprofile, 'Desktop') if userprofile else '',
            os.path.join(userprofile, 'Documents') if userprofile else '',
            os.path.join(userprofile, 'OneDrive') if userprofile else '',
        ]
        
        found_count = 0
        max_results = 100  # Limit results
        
        for location in search_locations:
            if not location or not os.path.exists(location):
                continue
            
            try:
                for root, dirs, files in os.walk(location):
                    # Check directories
                    for d in dirs:
                        if found_count >= max_results:
                            break
                        if search_term_lower in d.lower():
                            full_path = os.path.join(root, d)
                            if os.path.exists(full_path):
                                self.search_results.append(full_path)
                                display = f"📁 {full_path}"
                                if len(display) > 80:
                                    display = "📁 ..." + display[-76:]
                                listbox.insert(tk.END, display)
                                found_count += 1
                    
                    # Limit depth to avoid too much searching
                    if root.count(os.sep) - location.count(os.sep) > 3:
                        dirs[:] = []
                    
                    if found_count >= max_results:
                        break
                
                if found_count >= max_results:
                    break
            except:
                continue
        
        if found_count == 0:
            listbox.insert(0, "No results found. Try a different search term.")
        elif found_count >= max_results:
            listbox.insert(tk.END, f"\n... (showing first {max_results} results)")
    
    def _protect_selected_from_search(self, listbox, window):
        """Protect selected paths from search results."""
        selection = listbox.curselection()
        if not selection:
            messagebox.showinfo("No Selection", "Please select paths to protect.")
            return
        
        protected_count = 0
        for index in selection:
            if index < len(self.search_results):
                path = self.search_results[index]
                if path not in PROTECTED_PATHS:
                    PROTECTED_PATHS.append(path)
                    protected_count += 1
        
        if protected_count > 0:
            save_protected_paths()
            self.update_protected_paths_list()
            messagebox.showinfo("Paths Protected", 
                              f"🛡️ Protected {protected_count} path(s).\n\n"
                              f"These locations will never be deleted.")
            window.destroy()
        else:
            messagebox.showinfo("Already Protected", "Selected paths are already protected.")
    
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
            ("Scan Time:", "time", "0s"),
            ("Top 5 Size:", "top5", "0.00 GB")
        ]
        
        for label, key, default in stats_data:
            frame = ttk.Frame(stats_frame)
            frame.pack(fill=tk.X, pady=2)
            
            ttk.Label(frame, text=label).pack(side=tk.LEFT)
            self.stats_labels[key] = ttk.Label(frame, text=default,
                                             font=("Segoe UI", 10, "bold"))
            self.stats_labels[key].pack(side=tk.RIGHT)
        
        # Initialize top5 if not in stats_data loop
        if "top5" not in self.stats_labels:
            frame = ttk.Frame(stats_frame)
            frame.pack(fill=tk.X, pady=2)
            ttk.Label(frame, text="Top 5 Size:").pack(side=tk.LEFT)
            self.stats_labels["top5"] = ttk.Label(frame, text="0.00 GB",
                                                font=("Segoe UI", 10, "bold"))
            self.stats_labels["top5"].pack(side=tk.RIGHT)
    
    def _build_visualization_panel(self, parent):
        """Build disk space visualization panel."""
        viz_frame = ttk.LabelFrame(parent, text="Space Breakdown", padding="10")
        viz_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Canvas for visualization
        self.viz_canvas = tk.Canvas(viz_frame, height=200, bg="white")
        self.viz_canvas.pack(fill=tk.BOTH, expand=True)
        
        # Bind canvas resize to update visualization
        self.viz_canvas.bind('<Configure>', lambda e: self.update_visualization())
        
        # Label for visualization info
        self.viz_label = ttk.Label(viz_frame, text="Scan files to see space breakdown",
                                  font=("Segoe UI", 9))
        self.viz_label.pack(pady=5)
    
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
        table_frame = ttk.LabelFrame(parent, text="Scan Results (Click column headers to sort)", padding="10")
        table_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create treeview
        columns = ("✓", "Type", "Size", "Age", "Category", "Safety", "Action", "Path")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="none")
        
        # Configure columns with sorting
        widths = [40, 40, 80, 60, 120, 80, 120, 800]
        self.sort_column = "Size"
        self.sort_reverse = True  # Start with largest first
        
        for col, width in zip(columns, widths):
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_by_column(c))
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
        
        self.status_label = ttk.Label(status_frame, 
                                       text="✨ Ready to scan - Click a button above to get started!",
                                       font=("Segoe UI", 9))
        self.status_label.pack(side=tk.LEFT)
        
        # Add helpful tip
        tips = [
            "💡 Tip: Try the AI Agent for natural language commands!",
            "💡 Tip: Your Portfolio and OneDrive are automatically protected!",
            "💡 Tip: Use 'One-Click Cleanup' for instant space freeing!",
        ]
        self.tip_label = ttk.Label(status_frame, 
                                   text=tips[0],
                                   font=("Segoe UI", 8),
                                   foreground="#7f8c8d")
        self.tip_label.pack(side=tk.RIGHT)
        
        # Rotate tips
        def rotate_tip():
            try:
                if not self.tip_label.winfo_exists():
                    return
                current_tip = self.tip_label.cget('text')
                current_index = tips.index(current_tip) if current_tip in tips else 0
                next_index = (current_index + 1) % len(tips)
                self.tip_label.config(text=tips[next_index])
                self._tip_rotate_id = self.root.after(10000, rotate_tip)
            except tk.TclError:
                return
        
        self._tip_rotate_id = self.root.after(10000, rotate_tip)
    
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
    
    def one_click_cleanup(self):
        """One-click cleanup: scan common locations, auto-select safe files, show preview."""
        if self.is_scanning:
            messagebox.showinfo("Scan in Progress", "Please wait for the current scan to complete.")
            return
        
        # Show main UI if on welcome screen
        if not self.advanced_mode:
            self.show_main_ui()
            self.root.update()
            time.sleep(0.1)  # Brief pause for UI to render
        
        # Get all common locations (deduped: TEMP/TMP/AppData\Local\Temp collapse)
        locations = dedupe_scan_locations(get_common_locations())
        if not locations:
            messagebox.showwarning("No Locations", "Could not find common cleanup locations.")
            return
        
        # Ask user to confirm
        response = messagebox.askyesno(
            "One-Click Cleanup",
            f"This will scan {len(locations)} common locations:\n\n" +
            "\n".join([f"• {loc}" for loc in locations[:5]]) +
            (f"\n... and {len(locations)-5} more" if len(locations) > 5 else "") +
            "\n\nSafe files will be auto-selected for deletion.\n\nContinue?",
            icon=messagebox.QUESTION
        )
        
        if not response:
            return
        
        # Clear previous results
        self.tree.delete(*self.tree.get_children())
        self.all_records.clear()
        
        # Set scan parameters for one-click (lower threshold, all categories)
        self.min_mb_var.set(5)  # Focus on meaningful cleanup targets
        self.age_days_var.set(0)  # All ages
        
        # Store locations to scan
        self.one_click_locations = locations
        self.one_click_current_location = 0
        self.one_click_results = []
        
        # Start scanning first location
        if locations:
            self.current_path = locations[0]
            self.one_click_scan_next_location()
    
    def one_click_scan_next_location(self):
        """Scan next location in one-click cleanup."""
        if self.one_click_current_location >= len(self.one_click_locations):
            # All locations scanned, process results
            self._process_one_click_results()
            return
        
        location = self.one_click_locations[self.one_click_current_location]
        self.current_path = location
        self.is_scanning = True
        self.progress_text.config(text=f"Scanning location {self.one_click_current_location + 1}/{len(self.one_click_locations)}: {location}")
        
        # Start scan thread
        selected_categories = list(self.rule_manager.get_all_categories())
        self.scan_thread = threading.Thread(
            target=self._one_click_scan_worker,
            args=(location, self.min_mb_var.get(), 0, selected_categories),
            daemon=True
        )
        self.scan_thread.start()
    
    def _one_click_scan_worker(self, path, min_mb, age_days, categories):
        """Worker for one-click cleanup scanning."""
        try:
            scan_gen = self.scanner.scan(path, min_mb, age_days, categories)
            location_results = []
            
            for item in scan_gen:
                if item[0] == 'progress':
                    _, progress, scanned, total = item
                    # Adjust progress for multi-location scan; clamp to 99 until all done
                    base_progress = (self.one_click_current_location / len(self.one_click_locations)) * 100
                    location_progress = (min(99, progress) / len(self.one_click_locations))
                    total_progress = base_progress + location_progress
                    self.scan_queue.put(('progress', (min(99, total_progress), scanned, total)))
                
                elif item[0] == 'result':
                    _, result = item
                    location_results.append(result)
                    self.scan_queue.put(('result', result))
                
                elif item[0] == 'complete':
                    self.one_click_results.extend(location_results)
                    self.one_click_current_location += 1
                    self.scan_queue.put(('one_click_next', None))
                    break
                
                elif item[0] == 'error':
                    self.one_click_current_location += 1
                    self.scan_queue.put(('one_click_next', None))
                    break
        
        except Exception as e:
            self.scan_queue.put(('error', str(e)))
            self.one_click_current_location += 1
            self.scan_queue.put(('one_click_next', None))
    
    def _process_one_click_results(self):
        """Process results from one-click cleanup."""
        # Process results
        for result in self.one_click_results:
            iid = result['path']
            self.all_records[iid] = result
            
            # Auto-select safe files
            if result['safe'] and "Safe" in result['action']:
                result['checked'] = True
        
        # Update UI
        self.is_scanning = False
        self.progress_bar['value'] = 100
        self.progress_text.config(text="Scan complete")
        
        # Show results and auto-select summary
        safe_count = sum(1 for r in self.all_records.values() if r.get('checked', False))
        safe_size = sum(r['size'] for r in self.all_records.values() if r.get('checked', False))
        
        self.apply_filters()
        self.update_visualization()
        
        messagebox.showinfo(
            "One-Click Cleanup Complete",
            f"Found {len(self.all_records):,} files.\n\n"
            f"✅ Auto-selected {safe_count:,} safe files ({bytes_to_readable(safe_size)})\n\n"
            f"Review the selection and click 'Delete Selected' to free up space."
        )
    
    def smart_scan(self):
        """Smart scan: find biggest space wasters in user profile."""
        if self.is_scanning:
            messagebox.showinfo("Scan in Progress", "Please wait for the current scan to complete.")
            return
        
        # Show main UI if on welcome screen
        if not self.advanced_mode:
            self.show_main_ui()
            self.root.update()
        
        userprofile = os.environ.get('USERPROFILE', '')
        if not userprofile or not os.path.exists(userprofile):
            messagebox.showwarning("No User Profile", "Could not find user profile directory.")
            return
        
        response = messagebox.askyesno(
            "Smart Scan",
            f"This will scan your entire user profile:\n{userprofile}\n\n"
            "It will find the biggest space wasters and highlight them.\n\nContinue?",
            icon=messagebox.QUESTION
        )
        
        if not response:
            return
        
        # Clear and start scan
        self.tree.delete(*self.tree.get_children())
        self.all_records.clear()
        self.current_path = userprofile
        
        # Set parameters for smart scan (focus on larger files)
        self.min_mb_var.set(50)  # Focus on larger files
        self.age_days_var.set(0)
        
        self.start_scan()
    
    def quick_clean(self):
        """Quick clean of common locations."""
        locations = get_common_locations()
        
        if locations:
            self.current_path = locations[0]
            self.start_scan()
        else:
            messagebox.showwarning("No Locations", "Could not find common cleanup locations.")
    
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
    
    def _upsert_result_row(self, result):
        """Insert or update a result row without duplicate-iid crashes."""
        iid = result['path']
        self.all_records[iid] = result
        
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
        
        if self.tree.exists(iid):
            self.tree.item(iid, values=values)
        else:
            self.tree.insert("", "end", iid=iid, values=values)
        
        if color == 'danger':
            self.tree.tag_configure('danger', foreground=self.colors['danger'])
            self.tree.item(iid, tags=('danger',))
        elif color == 'warning':
            self.tree.tag_configure('warning', foreground=self.colors['warning'])
            self.tree.item(iid, tags=('warning',))
        elif color == 'safe':
            self.tree.tag_configure('safe', foreground=self.colors['safe'])
            self.tree.item(iid, tags=('safe',))
    
    def _poll_queue(self):
        """Poll the queue for updates."""
        try:
            if not self.root.winfo_exists():
                return
        except tk.TclError:
            return
        try:
            while True:
                try:
                    item = self.scan_queue.get_nowait()
                except queue.Empty:
                    break
                
                try:
                    if not isinstance(item, tuple):
                        continue
                    
                    cmd, data = item
                    
                    if cmd == 'progress':
                        progress, scanned, total = data
                        progress = min(100, progress)
                        self.progress_bar['value'] = progress
                        self.progress_percent.config(text=f"{progress:.1f}%")
                        self.status_label.config(
                            text=f"Scanned: {scanned:,} of {total:,} files"
                        )
                        current_file = self.scanner.current_file
                        if len(current_file) > 80:
                            current_file = "..." + current_file[-77:]
                        self.current_file_label.config(text=current_file)
                    
                    elif cmd == 'result':
                        self._upsert_result_row(data)
                    
                    elif cmd == 'stats':
                        stats = data
                        self.stats_labels['total_files'].config(text=f"{stats['files_found']:,}")
                        self.stats_labels['total_size'].config(text=bytes_to_readable(stats['total_size']))
                        self.stats_labels['time'].config(text=f"{stats['end_time'] - stats['start_time']:.1f}s")
                        
                        safe_size = 0
                        for rec in self.all_records.values():
                            if "Safe" in rec['action']:
                                safe_size += rec['size']
                        
                        self.stats_labels['potential'].config(text=bytes_to_readable(safe_size))
                        self.stats['potential_savings'] = safe_size
                        
                        sorted_files = sorted(self.all_records.values(), key=lambda x: x['size'], reverse=True)
                        top5_size = sum(f['size'] for f in sorted_files[:5])
                        self.stats_labels['top5'].config(text=bytes_to_readable(top5_size))
                    
                    elif cmd == 'complete':
                        self.is_scanning = False
                        self.progress_bar['value'] = 100
                        self.progress_percent.config(text="100.0%")
                        self.progress_text.config(text="✅ Scan complete!")
                        
                        file_count = len(self.all_records)
                        total_size = self.scanner.stats['total_size']
                        completion_msgs = [
                            f"🎉 Found {file_count:,} files ({bytes_to_readable(total_size)}) - Ready to clean!",
                            f"✨ Scan complete! {file_count:,} files found, {bytes_to_readable(total_size)} total",
                            f"🚀 Done scanning! {file_count:,} files ready for review",
                        ]
                        self.status_label.config(text=completion_msgs[file_count % len(completion_msgs)])
                        self.current_file_label.config(text="")
                        
                        self.apply_filters()
                        self.update_visualization()
                        
                        if file_count > 0:
                            safe_count = sum(1 for r in self.all_records.values() if r['safe'] and "Safe" in r['action'])
                            if safe_count > 0:
                                self.root.after(1000, lambda: self._suggest_ai_action(safe_count))
                    
                    elif cmd == 'error':
                        messagebox.showerror("Scan Error", f"An error occurred:\n\n{data}")
                        self.is_scanning = False
                    
                    elif cmd == 'one_click_next':
                        self.one_click_scan_next_location()
                
                except Exception as e:
                    print(f"Poll queue item error: {e}")
        
        except queue.Empty:
            pass
        
        # Reschedule polling unless window is closing
        try:
            if self.root.winfo_exists():
                self._poll_queue_id = self.root.after(100, self._poll_queue)
        except tk.TclError:
            pass
    
    def _suggest_ai_action(self, safe_count):
        """Suggest AI action after scan."""
        if hasattr(self, 'ai_chat_text') and self.ai_chat_text.winfo_exists():
            self.ai_chat_text.config(state=tk.NORMAL)
            suggestion = f"\n💡 Tip: I found {safe_count:,} safe files! Try saying 'delete all safe files' to select them quickly! 😊\n"
            self.ai_chat_text.insert(tk.END, suggestion)
            self.ai_chat_text.see(tk.END)
            self.ai_chat_text.config(state=tk.DISABLED)
    
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
    
    def select_all_safe(self):
        """Select all files marked as safe to delete."""
        count = 0
        for iid, rec in self.all_records.items():
            if rec['safe'] and "Safe" in rec['action']:
                rec['checked'] = True
                count += 1
                if iid in self.tree.get_children():
                    self.tree.set(iid, "✓", "☑")
        self._update_selection_stats()
        self.status_label.config(text=f"Selected {count:,} safe files")
    
    def select_large_files(self, min_size_mb=100):
        """Select all files larger than specified size."""
        min_size_bytes = min_size_mb * 1024 * 1024
        count = 0
        for iid, rec in self.all_records.items():
            if rec['size'] >= min_size_bytes and rec['safe']:
                rec['checked'] = True
                count += 1
                if iid in self.tree.get_children():
                    self.tree.set(iid, "✓", "☑")
        self._update_selection_stats()
        self.status_label.config(text=f"Selected {count:,} files larger than {min_size_mb}MB")
    
    def select_old_files(self, min_days=90):
        """Select all files older than specified days."""
        count = 0
        for iid, rec in self.all_records.items():
            if rec['age_days'] >= min_days and rec['safe']:
                rec['checked'] = True
                count += 1
                if iid in self.tree.get_children():
                    self.tree.set(iid, "✓", "☑")
        self._update_selection_stats()
        self.status_label.config(text=f"Selected {count:,} files older than {min_days} days")
    
    def find_duplicates(self):
        """Find duplicate files by hash."""
        if not self.all_records:
            messagebox.showinfo("No Files", "Please scan some files first.")
            return
        
        messagebox.showinfo("Finding Duplicates", "This may take a while for large scans...")
        
        # Group files by size first (quick filter)
        size_groups = defaultdict(list)
        for rec in self.all_records.values():
            if rec['safe']:  # Only check safe files
                size_groups[rec['size']].append(rec)
        
        # Find potential duplicates (same size)
        potential_duplicates = {size: files for size, files in size_groups.items() if len(files) > 1}
        
        if not potential_duplicates:
            messagebox.showinfo("No Duplicates", "No duplicate files found (by size).")
            return
        
        # Hash files with same size
        hash_groups = defaultdict(list)
        total_to_check = sum(len(files) for files in potential_duplicates.values())
        checked = 0
        
        for size, files in potential_duplicates.items():
            for rec in files:
                checked += 1
                if checked % 10 == 0:
                    self.status_label.config(text=f"Checking duplicates: {checked}/{total_to_check}")
                    self.root.update()
                
                file_hash = get_file_hash(rec['path'])
                if file_hash:
                    hash_groups[file_hash].append(rec)
        
        # Find actual duplicates (same hash)
        actual_duplicates = {h: files for h, files in hash_groups.items() if len(files) > 1}
        
        if not actual_duplicates:
            messagebox.showinfo("No Duplicates", "No duplicate files found.")
            return
        
        # Store duplicate groups
        self.duplicate_groups = actual_duplicates
        
        # Show duplicates window
        dup_window = tk.Toplevel(self.root)
        dup_window.title("Duplicate Files Found")
        dup_window.geometry("800x600")
        
        text_widget = tk.Text(dup_window, wrap=tk.WORD)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        text_content = f"Found {len(actual_duplicates)} groups of duplicate files:\n\n"
        text_content += "=" * 70 + "\n\n"
        
        total_duplicate_size = 0
        for i, (file_hash, files) in enumerate(actual_duplicates.items(), 1):
            total_size = files[0]['size'] * (len(files) - 1)  # Size of duplicates (excluding one)
            total_duplicate_size += total_size
            
            text_content += f"Group {i}: {len(files)} copies ({bytes_to_readable(files[0]['size'])} each)\n"
            text_content += f"Wasted space: {bytes_to_readable(total_size)}\n"
            text_content += "Files:\n"
            for j, rec in enumerate(files):
                marker = " [KEEP]" if j == 0 else " [DELETE]"
                text_content += f"  {j+1}. {rec['path']}{marker}\n"
            text_content += "\n" + "-" * 70 + "\n\n"
        
        text_content += f"\nTotal wasted space: {bytes_to_readable(total_duplicate_size)}\n"
        text_content += "\nTip: Keep the first file in each group, delete the rest."
        
        text_widget.insert(1.0, text_content)
        text_widget.config(state=tk.DISABLED)
        
        # Auto-select duplicates (all except first in each group)
        selected_count = 0
        for files in actual_duplicates.values():
            for rec in files[1:]:  # Skip first file
                if rec['path'] in self.all_records:
                    self.all_records[rec['path']]['checked'] = True
                    selected_count += 1
        
        self.apply_filters()
        self._update_selection_stats()
        
        ttk.Button(dup_window, text="Close",
                  command=dup_window.destroy).pack(pady=10)
        
        messagebox.showinfo("Duplicates Selected",
                          f"Found {len(actual_duplicates)} duplicate groups.\n"
                          f"Auto-selected {selected_count} duplicate files for deletion.")
    
    def sort_by_column(self, column):
        """Sort treeview by column."""
        # Toggle sort direction if same column
        if self.sort_column == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = column
            self.sort_reverse = True
        
        # Get all items with their values
        items = []
        for iid in self.tree.get_children():
            values = self.tree.item(iid)['values']
            rec = self.all_records.get(iid)
            if rec:
                # Get sort value based on column
                col_index = list(self.tree['columns']).index(column)
                if column == "Size":
                    sort_value = rec['size']
                elif column == "Age":
                    sort_value = rec['age_days']
                else:
                    sort_value = values[col_index] if col_index < len(values) else ""
                items.append((sort_value, iid, values))
        
        # Sort items
        try:
            items.sort(key=lambda x: x[0], reverse=self.sort_reverse)
        except:
            items.sort(key=lambda x: str(x[0]), reverse=self.sort_reverse)
        
        # Reorder in treeview
        for sort_value, iid, values in items:
            self.tree.move(iid, "", "end")
        
        # Update column header to show sort direction
        for col in self.tree['columns']:
            header = col
            if col == self.sort_column:
                header += " ▲" if self.sort_reverse else " ▼"
            self.tree.heading(col, text=header)
    
    def update_visualization(self):
        """Update the disk space visualization."""
        if not self.all_records:
            self.viz_label.config(text="Scan files to see space breakdown")
            self.viz_canvas.delete("all")
            return
        
        # Calculate breakdown by category
        category_sizes = defaultdict(int)
        for rec in self.all_records.values():
            category_sizes[rec['category']] += rec['size']
        
        # Sort by size
        sorted_categories = sorted(category_sizes.items(), key=lambda x: x[1], reverse=True)
        
        if not sorted_categories:
            return
        
        # Draw visualization
        self.viz_canvas.delete("all")
        canvas_width = self.viz_canvas.winfo_width()
        canvas_height = self.viz_canvas.winfo_height()
        
        if canvas_width < 10:  # Canvas not yet rendered
            return
        
        # Draw bar chart
        total_size = sum(size for _, size in sorted_categories)
        max_size = max(size for _, size in sorted_categories)
        
        bar_width = (canvas_width - 40) / len(sorted_categories)
        x = 20
        colors = ['#e74c3c', '#3498db', '#2ecc71', '#f39c12', '#9b59b6', '#1abc9c', '#34495e']
        
        for i, (category, size) in enumerate(sorted_categories[:10]):  # Top 10
            bar_height = (size / max_size) * (canvas_height - 60) if max_size > 0 else 0
            color = colors[i % len(colors)]
            
            # Draw bar
            self.viz_canvas.create_rectangle(
                x, canvas_height - 40 - bar_height,
                x + bar_width - 5, canvas_height - 40,
                fill=color, outline="black", width=1
            )
            
            # Draw label
            percent = (size / total_size * 100) if total_size > 0 else 0
            label = f"{category[:8]}\n{percent:.1f}%"
            self.viz_canvas.create_text(
                x + bar_width/2 - 2.5, canvas_height - 20,
                text=label, font=("Segoe UI", 7), fill="black"
            )
            
            x += bar_width
        
        # Update label
        self.viz_label.config(
            text=f"Top categories: {len(sorted_categories)} | Total: {bytes_to_readable(total_size)}"
        )
    
    def export_results(self):
        """Export scan results to JSON file."""
        if not self.all_records:
            messagebox.showinfo("No Data", "No scan results to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if not filename:
            return
        
        try:
            export_data = {
                'timestamp': datetime.now().isoformat(),
                'scan_path': self.current_path,
                'total_files': len(self.all_records),
                'files': []
            }
            
            for rec in self.all_records.values():
                export_data['files'].append({
                    'path': rec['path'],
                    'size': rec['size'],
                    'category': rec['category'],
                    'age_days': rec['age_days'],
                    'action': rec['action'],
                    'safe': rec['safe']
                })
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2)
            
            messagebox.showinfo("Export Complete", f"Results exported to:\n{filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export results:\n{str(e)}")
    
    def import_results(self):
        """Import scan results from JSON file."""
        filename = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if not filename:
            return
        
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                import_data = json.load(f)
            
            # Clear current results
            self.tree.delete(*self.tree.get_children())
            self.all_records.clear()
            
            # Import files
            for file_data in import_data.get('files', []):
                path = file_data['path']
                if os.path.exists(path):
                    # Re-analyze file
                    safe, reason = is_system_file_safe(path)
                    file_size = file_data.get('size', os.path.getsize(path))
                    rule = self.rule_manager.analyze(path, file_size)
                    
                    result = {
                        'path': path,
                        'size': file_size,
                        'size_display': bytes_to_readable(file_data.get('size', os.path.getsize(path))),
                        'category': file_data.get('category', rule.get('category', 'Unknown')),
                        'description': rule.get('description', ''),
                        'action': file_data.get('action', rule.get('action', 'Review')),
                        'confidence': rule.get('confidence', 50),
                        'icon': rule.get('icon', '📄'),
                        'age_days': file_data.get('age_days', get_file_age_days(path)),
                        'project': get_project_type(path),
                        'safe': file_data.get('safe', safe),
                        'reason': reason,
                        'checked': False
                    }
                    
                    self.all_records[path] = result
            
            self.apply_filters()
            self.update_visualization()
            
            messagebox.showinfo("Import Complete",
                              f"Imported {len(self.all_records)} files from:\n{filename}")
        except Exception as e:
            messagebox.showerror("Import Error", f"Failed to import results:\n{str(e)}")
    
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
        # Update visualization after filtering
        self.root.after(100, self.update_visualization)
    
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
        
        # Check for unsafe files and protected paths
        unsafe_files = []
        protected_files = []
        for rec in selected:
            if not rec['safe']:
                unsafe_files.append(rec['path'])
            # Double-check protected paths
            is_protected, protect_reason = is_path_protected(rec['path'])
            if is_protected:
                protected_files.append((rec['path'], protect_reason))
        
        # Remove protected files from selection
        if protected_files:
            protected_paths_list = "\n".join([f"• {path}" for path, _ in protected_files[:5]])
            if len(protected_files) > 5:
                protected_paths_list += f"\n... and {len(protected_files)-5} more"
            
            messagebox.showwarning(
                "Protected Files",
                f"Cannot delete {len(protected_files)} protected files!\n\n"
                f"These files are in protected locations (Portfolio, OneDrive, etc.):\n\n"
                f"{protected_paths_list}\n\n"
                f"These files will be removed from selection."
            )
            # Remove protected files from selection
            protected_paths = {path for path, _ in protected_files}
            selected = [r for r in selected if r['path'] not in protected_paths]
        
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
        
        # Show success message with personality
        if deleted > 0:
            success_msgs = [
                f"🎉 Awesome! Successfully deleted {deleted} files!",
                f"✨ Great job! {deleted} files removed and space freed!",
                f"🚀 Perfect! {deleted} files deleted. Your disk is breathing easier now!",
            ]
            result_msg = success_msgs[deleted % len(success_msgs)] + "\n\n" + result_msg.split('\n', 1)[1] if '\n' in result_msg else result_msg
        
        messagebox.showinfo("Deletion Complete", result_msg)
        selected_size = sum(r['size'] for r in selected)
        self.status_label.config(text=f"✅ Deleted {deleted} files - {bytes_to_readable(selected_size)} freed!")
        self.apply_filters()
        self.update_visualization()
    
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
        self._cancel_scheduled_callbacks(include_poll=True)
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
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (AttributeError, OSError):
            pass
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