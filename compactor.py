# -*- coding: utf-8 -*-
# NTFS Advanced Compression GUI (XPRESS/LZX) — Tkinter
# Features:
# - Select folder
# - Algorithm selection (XPRESS4K/8K/16K, LZX) — with descriptions
# - Behavior: "Skip" or "Recompress file by file if algorithm differs"
# - "Show Status": Status | Algorithm | Size → On Disk | Savings % | Path
# - Progress bar + live log
# - Only files are listed, folders don't appear in report
# - Long paths are wrapped in Text widget
# - Size on disk: GetCompressedFileSizeW
# - Exact XPRESS/LZX detection through WofIsExternalFile
# - Legacy NTFS compression detection through the compressed file attribute
#
# Notes:
# - "Recompress if algorithm differs" uses compact /F

import os
import sys
import threading
import queue
import subprocess
import ctypes
from ctypes import wintypes
import webbrowser
import csv
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import re

APP_VERSION = "1.2.0"

# -------------------------
# Windows API — size and attribute helpers
# -------------------------

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# GetCompressedFileSizeW
kernel32.GetCompressedFileSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
kernel32.GetCompressedFileSizeW.restype = wintypes.DWORD

# GetFileAttributesW
kernel32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
kernel32.GetFileAttributesW.restype = wintypes.DWORD

# Memory Status for batch sizing
class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_uint64),
        ("ullAvailPhys", ctypes.c_uint64),
        ("ullTotalPageFile", ctypes.c_uint64),
        ("ullAvailPageFile", ctypes.c_uint64),
        ("ullTotalVirtual", ctypes.c_uint64),
        ("ullAvailVirtual", ctypes.c_uint64),
        ("ullAvailExtendedVirtual", ctypes.c_uint64),
    ]

kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MEMORYSTATUSEX)]
kernel32.GlobalMemoryStatusEx.restype = wintypes.BOOL

def get_optimal_batch_size():
    try:
        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(stat)
        if kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
            total_gb = stat.ullTotalPhys / (1024**3)
            # User reported OOM with 50 files on 16GB.
            # Conservative scaling: ~1.0 files per GB.
            # 16GB -> 16 files.
            # 8GB -> 8 files.
            # Cap at 15 to be safe.
            size = int(total_gb * 1.0)
            return max(5, min(15, size))
    except:
        pass
    return 10

FILE_ATTRIBUTE_COMPRESSED = 0x800
WOF_PROVIDER_FILE = 2

WOF_ALGORITHMS = {
    0: "XPRESS4K",
    1: "LZX",
    2: "XPRESS8K",
    3: "XPRESS16K",
}

class WofFileCompressionInfo(ctypes.Structure):
    _fields_ = [
        ("Algorithm", wintypes.ULONG),
        ("Flags", wintypes.ULONG),
    ]

try:
    wofutil = ctypes.WinDLL("Wofutil.dll")
    wofutil.WofIsExternalFile.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(wintypes.ULONG),
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.ULONG),
    ]
    wofutil.WofIsExternalFile.restype = wintypes.LONG
except OSError:
    wofutil = None

def get_folder_sizes(folder):
    total_orig = 0
    total_disk = 0
    for root, dirs, files in os.walk(folder):
        for f in files:
            path = os.path.join(root, f)
            try:
                total_orig += os.path.getsize(path)
                ondisk = get_size_on_disk(path)
                if ondisk:
                    total_disk += ondisk
            except Exception:
                pass
    return total_orig, total_disk


def get_size_on_disk(path):
    high = wintypes.DWORD(0)
    low = kernel32.GetCompressedFileSizeW(path, ctypes.byref(high))
    err = ctypes.get_last_error()
    if low == 0xFFFFFFFF and err != 0:
        return None
    return (high.value << 32) + low

def is_compressed_attribute(path):
    """Does the file have compressed attribute? (Could be LZNT1 or system compression)"""
    attrs = kernel32.GetFileAttributesW(path)
    if attrs == 0xFFFFFFFF:
        return None  # access error
    return bool(attrs & FILE_ATTRIBUTE_COMPRESSED)

def get_compression_algorithm(path):
    """Return the exact WOF algorithm, LZNT1/Unknown, "-", or None on access error."""
    if wofutil is not None:
        is_external = wintypes.BOOL()
        provider = wintypes.ULONG()
        info = WofFileCompressionInfo()
        info_size = wintypes.ULONG(ctypes.sizeof(info))
        result = wofutil.WofIsExternalFile(
            path,
            ctypes.byref(is_external),
            ctypes.byref(provider),
            ctypes.byref(info),
            ctypes.byref(info_size),
        )
        if result == 0 and is_external.value:
            if provider.value == WOF_PROVIDER_FILE:
                return WOF_ALGORITHMS.get(info.Algorithm, "WOF/Unknown")
            return "External/Unknown"

    compressed = is_compressed_attribute(path)
    if compressed is None:
        return None
    return "LZNT1/Unknown" if compressed else "-"

# -------------------------
# compact.exe helpers
# -------------------------

def compact_query_line_for_algorithm(line):
    """Capture algorithm name from compact /q output line.
       Algorithm names in parentheses (LZX/XPRESS*) appear regardless of locale."""
    s = line.upper()
    for tag in ("(LZX)", "(XPRESS4K)", "(XPRESS8K)", "(XPRESS16K)"):
        if tag in s:
            return tag.strip("()")
    return None

def run_compact(args, cwd=None):
    cmd = ["compact.exe"] + args
    try:
        # CREATE_NO_WINDOW flag prevents console window from appearing
        CREATE_NO_WINDOW = 0x08000000
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding="utf-8",       # encoding added
            errors="ignore",        # ignore problematic characters
            cwd=cwd,
            check=False,
            creationflags=CREATE_NO_WINDOW  # Prevents console window flashing
        )
        return p.returncode, p.stdout
    except Exception as e:
        return 1, f"[compact error] {e}"

def compact_query_folder(folder):
    """Return output from compact /s:"folder" (without /q to ensure file listing)."""
    return run_compact(["/s:{}".format(folder)])

def compact_compress_file(path, algorithm_switch, force=False):
    """Compress specified file with selected algorithm (/c /exe:xxx)."""
    args = ["/c", "/i"]
    if force:
        args.append("/f")
    args.extend(["/exe:{}".format(algorithm_switch), path])
    return run_compact(args)

def run_compact_stream(args, files, callback_line, stop_event=None, progress_callback=None):
    """Run compact.exe on a batch of files, streaming output to callback."""
    # Windows CreateProcess limit is 32k chars.
    # We must respect both the file count limit (to avoid OOM) AND the character limit.
    # Optimization: Group by directory and use CWD to reduce command line length.
    
    max_files_per_batch = get_optimal_batch_size()
    max_chars = 30000 # Safe limit below 32767
    
    base_cmd = ["compact.exe"] + args
    base_len = sum(len(a) + 1 for a in base_cmd) # +1 for spaces
    
    current_batch = []
    current_batch_dir = None
    current_batch_len = base_len
    
    def execute_batch(batch, cwd):
        if not batch: return

        # Recursive retry logic for OOM
        def run_subset(subset):
            if not subset: return
            
            cmd = base_cmd + subset
            output_buffer = []
            oom_detected = False
            
            try:
                CREATE_NO_WINDOW = 0x08000000
                p = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    encoding="utf-8",
                    errors="ignore",
                    creationflags=CREATE_NO_WINDOW,
                    bufsize=1,
                    universal_newlines=True,
                    cwd=cwd
                )
                
                for line in p.stdout:
                    if stop_event and stop_event.is_set():
                        p.terminate()
                        break
                    line_stripped = line.strip()
                    output_buffer.append(line_stripped)
                    if "Out of memory" in line_stripped:
                        oom_detected = True
                
                p.wait()
                
                if stop_event and stop_event.is_set():
                    return

                if oom_detected:
                    if len(subset) > 1:
                        # OOM detected and we can split
                        mid = len(subset) // 2
                        run_subset(subset[:mid])
                        run_subset(subset[mid:])
                    else:
                        # Single file failed with OOM.
                        # As per user request: Assume it's due to path depth and skip immediately.
                        callback_line(f"[Error] Path too deep, skipped: {subset[0]}")
                else:
                    # No OOM -> flush output
                    for line in output_buffer:
                        callback_line(line)
                    
                    if progress_callback:
                        progress_callback(len(subset))

            except Exception as e:
                callback_line(f"[Error] Batch execution failed: {e}")

        run_subset(batch)

    for path in files:
        if stop_event and stop_event.is_set():
            break
            
        # Pre-check: Skip paths that are likely too long for compact.exe
        # Standard MAX_PATH is 260. We use a safe margin.
        if len(os.path.abspath(path)) > 255:
            callback_line(f"[Skipped] Path too long (>255 chars): {path}")
            if progress_callback:
                progress_callback(1)
            continue
            
        dname, fname = os.path.split(path)
        
        # If directory changed, flush previous batch
        if current_batch and dname != current_batch_dir:
            execute_batch(current_batch, current_batch_dir)
            current_batch = []
            current_batch_dir = None
            current_batch_len = base_len
            
        current_batch_dir = dname
        
        # Quote path length approximation (fname + 2 quotes + 1 space)
        path_len = len(fname) + 3 
        
        # Check limits
        if (len(current_batch) >= max_files_per_batch) or \
           (current_batch_len + path_len > max_chars):
            execute_batch(current_batch, current_batch_dir)
            current_batch = []
            current_batch_len = base_len
            
        current_batch.append(fname)
        current_batch_len += path_len
        
    # Execute remaining
    if current_batch and not (stop_event and stop_event.is_set()):
        execute_batch(current_batch, current_batch_dir)

# -------------------------
# Helper — size formatting
# -------------------------

def fmt_bytes(n):
    if n is None:
        return "?"
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(n)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{size:.0f} {unit}"
            else:
                return f"{size:.2f} {unit}"
        size /= 1024.0

def human_size_pair(orig, ondisk):
    left = fmt_bytes(orig) if orig is not None else "?"
    right = fmt_bytes(ondisk) if ondisk is not None else "?"
    return f"{left} → {right}"

def percent_saving(orig, ondisk):
    if orig is None or ondisk is None or orig <= 0:
        return "?"
    if ondisk >= orig:
        return "0%"
    pct = (1.0 - (ondisk / orig)) * 100.0
    return f"{pct:.0f}%"

# -------------------------
# Core functions (Status and Compression)
# -------------------------

def iter_files_under(folder):
    """Yield all files (not folders) under folder."""
    for root, dirs, files in os.walk(folder):
        for name in files:
            yield os.path.join(root, name)

def compression_action(current_alg, target_alg, behavior):
    """Return skip, compress, or recompress for a file."""
    if not current_alg:
        return "compress"
    if behavior == "skip" or current_alg.casefold() == target_alg.casefold():
        return "skip"
    return "recompress"

def detect_algorithm_via_compact_map(folder):
    """Parse compact /s output line by line:
       Extract path -> algorithm mapping based on flags:
       x -> XPRESS4K
       X -> XPRESS8K/16K (Ambiguous)
       l -> LZX
       C -> LZNT1
    """
    ret, out = compact_query_folder(folder)
    algomap = {}
    if not out:
        return algomap

    current_dir = None
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue

        # Check for directory header (e.g. "Listing C:\Path\")
        if line.endswith("\\"):
            # Try to find drive letter sequence like "C:\"
            idx = line.find(":\\")
            if idx != -1 and idx > 0:
                candidate = line[idx-1:]
                if os.path.isdir(candidate):
                    current_dir = candidate
                else:
                    current_dir = candidate
        
        # Try to parse file line with flag
        # Format: Size : Compressed = Ratio ... 1 Flag Filename
        # Regex: ^\d+\s*:\s*\d+\s*=\s*[\d,.]+\s+.*?\s+1\s+([CxlX])\s+(.*)$
        match = re.match(r'^\d+\s*:\s*\d+\s*=\s*[\d,.]+\s+.*?\s+1\s+([CxlX])\s+(.*)$', line)
        if match:
            flag, filename = match.groups()
            alg = None
            if flag == 'x': alg = "XPRESS4K"
            elif flag == 'X': alg = "XPRESS8K/16K"
            elif flag == 'l': alg = "LZX"
            elif flag == 'C': alg = "LZNT1"
            
            if alg:
                fname = filename.strip()
                if current_dir:
                    fullpath = os.path.join(current_dir, fname)
                else:
                    fullpath = os.path.join(folder, fname)
                
                # Normalize path for consistent lookup
                norm_path = os.path.normcase(os.path.abspath(fullpath))
                algomap[norm_path] = alg
                continue

        # Fallback: Check for (ALG) format if compact /q style is present
        alg = compact_query_line_for_algorithm(line)
        if alg:
            parts = line.split(f"({alg})")
            if len(parts) > 1:
                filename = parts[-1].strip()
                if current_dir:
                    fullpath = os.path.join(current_dir, filename)
                else:
                    fullpath = os.path.join(folder, filename)
                
                norm_path = os.path.normcase(os.path.abspath(fullpath))
                algomap[norm_path] = alg

    return algomap

# -------------------------
# GUI
# -------------------------

ALG_OPTIONS = [
    ("XPRESS4K (Fast, low compression)", "xpress4k"),
    ("XPRESS8K (Medium, balanced)", "xpress8k"),
    ("XPRESS16K (Slow, higher compression)", "xpress16k"),
    ("LZX (Ultra, highest ratio)", "lzx"),
]

BEHAVIOR_OPTIONS = [
    ("Skip (don't touch if already compressed)", "skip"),
    ("Recompress file by file if algorithm differs", "recompress_if_different"),
]

# Status report Treeview columns
# (column_id, header_label, default_width, anchor)
STATUS_COLUMNS = [
    ("status",    "Status",    90,  "w"),
    ("algorithm", "Algorithm", 90,  "w"),
    ("size",      "Size",      90,  "e"),
    ("ondisk",    "On Disk",   90,  "e"),
    ("savings",   "Savings %", 80,  "e"),
    ("path",      "File Path", 480, "w"),
]
STATUS_COL_IDS = [c[0] for c in STATUS_COLUMNS]
STATUS_COL_HEADINGS = {c[0]: c[1] for c in STATUS_COLUMNS}

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"NTFS Advanced Compression v{APP_VERSION} (XPRESS/LZX)")
        self.geometry("980x640")

        self.folder = tk.StringVar()
        self.alg_label = tk.StringVar(value=ALG_OPTIONS[-1][0])  # default LZX
        self.beh_label = tk.StringVar(value=BEHAVIOR_OPTIONS[1][0])  # default recompress_if_different
        self.verbose = tk.BooleanVar(value=False)

        self._build_ui()

        # thread communication
        self.log_q = queue.Queue()
        self.ui_q = queue.Queue()
        self.worker = None
        self.stop_flag = threading.Event()

    def _build_ui(self):
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)

        # Top: folder selection + options
        top = ttk.Frame(frm)
        top.pack(fill="x", pady=(0,8))

        # Left side: folder controls
        ttk.Label(top, text="Folder:").pack(side="left")
        self.ent_folder = ttk.Entry(top, textvariable=self.folder, width=70)
        self.ent_folder.pack(side="left", padx=6)
        ttk.Button(top, text="Browse...", command=self.choose_folder).pack(side="left")
        ttk.Checkbutton(top, text="Verbose Logging", variable=self.verbose).pack(side="left", padx=8)

        # Right side: Support button (opens Buy Me a Coffee link)
        # Using a unicode coffee emoji to avoid external image dependencies.
        btn_support = ttk.Button(top, text="☕ Support", command=lambda: webbrowser.open_new_tab("https://buymeacoffee.com/bariselcii"))
        btn_support.pack(side="right")

        self.size_label = ttk.Label(frm, text="On Disk: - / Actual: -")
        self.size_label.pack(fill="x", pady=(0,6))
        self.before_disk = None

        # Options
        opts = ttk.Frame(frm)
        opts.pack(fill="x", pady=(0,8))

        # Algorithm dropdown
        ttk.Label(opts, text="Algorithm:").grid(row=0, column=0, sticky="w")
        self.alg_combo = ttk.Combobox(opts, state="readonly", width=36,
                                      values=[label for (label, val) in ALG_OPTIONS],
                                      textvariable=self.alg_label)
        self.alg_combo.grid(row=0, column=1, sticky="w", padx=6)

        # Behavior dropdown
        ttk.Label(opts, text="Behavior:").grid(row=0, column=2, sticky="w", padx=(16,0))
        self.beh_combo = ttk.Combobox(opts, state="readonly", width=44,
                                      values=[label for (label, val) in BEHAVIOR_OPTIONS],
                                      textvariable=self.beh_label)
        self.beh_combo.grid(row=0, column=3, sticky="w", padx=6)

        # Buttons
        btns = ttk.Frame(frm)
        btns.pack(fill="x", pady=(0,8))

        self.btn_status = ttk.Button(btns, text="Show Status", command=self.on_status)
        self.btn_status.pack(side="left")

        self.btn_save_report = ttk.Button(btns, text="Save Report...", command=self.on_save_report, state="disabled")
        self.btn_save_report.pack(side="left", padx=6)

        self.btn_clear_report = ttk.Button(btns, text="Clear Report", command=self.on_clear_report, state="disabled")
        self.btn_clear_report.pack(side="left", padx=6)

        self.btn_compress = ttk.Button(btns, text="Compress", command=self.on_compress)
        self.btn_compress.pack(side="left", padx=6)

        self.btn_stop = ttk.Button(btns, text="Stop", command=self.on_stop, state="disabled")
        self.btn_stop.pack(side="left", padx=6)

        # Progress bar
        pfrm = ttk.Frame(frm)
        pfrm.pack(fill="x", pady=(0,8))
        self.progress = ttk.Progressbar(pfrm, mode="determinate")
        self.progress.pack(fill="x")

        # Notebook with two tabs: Status Report (Treeview) and Compression Log (Text)
        self.notebook = ttk.Notebook(frm)
        self.notebook.pack(fill="both", expand=True)

        # --- Status Report tab ---
        status_tab = ttk.Frame(self.notebook)
        self.notebook.add(status_tab, text="Status Report")

        status_outer = ttk.Frame(status_tab)
        status_outer.pack(fill="both", expand=True)

        self.status_tree = ttk.Treeview(
            status_outer,
            columns=STATUS_COL_IDS,
            show="headings",
            selectmode="extended",
        )
        for col_id, label, width, anchor in STATUS_COLUMNS:
            self.status_tree.heading(
                col_id,
                text=label,
                command=lambda c=col_id: self._sort_status(c),
            )
            self.status_tree.column(col_id, width=width, anchor=anchor, stretch=(col_id == "path"))

        # Configure zebra striping tags
        self.status_tree.tag_configure("oddrow", background="#f5f5f5")
        self.status_tree.tag_configure("evenrow", background="#ffffff")

        vsb = ttk.Scrollbar(status_outer, orient="vertical", command=self.status_tree.yview)
        hsb = ttk.Scrollbar(status_outer, orient="horizontal", command=self.status_tree.xview)
        self.status_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.status_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        status_outer.rowconfigure(0, weight=1)
        status_outer.columnconfigure(0, weight=1)

        # Right-click context menu for the status report
        self.status_menu = tk.Menu(self, tearoff=0)
        self.status_menu.add_command(label="Copy Row", command=self._copy_status_row)
        self.status_menu.add_command(label="Copy All", command=self._copy_status_all)
        self.status_menu.add_separator()
        self.status_menu.add_command(label="Save as CSV...", command=self.on_save_report)
        self.status_tree.bind("<Button-3>", self._show_status_menu)

        # Storage backing the Treeview (used for sorting)
        self._status_raw = {}  # iid -> dict of raw values keyed by column id
        self._status_sort_state = {}  # col_id -> "asc" | "desc"
        self._status_row_count = 0

        # --- Compression Log tab ---
        log_tab = ttk.Frame(self.notebook)
        self.notebook.add(log_tab, text="Compression Log")

        logfrm = ttk.Frame(log_tab)
        logfrm.pack(fill="both", expand=True)
        self.txt = tk.Text(logfrm, wrap="word", height=24)
        self.txt.pack(side="left", fill="both", expand=True)
        yscroll = ttk.Scrollbar(logfrm, orient="vertical", command=self.txt.yview)
        yscroll.pack(side="right", fill="y")
        self.txt.configure(yscrollcommand=yscroll.set)

        # Switch to the Log tab when a compression run starts; switch to Report when status completes.
        self._switch_to_log_on_compress = True

        # Periodic log consumption
        self.after(100, self._drain_log_queue)

    # -------------
    # UI Helpers
    # -------------
    def choose_folder(self):
        path = filedialog.askdirectory()
        if path:
            self.folder.set(path)
            self.before_disk = None
            self.size_label.config(text="Measurement will be done during compression")

    def append_log(self, s):
        self.txt.insert("end", s + "\n")
        self.txt.see("end")

    def clear_log(self):
        self.txt.delete("1.0", "end")

    def _disable_actions(self):
        self.btn_status.config(state="disabled")
        self.btn_compress.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.alg_combo.config(state="disabled")
        self.beh_combo.config(state="disabled")
        # Don't disable Save/Clear Report while a scan is running; user may still export.

    def _enable_actions(self):
        self.btn_status.config(state="normal")
        self.btn_compress.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.alg_combo.config(state="readonly")
        self.beh_combo.config(state="readonly")
        if self.status_tree.get_children():
            self.btn_save_report.config(state="normal")
            self.btn_clear_report.config(state="normal")

    def _drain_log_queue(self):
        try:
            messages = []
            while True:
                try:
                    msg = self.log_q.get_nowait()
                    messages.append(msg)
                    # Limit batch size to keep UI responsive during heavy logging
                    if len(messages) >= 500:
                        break
                except queue.Empty:
                    break

            if messages:
                self.append_log_batch(messages)

            latest_progress = None
            status_rows = []
            status_clear = False
            while True:
                try:
                    action, value = self.ui_q.get_nowait()
                except queue.Empty:
                    break
                if action == "progress":
                    latest_progress = value
                elif action == "progress_max":
                    self.progress["maximum"] = value
                    self.progress["value"] = 0
                elif action == "enable":
                    self._enable_actions()
                elif action == "size":
                    self.size_label.config(text=value)
                elif action == "status_row":
                    status_rows.append(value)
                    if len(status_rows) >= 500:
                        self._add_status_rows(status_rows)
                        status_rows = []
                elif action == "status_clear":
                    status_clear = True
            if status_clear:
                self._clear_status_report()
            if status_rows:
                self._add_status_rows(status_rows)
            if latest_progress is not None:
                self.progress["value"] = latest_progress

        except Exception:
            pass
        finally:
            self.after(100, self._drain_log_queue)

    def append_log_batch(self, messages):
        for msg in messages:
            if msg.startswith("\r"):
                # Replace last line
                # Check if there is any text to replace
                if self.txt.index("end-1c") != "1.0":
                    # Delete current last line (excluding the final newline of the widget)
                    # "end-1c" is the last character (usually \n). 
                    # "end-1c linestart" is the start of that line.
                    self.txt.delete("end-1c linestart", "end-1c")
                self.txt.insert("end", msg[1:]) # Insert new text (no newline at end to keep it on same line)
            else:
                # Normal append
                # Ensure we are on a new line if the previous one was a progress line
                if self.txt.get("end-1c linestart", "end-1c").strip():
                     self.txt.insert("end", "\n")
                self.txt.insert("end", msg + "\n")
        
        # Truncate log if it gets too long (keep last ~2000 lines)
        # This prevents the Text widget from slowing down the whole app
        try:
            num_lines = int(self.txt.index('end-1c').split('.')[0])
            if num_lines > 2500:
                self.txt.delete("1.0", f"{num_lines - 2000}.0")
        except Exception:
            pass
            
        self.txt.see("end")

    def on_stop(self):
        self.stop_flag.set()

    # -------------
    # Status report (Treeview) helpers
    # -------------
    def _clear_status_report(self):
        for iid in self.status_tree.get_children(""):
            self.status_tree.delete(iid)
        self._status_raw.clear()
        self._status_sort_state.clear()
        self._status_row_count = 0
        self.btn_save_report.config(state="disabled")
        self.btn_clear_report.config(state="disabled")

    def _add_status_rows(self, rows):
        for row in rows:
            iid = str(self._status_row_count)
            self._status_row_count += 1
            tag = "evenrow" if (self._status_row_count % 2 == 0) else "oddrow"
            values = (
                row.get("status", ""),
                row.get("algorithm", ""),
                row.get("size_disp", ""),
                row.get("ondisk_disp", ""),
                row.get("savings_disp", ""),
                row.get("path", ""),
            )
            self.status_tree.insert("", "end", iid=iid, values=values, tags=(tag,))
            # Store raw values for sorting
            self._status_raw[iid] = {
                "status":    row.get("status", ""),
                "algorithm": row.get("algorithm", ""),
                "size":      row.get("size_raw", -1),
                "ondisk":    row.get("ondisk_raw", -1),
                "savings":   row.get("savings_raw", -1.0),
                "path":      row.get("path_raw", row.get("path", "").casefold()),
            }
        # Enable Save/Clear once we have at least one row
        if rows:
            self.btn_save_report.config(state="normal")
            self.btn_clear_report.config(state="normal")

    def _sort_status(self, col):
        if not self._status_raw:
            return
        raw = self._status_raw
        prev = self._status_sort_state.get(col)
        if prev is None:
            reverse = False
            self._status_sort_state[col] = "asc"
        elif prev == "asc":
            reverse = True
            self._status_sort_state[col] = "desc"
        else:
            reverse = False
            self._status_sort_state[col] = "asc"

        def sort_key(iid):
            v = raw[iid].get(col)
            if v is None:
                return (1, 0)
            if isinstance(v, bool):
                return (0, int(v))
            if isinstance(v, (int, float)):
                return (0, v)
            return (0, str(v).lower())

        items = list(self.status_tree.get_children(""))
        items.sort(key=sort_key, reverse=reverse)
        for idx, iid in enumerate(items):
            self.status_tree.move(iid, "", idx)
        self._apply_zebra()
        # Update heading to show direction indicator
        for c in STATUS_COL_IDS:
            label = STATUS_COL_HEADINGS[c]
            if c == col:
                indicator = " ▲" if not reverse else " ▼"
                self.status_tree.heading(c, text=label + indicator)
            else:
                self.status_tree.heading(c, text=label)

    def _apply_zebra(self):
        for idx, iid in enumerate(self.status_tree.get_children("")):
            tag = "evenrow" if (idx % 2 == 0) else "oddrow"
            self.status_tree.item(iid, tags=(tag,))

    def on_clear_report(self):
        self._clear_status_report()

    def on_save_report(self):
        items = self.status_tree.get_children("")
        if not items:
            messagebox.showinfo("Save Report", "There is no status report to export.")
            return
        path = filedialog.asksaveasfilename(
            title="Save Status Report",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([STATUS_COL_HEADINGS[c] for c in STATUS_COL_IDS])
                for iid in items:
                    writer.writerow([self.status_tree.set(iid, c) for c in STATUS_COL_IDS])
        except Exception as e:
            messagebox.showerror("Save Report", f"Failed to save report: {e}")
            return
        messagebox.showinfo("Save Report", f"Report saved to:\n{path}")

    def _show_status_menu(self, event):
        iid = self.status_tree.identify_row(event.y)
        if iid:
            if iid not in self.status_tree.selection():
                self.status_tree.selection_set(iid)
            self.status_tree.focus(iid)
        try:
            self.status_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.status_menu.grab_release()

    def _copy_status_row(self):
        sel = self.status_tree.selection()
        if not sel:
            return
        iid = sel[0]
        row = "\t".join(self.status_tree.set(iid, c) for c in STATUS_COL_IDS)
        self.clipboard_clear()
        self.clipboard_append(row)
        self.update()  # keep clipboard content after window closes

    def _copy_status_all(self):
        lines = ["\t".join(STATUS_COL_HEADINGS[c] for c in STATUS_COL_IDS)]
        for iid in self.status_tree.get_children(""):
            lines.append("\t".join(self.status_tree.set(iid, c) for c in STATUS_COL_IDS))
        if len(lines) == 1:
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))
        self.update()

    # -------------
    # Operations
    # -------------
    def on_status(self):
        folder = self.folder.get().strip()
        if not folder:
            messagebox.showwarning("Warning", "Please select a folder first.")
            return
        if not os.path.isdir(folder):
            messagebox.showerror("Error", "Folder not found.")
            return

        self.ui_q.put(("status_clear", None))
        try:
            self.notebook.select(0)
        except Exception:
            pass
        self.stop_flag.clear()
        self._disable_actions()

        def worker():
            try:
                files = list(iter_files_under(folder))
                total = len(files)
                self.ui_q.put(("progress_max", max(total, 1)))

                for idx, path in enumerate(files, 1):
                    if self.stop_flag.is_set():
                        break

                    try:
                        # Algorithm
                        alg = get_compression_algorithm(path)
                        if alg is None:
                            # Access denied - record an error row
                            self.ui_q.put(("status_row", {
                                "status":    "Error",
                                "algorithm": "-",
                                "size_disp": "?",
                                "size_raw":  -1,
                                "ondisk_disp": "?",
                                "ondisk_raw": -1,
                                "savings_disp": "?",
                                "savings_raw": -1.0,
                                "path":      path,
                                "path_raw":  path.casefold(),
                            }))
                            self.ui_q.put(("progress", idx))
                            continue

                        # Sizes
                        try:
                            orig = os.path.getsize(path)
                        except Exception:
                            orig = None
                        ondisk = get_size_on_disk(path)

                        # Status
                        status = "Compressed" if (alg != "-" and alg is not None) else "Uncompressed"

                        # Savings raw value (used for sorting)
                        savings_raw = -1.0
                        if orig is not None and ondisk is not None and orig > 0:
                            if ondisk < orig:
                                savings_raw = (1.0 - (ondisk / orig)) * 100.0
                            else:
                                savings_raw = 0.0

                        size_raw = orig if orig is not None else -1
                        ondisk_raw = ondisk if ondisk is not None else -1

                        self.ui_q.put(("status_row", {
                            "status":      status,
                            "algorithm":   alg if alg is not None else "-",
                            "size_disp":   fmt_bytes(orig),
                            "size_raw":    size_raw,
                            "ondisk_disp": fmt_bytes(ondisk),
                            "ondisk_raw":  ondisk_raw,
                            "savings_disp": percent_saving(orig, ondisk),
                            "savings_raw": savings_raw,
                            "path":        path,
                            "path_raw":    path.casefold(),
                        }))

                    except Exception as e:
                        self.ui_q.put(("status_row", {
                            "status":      "Error",
                            "algorithm":   "-",
                            "size_disp":   "?",
                            "size_raw":    -1,
                            "ondisk_disp": "?",
                            "ondisk_raw":  -1,
                            "savings_disp": "?",
                            "savings_raw": -1.0,
                            "path":        f"[Error: {e}] {path}",
                            "path_raw":    path.casefold(),
                        }))

                    self.ui_q.put(("progress", idx))

            finally:
                self.ui_q.put(("enable", None))

        self.worker = threading.Thread(target=worker, daemon=True)
        self.worker.start()

    def on_compress(self):
        folder = self.folder.get().strip()
        if not folder or not os.path.isdir(folder):
            messagebox.showwarning("Warning", "Please select a valid folder.")
            return

        # Algorithm selection
        alg_label = self.alg_label.get()
        alg_switch = None
        for label, val in ALG_OPTIONS:
            if label == alg_label:
                alg_switch = val
                break
        if not alg_switch:
            messagebox.showerror("Error", "Could not select algorithm.")
            return

        # Behavior selection
        beh_label = self.beh_label.get()
        behavior = None
        for label, val in BEHAVIOR_OPTIONS:
            if label == beh_label:
                behavior = val
                break
        
        is_verbose = self.verbose.get()

        self.clear_log()
        self.append_log(f"Starting compression → Algorithm: {alg_label}, Behavior: {beh_label}")
        # Switch to the compression log tab so streaming output is visible.
        try:
            self.notebook.select(1)
        except Exception:
            pass
        self.stop_flag.clear()
        self._disable_actions()
        
        def worker():
            try:
                self.log_q.put("Performing initial measurement (this may take a while)...")
                self.ui_q.put(("size", "Performing initial measurement..."))
                
                orig, disk = get_folder_sizes(folder)
                self.before_disk = disk
                
                res_text = f"On Disk (Initial): {fmt_bytes(disk)} / Actual: {fmt_bytes(orig)}"
                self.ui_q.put(("size", res_text))
                self.log_q.put(f"Initial size: {fmt_bytes(disk)} (On Disk) / {fmt_bytes(orig)} (Actual)")

                self.log_q.put("Listing files...")
                files = list(iter_files_under(folder))
                total = len(files)
                self.ui_q.put(("progress_max", max(total, 1)))
                self.log_q.put(f"Found {total} files. Analyzing compression status...")
                
                to_compress = []

                for idx, path in enumerate(files, 1):
                    if self.stop_flag.is_set():
                        self.log_q.put("[Stopped]")
                        return

                    try:
                        current_alg = get_compression_algorithm(path)
                        if current_alg is None:
                            self.log_q.put(f"[Error: Access denied] {path}")
                            continue
                        if current_alg == "-":
                            current_alg = None

                        if compression_action(current_alg, alg_switch, behavior) != "skip":
                            to_compress.append(path)

                    except Exception as e:
                        self.log_q.put(f"[Error: {e}] {path}")

                    if is_verbose and idx % 100 == 0:
                         self.log_q.put(f"Analyzed {idx}/{total} files...")
                    self.ui_q.put(("progress", idx))

                self.log_q.put(f"Analysis complete. Compressing {len(to_compress)} files.")
                
                batch_size = get_optimal_batch_size()
                self.log_q.put(f"Batch size calculated: {batch_size} files per chunk (based on system memory).")

                total_ops = len(to_compress)
                self.ui_q.put(("progress_max", max(total_ops, 1)))
                
                current_progress = 0
                current_header_dir = ""
                
                # Error counters for non-verbose mode
                error_counts = {"Long Path": 0, "Other": 0}
                last_update_time = 0

                def update_status_line(force=False):
                    import time
                    nonlocal last_update_time
                    now = time.time()
                    # Update at most every 0.5 seconds unless forced, to avoid UI flicker
                    if not force and (now - last_update_time < 0.5):
                        return
                    last_update_time = now

                    pct = (current_progress / max(total_ops, 1)) * 100.0
                    pct_str = f"{int(pct)}%" if pct % 1 == 0 else f"{pct:.2f}%"
                    
                    # ASCII Bar: [████░░░░░░]
                    bar_len = 20
                    filled = int((pct / 100.0) * bar_len)
                    bar = "█" * filled + "░" * (bar_len - filled)
                    
                    status_msg = f"\rCompressing [{bar}] {pct_str} complete"
                    
                    err_parts = []
                    if error_counts["Long Path"] > 0:
                        err_parts.append(f"{error_counts['Long Path']} (Long Path)")
                    if error_counts["Other"] > 0:
                        err_parts.append(f"{error_counts['Other']} (Other)")
                    
                    if err_parts:
                        status_msg += " | Errors: " + ", ".join(err_parts)
                    
                    self.log_q.put(status_msg)

                def progress_cb(count):
                    nonlocal current_progress
                    current_progress += count
                    self.ui_q.put(("progress", current_progress))
                    if not is_verbose:
                        update_status_line()

                def log_callback(line):
                    nonlocal current_header_dir
                    
                    # Filter empty lines
                    if not line.strip():
                        return
                    
                    # Check for errors/skips to update counters
                    if line.startswith("[Skipped] Path too long"):
                        error_counts["Long Path"] += 1
                        if not is_verbose:
                            update_status_line(force=True)
                            return
                    elif line.startswith("[Error]"):
                        error_counts["Other"] += 1
                        if not is_verbose:
                            update_status_line(force=True)
                            return

                    # Capture directory header
                    if "Compressing files in" in line:
                        parts = line.split("Compressing files in")
                        if len(parts) > 1:
                            current_header_dir = parts[1].strip()
                        return

                    # Filter batch summary lines
                    # "50 files within 50 directories were compressed."
                    # "206.705.328 total bytes of data are stored in 178.282.496 bytes."
                    # "The compression ratio is 1,2 to 1."
                    if "files within" in line and "directories were compressed" in line:
                        return
                    if "total bytes of data are stored in" in line:
                        return
                    if "The compression ratio is" in line:
                        return
                    
                    # Parse compact.exe file output
                    
                    # Regex 1: compact /c output (Compression)
                    # Format: Filename   Size : Compressed = Ratio to 1 [OK]
                    # Example: test.txt   100 : 50 = 2,0 to 1 [OK]
                    match_c = re.match(r'^(.*?)\s+(\d+)\s*:\s*(\d+)\s*=\s*([\d,.]+)\s+to\s+1\s+\[OK\]$', line)
                    if match_c:
                        filename, orig_s, comp_s, ratio_s = match_c.groups()
                        try:
                            orig = int(orig_s)
                            comp = int(comp_s)
                            if orig > 0:
                                percentage = (comp / orig) * 100.0
                            else:
                                percentage = 100.0
                            
                            # Format path: ...\parent\filename
                            fname = filename.strip()
                            if current_header_dir:
                                fname = os.path.join(current_header_dir, fname)

                            try:
                                head, tail = os.path.split(fname)
                                if head:
                                    parent = os.path.basename(head)
                                    display_name = f"...{os.path.sep}{parent}{os.path.sep}{tail}"
                                else:
                                    display_name = fname
                            except:
                                display_name = fname
                            
                            pair = human_size_pair(orig, comp)
                            if is_verbose:
                                self.log_q.put(f"[OK] {display_name} | {pair} ({percentage:.1f}%)")
                            return
                        except ValueError:
                            pass

                    # Regex 2: compact /q output (Query - if used)
                    # Format:   Size : Compressed = Ratio to 1 Attr Filename
                    match_q = re.match(r'^\s*(\d+)\s*:\s*(\d+)\s*=\s*([\d,.]+)\s+to\s+1\s+[A-Z]+\s+(.*)$', line)
                    if match_q:
                        orig_s, comp_s, ratio_s, filename = match_q.groups()
                        try:
                            orig = int(orig_s)
                            comp = int(comp_s)
                            if orig > 0:
                                percentage = (comp / orig) * 100.0
                            else:
                                percentage = 100.0
                            
                            pair = human_size_pair(orig, comp)
                            if is_verbose:
                                self.log_q.put(f"[OK] {filename.strip()} | {pair} ({percentage:.1f}%)")
                            return
                        except ValueError:
                            pass
                    
                    if is_verbose:
                        self.log_q.put(line)

                if self.stop_flag.is_set():
                    self.log_q.put("[Stopped]")
                    return

                # 2) Compress batch (Use /f to force recompression if needed)
                if to_compress:
                    if is_verbose:
                        self.log_q.put("--- Compressing ---")
                    else:
                        # Initial status line
                        update_status_line(force=True)
                        
                    run_compact_stream(["/c", "/i", "/f", "/exe:{}".format(alg_switch)], to_compress, log_callback, self.stop_flag, progress_cb)

                self.log_q.put("\nFinished.")

            finally:
                self.ui_q.put(("enable", None))
                orig, disk = get_folder_sizes(folder)
                text = f"On Disk: {fmt_bytes(disk)} / Actual: {fmt_bytes(orig)}"
                if self.before_disk:
                    text += f"   (Before: {fmt_bytes(self.before_disk)})"
                self.ui_q.put(("size", text))

        self.worker = threading.Thread(target=worker, daemon=True)
        self.worker.start()

if __name__ == "__main__":
    if os.name != "nt":
        messagebox.showerror("Error", "This tool only works on Windows.")
        sys.exit(1)
    app = App()
    app.mainloop()
