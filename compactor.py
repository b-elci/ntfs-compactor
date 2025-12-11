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
# - Two ways to detect current algorithm:
#    1) Via compact /q - if line contains "(LZX|XPRESS4K|...)" parse it
#    2) Otherwise check Windows attribute for "compressed" (probably LZNT1)
#
# Notes:
# - Output language varies by Windows locale, but algorithm names (LZX/XPRESS*) appear verbatim.
# - "Recompress if algorithm differs" in safe mode, file by file: first /u, then /c /exe:ALG

import os
import sys
import threading
import queue
import subprocess
import ctypes
from ctypes import wintypes
import webbrowser
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import re

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

def compact_compress_file(path, algorithm_switch):
    """Compress specified file with selected algorithm (/c /exe:xxx)."""
    return run_compact(["/c", "/i", "/exe:{}".format(algorithm_switch), path])

def compact_uncompress_file(path):
    r, out = run_compact(["/u", "/i", path])
    return r, out  # also log the output

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

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NTFS Advanced Compression (XPRESS/LZX)")
        self.geometry("980x640")

        self.folder = tk.StringVar()
        self.alg_label = tk.StringVar(value=ALG_OPTIONS[-1][0])  # default LZX
        self.beh_label = tk.StringVar(value=BEHAVIOR_OPTIONS[1][0])  # default recompress_if_different
        self.verbose = tk.BooleanVar(value=False)

        self._build_ui()

        # thread communication
        self.log_q = queue.Queue()
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

        self.btn_compress = ttk.Button(btns, text="Compress", command=self.on_compress)
        self.btn_compress.pack(side="left", padx=6)

        self.btn_stop = ttk.Button(btns, text="Stop", command=self.on_stop, state="disabled")
        self.btn_stop.pack(side="left", padx=6)

        # Progress bar
        pfrm = ttk.Frame(frm)
        pfrm.pack(fill="x", pady=(0,8))
        self.progress = ttk.Progressbar(pfrm, mode="determinate")
        self.progress.pack(fill="x")

        # Log area — wrap ON
        logfrm = ttk.LabelFrame(frm, text="Output / Report")
        logfrm.pack(fill="both", expand=True)
        self.txt = tk.Text(logfrm, wrap="word", height=24)
        self.txt.pack(side="left", fill="both", expand=True)
        yscroll = ttk.Scrollbar(logfrm, orient="vertical", command=self.txt.yview)
        yscroll.pack(side="right", fill="y")
        self.txt.configure(yscrollcommand=yscroll.set)

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

    def _enable_actions(self):
        self.btn_status.config(state="normal")
        self.btn_compress.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.alg_combo.config(state="readonly")
        self.beh_combo.config(state="readonly")

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

        self.clear_log()
        self.append_log("Starting status scan...")
        self.stop_flag.clear()
        self._disable_actions()

        def worker():
            try:
                files = list(iter_files_under(folder))
                total = len(files)
                self.progress["maximum"] = max(total, 1)
                self.progress["value"] = 0

                # Extract algorithm map if possible (compact /q /s)
                algomap = detect_algorithm_via_compact_map(folder)

                # Header
                self.log_q.put("Status | Algorithm | Size → On Disk | Savings % | File Path")
                self.log_q.put("-" * 88)

                for idx, path in enumerate(files, 1):
                    if self.stop_flag.is_set():
                        self.log_q.put("[Stopped]")
                        break

                    try:
                        # Algorithm
                        alg = algomap.get(path)
                        if not alg:
                            comp_attr = is_compressed_attribute(path)
                            if comp_attr is None:
                                # no access
                                self.log_q.put(f"[Error: Access denied] {path}")
                                continue
                            alg = "LZNT1/Unknown" if comp_attr else "-"

                        # Sizes
                        try:
                            orig = os.path.getsize(path)
                        except Exception:
                            orig = None
                        ondisk = get_size_on_disk(path)

                        # Status
                        status = "Compressed" if (alg != "-" and alg is not None) else "Uncompressed"

                        # Line
                        pair = human_size_pair(orig, ondisk)
                        pct = percent_saving(orig, ondisk)
                        self.log_q.put(f"{status:12} | {alg:12} | {pair:22} | {pct:6} | {path}")

                    except Exception as e:
                        self.log_q.put(f"[Error: {e}] {path}")

                    self.progress["value"] = idx

            finally:
                self._enable_actions()

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
        self.stop_flag.clear()
        self._disable_actions()
        
        def worker():
            try:
                self.log_q.put("Performing initial measurement (this may take a while)...")
                self.after(0, lambda: self.size_label.config(text="Performing initial measurement..."))
                
                orig, disk = get_folder_sizes(folder)
                self.before_disk = disk
                
                res_text = f"On Disk (Initial): {fmt_bytes(disk)} / Actual: {fmt_bytes(orig)}"
                self.after(0, lambda: self.size_label.config(text=res_text))
                self.log_q.put(f"Initial size: {fmt_bytes(disk)} (On Disk) / {fmt_bytes(orig)} (Actual)")

                self.log_q.put("Listing files...")
                files = list(iter_files_under(folder))
                total = len(files)
                self.progress["maximum"] = max(total, 1)
                self.progress["value"] = 0
                self.log_q.put(f"Found {total} files. Analyzing compression status...")

                # Current algorithms (if any) — will use for decision
                algomap = detect_algorithm_via_compact_map(folder)
                
                to_compress = []

                for idx, path in enumerate(files, 1):
                    if self.stop_flag.is_set():
                        self.log_q.put("[Stopped]")
                        return

                    try:
                        # Behavior logic:
                        should_compress = True # Default to compress unless skipped
                        
                        # Normalize path for lookup
                        norm_path = os.path.normcase(os.path.abspath(path))
                        
                        current_alg = None
                        if norm_path in algomap:
                            current_alg = algomap[norm_path]  # LZX/XPRESS*
                        else:
                            comp_attr = is_compressed_attribute(path)
                            if comp_attr:
                                current_alg = "LZNT1/Unknown"

                        if behavior == "recompress_if_different":
                            if current_alg:
                                # Same? skip; different? recompress (force)
                                if current_alg == "XPRESS8K/16K":
                                    # Ambiguous case: if target is 8K or 16K, assume match to avoid loop
                                    if alg_switch.upper() in ["XPRESS8K", "XPRESS16K"]:
                                        should_compress = False
                                elif current_alg.upper() == alg_switch.upper():
                                    should_compress = False # Already same algo
                        elif behavior == "skip":
                             if current_alg:
                                 should_compress = False
                        
                        if should_compress:
                            to_compress.append(path)

                    except Exception as e:
                        self.log_q.put(f"[Error: {e}] {path}")

                    if is_verbose and idx % 100 == 0:
                         self.log_q.put(f"Analyzed {idx}/{total} files...")

                self.log_q.put(f"Analysis complete. Compressing {len(to_compress)} files.")
                
                batch_size = get_optimal_batch_size()
                self.log_q.put(f"Batch size calculated: {batch_size} files per chunk (based on system memory).")

                total_ops = len(to_compress)
                self.progress["maximum"] = max(total_ops, 1)
                self.progress["value"] = 0
                
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
                    self.progress["value"] = current_progress
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
                self._enable_actions()
                orig, disk = get_folder_sizes(folder)
                text = f"On Disk: {fmt_bytes(disk)} / Actual: {fmt_bytes(orig)}"
                if self.before_disk:
                    text += f"   (Before: {fmt_bytes(self.before_disk)})"
                self.after(0, lambda: self.size_label.config(text=text))
                self.progress["value"] = self.progress["maximum"]

        self.worker = threading.Thread(target=worker, daemon=True)
        self.worker.start()

if __name__ == "__main__":
    if os.name != "nt":
        messagebox.showerror("Error", "This tool only works on Windows.")
        sys.exit(1)
    app = App()
    app.mainloop()
