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
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

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
    """Return output from compact /q /s:"folder"."""
    return run_compact(["/q", "/s:{}".format(folder)])

def compact_compress_file(path, algorithm_switch):
    """Compress specified file with selected algorithm (/c /exe:xxx)."""
    return run_compact(["/c", "/i", "/exe:{}".format(algorithm_switch), path])

def compact_uncompress_file(path):
    r, out = run_compact(["/u", "/i", path])
    return r, out  # also log the output

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
    """Parse compact /q /s output line by line:
       Extract path -> algorithm (LZX/XPRESS4K/XPRESS8K/XPRESS16K) mapping.
       If not found, path won't be in the map."""
    ret, out = compact_query_folder(folder)
    algomap = {}
    if out:
        for line in out.splitlines():
            alg = compact_query_line_for_algorithm(line)
            if alg:
                # File path is usually at the end of the line; find path after last space
                # Windows output is sometimes "path : ..." format; safest approach is not to split by ' ',
                # but to detect the file path: doesn't come in quotes; practical approach:
                # If we found the algorithm name, search for path after ":" or " ".
                # Most reliable: verify existing file paths in the line one by one.
                # Here's a quick heuristic: find the longest existing path.
                tokens = line.strip().split()
                candidates = []
                # Test paths by combining parts
                for i in range(len(tokens)):
                    for j in range(i+1, len(tokens)+1):
                        cand = " ".join(tokens[i:j])
                        if os.path.isfile(cand):
                            candidates.append(cand)
                if candidates:
                    # Select the longest path
                    path = max(candidates, key=len)
                    algomap[path] = alg
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

        ttk.Label(top, text="Folder:").pack(side="left")
        self.ent_folder = ttk.Entry(top, textvariable=self.folder, width=70)
        self.ent_folder.pack(side="left", padx=6)
        ttk.Button(top, text="Browse...", command=self.choose_folder).pack(side="left")
        self.defer_measure = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Defer measurement", variable=self.defer_measure).pack(side="left", padx=8)

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
            if self.defer_measure.get():
                self.before_disk = None
                self.size_label.config(text="Measurement will be done during compression")
            else:
                orig, disk = get_folder_sizes(path)
                self.before_disk = disk
                self.size_label.config(
                    text=f"On Disk: {fmt_bytes(disk)} / Actual: {fmt_bytes(orig)}"
                )

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
            while True:
                msg = self.log_q.get_nowait()
                self.append_log(msg)
        except queue.Empty:
            pass
        self.after(100, self._drain_log_queue)

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

        # If defer measurement is checked, measure before starting compression
        if self.defer_measure.get():
            self.size_label.config(text="Performing initial measurement...")
            orig, disk = get_folder_sizes(folder)
            self.before_disk = disk
            self.size_label.config(
                text=f"On Disk (Initial): {fmt_bytes(disk)} / Actual: {fmt_bytes(orig)}"
            )
        if not os.path.isdir(folder):
            messagebox.showerror("Error", "Folder not found.")
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

        self.clear_log()
        self.append_log(f"Starting compression → Algorithm: {alg_label}, Behavior: {beh_label}")
        self.stop_flag.clear()
        self._disable_actions()

        def worker():
            try:
                files = list(iter_files_under(folder))
                total = len(files)
                self.progress["maximum"] = max(total, 1)
                self.progress["value"] = 0

                # Current algorithms (if any) — will use for decision
                algomap = detect_algorithm_via_compact_map(folder)

                for idx, path in enumerate(files, 1):
                    if self.stop_flag.is_set():
                        self.log_q.put("[Stopped]")
                        break

                    try:
                        # Behavior logic:
                        do_uncompress = False
                        if behavior == "recompress_if_different":
                            current_alg = None
                            if path in algomap:
                                current_alg = algomap[path]  # LZX/XPRESS*
                            else:
                                comp_attr = is_compressed_attribute(path)
                                if comp_attr:
                                    current_alg = "LZNT1/Unknown"

                            if current_alg:
                                # Same? skip; different? first /u
                                if current_alg.upper() != alg_switch.upper():
                                    do_uncompress = True

                        # 1) Uncompress if needed
                        if do_uncompress:
                            r1, o1 = compact_uncompress_file(path)
                            if r1 != 0:
                                self.log_q.put(f"[Error: uncompress failed] {path} | {o1.strip()}")
                                # Skip without continuing
                                self.progress["value"] = idx
                                continue

                        # 2) Compress with /c /exe:ALG
                        r2, o2 = compact_compress_file(path, alg_switch)
                        if r2 != 0:
                            self.log_q.put(f"[Error: compression failed] {path}")
                        else:
                            # Summary line
                            try:
                                orig = os.path.getsize(path)
                            except Exception:
                                orig = None
                            ondisk = get_size_on_disk(path)
                            pair = human_size_pair(orig, ondisk)
                            pct = percent_saving(orig, ondisk)
                            self.log_q.put(f"[OK] {pair:22} | {pct:6} | {path}")

                    except Exception as e:
                        self.log_q.put(f"[Error: {e}] {path}")

                    self.progress["value"] = idx

                self.log_q.put("Finished.")

            finally:
                self._enable_actions()
                orig, disk = get_folder_sizes(folder)
                text = f"On Disk: {fmt_bytes(disk)} / Actual: {fmt_bytes(orig)}"
                if self.before_disk:
                    text += f"   (Before: {fmt_bytes(self.before_disk)})"
                self.size_label.config(text=text)

        self.worker = threading.Thread(target=worker, daemon=True)
        self.worker.start()

if __name__ == "__main__":
    if os.name != "nt":
        messagebox.showerror("Error", "This tool only works on Windows.")
        sys.exit(1)
    app = App()
    app.mainloop()
