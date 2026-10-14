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
import time
import tempfile
import json
import sqlite3
import fnmatch
import locale
import argparse

APP_VERSION = "1.6.0"

# -------------------------
# Windows API — size and attribute helpers
# -------------------------

if __name__ == "__main__" and os.name != "nt":
    sys.exit("NTFS Compactor requires Windows 10/11 and an NTFS volume.")

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

# GetCompressedFileSizeW
kernel32.GetCompressedFileSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
kernel32.GetCompressedFileSizeW.restype = wintypes.DWORD

# GetFileAttributesW
kernel32.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
kernel32.GetFileAttributesW.restype = wintypes.DWORD

def get_optimal_batch_size():
    """Initial batch size; the runner adapts between 1 and 128 files."""
    return 32


def windows_path(path):
    path = os.path.abspath(path)
    if os.name != "nt" or path.startswith("\\\\?\\"):
        return path
    if path.startswith("\\\\"):
        return "\\\\?\\UNC\\" + path[2:]
    return "\\\\?\\" + path


def compact_executable():
    if os.name == "nt":
        return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "compact.exe")
    return "compact.exe"


def compact_output_encoding():
    # Native console tools use the OEM code page, not Python's UTF-8 mode/ANSI locale.
    if os.name == "nt":
        api = kernel32.GetOEMCP
        api.argtypes = []
        api.restype = wintypes.UINT
        code_page = api()
        if code_page:
            return f"cp{code_page}"
    return locale.getpreferredencoding(False)


def check_volume(folder):
    """Return the filesystem name and fail clearly if it cannot be queried."""
    root = ctypes.create_unicode_buffer(32768)
    fs = ctypes.create_unicode_buffer(256)
    api = kernel32.GetVolumePathNameW
    api.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    api.restype = wintypes.BOOL
    if not api(windows_path(folder), root, len(root)):
        raise OSError(ctypes.get_last_error(), "Cannot determine the selected volume")
    api = kernel32.GetVolumeInformationW
    api.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD,
                   ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
                   ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR, wintypes.DWORD]
    api.restype = wintypes.BOOL
    if not api(root.value, None, 0, None, None, None, fs, len(fs)):
        raise OSError(ctypes.get_last_error(), "Cannot read volume information")
    return fs.value


def get_cluster_size(target):
    root = ctypes.create_unicode_buffer(32768)
    api = kernel32.GetVolumePathNameW
    api.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    api.restype = wintypes.BOOL
    if not api(windows_path(target), root, len(root)):
        raise OSError(ctypes.get_last_error(), "Cannot determine the selected volume")
    sectors, bytes_per_sector, free, total = (wintypes.DWORD() for _ in range(4))
    api = kernel32.GetDiskFreeSpaceW
    api.argtypes = [wintypes.LPCWSTR] + [ctypes.POINTER(wintypes.DWORD)] * 4
    api.restype = wintypes.BOOL
    if not api(root.value, ctypes.byref(sectors), ctypes.byref(bytes_per_sector), ctypes.byref(free), ctypes.byref(total)):
        raise OSError(ctypes.get_last_error(), "Cannot read volume cluster size")
    size = sectors.value * bytes_per_sector.value
    if size <= 0:
        raise OSError("Invalid volume cluster size")
    return size


COMPRESSED_FORMATS = frozenset((
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.avif', '.heic',
    '.mp4', '.mkv', '.webm', '.mov', '.avi', '.mp3', '.ogg', '.flac', '.aac',
    '.zip', '.7z', '.rar', '.gz', '.bz2', '.xz', '.zst', '.cab', '.wim',
))


def smart_skip_reason(path, size, cluster_size):
    if size <= cluster_size:
        return 'at most one disk cluster'
    if os.path.splitext(path)[1].casefold() in COMPRESSED_FORMATS:
        return 'already compressed file format'
    return None


class NoGainCache:
    """Remember only verified no-benefit outcomes, keyed by content metadata."""
    def __init__(self, path=None):
        if path is None:
            root = os.environ.get('LOCALAPPDATA') if os.name == 'nt' else None
            path = os.path.join(root or tempfile.gettempdir(), 'NTFSCompactor', 'no-gain.sqlite')
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute('CREATE TABLE IF NOT EXISTS no_gain (path TEXT, algorithm TEXT, size INTEGER, mtime INTEGER, ctime INTEGER, PRIMARY KEY(path, algorithm))')

    def fingerprint(self, path):
        info = os.stat(path)
        changed = file_change_time(path) if os.name == 'nt' else info.st_ctime_ns
        return info.st_size, info.st_mtime_ns, changed

    def contains(self, path, algorithm):
        record = self.db.execute('SELECT size,mtime,ctime FROM no_gain WHERE path=? AND algorithm=?',
            (os.path.normcase(os.path.abspath(path)), algorithm)).fetchone()
        return record is not None and tuple(record) == self.fingerprint(path)

    def add(self, path, algorithm):
        values = self.fingerprint(path)
        self.db.execute('INSERT OR REPLACE INTO no_gain VALUES (?,?,?,?,?)',
            (os.path.normcase(os.path.abspath(path)), algorithm, *values))
        self.db.commit()

    def close(self):
        self.db.close()


def file_change_time(path):
    # Windows st_ctime is creation time on older Python releases. NTFS ChangeTime
    # catches content replacements even when an updater preserves LastWriteTime.
    class BasicInfo(ctypes.Structure):
        _fields_ = [('created', ctypes.c_int64), ('accessed', ctypes.c_int64),
                    ('written', ctypes.c_int64), ('changed', ctypes.c_int64),
                    ('attributes', wintypes.DWORD)]
    create = kernel32.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    handle = create(windows_path(path), 0x80, 7, None, 3, 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), 'Cannot read file change time')
    close = kernel32.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    try:
        api = kernel32.GetFileInformationByHandleEx
        api.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        api.restype = wintypes.BOOL
        info = BasicInfo()
        if not api(handle, 0, ctypes.byref(info), ctypes.sizeof(info)):
            raise OSError(ctypes.get_last_error(), 'Cannot read file change time')
        return info.changed
    finally:
        close(handle)


def check_write_access(folder):
    # Test effective access rather than assuming administrator membership.
    with tempfile.TemporaryFile(dir=folder):
        pass


class ReportStore:
    """Keep the complete report on disk, rendering only one page in Tk."""
    def __init__(self):
        fd, self.path = tempfile.mkstemp(prefix="ntfs-report-", suffix=".sqlite")
        os.close(fd)
        self.db = sqlite3.connect(self.path)
        self.db.execute("CREATE TABLE report (id INTEGER PRIMARY KEY, data TEXT)")
        self.count = 0
        self.sort_column = None
        self.descending = False

    def clear(self):
        self.db.execute("DELETE FROM report")
        self.db.commit()
        self.count = 0
        self.sort_column = None
        self.descending = False

    def append(self, rows):
        self.db.executemany("INSERT INTO report(data) VALUES (?)",
                            [(json.dumps(row, ensure_ascii=False),) for row in rows])
        self.db.commit()
        self.count += len(rows)

    def rows(self, offset=0, limit=None):
        keys = {"status": "status", "algorithm": "algorithm", "size": "size_raw",
                "ondisk": "ondisk_raw", "savings": "savings_raw", "path": "path_raw"}
        order = "id"
        if self.sort_column in keys:
            order = "json_extract(data, '$.%s') %s, id" % (
                keys[self.sort_column], "DESC" if self.descending else "ASC")
        sql = "SELECT data FROM report ORDER BY " + order
        args = ()
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            args = (limit, offset)
        for (data,) in self.db.execute(sql, args):
            yield json.loads(data)

    def close(self):
        self.db.close()
        os.unlink(self.path)


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

def get_size_on_disk(path):
    high = wintypes.DWORD(0)
    ctypes.set_last_error(0)
    low = kernel32.GetCompressedFileSizeW(windows_path(path), ctypes.byref(high))
    err = ctypes.get_last_error()
    if low == 0xFFFFFFFF and err != 0:
        return None
    return (high.value << 32) + low

def is_compressed_attribute(path):
    """Does the file have compressed attribute? (Could be LZNT1 or system compression)"""
    attrs = kernel32.GetFileAttributesW(windows_path(path))
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
            windows_path(path),
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

def native_file_operation(path, operation, algorithm):
    """Use documented WOF/NTFS APIs when compact.exe cannot handle a path."""
    current = get_compression_algorithm(path)
    if current is None:
        raise OSError("Cannot read compression state: " + path)
    create = kernel32.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    close = kernel32.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    handle = create(windows_path(path), 0xC0000000, 7, None, 3, 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), "Cannot open " + path)
    try:
        control = kernel32.DeviceIoControl
        control.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                            ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        control.restype = wintypes.BOOL
        returned = wintypes.DWORD()
        if current in WOF_ALGORITHMS.values():
            # FSCTL_DELETE_EXTERNAL_BACKING reads/decompresses the file in place.
            if not control(handle, 0x00090314, None, 0, None, 0, ctypes.byref(returned), None):
                raise OSError(ctypes.get_last_error(), "Cannot remove WOF backing")
        elif current == 'LZNT1/Unknown':
            uncompressed = ctypes.c_ushort(0)
            if not control(handle, 0x0009C040, ctypes.byref(uncompressed), 2, None, 0, ctypes.byref(returned), None):
                raise OSError(ctypes.get_last_error(), "Cannot remove NTFS compression")
        elif current != '-':
            raise OSError("Unsupported external backing provider")
        if operation == 'decompress':
            return {'status': 'passed'}
        if wofutil is None:
            raise OSError("Wofutil.dll is unavailable")
        algorithms = {name.casefold(): number for number, name in WOF_ALGORITHMS.items()}
        info = WofFileCompressionInfo(algorithms[algorithm], 0)
        api = wofutil.WofSetFileDataLocation
        api.argtypes = [wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG]
        api.restype = wintypes.LONG
        result = api(handle, WOF_PROVIDER_FILE, ctypes.byref(info), ctypes.sizeof(info))
        if result & 0xFFFFFFFF == 0x80070158:  # ERROR_COMPRESSION_NOT_BENEFICIAL
            if current in WOF_ALGORITHMS.values():
                previous = WofFileCompressionInfo(algorithms[current.casefold()], 0)
                restored = api(handle, WOF_PROVIDER_FILE, ctypes.byref(previous), ctypes.sizeof(previous))
                if restored != 0:
                    raise OSError('No benefit from new algorithm; original compression could not be restored')
            return {'status': 'skipped', 'reason': 'no-benefit'}
        if result != 0:
            raise OSError("WOF compression failed: HRESULT 0x%08X" % (result & 0xFFFFFFFF))
        return {'status': 'passed'}
    finally:
        close(handle)


def launch_command():
    if getattr(sys, 'frozen', False):
        return [sys.executable]
    return [sys.executable, os.path.abspath(__file__)]


def needs_native_path(path):
    return os.name == 'nt' and len(os.path.abspath(path)) >= 260


def register_context_menu(remove=False):
    import winreg
    roots = (r'Software\Classes\Directory\shell\NTFSCompactor',
             r'Software\Classes\Directory\Background\shell\NTFSCompactor',
             r'Software\Classes\*\shell\NTFSCompactor')
    def delete_tree(path):
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
            while True:
                try:
                    name = winreg.EnumKey(key, 0)
                except OSError as exc:
                    if getattr(exc, 'winerror', exc.errno) != 259:
                        raise
                    break
                delete_tree(path + '\\' + name)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
    for root in roots:
        try:
            existing = winreg.OpenKey(winreg.HKEY_CURRENT_USER, root)
        except FileNotFoundError:
            if remove:
                continue
        else:
            with existing as key:
                try:
                    owner, _ = winreg.QueryValueEx(key, 'NTFSCompactor.Owner')
                except FileNotFoundError:
                    raise ValueError('An unowned context menu already uses this key')
                if owner != 'NTFSCompactor':
                    raise ValueError('An unrelated context menu already uses this key')
        if remove:
            delete_tree(root)
            continue
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, root) as key:
            for name, value in (('MUIVerb', 'NTFS Compactor'), ('SubCommands', ''),
                                ('NTFSCompactor.Owner', 'NTFSCompactor')):
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
        placeholder = '%V' if '\\Background\\' in root else '%1'
        for action, label in (('scan', 'Show status'), ('compress', 'Compress'), ('decompress', 'Decompress')):
            entry = root + '\\shell\\' + action
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, entry) as key:
                winreg.SetValueEx(key, '', 0, winreg.REG_SZ, label)
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, entry + r'\command') as key:
                command = subprocess.list2cmdline(launch_command()) + ' --action ' + action + ' "' + placeholder + '"'
                winreg.SetValueEx(key, '', 0, winreg.REG_SZ, command)


def run_compact(args, cwd=None):
    cmd = [compact_executable()] + args
    try:
        # CREATE_NO_WINDOW flag prevents console window from appearing
        CREATE_NO_WINDOW = 0x08000000
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding=compact_output_encoding(),
            errors="replace",
            cwd=cwd,
            check=False,
            creationflags=CREATE_NO_WINDOW  # Prevents console window flashing
        )
        return p.returncode, p.stdout
    except Exception as e:
        return 1, f"[compact error] {e}"

def compact_compress_file(path, algorithm_switch, force=False):
    """Compress specified file with selected algorithm (/c /exe:xxx)."""
    args = ["/c", "/i"]
    if force:
        args.append("/f")
    args.extend(["/exe:{}".format(algorithm_switch), path])
    return run_compact(args)

def run_compact_stream(args, files, callback_line, stop_event=None,
                       progress_callback=None, verify=None, result_callback=None, skip_callback=None):
    """Run adaptive batches with cancellable pipe reads and explicit outcomes.

    files may be an iterator of paths or (path, logical_size) pairs.
    verify(path) checks the requested final state independently of localized output.
    """
    stats = dict(successful=0, failed=0, skipped=0, cancelled=0, bytes=0)
    batch_limit = get_optimal_batch_size()
    growth_cooldown = 0
    stop_event = stop_event or threading.Event()
    base_cmd = [compact_executable()] + args
    base_length = len(subprocess.list2cmdline(base_cmd).encode("utf-16-le")) // 2

    def record(kind, entries):
        stats[kind] += len(entries)
        stats["bytes"] += sum(size for _, size in entries)
        if progress_callback:
            progress_callback(len(entries))
        if result_callback:
            result_callback(dict(stats))

    def execute(entries, directory, grow=True, native=False):
        nonlocal batch_limit, growth_cooldown
        if stop_event.is_set():
            stats["cancelled"] += len(entries)
            return
        use_native = native or any(needs_native_path(path) for path, _ in entries)
        if use_native and len(entries) > 1:
            for entry in entries:
                execute([entry], directory, grow=False, native=True)
            return
        helper_report = None
        if use_native:
            fd, helper_report = tempfile.mkstemp(prefix='ntfs-native-', suffix='.json')
            os.close(fd)
            algorithm = next((arg.split(':', 1)[1] for arg in args if arg.lower().startswith('/exe:')), 'xpress8k')
            operation = 'decompress' if '/u' in args else 'compress'
            cmd = launch_command() + ['--native-file-op', operation, '--algorithm', algorithm,
                                      '--result', helper_report, entries[0][0]]
        else:
            cmd = base_cmd + [os.path.basename(path) for path, _ in entries]
        output = queue.Queue(maxsize=256)
        reader_done = threading.Event()
        reader_errors = []
        process = None
        reader = None
        cancelled = False
        tail = []
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, encoding=compact_output_encoding(),
                errors="replace", creationflags=0x08000000, bufsize=1,
                cwd=os.path.dirname(sys.executable) if use_native else windows_path(directory))

            def read_output():
                try:
                    for line in process.stdout:
                        if stop_event.is_set():
                            break
                        while not stop_event.is_set():
                            try:
                                output.put(line.rstrip(), timeout=0.05)
                                break
                            except queue.Full:
                                continue
                except Exception as exc:
                    reader_errors.append(str(exc))
                finally:
                    reader_done.set()

            reader = threading.Thread(target=read_output, daemon=True)
            reader.start()
            while not reader_done.is_set() or not output.empty():
                if stop_event.is_set():
                    cancelled = True
                    if process.poll() is None:
                        process.terminate()
                    break
                try:
                    line = output.get(timeout=0.05)
                except queue.Empty:
                    continue
                tail.append(line)
                tail = tail[-20:]
                callback_line(line)
            # A process may close stdout before it exits; keep cancellation active.
            while not cancelled and process.poll() is None:
                if stop_event.wait(0.05):
                    cancelled = True
                    process.terminate()
            try:
                code = process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                code = process.wait()
            if reader_errors:
                raise OSError("Cannot read compact output: " + "; ".join(reader_errors))
            if cancelled or stop_event.is_set():
                stats["cancelled"] += len(entries)
                return
            if helper_report:
                with open(helper_report, encoding='utf-8') as report:
                    outcome = json.load(report)
                if outcome.get('status') == 'skipped' and code == 0:
                    record('skipped', entries)
                    callback_line('[Skipped] No disk-space benefit: ' + entries[0][0])
                    if skip_callback:
                        skip_callback(entries[0][0], outcome.get('reason'))
                    return
                if outcome.get('status') != 'passed':
                    callback_line('[Error] ' + outcome.get('error', 'Native operation failed'))
            succeeded, failed = [], []
            for entry in entries:
                try:
                    ok = verify(entry[0]) if verify else code == 0
                except Exception:
                    ok = False
                (succeeded if ok else failed).append(entry)
            record("successful", succeeded)
            if failed and len(entries) > 1:
                batch_limit = max(1, batch_limit // 2)
                growth_cooldown = 4
                # Retry only unverified files; do not recompress successes.
                middle = max(1, len(failed) // 2)
                execute(failed[:middle], directory, grow=False)
                if failed[middle:]:
                    execute(failed[middle:], directory, grow=False)
            elif failed and not use_native and verify is not None and os.name == 'nt':
                execute(failed, directory, grow=False, native=True)
            elif failed:
                record("failed", failed)
                callback_line("[Error] Failed: %s (exit %s) %s" %
                              (failed[0][0], code, " | ".join(tail[-3:])))
            elif succeeded and grow:
                if growth_cooldown:
                    growth_cooldown -= 1
                else:
                    batch_limit = min(128, batch_limit * 2)
        except Exception as exc:
            if stop_event.is_set():
                stats["cancelled"] += len(entries)
            else:
                record("failed", entries)
                callback_line("[Error] Batch failed: %s" % exc)
        finally:
            if helper_report:
                try:
                    os.unlink(helper_report)
                except FileNotFoundError:
                    pass
            if process is not None:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                if reader is not None:
                    reader.join(timeout=2)
                if process.stdout is not None:
                    process.stdout.close()

    batch, directory, length = [], None, 0
    for item in files:
        if stop_event.is_set():
            break
        path, size = item if isinstance(item, tuple) else (item, 0)
        parent, name = os.path.split(path)
        # CreateProcess counts UTF-16 code units, including quoting and spaces.
        name_length = len(subprocess.list2cmdline([name]).encode("utf-16-le")) // 2 + 1
        candidate_length = base_length + name_length
        if batch and (parent != directory or len(batch) >= batch_limit or
                      length + name_length > 30000):
            execute(batch, directory)
            batch, length = [], 0
            if stop_event.is_set():
                break
        directory = parent
        if candidate_length > 30000:
            record("skipped", [(path, size)])
            callback_line("[Skipped] Command argument too long: " + path)
            continue
        if not batch:
            length = base_length
        batch.append((path, size))
        length += name_length
    if batch:
        execute(batch, directory)
    return stats

# -------------------------
# Helper — size formatting
# -------------------------

def fmt_bytes(n):
    if n is None:
        return "?"
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(n)
    for unit in units:
        if abs(size) < 1024.0 or unit == units[-1]:
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

def parse_patterns(text):
    return tuple(part.strip().casefold() for part in text.split(";") if part.strip())


def iter_files_under(folder, excluded_extensions=(), excluded_folders=(),
                     stop_event=None, on_error=None):
    """Walk once, pruning exclusions and directory links/junctions."""
    root_folder = os.path.abspath(folder)
    def extension_excluded(name):
        return any(fnmatch.fnmatchcase(name.casefold(),
                    pattern if '*' in pattern or '?' in pattern else '*' +
                    (pattern if pattern.startswith('.') else '.' + pattern))
                   for pattern in excluded_extensions)
    if os.path.isfile(root_folder):
        if not (stop_event and stop_event.is_set()) and not os.path.islink(root_folder) and not extension_excluded(os.path.basename(root_folder)):
            yield root_folder
        return
    def walk_error(exc):
        if on_error:
            on_error(exc)
    for root, dirs, files in os.walk(root_folder, followlinks=False, onerror=walk_error):
        if stop_event and stop_event.is_set():
            return
        kept = []
        for name in dirs:
            path = os.path.join(root, name)
            relative = os.path.relpath(path, root_folder).replace("\\", "/").casefold()
            if os.path.islink(path) or (hasattr(os.path, "isjunction") and os.path.isjunction(path)):
                continue
            if any(fnmatch.fnmatchcase(name.casefold(), pattern) or
                   fnmatch.fnmatchcase(relative, pattern.replace("\\", "/"))
                   for pattern in excluded_folders):
                continue
            kept.append(name)
        dirs[:] = kept
        for name in files:
            if stop_event and stop_event.is_set():
                return
            if extension_excluded(name):
                continue
            path = os.path.join(root, name)
            if not os.path.islink(path):
                yield path


def scan_files(folder, excluded_extensions=(), excluded_folders=(),
               stop_event=None, on_error=None):
    for path in iter_files_under(folder, excluded_extensions, excluded_folders,
                                 stop_event, on_error):
        try:
            size = os.stat(path).st_size
            disk = get_size_on_disk(path)
            algorithm = get_compression_algorithm(path)
            if disk is None or algorithm is None:
                raise OSError("Cannot read file size or compression state: " + path)
            yield dict(path=path, size=size, disk=disk, algorithm=algorithm)
        except Exception as exc:
            if on_error:
                on_error(exc)


def compression_action(current_alg, target_alg, behavior):
    """Return skip, compress, or recompress for a file."""
    if not current_alg:
        return "compress"
    if behavior == "skip" or current_alg.casefold() == target_alg.casefold():
        return "skip"
    return "recompress"

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
        self.geometry("1120x720")

        self.folder = tk.StringVar()
        self.alg_label = tk.StringVar(value=ALG_OPTIONS[1][0])  # balanced XPRESS8K
        self.beh_label = tk.StringVar(value=BEHAVIOR_OPTIONS[0][0])  # skip existing compressed files
        self.verbose = tk.BooleanVar(value=False)

        self.report_store = ReportStore()
        self.report_page = 0
        self.page_size = 500
        self._busy = False
        self._closing = False
        self._build_ui()

        # thread communication
        self.log_q = queue.Queue(maxsize=2000)
        self.ui_q = queue.Queue(maxsize=2000)
        self.worker = None
        self.stop_flag = threading.Event()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def _build_ui(self):
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)

        # Top: folder selection + options
        top = ttk.Frame(frm)
        top.pack(fill="x", pady=(0,8))

        # Left side: folder controls
        ttk.Label(top, text="Target:").pack(side="left")
        self.ent_folder = ttk.Entry(top, textvariable=self.folder, width=70)
        self.ent_folder.pack(side="left", padx=6)
        self.btn_browse = ttk.Button(top, text="Browse...", command=self.choose_folder)
        self.btn_browse.pack(side="left")
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

        filters = ttk.Frame(frm)
        filters.pack(fill="x", pady=(0, 8))
        self.exclude_extensions = tk.StringVar()
        self.exclude_folders = tk.StringVar()
        self.smart_filter = tk.BooleanVar(value=True)
        ttk.Label(filters, text="Exclude extensions (;):").pack(side="left")
        self.ext_entry = ttk.Entry(filters, textvariable=self.exclude_extensions, width=24)
        self.ext_entry.pack(side="left", padx=6)
        ttk.Label(filters, text="Exclude folders (;):").pack(side="left")
        self.exclude_entry = ttk.Entry(filters, textvariable=self.exclude_folders, width=30)
        self.exclude_entry.pack(side="left", padx=6)
        self.smart_check = ttk.Checkbutton(filters, text="Smart filtering", variable=self.smart_filter)
        self.smart_check.pack(side="left", padx=8)
        menu = tk.Menu(self)
        tools = tk.Menu(menu, tearoff=False)
        tools.add_command(label="Choose file...", command=self.choose_file)
        tools.add_separator()
        tools.add_command(label="Install Explorer menu", command=lambda: self.configure_shell(False))
        tools.add_command(label="Remove Explorer menu", command=lambda: self.configure_shell(True))
        menu.add_cascade(label="Tools", menu=tools)
        self.config(menu=menu)
        self.metrics_label = ttk.Label(frm, text="Ready")
        self.metrics_label.pack(fill="x", pady=(0, 6))

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

        self.btn_decompress = ttk.Button(btns, text="Decompress", command=lambda: self.on_compress(decompress=True))
        self.btn_decompress.pack(side="left", padx=6)

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
        self.status_menu.add_command(label="Copy Page", command=self._copy_status_all)
        self.status_menu.add_separator()
        self.status_menu.add_command(label="Save as CSV...", command=self.on_save_report)
        self.status_tree.bind("<Button-3>", self._show_status_menu)

        paging = ttk.Frame(status_tab)
        paging.pack(fill="x")
        self.btn_previous = ttk.Button(paging, text="Previous", command=lambda: self._change_page(-1))
        self.btn_previous.pack(side="left")
        self.page_label = ttk.Label(paging, text="Page 1 / 1 — 0 files")
        self.page_label.pack(side="left", padx=8)
        self.btn_next = ttk.Button(paging, text="Next", command=lambda: self._change_page(1))
        self.btn_next.pack(side="left")

        # Storage backing the visible Treeview page (used for sorting)
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
        self._drain_after = self.after(100, self._drain_log_queue)

    # -------------
    # UI Helpers
    # -------------
    def choose_folder(self):
        if self._busy:
            return
        path = filedialog.askdirectory()
        if path:
            self.folder.set(path)
            self.before_disk = None
            self.size_label.config(text="Measurement will be done during compression")

    def choose_file(self):
        if self._busy:
            return
        path = filedialog.askopenfilename()
        if path:
            self.folder.set(path)
            self.size_label.config(text="Measurement will be done during the operation")

    def configure_shell(self, remove):
        if self._busy:
            return
        try:
            if os.name != 'nt':
                raise OSError('Explorer integration requires Windows')
            register_context_menu(remove=remove)
        except Exception as exc:
            messagebox.showerror('Explorer menu', str(exc))
        else:
            messagebox.showinfo('Explorer menu', 'Menu removed.' if remove else 'Menu installed for your account. On Windows 11, use Show more options.')

    def append_log(self, s):
        self.txt.insert("end", s + "\n")
        self.txt.see("end")

    def clear_log(self):
        self.txt.delete("1.0", "end")

    def _disable_actions(self):
        self._busy = True
        for widget in (self.btn_status, self.btn_compress, self.btn_decompress,
                       self.btn_browse, self.ent_folder, self.ext_entry, self.exclude_entry,
                       self.alg_combo, self.beh_combo, self.smart_check, self.btn_clear_report):
            widget.config(state="disabled")
        self.btn_stop.config(state="normal")

    def _enable_actions(self):
        self.progress.stop()
        self.progress.configure(mode="determinate")
        self._busy = False
        for widget in (self.btn_status, self.btn_compress, self.btn_decompress,
                       self.btn_browse, self.ent_folder, self.ext_entry, self.exclude_entry, self.smart_check):
            widget.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.alg_combo.config(state="readonly")
        self.beh_combo.config(state="readonly")
        if self.report_store.count:
            self.btn_save_report.config(state="normal")
            self.btn_clear_report.config(state="normal")

    def _send_log(self, message):
        while not self._closing:
            try:
                self.log_q.put(message, timeout=0.05)
                return
            except queue.Full:
                continue

    def _send_ui(self, action, value=None, cancellable=False):
        while not self._closing:
            if cancellable and self.stop_flag.is_set():
                return False
            try:
                self.ui_q.put((action, value), timeout=0.05)
                return True
            except queue.Full:
                continue
        return False

    def _drain_log_queue(self):
        messages = []
        for _ in range(100):
            try:
                messages.append(self.log_q.get_nowait())
            except queue.Empty:
                break
        if messages:
            self.append_log_batch(messages)
        deadline = time.monotonic() + 0.015
        rows = []
        latest_progress = None
        try:
            for _ in range(250):
                if time.monotonic() >= deadline:
                    break
                try:
                    action, value = self.ui_q.get_nowait()
                except queue.Empty:
                    break
                if action == "status_clear":
                    # Respect queue order; never clear rows added after this marker.
                    if rows:
                        self._add_status_rows(rows)
                        rows = []
                    self._clear_status_report()
                elif action == "status_row":
                    rows.append(value)
                elif action == "progress":
                    latest_progress = value
                elif action == "progress_max":
                    latest_progress = 0
                    self.progress["maximum"] = max(value, 1)
                elif action == "enable":
                    self._enable_actions()
                elif action == "size":
                    self.size_label.config(text=value)
                elif action == "metrics":
                    self.metrics_label.config(text=value)
            if rows:
                self._add_status_rows(rows)
            if latest_progress is not None:
                self.progress["value"] = latest_progress
        except Exception as exc:
            self.append_log("[UI error] " + str(exc))
        finally:
            if not self._closing:
                self._drain_after = self.after(50, self._drain_log_queue)

    def append_log_batch(self, messages):
        self.txt.insert("end", "\n".join(messages) + "\n")
        
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
        self.report_store.clear()
        self.report_page = 0
        self._status_sort_state.clear()
        self._render_report_page()
        self.btn_save_report.config(state="disabled")
        self.btn_clear_report.config(state="disabled")

    def _add_status_rows(self, rows):
        previous = self.report_store.count
        self.report_store.append(rows)
        if previous < (self.report_page + 1) * self.page_size:
            self._render_report_page()
        else:
            self._update_page_controls()
        self.btn_save_report.config(state="normal")
        if not self._busy:
            self.btn_clear_report.config(state="normal")

    def _render_report_page(self):
        items = self.status_tree.get_children("")
        if items:
            self.status_tree.delete(*items)
        self._status_raw.clear()
        for index, row in enumerate(self.report_store.rows(self.report_page * self.page_size, self.page_size)):
            iid = str(index)
            values = tuple(row.get(key, "") for key in
                ("status", "algorithm", "size_disp", "ondisk_disp", "savings_disp", "path"))
            self.status_tree.insert("", "end", iid=iid, values=values,
                                   tags=("evenrow" if index % 2 == 0 else "oddrow",))
            self._status_raw[iid] = row
        self._update_page_controls()

    def _update_page_controls(self):
        pages = max(1, (self.report_store.count + self.page_size - 1) // self.page_size)
        self.page_label.config(text="Page %d / %d — %d files" %
                               (self.report_page + 1, pages, self.report_store.count))
        self.btn_previous.config(state="normal" if self.report_page else "disabled")
        self.btn_next.config(state="normal" if self.report_page + 1 < pages else "disabled")

    def _change_page(self, delta):
        pages = max(1, (self.report_store.count + self.page_size - 1) // self.page_size)
        self.report_page = max(0, min(pages - 1, self.report_page + delta))
        self._render_report_page()

    def _sort_status(self, col):
        if self._busy:
            return
        reverse = self._status_sort_state.get(col) == "asc"
        self._status_sort_state[col] = "desc" if reverse else "asc"
        self.report_store.sort_column = col
        self.report_store.descending = reverse
        self.report_page = 0
        self._render_report_page()
        for column in STATUS_COL_IDS:
            self.status_tree.heading(column, text=STATUS_COL_HEADINGS[column] +
                ((" ▼" if reverse else " ▲") if column == col else ""))

    def on_clear_report(self):
        if not self._busy:
            self._clear_status_report()

    def on_save_report(self):
        if not self.report_store.count:
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
                for row in self.report_store.rows():
                    writer.writerow([row.get(key, "") for key in ("status", "algorithm", "size_disp", "ondisk_disp", "savings_disp", "path")])
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
        for row in self.report_store.rows(self.report_page * self.page_size, self.page_size):
            lines.append("\t".join(str(row.get(key, "")) for key in ("status", "algorithm", "size_disp", "ondisk_disp", "savings_disp", "path")))
        if len(lines) == 1:
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))
        self.update()

    # -------------
    # Operations
    # -------------
    def _filters(self):
        return parse_patterns(self.exclude_extensions.get()), parse_patterns(self.exclude_folders.get())

    def on_close(self):
        self.stop_flag.set()
        self._closing = True
        if self._drain_after is not None:
            self.after_cancel(self._drain_after)
            self._drain_after = None
        if self.worker and self.worker.is_alive():
            self.after(50, self.on_close)
            return
        self.worker = None
        self.report_store.close()
        self.destroy()

    def on_status(self):
        folder = self.folder.get().strip()
        if self._busy:
            return
        if not folder or not (os.path.isdir(folder) or os.path.isfile(folder)):
            messagebox.showwarning("Warning", "Please select an existing file or folder.")
            return
        extensions, folders = self._filters()
        self._clear_status_report()
        self.notebook.select(0)
        self.stop_flag.clear()
        self._disable_actions()
        self.progress.configure(mode="indeterminate")
        self.progress.start()

        def worker():
            count = 0
            last_update = 0
            try:
                def error(exc):
                    self._send_log("[Error] " + str(exc))
                    self._send_ui("status_row", dict(status="Error", algorithm="?",
                        path=str(exc), path_raw=str(exc).casefold(), size_raw=-1,
                        ondisk_raw=-1, savings_raw=-1), cancellable=True)
                for info in scan_files(folder, extensions, folders, self.stop_flag, error):
                    orig, disk, alg, path = info["size"], info["disk"], info["algorithm"], info["path"]
                    row = dict(status="Uncompressed" if alg == "-" else "Compressed",
                        algorithm=alg, size_disp=fmt_bytes(orig), size_raw=orig,
                        ondisk_disp=fmt_bytes(disk), ondisk_raw=disk,
                        savings_disp=percent_saving(orig, disk),
                        savings_raw=max(0, (1 - disk / orig) * 100) if orig else 0,
                        path=path, path_raw=path.casefold())
                    if not self._send_ui("status_row", row, cancellable=True):
                        break
                    count += 1
                    if time.monotonic() - last_update >= 0.25:
                        self._send_ui("metrics", "Scanned %d files" % count)
                        last_update = time.monotonic()
                self._send_ui("metrics", "%s: %d files" %
                              ("Scan stopped" if self.stop_flag.is_set() else "Scan complete", count))
            except Exception as exc:
                self._send_log("[Error] Scan failed: " + str(exc))
            finally:
                self._send_ui("enable")
        self.worker = threading.Thread(target=worker, daemon=True)
        self.worker.start()

    def on_compress(self, decompress=False):
        if self._busy:
            return
        folder = self.folder.get().strip()
        if not folder or not (os.path.isdir(folder) or os.path.isfile(folder)):
            messagebox.showwarning("Warning", "Please select an existing file or folder.")
            return
        try:
            if check_volume(folder).upper() != "NTFS":
                raise OSError("This operation requires an NTFS volume.")
            check_write_access(os.path.dirname(folder) if os.path.isfile(folder) else folder)
            cluster_size = get_cluster_size(folder) if self.smart_filter.get() and not decompress else 0
        except Exception as exc:
            messagebox.showerror("Cannot start", str(exc))
            return
        extensions, folders = self._filters()
        algorithm = dict(ALG_OPTIONS).get(self.alg_label.get())
        behavior = dict(BEHAVIOR_OPTIONS).get(self.beh_label.get())
        if not algorithm or not behavior:
            messagebox.showerror("Error", "Invalid operation options.")
            return
        if decompress and not messagebox.askyesno("Decompress", "Remove compression from matching files in this folder?"):
            return
        verbose = self.verbose.get()
        smart = self.smart_filter.get() and not decompress
        self.clear_log()
        self.notebook.select(1)
        self.stop_flag.clear()
        self._disable_actions()
        self.progress.stop()
        self.progress.configure(mode="determinate", value=0, maximum=1)

        def worker():
            before = original = eligible = eligible_bytes = skipped = scan_errors = 0
            measurement_errors = 0
            started = time.monotonic()
            last_update = 0
            stats = dict(successful=0, failed=0, skipped=0, cancelled=0, bytes=0)
            cache = None
            def scan_error(exc):
                nonlocal scan_errors
                scan_errors += 1
                self._send_log("[Error] " + str(exc))
            try:
                if smart:
                    try:
                        cache = NoGainCache()
                    except (OSError, sqlite3.Error) as exc:
                        self._send_log('[Warning] No-benefit cache unavailable: ' + str(exc))
                # Disk-backed operation plan avoids retaining every path in memory.
                with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as plan:
                    self._send_ui("metrics", "Scanning matching files...")
                    scanned = 0
                    for info in scan_files(folder, extensions, folders, self.stop_flag, scan_error):
                        scanned += 1
                        before += info["disk"]
                        original += info["size"]
                        current = info["algorithm"]
                        needed = current != "-" if decompress else compression_action(
                            None if current == "-" else current, algorithm, behavior) != "skip"
                        if needed and smart:
                            reason = smart_skip_reason(info['path'], info['size'], cluster_size)
                            if reason is None and cache is not None:
                                try:
                                    if cache.contains(info['path'], algorithm):
                                        reason = 'unchanged file previously yielded no disk-space benefit'
                                except (OSError, sqlite3.Error) as exc:
                                    self._send_log('[Warning] Cannot read no-benefit cache: ' + str(exc))
                            if reason:
                                needed = False
                                if verbose:
                                    self._send_log('[Skipped] ' + reason + ': ' + info['path'])
                        if needed:
                            eligible += 1
                            eligible_bytes += info["size"]
                            plan.write(json.dumps((info["path"], info["size"])) + "\n")
                        else:
                            skipped += 1
                        if time.monotonic() - last_update >= 0.25:
                            self._send_ui("metrics", "Scanned %d | Selected %d | Skipped %d" % (scanned, eligible, skipped))
                            last_update = time.monotonic()
                    self.before_disk = before
                    self._send_ui("size", "Matching files — Before: %s / Actual: %s" % (fmt_bytes(before), fmt_bytes(original)))
                    self._send_ui("progress_max", eligible)
                    if self.stop_flag.is_set():
                        self._send_log("Stopped during scan; no operation started.")
                        self._send_ui("metrics", "Stopped during scan; no files changed.")
                        return
                    operation_start = time.monotonic()
                    last_update = 0
                    def metrics(current, force=False):
                        nonlocal last_update
                        now = time.monotonic()
                        if not force and now - last_update < 0.25:
                            return
                        last_update = now
                        elapsed = now - operation_start
                        processed = current["successful"] + current["failed"] + current["skipped"]
                        speed = current["bytes"] / max(elapsed, 0.001)
                        remaining = max(0, eligible_bytes - current["bytes"])
                        eta = "%.0fs" % (remaining / speed) if speed else "?"
                        self._send_ui("progress", processed)
                        self._send_ui("metrics", "Success %d | Failed %d | Scan errors %d | Skipped %d | Elapsed %.0fs | Processed %s/s | ETA ~%s" %
                            (current["successful"], current["failed"], scan_errors,
                             skipped + current["skipped"], now - started, fmt_bytes(speed), eta))
                    def verify(path):
                        final = get_compression_algorithm(path)
                        return final == "-" if decompress else final is not None and final.casefold() == algorithm.casefold()
                    def output(line):
                        if verbose or line.startswith(("[Error]", "[Skipped]")):
                            self._send_log(line)
                    plan.seek(0)
                    files = (tuple(json.loads(line)) for line in plan)
                    args = ["/u", "/i", "/f"] if decompress else ["/c", "/i", "/f", "/exe:" + algorithm]
                    def remember_skip(path, reason):
                        if cache is not None and reason == 'no-benefit':
                            try:
                                cache.add(path, algorithm)
                            except (OSError, sqlite3.Error) as exc:
                                self._send_log('[Warning] Cannot cache no-benefit result: ' + str(exc))
                    stats = run_compact_stream(args, files, output, self.stop_flag,
                        verify=verify, result_callback=metrics, skip_callback=remember_skip)
                    metrics(stats, force=True)
                cancelled = self.stop_flag.is_set()
                # Invalidate the pre-operation report even if final measurement fails.
                self._send_ui("status_clear")
                # Remeasure only the same filtered scope. Cancellation skips the expensive pass.
                if not cancelled:
                    self._send_ui("metrics", "Verifying final size...")
                    after = 0
                    measured = 0
                    final_errors = 0
                    def final_error(exc):
                        nonlocal final_errors
                        final_errors += 1
                        self._send_log("[Error] Final measurement: " + str(exc))
                    for path in iter_files_under(folder, extensions, folders, self.stop_flag, final_error):
                        disk = get_size_on_disk(path)
                        if disk is None:
                            final_error(OSError("Cannot measure " + path))
                        else:
                            after += disk
                            measured += 1
                    if not self.stop_flag.is_set():
                        self._send_ui("size", "Matching files — Before: %s | After: %s | Change: %s%s" %
                            (fmt_bytes(before), fmt_bytes(after), fmt_bytes(before - after),
                             " (partial measurement)" if scan_errors or final_errors or measured != scanned else ""))
                    measurement_errors = final_errors
                remaining = max(0, eligible - stats["successful"] - stats["failed"] - stats["skipped"])
                summary = "%s — Successful: %d; Failed: %d; Skipped: %d; Unprocessed: %d; Scan errors: %d; Measurement errors: %d; Elapsed: %.1fs" % (
                    "Stopped" if self.stop_flag.is_set() else "Completed with errors" if stats["failed"] or scan_errors or measurement_errors else "Completed",
                    stats["successful"], stats["failed"], skipped + stats["skipped"],
                    remaining, scan_errors, measurement_errors, time.monotonic() - started)
                self._send_log(summary)
                self._send_ui("metrics", summary)

            except Exception as exc:
                self._send_log("[Error] Operation failed: " + str(exc))
                self._send_ui("metrics", "Operation failed: " + str(exc))
            finally:
                if cache is not None:
                    cache.close()
                self._send_ui("enable")
        self.worker = threading.Thread(target=worker, daemon=True)
        self.worker.start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='NTFS Compactor')
    parser.add_argument('target', nargs='?')
    parser.add_argument('--action', choices=('scan', 'compress', 'decompress'), default='scan')
    shell = parser.add_mutually_exclusive_group()
    shell.add_argument('--install-context-menu', action='store_true')
    shell.add_argument('--remove-context-menu', action='store_true')
    parser.add_argument('--native-file-op', choices=('compress', 'decompress'), help=argparse.SUPPRESS)
    parser.add_argument('--algorithm', choices=('xpress4k', 'xpress8k', 'xpress16k', 'lzx'), default='xpress8k', help=argparse.SUPPRESS)
    parser.add_argument('--result', help=argparse.SUPPRESS)
    options = parser.parse_args()
    if options.native_file_op:
        if not options.target or not options.result:
            sys.exit(1)
        try:
            outcome = native_file_operation(options.target, options.native_file_op, options.algorithm)
        except Exception as exc:
            outcome = {'status': 'failed', 'error': str(exc)}
        with open(options.result, 'w', encoding='utf-8') as report:
            json.dump(outcome, report)
        sys.exit(0 if outcome['status'] in ('passed', 'skipped') else 1)
    if options.install_context_menu or options.remove_context_menu:
        try:
            register_context_menu(remove=options.remove_context_menu)
            text = 'Explorer menu removed.' if options.remove_context_menu else 'Explorer menu installed. On Windows 11, use Show more options.'
            code = 0
        except Exception as exc:
            text, code = str(exc), 1
        user32 = ctypes.WinDLL('user32')
        user32.MessageBoxW.argtypes = [wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.UINT]
        user32.MessageBoxW(None, text, 'NTFS Compactor', 0x10 if code else 0x40)
        sys.exit(code)
    app = App()
    if options.target:
        app.folder.set(os.path.abspath(options.target))
        action = app.on_status if options.action == 'scan' else lambda: app.on_compress(decompress=options.action == 'decompress')
        app.after(150, action)
    app.mainloop()
