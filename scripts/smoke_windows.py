"""Exercise actual Windows NTFS APIs and the packaged GUI before release."""
import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def check_packaged_gui(executable, version):
    user32 = ctypes.WinDLL('user32', use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user32.EnumWindows.argtypes = [callback_type, wintypes.LPARAM]
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    process = subprocess.Popen([str(executable)], cwd=executable.parent)
    window = None
    deadline = time.monotonic() + 20
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError('Packaged GUI exited before showing its window')
            found = []
            @callback_type
            def inspect(handle, _):
                pid = wintypes.DWORD()
                user32.GetWindowThreadProcessId(handle, ctypes.byref(pid))
                if pid.value == process.pid and user32.IsWindowVisible(handle):
                    title = ctypes.create_unicode_buffer(512)
                    user32.GetWindowTextW(handle, title, len(title))
                    if title.value == f'NTFS Advanced Compression v{version} (XPRESS/LZX)':
                        found.append(handle)
                return True
            user32.EnumWindows(inspect, 0)
            if found:
                window = found[0]
                break
            time.sleep(0.1)
        if window is None:
            raise RuntimeError('Expected packaged application window was not found')
        user32.PostMessageW(window, 0x0010, 0, 0)  # WM_CLOSE
        if process.wait(timeout=10) != 0:
            raise RuntimeError('Packaged application did not close cleanly')
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def main():
    if os.name != 'nt':
        raise SystemExit('This smoke test requires real Windows and NTFS.')
    parser = argparse.ArgumentParser()
    parser.add_argument('--exe', required=True, type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import compactor
    completed = []
    with tempfile.TemporaryDirectory(prefix='ntfs-release-test-') as folder:
        if compactor.check_volume(folder).upper() != 'NTFS':
            raise RuntimeError('Smoke test temporary directory must be on NTFS')
        compactor.check_write_access(folder)
        path = Path(folder) / 'Türkçe-şğıöçü.txt'
        payload = ('NTFS compression release validation — şğıöçü\n' * 32768).encode('utf-8')
        path.write_bytes(payload)
        for algorithm in ('xpress4k', 'xpress8k', 'xpress16k', 'lzx'):
            result = compactor.run_compact_stream(
                ['/c', '/i', '/f', '/exe:' + algorithm], [(str(path), len(payload))], print,
                verify=lambda file: compactor.get_compression_algorithm(file) == algorithm.upper())
            if result['successful'] != 1 or result['failed']:
                raise RuntimeError('Native compression verification failed: ' + algorithm)
            if path.read_bytes() != payload:
                raise RuntimeError('File contents changed during compression')
            completed.append(algorithm)
        result = compactor.run_compact_stream(['/u', '/i', '/f'], [str(path)], print,
                    verify=lambda file: compactor.get_compression_algorithm(file) == '-')
        if result['successful'] != 1 or path.read_bytes() != payload:
            raise RuntimeError('Native decompression verification failed')
        completed.append('decompression-content-integrity')
        long_dir = Path(folder) / ('a' * 90) / ('b' * 90) / ('c' * 90)
        os.makedirs(compactor.windows_path(str(long_dir)))
        long_file = str(long_dir / 'uzun-ş.txt')
        with open(compactor.windows_path(long_file), 'wb') as target:
            target.write(payload)
        result = compactor.run_compact_stream(['/c', '/i', '/f', '/exe:xpress8k'], [long_file], print,
                    verify=lambda file: compactor.get_compression_algorithm(file) == 'XPRESS8K')
        if result['successful'] != 1:
            raise RuntimeError('Extended-path compression verification failed')
        completed.append('long-path-compression')
    check_packaged_gui(args.exe.resolve(), compactor.APP_VERSION)
    completed.append('packaged-gui-startup-and-clean-close')
    args.report.write_text(json.dumps({'status': 'passed', 'checks': completed}, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
