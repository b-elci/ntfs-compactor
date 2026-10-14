import unittest
from unittest import mock
import ctypes
import io
import os
from pathlib import Path
import queue
import tempfile
import threading
import time
import sys
from types import SimpleNamespace

# Linux logic tests must not call or pretend to implement native Windows APIs.
if hasattr(ctypes, "WinDLL"):
    import compactor
else:
    def unavailable(*args, **kwargs):
        raise RuntimeError("Windows API unavailable in Linux logic tests")

    library = mock.Mock()
    for name in ("GetCompressedFileSizeW", "GetFileAttributesW", "GlobalMemoryStatusEx",
                 "GetVolumePathNameW", "GetVolumeInformationW"):
        setattr(library, name, mock.Mock(side_effect=unavailable))
    with mock.patch.object(ctypes, "WinDLL", return_value=library, create=True):
        import compactor


class CompressionActionTests(unittest.TestCase):
    def test_uncompressed_file_is_compressed(self):
        self.assertEqual(compactor.compression_action(None, "lzx", "skip"), "compress")

    def test_skip_behavior_skips_any_compressed_file(self):
        self.assertEqual(
            compactor.compression_action("XPRESS4K", "lzx", "skip"),
            "skip",
        )

    def test_same_algorithm_is_not_reprocessed(self):
        self.assertEqual(
            compactor.compression_action("LZX", "lzx", "recompress_if_different"),
            "skip",
        )

    def test_different_algorithm_is_recompressed(self):
        self.assertEqual(
            compactor.compression_action("XPRESS4K", "lzx", "recompress_if_different"),
            "recompress",
        )

    def test_recompression_uses_force_switch(self):
        with mock.patch.object(compactor, "run_compact", return_value=(0, "")) as run:
            compactor.compact_compress_file(r"C:\data.bin", "lzx", force=True)

        run.assert_called_once_with(
            ["/c", "/i", "/f", "/exe:lzx", r"C:\data.bin"]
        )


class FileScanTests(unittest.TestCase):
    def test_explicit_file_target_respects_extension_filters(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'target.txt'
            path.touch()
            self.assertEqual(list(compactor.iter_files_under(str(path))), [str(path)])
            self.assertEqual(list(compactor.iter_files_under(str(path), excluded_extensions=('txt',))), [])
    def test_windows_path_handles_local_unc_and_extended_paths(self):
        import ntpath
        with mock.patch.object(compactor.os, "name", "nt"), \
             mock.patch.object(compactor.os, "path", ntpath):
            self.assertEqual(compactor.windows_path(r"C:\data\a.txt"), r"\\?\C:\data\a.txt")
            self.assertEqual(compactor.windows_path(r"\\server\share\a.txt"), r"\\?\UNC\server\share\a.txt")
            self.assertEqual(compactor.windows_path(r"\\?\C:\data\a.txt"), r"\\?\C:\data\a.txt")

    def test_filters_prune_folders_and_match_extensions_case_insensitively(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "Cache").mkdir()
            (root / "Cache" / "hidden.txt").write_text("hidden")
            (root / "keep.txt").write_text("keep")
            (root / "movie.MP4").write_text("video")
            (root / "archive.zip").write_text("zip")
            files = list(compactor.iter_files_under(folder,
                         compactor.parse_patterns("mp4; *.zip"),
                         compactor.parse_patterns("cache")))
            self.assertEqual([Path(path).name for path in files], ["keep.txt"])

    def test_relative_folder_pattern_prunes_nested_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "nested" / "skip").mkdir(parents=True)
            (root / "nested" / "skip" / "a.txt").touch()
            (root / "nested" / "keep.txt").touch()
            files = list(compactor.iter_files_under(folder, excluded_folders=("nested/skip",)))
            self.assertEqual([Path(path).name for path in files], ["keep.txt"])

    def test_scan_is_cancellable_before_enumeration(self):
        stop = threading.Event()
        stop.set()
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "a.txt").touch()
            self.assertEqual(list(compactor.scan_files(folder, stop_event=stop)), [])

    def test_scan_reports_unreadable_file_instead_of_counting_zero_bytes(self):
        errors = []
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "a.txt").write_text("test")
            with mock.patch.object(compactor, "get_size_on_disk", return_value=None), \
                 mock.patch.object(compactor, "get_compression_algorithm", return_value="-"):
                self.assertEqual(list(compactor.scan_files(folder, on_error=errors.append)), [])
        self.assertEqual(len(errors), 1)

    def test_scan_does_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "original.txt").touch()
            try:
                (root / "alias.txt").symlink_to(root / "original.txt")
                (root / "loop").symlink_to(root, target_is_directory=True)
            except OSError:
                self.skipTest("Symlink creation is unavailable")
            self.assertEqual(len(list(compactor.iter_files_under(folder))), 1)


class FakeProcess:
    def __init__(self, code=0, output=""):
        self.returncode = code
        self.stdout = io.StringIO(output)
        self.terminated = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -1

    def kill(self):
        self.terminate()


class BatchRunnerTests(unittest.TestCase):
    def test_turkish_console_output_uses_oem_codepage(self):
        with mock.patch.object(compactor, 'os', SimpleNamespace(name='nt')), \
             mock.patch.object(compactor.kernel32, 'GetOEMCP', return_value=857, create=True):
            encoding = compactor.compact_output_encoding()
            self.assertEqual(encoding, 'cp857')
            self.assertEqual('şğıöçü'.encode('cp857').decode(encoding), 'şğıöçü')

    def run_batch(self, files, factory, **kwargs):
        def launch(cmd, **options):
            process = factory(cmd, **options)
            if '--result' in cmd:
                import json
                Path(cmd[cmd.index('--result') + 1]).write_text(
                    json.dumps({'status': 'passed' if process.returncode == 0 else 'failed'}))
            return process
        with mock.patch.object(compactor.subprocess, "Popen", side_effect=launch):
            return compactor.run_compact_stream(["/c", "/exe:lzx"], files,
                                                lambda line: None, **kwargs)

    def test_nonzero_exit_counts_failure_not_success(self):
        progress = []
        stats = self.run_batch([("/data/file.bin", 100)],
                              lambda *a, **k: FakeProcess(1, "Erişim engellendi\n"),
                              progress_callback=progress.append)
        self.assertEqual(stats["successful"], 0)
        self.assertEqual(stats["failed"], 1)
        self.assertEqual(stats["bytes"], 100)
        self.assertEqual(sum(progress), 1)

    def test_zero_exit_still_requires_requested_final_state(self):
        stats = self.run_batch(["/data/file.bin"], lambda *a, **k: FakeProcess(),
                              verify=lambda path: False)
        self.assertEqual(stats["failed"], 1)
        self.assertEqual(stats["successful"], 0)

    def test_partial_batch_retries_only_unverified_files(self):
        calls = []
        def factory(cmd, **kwargs):
            calls.append(cmd)
            return FakeProcess(1 if len(calls) == 1 else 0)
        def verify(path):
            return path.endswith("a.bin") or len(calls) > 1
        stats = self.run_batch(["/data/a.bin", "/data/b.bin"], factory, verify=verify)
        self.assertEqual(stats["successful"], 2)
        self.assertEqual(stats["failed"], 0)
        self.assertEqual(calls[1][-1], "b.bin")
        self.assertNotIn("a.bin", calls[1])

    def test_adaptive_batches_reduce_process_startups(self):
        batches = []
        def factory(cmd, **kwargs):
            batches.append(len(cmd) - 3)
            return FakeProcess()
        stats = self.run_batch((("/data/file%d.bin" % i, 10) for i in range(1000)), factory)
        self.assertEqual(stats["successful"], 1000)
        self.assertEqual(stats["bytes"], 10000)
        self.assertLess(len(batches), 15)
        self.assertLessEqual(max(batches), 128)

    def test_failed_batches_shrink_without_infinite_retries(self):
        calls = []
        def factory(cmd, **kwargs):
            calls.append(cmd)
            return FakeProcess(1)
        stats = self.run_batch(["/data/a", "/data/b", "/data/c"], factory)
        self.assertEqual(stats["failed"], 3)
        self.assertLessEqual(len(calls), 5)

    def test_retry_success_does_not_immediately_regrow_failed_batch(self):
        sizes = []
        def factory(cmd, **kwargs):
            sizes.append(len(cmd) - 3)
            return FakeProcess(1 if len(sizes) == 1 else 0)
        stats = self.run_batch(["/data/file%d" % index for index in range(100)], factory)
        self.assertEqual(stats["successful"], 100)
        self.assertEqual(sizes[:4], [32, 16, 16, 16])

    def test_pre_cancelled_run_does_not_start_process(self):
        stop = threading.Event()
        stop.set()
        factory = mock.Mock()
        self.run_batch(["/data/a"], factory, stop_event=stop)
        factory.assert_not_called()

    def test_stop_terminates_process_even_without_stdout(self):
        released = threading.Event()
        stop = threading.Event()
        class BlockingOutput:
            def __iter__(self):
                released.wait(3)
                return iter(())
            def close(self):
                pass
        process = FakeProcess()
        process.returncode = None
        process.stdout = BlockingOutput()
        def terminate():
            process.terminated = True
            process.returncode = -1
            released.set()
        process.terminate = terminate
        process.kill = terminate
        timer = threading.Timer(0.1, stop.set)
        started = time.monotonic()
        timer.start()
        try:
            stats = self.run_batch(["/data/a"], lambda *a, **k: process, stop_event=stop)
        finally:
            timer.cancel()
            released.set()
        self.assertTrue(process.terminated)
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(stats["cancelled"], 1)
        self.assertEqual(stats["successful"], 0)

    def test_long_parent_path_is_not_silently_skipped(self):
        path = "/data/" + "nested/" * 50 + "a.bin"
        stats = self.run_batch([path], lambda *a, **k: FakeProcess())
        self.assertEqual(stats["successful"], 1)
        self.assertEqual(stats["skipped"], 0)

    def test_unicode_command_length_stays_within_utf16_limit(self):
        calls = []
        def factory(cmd, **kwargs):
            calls.append(cmd)
            return FakeProcess()
        files = ["/data/" + "😀" * 120 + str(i) + ".bin" for i in range(200)]
        stats = self.run_batch(files, factory)
        self.assertEqual(stats["successful"], 200)
        for command in calls:
            self.assertLessEqual(len(compactor.subprocess.list2cmdline(command).encode("utf-16-le")) // 2, 30000)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.store = compactor.ReportStore()

    def tearDown(self):
        self.store.close()

    def test_complete_report_survives_pagination_and_numeric_sort(self):
        self.store.append([dict(path=str(i), size_raw=i) for i in range(1201)])
        self.assertEqual(len(list(self.store.rows(0, 500))), 500)
        self.assertEqual(len(list(self.store.rows(1000, 500))), 201)
        self.assertEqual(len(list(self.store.rows())), 1201)
        self.store.sort_column = "size"
        self.store.descending = True
        self.assertEqual(next(self.store.rows())["size_raw"], 1200)

    def test_queue_clear_does_not_delete_later_rows(self):
        ui = queue.Queue()
        ui.put(("status_clear", None))
        for i in range(1201):
            ui.put(("status_row", dict(path=str(i))))
        app = SimpleNamespace(log_q=queue.Queue(), ui_q=ui, _closing=False,
            _add_status_rows=self.store.append, _clear_status_report=self.store.clear,
            after=lambda *args: None, _drain_log_queue=lambda: None,
            append_log=lambda message: self.fail(message))
        while not ui.empty():
            compactor.App._drain_log_queue(app)
        self.assertEqual(self.store.count, 1201)

    def test_queue_drain_is_bounded_per_tick(self):
        ui = queue.Queue()
        for i in range(600):
            ui.put(("status_row", dict(path=str(i))))
        app = SimpleNamespace(log_q=queue.Queue(), ui_q=ui, _closing=False,
            _add_status_rows=self.store.append, after=lambda *args: None,
            _drain_log_queue=lambda: None, append_log=lambda message: self.fail(message))
        compactor.App._drain_log_queue(app)
        self.assertLessEqual(self.store.count, 250)
        self.assertFalse(ui.empty())

    def test_csv_export_includes_all_pages(self):
        import csv
        self.store.append([dict(path=str(i), status="Uncompressed") for i in range(1201)])
        app = SimpleNamespace(report_store=self.store)
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "report.csv")
            with mock.patch.object(compactor.filedialog, "asksaveasfilename", return_value=path), \
                 mock.patch.object(compactor.messagebox, "showinfo"), \
                 mock.patch.object(compactor.messagebox, "showerror") as error:
                compactor.App.on_save_report(app)
            error.assert_not_called()
            with open(path, newline="", encoding="utf-8") as source:
                self.assertEqual(len(list(csv.reader(source))), 1202)


class SmartFilteringTests(unittest.TestCase):
    def test_volume_cluster_size_drives_small_file_threshold(self):
        self.assertIsNotNone(compactor.smart_skip_reason('small.bin', 4096, 4096))
        self.assertIsNone(compactor.smart_skip_reason('larger.bin', 4097, 4096))
        self.assertIsNotNone(compactor.smart_skip_reason('larger.bin', 8192, 65536))

    def test_compressed_formats_are_optional_heuristics(self):
        for extension in ('JPG', 'mp4', 'ogg', 'mp3', 'zip', '7z'):
            self.assertEqual(compactor.smart_skip_reason('file.' + extension, 100000, 4096), 'already compressed file format')
        self.assertIsNone(compactor.smart_skip_reason('game.dat', 100000, 4096))

    def test_no_benefit_cache_invalidates_when_file_changes_or_algorithm_changes(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'game.dat'
            path.write_bytes(b'first')
            cache = compactor.NoGainCache(str(Path(folder) / 'cache.sqlite'))
            try:
                cache.add(str(path), 'lzx')
                self.assertTrue(cache.contains(str(path), 'lzx'))
                self.assertFalse(cache.contains(str(path), 'xpress8k'))
                path.write_bytes(b'changed contents')
                self.assertFalse(cache.contains(str(path), 'lzx'))
            finally:
                cache.close()

    def test_no_benefit_cache_catches_same_size_edits_with_preserved_write_time(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'game.dat'
            path.write_bytes(b'first')
            original = path.stat()
            cache = compactor.NoGainCache(str(Path(folder) / 'cache.sqlite'))
            try:
                cache.add(str(path), 'lzx')
                path.write_bytes(b'other')
                os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
                self.assertFalse(cache.contains(str(path), 'lzx'))
            finally:
                cache.close()

    def test_native_no_benefit_is_skipped_and_handle_is_closed(self):
        library = mock.Mock()
        library.CreateFileW.return_value = 123
        wof = mock.Mock()
        wof.WofSetFileDataLocation.return_value = 0x80070158
        with mock.patch.object(compactor, 'kernel32', library), \
             mock.patch.object(compactor, 'wofutil', wof), \
             mock.patch.object(compactor, 'get_compression_algorithm', return_value='-'):
            outcome = compactor.native_file_operation('file.bin', 'compress', 'lzx')
        self.assertEqual(outcome, {'status': 'skipped', 'reason': 'no-benefit'})
        library.CloseHandle.assert_called_once_with(123)

    def test_unhelpful_recompression_restores_original_algorithm(self):
        library = mock.Mock()
        library.CreateFileW.return_value = 123
        library.DeviceIoControl.return_value = True
        wof = mock.Mock()
        wof.WofSetFileDataLocation.side_effect = [0x80070158, 0]
        with mock.patch.object(compactor, 'kernel32', library), \
             mock.patch.object(compactor, 'wofutil', wof), \
             mock.patch.object(compactor, 'get_compression_algorithm', return_value='LZX'):
            result = compactor.native_file_operation('file.bin', 'compress', 'xpress4k')
        self.assertEqual(result['status'], 'skipped')
        self.assertEqual(wof.WofSetFileDataLocation.call_count, 2)
        self.assertEqual(library.DeviceIoControl.call_args.args[1], 0x00090314)

    def test_native_helper_skip_does_not_turn_into_a_failed_verification(self):
        import json
        def factory(cmd, **kwargs):
            Path(cmd[cmd.index('--result') + 1]).write_text(json.dumps({'status': 'skipped', 'reason': 'no-benefit'}))
            return FakeProcess()
        skipped = []
        with mock.patch.object(compactor, 'needs_native_path', return_value=True), \
             mock.patch.object(compactor.subprocess, 'Popen', side_effect=factory):
            result = compactor.run_compact_stream(['/c', '/exe:lzx'], ['file.bin'], lambda text: None,
                         verify=lambda path: False, skip_callback=lambda *args: skipped.append(args))
        self.assertEqual(result['skipped'], 1)
        self.assertEqual(result['failed'], 0)
        self.assertEqual(skipped, [('file.bin', 'no-benefit')])


class FakeRegistry:
    HKEY_CURRENT_USER = 'HKCU'
    REG_SZ = 1
    KEY_READ = 1
    KEY_WRITE = 2
    def __init__(self):
        self.keys = {}
    class Key:
        def __init__(self, path): self.path = path
        def __enter__(self): return self
        def __exit__(self, *args): pass
    def OpenKey(self, hive, path, *args):
        if path not in self.keys: raise FileNotFoundError(path)
        return self.Key(path)
    def CreateKey(self, hive, path):
        parent, marker, tail = path.partition('\\NTFSCompactor')
        current = parent + marker
        self.keys.setdefault(current, {})
        for part in tail.strip('\\').split('\\'):
            if part:
                current += '\\' + part
                self.keys.setdefault(current, {})
        return self.Key(path)
    def SetValueEx(self, key, name, _, kind, value):
        self.keys[key.path][name] = value
    def QueryValueEx(self, key, name):
        if name not in self.keys[key.path]: raise FileNotFoundError(name)
        return self.keys[key.path][name], self.REG_SZ
    def EnumKey(self, key, index):
        prefix = key.path + '\\'
        children = sorted({path[len(prefix):].split('\\')[0] for path in self.keys if path.startswith(prefix)})
        if index >= len(children): raise OSError(259, 'No more items')
        return children[index]
    def DeleteKey(self, hive, path):
        del self.keys[path]


class ShellIntegrationTests(unittest.TestCase):
    def test_per_user_install_handles_files_folders_and_background_and_uninstalls(self):
        registry = FakeRegistry()
        with mock.patch.dict(sys.modules, {'winreg': registry}), \
             mock.patch.object(compactor, 'launch_command', return_value=[r'C:\App Folder\NTFS.exe']):
            compactor.register_context_menu()
            commands = {path: values[''] for path, values in registry.keys.items() if path.endswith('\\command')}
            self.assertEqual(len(commands), 9)
            for path, command in commands.items():
                self.assertTrue(command.startswith('"C:\\App Folder\\NTFS.exe" --action '))
                self.assertTrue(command.endswith('"%V"' if '\\Background\\' in path else '"%1"'))
            compactor.register_context_menu(remove=True)
        self.assertEqual(registry.keys, {})

    def test_existing_unowned_registry_entry_is_preserved(self):
        registry = FakeRegistry()
        key = r'Software\Classes\Directory\shell\NTFSCompactor'
        registry.keys[key] = {'MUIVerb': 'Existing application'}
        with mock.patch.dict(sys.modules, {'winreg': registry}), self.assertRaises(ValueError):
            compactor.register_context_menu()
        self.assertEqual(registry.keys[key], {'MUIVerb': 'Existing application'})


@unittest.skipUnless(os.name == "nt" or os.environ.get("DISPLAY"),
                     "Tk workflow tests require Windows or an X display")
class GuiWorkflowTests(unittest.TestCase):
    """Real widgets and worker threads; compression/native APIs remain mocked."""
    def setUp(self):
        self.app = compactor.App()
        self.app.withdraw()
        self.app.smart_filter.set(False)
        self.ui_errors = []
        self.app.report_callback_exception = lambda *args: self.ui_errors.append(args)
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.app.folder.set(str(self.root))

    def tearDown(self):
        import gc
        if self.app.worker:
            self.app.worker.join(timeout=3)
        self.app.on_close()
        self.app = None
        # Tk interpreter finalizers must run on the main thread between roots.
        gc.collect()
        self.temp.cleanup()

    def pump(self):
        deadline = time.monotonic() + 10
        while (self.app._busy or not self.app.ui_q.empty()) and time.monotonic() < deadline:
            self.app.update()
            time.sleep(0.005)
        self.assertFalse(self.app._busy, "Worker failed to complete")
        self.assertTrue(self.app.ui_q.empty())
        self.assertFalse(self.ui_errors)

    def test_large_scan_pagination_and_locked_controls(self):
        for index in range(1201):
            (self.root / ("file%d.txt" % index)).touch()
        (self.root / "excluded.zip").touch()
        self.app.exclude_extensions.set("zip")
        with mock.patch.object(compactor, "get_size_on_disk", return_value=0), \
             mock.patch.object(compactor, "get_compression_algorithm", return_value="-"):
            self.app.on_status()
            self.assertEqual(str(self.app.btn_browse["state"]), "disabled")
            self.assertEqual(str(self.app.ent_folder["state"]), "disabled")
            self.pump()
        self.assertEqual(self.app.report_store.count, 1201)
        self.assertEqual(len(self.app.status_tree.get_children()), 500)
        self.app._change_page(2)
        self.assertEqual(len(self.app.status_tree.get_children()), 201)
        self.assertEqual(str(self.app.btn_browse["state"]), "normal")

    def test_compression_and_decompression_verify_results_and_finish_measurement(self):
        states = {}
        for name in ("a.txt", "b.txt", "c.txt"):
            path = self.root / name
            path.write_text("sample")
            states[str(path)] = "-"
        def factory(cmd, **kwargs):
            target = "-" if "/u" in cmd else "XPRESS8K"
            for name in cmd:
                if name.endswith(".txt"):
                    states[str(Path(str(kwargs["cwd"]).removeprefix("\\\\?\\")) / name)] = target
            return FakeProcess()
        with mock.patch.object(compactor, "check_volume", return_value="NTFS"), \
             mock.patch.object(compactor, "get_size_on_disk", return_value=6), \
             mock.patch.object(compactor, "get_compression_algorithm", side_effect=lambda path: states[path]), \
             mock.patch.object(compactor.subprocess, "Popen", side_effect=factory):
            self.app.on_compress()
            self.pump()
            self.assertTrue(all(value == "XPRESS8K" for value in states.values()))
            self.assertIn("Successful: 3", self.app.metrics_label["text"])
            self.assertIn("After:", self.app.size_label["text"])
            with mock.patch.object(compactor.messagebox, "askyesno", return_value=True):
                self.app.on_compress(decompress=True)
            self.pump()
            self.assertTrue(all(value == "-" for value in states.values()))
            self.assertIn("Successful: 3", self.app.metrics_label["text"])

    def test_non_ntfs_and_write_access_failures_prevent_operation(self):
        for filesystem, write_error in (("FAT32", None), ("NTFS", PermissionError("No access"))):
            with self.subTest(filesystem=filesystem), \
                 mock.patch.object(compactor, "check_volume", return_value=filesystem), \
                 mock.patch.object(compactor, "check_write_access", side_effect=write_error), \
                 mock.patch.object(compactor.messagebox, "showerror") as error, \
                 mock.patch.object(compactor.subprocess, "Popen") as process:
                self.app.on_compress()
                error.assert_called_once()
                process.assert_not_called()
                self.assertFalse(self.app._busy)

    def test_failed_compression_has_error_summary(self):
        (self.root / "a.txt").write_text("sample")
        with mock.patch.object(compactor, "check_volume", return_value="NTFS"), \
             mock.patch.object(compactor, "get_size_on_disk", return_value=6), \
             mock.patch.object(compactor, "get_compression_algorithm", return_value="-"), \
             mock.patch.object(compactor.subprocess, "Popen", return_value=FakeProcess(1)):
            self.app.on_compress()
            self.pump()
        self.assertIn("Completed with errors", self.app.metrics_label["text"])
        self.assertIn("Successful: 0; Failed: 1", self.app.metrics_label["text"])

    def test_cancelled_initial_scan_never_starts_compact(self):
        def scan(*args, **kwargs):
            yield dict(path=str(self.root / "a.txt"), size=6, disk=6, algorithm="-")
            self.app.stop_flag.set()
        with mock.patch.object(compactor, "check_volume", return_value="NTFS"), \
             mock.patch.object(compactor, "scan_files", side_effect=scan), \
             mock.patch.object(compactor.subprocess, "Popen") as process:
            self.app.on_compress()
            self.pump()
        process.assert_not_called()
        self.assertIn("Stopped during scan", self.app.metrics_label["text"])
        self.assertEqual(str(self.app.btn_browse["state"]), "normal")

    def test_smart_filter_skips_small_files_and_media_before_starting_process(self):
        self.app.smart_filter.set(True)
        (self.root / 'small.bin').write_bytes(b'small')
        (self.root / 'video.MP4').write_bytes(b'media' * 2000)
        with mock.patch.object(compactor, 'check_volume', return_value='NTFS'), \
             mock.patch.object(compactor, 'get_cluster_size', return_value=4096), \
             mock.patch.object(compactor, 'get_size_on_disk', side_effect=lambda path: Path(path).stat().st_size), \
             mock.patch.object(compactor, 'get_compression_algorithm', return_value='-'), \
             mock.patch.object(compactor.subprocess, 'Popen') as process:
            self.app.on_compress()
            self.pump()
        process.assert_not_called()
        self.assertIn('Skipped: 2', self.app.metrics_label['text'])

    def test_selected_file_operation_does_not_include_siblings(self):
        (self.root / 'selected.txt').write_text('chosen')
        (self.root / 'sibling.txt').write_text('other')
        self.app.folder.set(str(self.root / 'selected.txt'))
        with mock.patch.object(compactor, 'get_size_on_disk', return_value=6), \
             mock.patch.object(compactor, 'get_compression_algorithm', return_value='-'):
            self.app.on_status()
            self.pump()
        self.assertEqual(self.app.report_store.count, 1)
        self.assertTrue(next(self.app.report_store.rows())['path'].endswith('selected.txt'))


if __name__ == "__main__":
    unittest.main()
