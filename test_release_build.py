"""Release gating tests; these simulate Windows build tools, not native scans."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

spec = importlib.util.spec_from_file_location('build_windows', Path(__file__).parent / 'scripts' / 'build_windows.py')
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


class ReleaseGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / 'release').mkdir()
        (self.root / 'release' / 'README.txt').write_text('Unsigned candidate')
        (self.root / 'LICENSE').write_text('Test license')
        (self.root / 'compactor.py').write_text('APP_VERSION = "1.6.0"\n')
        self.package = self.root / 'dist' / 'NTFS-Compactor-v1.6.0'

    def tearDown(self):
        self.temp.cleanup()

    def command(self, args, log=None, env=None):
        if 'unittest' in args:
            return 'Ran 34 tests in 1.0s\nOK\n'
        if 'PyInstaller' in args:
            (self.package / '_internal').mkdir(parents=True)
            (self.package / 'NTFS-Compactor-v1.6.0.exe').write_bytes(b'test-executable')
            (self.package / '_internal' / 'runtime.dll').write_bytes(b'test-runtime')
        elif '--report' in args:
            report = Path(args[args.index('--report') + 1])
            report.write_text(json.dumps({'status': 'passed', 'checks': ['simulated-native-check']}))

    def perform(self, scan):
        with mock.patch.object(build, 'ROOT', self.root), \
             mock.patch.object(build, 'os', SimpleNamespace(name='nt', environ={})), \
             mock.patch.object(build, 'run', side_effect=self.command), \
             mock.patch.object(build, 'scan', side_effect=scan), \
             mock.patch.object(build.venv, 'EnvBuilder'), \
             mock.patch.object(build.sys, 'argv', ['build_windows.py']), \
             redirect_stdout(io.StringIO()):
            build.main()

    def test_archive_contains_runtime_and_records_unsigned_validation(self):
        self.perform(lambda *args: {'status': 'passed'})
        release = self.root / 'dist' / 'releases'
        archive = next(release.glob('*.zip'))
        with zipfile.ZipFile(archive) as packed:
            self.assertIn('NTFS-Compactor-v1.6.0/_internal/runtime.dll', packed.namelist())
            self.assertIn('NTFS-Compactor-v1.6.0/README.txt', packed.namelist())
        report = json.loads((release / 'validation.json').read_text())
        self.assertFalse(report['signed'])
        self.assertEqual(report['zip_sha256'], build.digest(archive))

    def test_scan_mutating_a_binary_blocks_release_output(self):
        def scan(path, report):
            (self.package / 'NTFS-Compactor-v1.6.0.exe').write_bytes(b'remediated-content')
            return {'status': 'passed'}
        with self.assertRaisesRegex(RuntimeError, 'contents changed'):
            self.perform(scan)
        self.assertFalse((self.root / 'dist' / 'releases').exists())

    def test_scan_mutating_final_zip_blocks_archive_delivery(self):
        def scan(path, report):
            if path.suffix == '.zip':
                path.write_bytes(b'remediated-zip')
            return {'status': 'passed'}
        with self.assertRaisesRegex(RuntimeError, 'ZIP changed'):
            self.perform(scan)
        self.assertFalse(list((self.root / 'dist' / 'releases').glob('*.zip')))


if __name__ == '__main__':
    unittest.main()
