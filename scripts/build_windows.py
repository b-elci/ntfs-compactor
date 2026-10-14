"""Build a Windows release candidate; native tests and Defender are mandatory."""
import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
import venv
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def app_version():
    for node in ast.parse((ROOT / 'compactor.py').read_text(encoding='utf-8')).body:
        if isinstance(node, ast.Assign) and any(isinstance(name, ast.Name) and name.id == 'APP_VERSION' for name in node.targets):
            version = ast.literal_eval(node.value)
            if re.fullmatch(r'\d+\.\d+\.\d+', version):
                return version
    raise RuntimeError('APP_VERSION is missing or invalid')


def digest(path):
    with open(path, 'rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def tree_hashes(folder):
    return {str(path.relative_to(folder)).replace('\\', '/'): digest(path)
            for path in sorted(folder.rglob('*')) if path.is_file()}


def run(command, log=None, env=None):
    child_env = dict(os.environ if env is None else env)
    child_env['PYTHONUTF8'] = '1'
    child_env['PYTHONIOENCODING'] = 'utf-8'
    if log:
        result = subprocess.run(command, cwd=ROOT, env=child_env, text=True,
                                encoding='utf-8', errors='replace',
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        log.write_text(result.stdout, encoding='utf-8')
        print(result.stdout)
        result.check_returncode()
        return result.stdout
    subprocess.run(command, cwd=ROOT, env=child_env, check=True)


def scan(path, report):
    env = os.environ.copy()
    env['NTFS_SCAN_ROOT'] = str(path)
    env['NTFS_SCAN_REPORT'] = str(report)
    script = (ROOT / 'scripts' / 'scan_defender.ps1').read_text(encoding='utf-8')
    run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script], env=env)
    data = json.loads(report.read_text(encoding='utf-8-sig'))
    if data.get('status') != 'passed':
        raise RuntimeError('Defender did not confirm a successful scan')
    return data


def sign(executable, thumbprint, timestamp):
    if not re.fullmatch(r'[A-Fa-f0-9]{40}', thumbprint) or not timestamp.startswith('https://'):
        raise RuntimeError('Provide a certificate thumbprint and HTTPS timestamp URL')
    tool = shutil.which('signtool.exe')
    if not tool:
        candidates = list(Path(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')).glob('Windows Kits/10/bin/*/x64/signtool.exe'))
        if not candidates:
            raise RuntimeError('Windows SDK SignTool is required for signing')
        tool = str(sorted(candidates)[-1])
    run([tool, 'sign', '/sha1', thumbprint, '/fd', 'SHA256', '/tr', timestamp, '/td', 'SHA256', str(executable)])
    run([tool, 'verify', '/pa', '/v', str(executable)])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--certificate-thumbprint')
    parser.add_argument('--timestamp-url')
    parser.add_argument('--require-signature', action='store_true')
    args = parser.parse_args()
    if os.name != 'nt' or sys.version_info < (3, 12) or struct.calcsize('P') != 8:
        raise SystemExit('Build on 64-bit Windows using Python 3.12 or newer.')
    if args.require_signature and not args.certificate_thumbprint:
        raise SystemExit('A trusted signing certificate is required; none was configured.')
    if bool(args.certificate_thumbprint) != bool(args.timestamp_url):
        raise SystemExit('Signing requires both the certificate thumbprint and timestamp URL.')
    version = app_version()
    name = f'NTFS-Compactor-v{version}'
    reports = ROOT / 'build' / 'release-validation'
    reports.mkdir(parents=True, exist_ok=True)
    # An isolated environment prevents accidental bundling of unrelated packages.
    environment = ROOT / '.venv-release'
    venv.EnvBuilder(with_pip=True, clear=True).create(environment)
    python = environment / 'Scripts' / 'python.exe'
    run([str(python), '-m', 'pip', 'install', '--require-hashes', '-r', str(ROOT / 'requirements-build.txt')])
    test_output = run([str(python), '-B', '-m', 'unittest', 'discover', '-v'], reports / 'tests.log')
    match = re.search(r'Ran (\d+) tests?', test_output)
    if not match or int(match[1]) < 34:
        raise RuntimeError('The expected test suite did not execute')
    run([str(python), '-m', 'PyInstaller', '--clean', '--noconfirm', str(ROOT / (name + '.spec'))])
    package = ROOT / 'dist' / name
    executable = package / (name + '.exe')
    if not executable.is_file() or not (package / '_internal').is_dir():
        raise RuntimeError('Expected Windows folder distribution is missing')
    if args.certificate_thumbprint:
        sign(executable, args.certificate_thumbprint, args.timestamp_url)
    run([str(python), str(ROOT / 'scripts' / 'smoke_windows.py'), '--exe', str(executable), '--report', str(reports / 'native.json')])
    shutil.copy2(ROOT / 'LICENSE', package / 'LICENSE')
    shutil.copy2(ROOT / 'release' / 'README.txt', package / 'README.txt')
    for script in ('Install-context-menu.cmd', 'Remove-context-menu.cmd'):
        shutil.copy2(ROOT / 'release' / script, package / script)
    metadata = {
        'version': version,
        'built_at_utc': datetime.now(timezone.utc).isoformat(),
        'python': sys.version,
        'platform': platform.platform(),
        'architecture': 'x64',
        'packaging': 'PyInstaller onedir; UPX disabled',
        'signed': bool(args.certificate_thumbprint),
        'unit_test_count': int(match[1]),
        'unit_tests_skipped': int(re.search(r'skipped=(\d+)', test_output)[1]) if re.search(r'skipped=(\d+)', test_output) else 0,
        'native_checks': json.loads((reports / 'native.json').read_text(encoding='utf-8')),
        'defender_evidence': 'See validation.json supplied alongside the ZIP',
        'warning': 'An unsigned application may trigger SmartScreen. A clean Defender result is not a guarantee for other products or future definitions.',
    }
    commit = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True, capture_output=True)
    if commit.returncode == 0:
        metadata['commit'] = commit.stdout.strip()
    (package / 'BUILD-INFO.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    hashes = tree_hashes(package)
    (package / 'SHA256SUMS.txt').write_text(''.join(f'{value}  {key}\n' for key, value in hashes.items()), encoding='utf-8')
    before_scan = tree_hashes(package)
    folder_scan = scan(package, reports / 'defender-folder.json')
    if tree_hashes(package) != before_scan:
        raise RuntimeError('Release contents changed during antivirus scanning')
    outputs = ROOT / 'dist' / 'releases'
    outputs.mkdir(parents=True, exist_ok=True)
    archive = outputs / f'{name}-Windows-x64.zip'
    # Publish the archive only after its own scan passes.
    temporary_archive = reports / archive.name
    with zipfile.ZipFile(temporary_archive, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as target:
        for path in sorted(package.rglob('*')):
            if path.is_file():
                target.write(path, str(path.relative_to(package.parent)))
    archive_hash = digest(temporary_archive)
    zip_scan = scan(temporary_archive, reports / 'defender-zip.json')
    if not temporary_archive.exists() or digest(temporary_archive) != archive_hash:
        raise RuntimeError('Release ZIP changed during antivirus scanning')
    shutil.copy2(temporary_archive, archive)
    (outputs / (archive.name + '.sha256')).write_text(f'{archive_hash}  {archive.name}\n', encoding='utf-8')
    validation = dict(metadata, folder_scan=folder_scan, zip_scan=zip_scan, zip_sha256=archive_hash)
    (outputs / 'validation.json').write_text(json.dumps(validation, indent=2), encoding='utf-8')
    print('Validated Windows release candidate:', archive)
    print('Signed:', metadata['signed'])
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
            output.write(f'version={version}\n')


if __name__ == '__main__':
    main()
