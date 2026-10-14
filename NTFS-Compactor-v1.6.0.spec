# -*- mode: python ; coding: utf-8 -*-
# Windows folder distribution: no UPX and no single-file runtime extraction.
from pathlib import Path

root = Path(SPECPATH)
a = Analysis(
    [str(root / 'compactor.py')],
    pathex=[str(root)],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='NTFS-Compactor-v1.6.0',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    icon=str(root / 'icon.ico'),
    version=str(root / 'release' / 'version_info.txt'),
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name='NTFS-Compactor-v1.6.0',
)
