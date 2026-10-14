# Building Windows release candidates

The v1.6.0 package is a Windows x64 **folder distribution**, built without UPX.
Extract the entire ZIP and keep `_internal` beside the EXE. The EXE carries
version/product metadata; metadata does not provide an Authenticode signature.

No signing certificate is configured for the automated candidate. It is
unsigned and may still trigger SmartScreen's unknown-publisher warning. No
packaging choice or single antivirus scan can guarantee acceptance by every
security product.

## Automatic Windows build

The `Windows release candidate` GitHub Actions workflow runs on Windows Server
2025 when a `release/v*` branch is pushed, or when started manually. It installs
Python 3.12 x64 and the exact SHA-256-verified build dependencies from
`requirements-build.txt`, using an isolated virtual environment. Action versions
are pinned to commit SHAs.

The workflow must pass all of the following before uploading a candidate:

1. The existing unit and real Tk workflow tests (native operations are mocked
   only where the tests explicitly do so).
2. Real NTFS compression using XPRESS4K, XPRESS8K, XPRESS16K, and LZX; algorithm
   verification through the Windows API; file-content integrity; decompression;
   Turkish filenames; an extended path; and packaged GUI startup/clean close.
3. Microsoft Defender scans of the full distribution and final ZIP, with a
   successful definition update. Inactive/unavailable Defender, scan errors,
   detections, and files altered by remediation block the package.

Successful runs upload the Windows ZIP, its SHA-256 checksum, and
`validation.json` as an Actions artifact, then create an **unpublished draft
release** for the tested commit. The draft records that it is unsigned.
The workflow does not publish the release. If GitHub Actions or Defender is
unavailable, the candidate remains unverified; inspect the failed job before
retrying. On a first run, repository settings may need to allow Actions or
workflow write access for creating the draft.

## Build on a Windows computer

From the repository root, using an official Python 3.12+ x64 installation:

```powershell
py -3.12 scripts/build_windows.py
```

The script creates `.venv-release`, installs the hash-pinned dependencies, runs
all checks, and produces:

```text
dist/releases/NTFS-Compactor-v1.6.0-Windows-x64.zip
dist/releases/NTFS-Compactor-v1.6.0-Windows-x64.zip.sha256
dist/releases/validation.json
```

The build requires an active Microsoft Defender installation. It never changes
Defender exclusions or disables protection. Check the command's exit status;
a failed run is not a validated release. Do not distribute a raw `dist` EXE
from a failed run. Linux cloud tasks cannot execute these native Windows checks
or cross-compile the EXE using Linux PyInstaller.

## Signing when a certificate becomes available

Use a trusted Authenticode signing certificate or signing service. Do not put
private keys/passwords into source files or chat. The script can use a
certificate already provisioned in the Windows certificate store, with Windows
SDK SignTool installed:

```powershell
py -3.12 scripts/build_windows.py --require-signature --certificate-thumbprint YOUR_CERTIFICATE_THUMBPRINT --timestamp-url https://YOUR_PROVIDER_TIMESTAMP_HOST
```

Replace the placeholders. The script signs and verifies the EXE before native
validation, Defender scanning, hashing, and ZIP creation. Signing failures stop
the build. A self-signed certificate does not establish public publisher trust;
signing also cannot guarantee SmartScreen reputation or remove every detection.
The automated workflow does not provision a signing certificate.

## Before publication

The build checks on Windows Server complement tests on Windows 10/11. Test the
exact ZIP on a target Windows computer with current security definitions,
including protected/locked files, exclusions, cancellation during a large file
and during scanning, and closing the window while working. Compare before/after
algorithm states and verify the complete CSV across report pages.

For performance comparisons, use fresh copies of the same dataset, algorithm,
disk, and antivirus settings. Record scan, operation, and total time separately
for many small files and a few large files; process startup counts alone do not
prove a corresponding improvement in MB/s.

If Defender detects the exact release artifact, retain its threat name and
SHA-256, then submit it as a suspected false positive through
[Microsoft's file submission portal](https://www.microsoft.com/en-us/wdsi/filesubmission).
For another security product, use that vendor's submission process. A changed
or newly signed EXE has a different hash and may need a new report. Do not ask
users to disable their antivirus or add an exclusion to run the release.
