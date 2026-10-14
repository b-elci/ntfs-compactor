NTFS Compactor v1.6.0 - Windows x64 Release Candidate

This release contains:
- NTFS-Compactor-v1.6.0.exe (Application)
- _internal/ (required Python runtime and libraries)
- LICENSE
- README.txt (this file)
- BUILD-INFO.json (build provenance and signing status)
- SHA256SUMS.txt (hashes of packaged files)
- Install-context-menu.cmd / Remove-context-menu.cmd (optional Explorer menu)

Support the project:
Visit https://buymeacoffee.com/bariselcii to buy me a coffee. Thank you!

Usage:
Extract the complete folder and run the application on Windows 10/11 x64:

    Double-click NTFS-Compactor-v1.6.0.exe

Keep _internal beside the EXE. Do not copy the EXE alone.
Python installation is not required. NTFS and write access are required for
compression/decompression; protected folders may require administrator rights.

This candidate is unsigned because a signing certificate is not configured.
SmartScreen may report an unknown publisher. A Microsoft Defender result from
the build machine does not guarantee acceptance by other antivirus products.
Do not disable your antivirus or add an exclusion to run this application.
If a threat is reported, keep the exact threat name and file hash for diagnosis.

Optional Explorer integration:
Use Tools > Install Explorer menu in the app, or Install-context-menu.cmd.
The menu is installed only for your Windows account and supports files, folders,
and folder backgrounds. Windows 11 shows it under Show more options.
Use Tools > Remove Explorer menu or Remove-context-menu.cmd to uninstall.
Reinstall the menu after moving the application folder.

Smart filtering is on by default: files at most one volume cluster and known
compressed media/archive formats are skipped during compression. Verified
no-benefit results are cached under your local application data and invalidated
when file metadata or the target algorithm changes. Disable Smart filtering
to explicitly try compressed formats; it does not affect status/decompression.

The ZIP is supplied with its SHA-256 and validation.json. Scan results apply
only to that exact artifact, using the definition version recorded in the report.
