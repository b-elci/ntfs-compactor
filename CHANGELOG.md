# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Optional per-user Explorer actions for files, folders, and folder backgrounds, including removal and single-file targeting (#1).
- Default smart filtering based on the actual volume cluster size, compressed-format heuristics, and a change-aware no-benefit cache (#4).
- v1.6.0 Windows x64 folder-release candidate with version metadata, hash-pinned build tools, Windows native smoke checks, and mandatory Defender scanning.
- GitHub Actions packaging and an unpublished draft release after validation succeeds.
- Decompression with confirmation and per-file Windows API verification.
- Extension and folder exclusion patterns, NTFS volume and write-access checks.
- Disk-backed, paginated status reports with full CSV export.
- Verified outcome counts, separate scan/measurement errors, elapsed time, throughput, and approximate ETA.
- Regression tests for failed processes, silent-process cancellation, filters, report pagination, and real Tk workflows with mocked Windows operations.

### Changed
- Default to XPRESS8K and skip already compressed files.
- Combine initial file enumeration, measurement, and compression analysis into one scan using a disk-backed operation plan.
- Adapt compression batches from 32 up to 128 files; reduce failed batches and retry only unverified files.
- Bound worker queues and limit UI work per tick; keep folder and filter settings fixed while operating.
- Use the system compact.exe path, extended Windows paths, and OEM-code-page subprocess decoding.
- Require Python 3.12+ for source development, including junction-aware scanning.
- Disable UPX in the current release spec and document Windows release/signing procedures.

### Fixed
- Handle paths beyond compact.exe's limit via a cancellable Windows API helper; verify both compression and decompression natively.
- Classify ERROR_COMPRESSION_NOT_BENEFICIAL as skipped and preserve original compression when a new algorithm yields no benefit.
- Prevent queued report clearing from deleting newly scanned rows.
- Do not count failed commands as successful compression or hide native error messages in quiet mode.
- Allow cancellation while compact.exe emits no output, and wait for workers before unlocking the UI or closing.
- Avoid uninterruptible final scans after cancellation and invalidate stale reports after operations.
- Reset the last Windows error before querying compressed file sizes.

## [1.2.0] - 2026-06-06

### Added
- Exact XPRESS4K, XPRESS8K, XPRESS16K, and LZX detection through the Windows `WofIsExternalFile` API.
- Automated tests for compression decision logic and forced recompression.
- Version number in the application window title.

### Changed
- Replaced locale-dependent `compact.exe` output parsing with direct Windows API queries.
- Skips files that already use the selected algorithm before starting batch compression.
- Recompression now uses `compact /F`, changing algorithms correctly in a single operation.
- UI progress and status updates are routed through the main thread for improved responsiveness and stability.
- Updated release documentation and download instructions.

### Fixed
- Fixed XPRESS8K and XPRESS16K being treated as an ambiguous shared algorithm.
- Fixed "Recompress if different" potentially failing to change the compression algorithm.
- Fixed unnecessary processing of files already compressed with the selected algorithm.

## [1.1.0] - 2025-12-11

### Added
- **Verbose Logging Option**: Added a checkbox to toggle verbose logging. Default is off for cleaner output.
- **Smart Progress Bar**: New ASCII-based progress bar in the log window when verbose mode is disabled.
- **Error Summary**: Real-time error counting (Long Path / Other) displayed in the status line.
- **OOM Prevention**: Implemented proactive skipping of paths longer than 255 characters to prevent "Out of Memory" errors.
- **Memory Management**: Dynamic batch sizing based on available RAM to prevent UI freezing on large datasets.

### Changed
- **UI Performance**: Significantly optimized log rendering with batching and truncation to handle millions of lines without lag.
- **Default Settings**: "Defer measurement" is now enabled by default for faster startup.
- **Log Format**: Improved log readability by showing parent folders.
- **Process Handling**: Optimized `compact.exe` calls using relative paths (`cwd`) to support deeper directory structures.

## [1.0.1] - 2025-11-01

### Fixed
- Fixed console window flashing issue when processing files
- Added CREATE_NO_WINDOW flag to subprocess calls to prevent console windows from appearing
- Improved performance by eliminating window creation overhead

### Changed
- Optimized subprocess execution for better performance and smoother user experience

## [1.0.0] - 2025-11-01

### Added
- Initial release of NTFS Advanced Compression Tool
- Modern Tkinter-based GUI interface
- Support for multiple compression algorithms:
  - XPRESS4K (Fast, low compression)
  - XPRESS8K (Medium, balanced)
  - XPRESS16K (Slow, higher compression)
  - LZX (Ultra, highest ratio)
- Compression behavior options:
  - Skip already compressed files
  - Recompress files if algorithm differs
- Status scanning functionality to view current compression state
- Real-time progress tracking with progress bar
- Live log output during operations
- Accurate size reporting using Windows API
- Support for stopping operations mid-process
- Defer measurement option for faster startup
- Before/after disk space comparison
- Comprehensive file-by-file reporting
- Windows-only (NTFS required)

### Technical Details
- Uses Windows `compact.exe` for compression operations
- Leverages `GetCompressedFileSizeW` API for accurate disk space reporting
- Multi-threaded architecture for responsive UI
- Standard library only - no external dependencies required
- Python 3.6+ compatible

### Documentation
- Comprehensive README with usage instructions
- MIT License
- Example screenshots and usage guide
- Troubleshooting section
- Best practices guide

[1.2.0]: https://github.com/b-elci/ntfs-compactor/releases/tag/v1.2.0
[1.1.0]: https://github.com/b-elci/ntfs-compactor/releases/tag/v1.1.0
[1.0.1]: https://github.com/b-elci/ntfs-compactor/releases/tag/v1.0.1
[1.0.0]: https://github.com/b-elci/ntfs-compactor/releases/tag/v1.0.0
