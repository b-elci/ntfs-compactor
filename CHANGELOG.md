# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
