$ErrorActionPreference = 'Stop'
$scanRoot = $env:NTFS_SCAN_ROOT
$reportPath = $env:NTFS_SCAN_REPORT
if (-not $scanRoot -or -not $reportPath -or -not (Test-Path -LiteralPath $scanRoot)) {
    throw 'A scan target and validation report path are required.'
}
Import-Module Defender -ErrorAction Stop
$status = Get-MpComputerStatus
if (-not $status.AMServiceEnabled -or -not $status.AntivirusEnabled) {
    throw 'Microsoft Defender is unavailable or inactive; this artifact has not been verified.'
}
$scanner = Get-ChildItem -Path "$env:ProgramData\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
if (-not $scanner) {
    $scanner = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'
}
if (-not (Test-Path -LiteralPath $scanner)) { throw 'MpCmdRun.exe was not found.' }
& $scanner -SignatureUpdate
if ($LASTEXITCODE -ne 0) { throw "Defender definition update failed: $LASTEXITCODE" }
$baseline = @(Get-MpThreatDetection | ForEach-Object { [string]$_.DetectionID })
$started = [DateTime]::UtcNow
& $scanner -Scan -ScanType 3 -File $scanRoot
$scanExit = $LASTEXITCODE
$newDetections = @(Get-MpThreatDetection | Where-Object { [string]$_.DetectionID -notin $baseline })
$status = Get-MpComputerStatus
$report = [ordered]@{
    status = $(if ($scanExit -eq 0 -and $newDetections.Count -eq 0) { 'passed' } else { 'failed' })
    scanner = 'Microsoft Defender'
    scanned_at_utc = $started.ToString('o')
    signature_version = $status.AntivirusSignatureVersion
    engine_version = $status.AMEngineVersion
    exit_code = $scanExit
    new_detection_count = $newDetections.Count
}
$report | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $reportPath -Encoding UTF8
if ($report.status -ne 'passed') {
    throw 'Defender reported a detection or scan failure; the release package is blocked.'
}
