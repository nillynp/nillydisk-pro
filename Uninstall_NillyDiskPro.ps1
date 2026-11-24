# ============================================================================
# NillyDisk Pro — Clean Uninstaller (Zero Admin)
# created by Nilly graphics (Sotiris Christos) — https://nillygraphics.com/
# ============================================================================
param([switch]$Silent)

$ErrorActionPreference = 'SilentlyContinue'
Write-Host ''
Write-Host '  Αφαίρεση καταχωρίσεων & συντομεύσεων του NillyDisk Pro...' -ForegroundColor Yellow

Stop-Process -Name 'NillyDiskPro' -Force -ErrorAction SilentlyContinue

$desktopLnk = Join-Path ([Environment]::GetFolderPath('Desktop')) 'NillyDisk Pro.lnk'
$startLnk = Join-Path ([Environment]::GetFolderPath('Programs')) 'Nilly graphics\NillyDisk Pro.lnk'
if (Test-Path $desktopLnk) { Remove-Item $desktopLnk -Force }
if (Test-Path $startLnk) { Remove-Item $startLnk -Force }

foreach ($rk in @(
    'HKCU\Software\Classes\Directory\shell\NillyDiskPro',
    'HKCU\Software\Classes\Directory\Background\shell\NillyDiskPro',
    'HKCU\Software\Classes\Drive\shell\NillyDiskPro'
)) {
    & reg.exe delete $rk /f 2>$null | Out-Null
}

Write-Host '  OK -> Αφαιρέθηκαν καθαρά οι συντομεύσεις και το δεξί κλικ του NillyDisk Pro.' -ForegroundColor Green
Write-Host ''
if (-not $Silent) { Read-Host '  Πάτησε Enter για κλείσιμο' }
