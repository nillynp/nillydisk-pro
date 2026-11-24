# ============================================================================
# NillyDisk Pro — Universal Windows 10/11 Installer (Zero Admin · Portable)
# created by Nilly graphics (Nillygraphics · Sotiris Christos) — https://nillygraphics.com/
# Ultra-Light Native Disk Analyzer, Interactive Treemap, SHA-256 Duplicate Finder & Safe Cleaner
# ============================================================================
param([switch]$Silent)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$exePath = Join-Path $root 'NillyDiskPro.exe'
$icoPath = Join-Path $root 'NillyDiskPro.ico'
$srcPath = Join-Path $root 'desktop\NillyDiskPro.cs'

Write-Host ''
Write-Host '  ============================================================' -ForegroundColor Cyan
Write-Host '   NillyDisk Pro — Disk Analyzer, Treemap & SHA-256 Cleaner' -ForegroundColor White
Write-Host '   created by Nilly graphics (Sotiris Christos)' -ForegroundColor DarkGray
Write-Host '   https://nillygraphics.com/' -ForegroundColor DarkGray
Write-Host '  ============================================================' -ForegroundColor Cyan
Write-Host ''

# 1. Unblock files if extracted from GitHub Portable ZIP
Get-ChildItem -Path $root -Recurse -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue

# 2. Auto-compile NillyDiskPro.exe if missing or older than source
$needBuild = (-not (Test-Path $exePath)) -or ((Test-Path $srcPath) -and ((Get-Item $srcPath).LastWriteTimeUtc -gt (Get-Item $exePath).LastWriteTimeUtc))
if ($needBuild) {
    $fxDir = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319'
    if (-not (Test-Path "$fxDir\csc.exe")) { $fxDir = 'C:\Windows\Microsoft.NET\Framework\v4.0.30319' }
    $csc = Join-Path $fxDir 'csc.exe'
    if (-not (Test-Path $csc)) { throw 'Δεν βρέθηκε ο .NET Framework 4.x C# compiler (csc.exe).' }
    Write-Host '  [1/3] Μεταγλώττιση NillyDiskPro.exe (100% Native Win32 Disk Engine)...' -ForegroundColor Yellow
    $cscArgs = @(
        '/nologo', '/target:winexe', '/optimize+', '/utf8output', '/platform:anycpu', "/out:$exePath",
        '/r:System.dll', '/r:System.Core.dll', '/r:System.Drawing.dll', '/r:System.Windows.Forms.dll'
    )
    if (Test-Path $icoPath) { $cscArgs += "/win32icon:$icoPath" }
    $cscArgs += $srcPath
    & $csc @cscArgs
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $exePath)) {
        throw "Αποτυχία μεταγλώττισης NillyDiskPro.exe (exit $LASTEXITCODE)"
    }
    Write-Host ("        OK -> " + [math]::Round((Get-Item $exePath).Length / 1KB, 1) + " KB") -ForegroundColor Green
} else {
    Write-Host '  [1/3] NillyDiskPro.exe έτοιμο.' -ForegroundColor Green
}

# 3. Safe Explorer Right-Click Menu on Folders & Drives (Zero Admin · HKCU via reg.exe)
Write-Host '  [2/3] Προσθήκη δεξί κλικ Explorer («Ανάλυση Χώρου με NillyDisk Pro»)...' -ForegroundColor Yellow
foreach ($rk in @(
    'HKCU\Software\Classes\Directory\shell\NillyDiskPro',
    'HKCU\Software\Classes\Directory\Background\shell\NillyDiskPro',
    'HKCU\Software\Classes\Drive\shell\NillyDiskPro'
)) {
    $arg = if ($rk -match 'Background') { '"%V"' } else { '"%1"' }
    & reg.exe add $rk /ve /t REG_SZ /d "Ανάλυση Χώρου με NillyDisk Pro" /f | Out-Null
    & reg.exe add $rk /v "Icon" /t REG_SZ /d "$exePath,0" /f | Out-Null
    & reg.exe add "$rk\command" /ve /t REG_SZ /d "`"$exePath`" $arg" /f | Out-Null
}
Write-Host '        OK -> Δεξί κλικ σε δίσκους & φακέλους έτοιμο!' -ForegroundColor Green

# 4. Desktop & Start Menu Shortcuts
Write-Host '  [3/3] Δημιουργία συντομεύσεων (Επιφάνεια Εργασίας & Start Menu)...' -ForegroundColor Yellow
$wsh = New-Object -ComObject WScript.Shell
$desktopDir = [Environment]::GetFolderPath('Desktop')
$startMenuDir = Join-Path ([Environment]::GetFolderPath('Programs')) 'Nilly graphics'
New-Item -ItemType Directory -Force -Path $startMenuDir | Out-Null

foreach ($lnkPath in @(
    (Join-Path $desktopDir 'NillyDisk Pro.lnk'),
    (Join-Path $startMenuDir 'NillyDisk Pro.lnk')
)) {
    $sc = $wsh.CreateShortcut($lnkPath)
    $sc.TargetPath = $exePath
    $sc.WorkingDirectory = $root
    $sc.Description = 'NillyDisk Pro — Native Disk Space Analyzer, Treemap, SHA-256 Duplicate Finder & Safe Cache Cleaner | created by Nilly graphics (Sotiris Christos)'
    $sc.IconLocation = "$exePath,0"
    $sc.Save()
}
Write-Host '        OK -> Έτοιμες οι συντομεύσεις!' -ForegroundColor Green
Write-Host ''
Write-Host '  ΟΛΟΚΛΗΡΩΘΗΚΕ! Άνοιξε το NillyDisk Pro από την Επιφάνεια Εργασίας, το Start Menu ή με δεξί κλικ σε οποιονδήποτε φάκελο/δίσκο.' -ForegroundColor Cyan
Write-Host ''

if (-not $Silent) {
    Start-Process -FilePath $exePath
}
