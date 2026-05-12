# CMT-IPAS Windows Online Installer (install.ps1)
# Usage: powershell -c "irm https://cmt-sys.com/install.ps1 | iex"

$url = "https://cmt-sys.com/CMT-IPAS-Release.zip"
$installPath = "$HOME\CMT-IPAS"
$zipFile = "$env:TEMP\cmt-ipas.zip"

Write-Host "--- CMT-IPAS Online Installer ---" -ForegroundColor Cyan

# 1. Download
Write-Host "Downloading CMT-IPAS from cmt-sys.com..."
Invoke-WebRequest -Uri $url -OutFile $zipFile

# 2. Extract
if (Test-Path $installPath) { Remove-Item -Recurse -Force $installPath }
New-Item -ItemType Directory -Path $installPath | Out-Null
Write-Host "Extracting to $installPath..."
Expand-Archive -Path $zipFile -DestinationPath $installPath -Force

# 3. Setup Startup Shortcut
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\CMT-IPAS.lnk")
$Shortcut.TargetPath = "$installPath\cmt-ipas.exe"
$Shortcut.WorkingDirectory = $installPath
$Shortcut.Save()

# 4. Clean up
Remove-Item $zipFile

Write-Host "Successfully installed to $installPath" -ForegroundColor Green
Write-Host "Shortcut added to Startup folder." -ForegroundColor Yellow
Write-Host "Starting application..." -ForegroundColor Cyan
Start-Process "$installPath\cmt-ipas.exe" -WorkingDirectory $installPath
