$ErrorActionPreference = 'Stop'
$desktopRoot = Split-Path $PSScriptRoot -Parent
Set-Location -LiteralPath $desktopRoot
$desktopPython = Join-Path $desktopRoot '.venv\Scripts\python.exe'
& $desktopPython -m PyInstaller --noconfirm --windowed --onedir --name CyberSentinel --paths src --collect-data cybersentinel --workpath .artifacts/build --specpath .artifacts run_desktop.py
if ($LASTEXITCODE -ne 0) { throw 'Desktop build failed.' }
Write-Output 'Portable application: dist\CyberSentinel\CyberSentinel.exe. Copy the entire folder.'
