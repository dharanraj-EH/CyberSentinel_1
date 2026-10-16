$ErrorActionPreference = 'Stop'
$desktopRoot = Split-Path $PSScriptRoot -Parent
Set-Location -LiteralPath $desktopRoot
& (Join-Path $desktopRoot '.venv\Scripts\python.exe') (Join-Path $desktopRoot 'run_desktop.py')
