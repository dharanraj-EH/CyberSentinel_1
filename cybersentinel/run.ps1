# PowerShell script to run CyberSentinel

# Stop on first error
$ErrorActionPreference = "Stop"

# Create virtual environment if it doesn't exist
if (-not (Test-Path "venv")) {
    Write-Host "Creating virtual environment..."
    python -m venv venv
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to create virtual environment. Please ensure Python 3.8+ is installed and in PATH."
        exit $LASTEXITCODE
    }
}

# Activate the virtual environment
$activateScript = ".\venv\Scripts\Activate.ps1"
if (-not (Test-Path $activateScript)) {
    $activateScript = ".\venv\bin\Activate.ps1"
}
if (-not (Test-Path $activateScript)) {
    Write-Error "Failed to find virtual environment activation script."
    exit 1
}

# Temporarily allow script execution
$originalPolicy = Get-ExecutionPolicy -Scope Process
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Activate the environment
. $activateScript

# Restore original execution policy
Set-ExecutionPolicy -ExecutionPolicy $originalPolicy -Scope Process

# Upgrade pip
Write-Host "Upgrading pip..."
python -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to upgrade pip."
    exit $LASTEXITCODE
}

# Install requirements
Write-Host "Installing requirements..."
pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to install requirements."
    exit $LASTEXITCODE
}

# Check for nmap
Write-Host "Checking for nmap..."
$nmapInstalled = $false
try {
    $null = Get-Command nmap -ErrorAction Stop
    $nmapInstalled = $true
} catch {
    # nmap not found
}

if (-not $nmapInstalled) {
    Write-Warning "nmap is not installed or not in PATH."
    Write-Warning "Nmap is required for port scanning functionality."
    Write-Warning "Please install nmap from https://nmap.org/download.html"
    Write-Warning "`nYou can still use the socket-based scanner, but it has limited functionality.`n"
    
    $confirmation = Read-Host "Do you want to continue without nmap? (Y/N)"
    if ($confirmation -ne 'Y' -and $confirmation -ne 'y') {
        exit 1
    }
}

# Run the application
Write-Host "`nStarting CyberSentinel...`n"
python -m cybersentinel.gui_main

# Keep the window open if there was an error
if ($LASTEXITCODE -ne 0) {
    Write-Host "`nThe application exited with an error (code $LASTEXITCODE)."
    Pause
}
