# PowerShell script to run CyberSentinel
Write-Host "Starting CyberSentinel..." -ForegroundColor Green
Write-Host ""

# Check if Python is available
try {
    $pythonVersion = python --version 2>&1
    Write-Host "Found Python: $pythonVersion" -ForegroundColor Yellow
} catch {
    Write-Host "Error: Python is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install Python 3.8 or later" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Check if virtual environment exists and activate it
if (Test-Path "venv\Scripts\Activate.ps1") {
    Write-Host "Activating virtual environment..." -ForegroundColor Yellow
    & "venv\Scripts\Activate.ps1"
} else {
    Write-Host "Warning: Virtual environment not found, using system Python" -ForegroundColor Yellow
}

# Install requirements if needed
if (Test-Path "requirements.txt") {
    Write-Host "Checking dependencies..." -ForegroundColor Yellow
    pip install -r requirements.txt --quiet
}

# Run the application
Write-Host "Launching CyberSentinel GUI..." -ForegroundColor Green
Write-Host ""

try {
    python run_cybersentinel.py
} catch {
    Write-Host ""
    Write-Host "Error: Failed to start CyberSentinel" -ForegroundColor Red
    Write-Host "Check the logs in $env:USERPROFILE\.cybersentinel\logs\" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
}
