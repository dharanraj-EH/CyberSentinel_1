@echo off
echo ========================================
echo    CYBERSENTINEL AUTO-LAUNCHER
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8 or later from https://python.org
    pause
    exit /b 1
)

REM Check if virtual environment exists
if exist "venv\Scripts\activate.bat" (
    echo 🔄 Activating virtual environment...
    call venv\Scripts\activate.bat
) else (
    echo ⚠️  Virtual environment not found, using system Python
)

REM Install psutil if not available (needed for process management)
python -c "import psutil" >nul 2>&1
if errorlevel 1 (
    echo 📦 Installing required dependency (psutil)...
    pip install psutil --quiet
)

echo 🚀 Starting CyberSentinel automatically...
echo.

REM Run the auto-launcher
python auto_launch.py

echo.
echo ========================================
pause
