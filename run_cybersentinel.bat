@echo off
echo Starting CyberSentinel...
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.8 or later
    pause
    exit /b 1
)

REM Check if virtual environment exists
if exist "venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call venv\Scripts\activate.bat
) else (
    echo Warning: Virtual environment not found, using system Python
)

REM Install requirements if needed
if exist "requirements.txt" (
    echo Checking dependencies...
    pip install -r requirements.txt --quiet
)

REM Run the application
echo Launching CyberSentinel GUI...
python cybersentinel_gui.py

if errorlevel 1 (
    echo.
    echo Error: Failed to start CyberSentinel
    echo Check the logs in %USERPROFILE%\.cybersentinel\logs\
    pause
)
