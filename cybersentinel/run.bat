@echo off

:: Create virtual environment if it doesn't exist
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
    if %ERRORLEVEL% NEQ 0 (
        echo Failed to create virtual environment. Please ensure Python 3.8+ is installed and in PATH.
        pause
        exit /b %ERRORLEVEL%
    )
)

:: Activate the virtual environment
call venv\Scripts\activate.bat
if %ERRORLEVEL% NEQ 0 (
    echo Failed to activate virtual environment.
    pause
    exit /b %ERRORLEVEL%
)

:: Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip
if %ERRORLEVEL% NEQ 0 (
    echo Failed to upgrade pip.
    pause
    exit /b %ERRORLEVEL%
)

:: Install requirements
echo Installing requirements...
pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
    echo Failed to install requirements.
    pause
    exit /b %ERRORLEVEL%
)

:: Check for nmap
echo Checking for nmap...
where nmap >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo WARNING: nmap is not installed or not in PATH.
    echo Nmap is required for port scanning functionality.
    echo Please install nmap from https://nmap.org/download.html
    echo.
    echo You can still use the socket-based scanner, but it has limited functionality.
    echo.
    pause
)

:: Run the application
echo.
echo Starting CyberSentinel...
python -m cybersentinel.gui_main

:: Keep the window open if there was an error
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo The application exited with an error (code %ERRORLEVEL%).
    pause
)
