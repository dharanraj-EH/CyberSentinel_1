@echo off
title CyberSentinel - Vulnerability Scanner
color 0A
echo.
echo ========================================
echo   CyberSentinel - Starting (Direct Mode)
echo ========================================
echo.

REM Change to the script directory
cd /d "%~dp0"

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.8 or later from python.org
    echo.
    pause
    exit /b 1
)

echo [OK] Python found
echo.

REM Run the CyberSentinel GUI (Direct Mode - No Authentication)
echo Starting CyberSentinel GUI directly...
echo.
python cyber_direct.py

if errorlevel 1 (
    echo.
    echo [ERROR] Failed to start CyberSentinel
    echo Check the error messages above
    echo.
    pause
)

exit
