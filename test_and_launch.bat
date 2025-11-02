@echo off
echo ============================================
echo     CYBERSENTINEL GUI TEST LAUNCHER
echo ============================================
echo.
echo This will:
echo 1. Test if GUI works (show test window)
echo 2. Launch main CyberSentinel application
echo.
echo Press any key to continue...
pause >nul

echo.
echo 🚀 Starting GUI test...
python test_gui_launch.py

echo.
echo ============================================
echo If you saw a test window, CyberSentinel should now be running!
echo Check your desktop and taskbar for the application window.
echo ============================================
pause
