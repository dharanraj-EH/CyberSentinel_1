#!/usr/bin/env python3
"""
CyberSentinel Auto-Launcher - Automatically runs the application with proper GUI handling
"""
import sys
import os
import time
import subprocess
import psutil
from pathlib import Path

def kill_existing_processes():
    """Kill any existing CyberSentinel processes."""
    print("🔄 Checking for existing CyberSentinel processes...")
    killed_count = 0

    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.info['name'] and 'python' in proc.info['name'].lower():
                cmdline = ' '.join(proc.info['cmdline'] or [])
                if 'cybersentinel' in cmdline.lower() or 'run_cybersentinel' in cmdline:
                    print(f"🛑 Killing existing process PID {proc.info['pid']}")
                    proc.kill()
                    killed_count += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if killed_count > 0:
        print(f"✅ Killed {killed_count} existing process(es)")
        time.sleep(2)  # Wait for processes to fully terminate

def check_dependencies():
    """Check if all required dependencies are installed."""
    print("📦 Checking dependencies...")

    required_modules = ['PyQt5', 'requests', 'cryptography', 'beautifulsoup4']
    missing_modules = []

    for module in required_modules:
        try:
            __import__(module)
            print(f"✅ {module} - OK")
        except ImportError:
            missing_modules.append(module)
            print(f"❌ {module} - MISSING")

    if missing_modules:
        print(f"\n⚠️  Missing modules: {', '.join(missing_modules)}")
        print("Installing missing dependencies...")
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install'] + missing_modules)
            print("✅ Dependencies installed successfully")
        except subprocess.CalledProcessError:
            print("❌ Failed to install dependencies")
            return False

    return True

def start_application():
    """Start the CyberSentinel application."""
    print("🚀 Starting CyberSentinel...")

    # Set environment variables to help with GUI visibility
    env = os.environ.copy()
    env['QT_QPA_PLATFORM_PLUGIN_PATH'] = ''
    env['QT_AUTO_SCREEN_SCALE_FACTOR'] = '1'

    try:
        # Launch the application
        process = subprocess.Popen(
            [sys.executable, 'run_cybersentinel.py'],
            cwd=os.getcwd(),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        print(f"✅ CyberSentinel launched (PID: {process.pid})")

        # Wait a moment for the application to start
        time.sleep(3)

        # Check if process is still running
        if process.poll() is None:
            print("✅ Application appears to be running successfully")

            # Try to bring window to front (Windows-specific)
            if os.name == 'nt':
                try:
                    import win32gui
                    import win32con

                    def callback(hwnd, extra):
                        title = win32gui.GetWindowText(hwnd)
                        if 'cybersentinel' in title.lower():
                            print(f"🎯 Found window: {title}")
                            win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
                            win32gui.SetForegroundWindow(hwnd)
                            return False
                        return True

                    win32gui.EnumWindows(callback, None)
                    print("✅ Attempted to bring CyberSentinel window to front")
                except ImportError:
                    print("⚠️  win32gui not available - window may need manual activation")

            return True
        else:
            stdout, stderr = process.communicate()
            print("❌ Application exited immediately")
            if stdout:
                print("STDOUT:", stdout)
            if stderr:
                print("STDERR:", stderr)
            return False

    except Exception as e:
        print(f"❌ Failed to start application: {e}")
        return False

def main():
    """Main launcher function."""
    print("🎯 CYBERSENTINEL AUTO-LAUNCHER")
    print("=" * 40)

    # Kill existing processes
    kill_existing_processes()

    # Check dependencies
    if not check_dependencies():
        print("❌ Dependency check failed - cannot continue")
        return False

    # Start application
    if start_application():
        print("\n🎉 CyberSentinel should now be running!")
        print("\n📋 Next steps:")
        print("   • Check your taskbar for the CyberSentinel icon")
        print("   • Use Alt+Tab to switch between windows")
        print("   • Look for a window titled 'CyberSentinel v0.1.0'")
        print("   • If not visible, check Windows Task Manager for python.exe")
        return True
    else:
        print("❌ Failed to start CyberSentinel")
        return False

if __name__ == "__main__":
    success = main()
    input("\nPress Enter to exit...")
    sys.exit(0 if success else 1)
