#!/usr/bin/env python3
"""
CyberSentinel Auto-Launcher - Automatically runs the application
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
        time.sleep(2)

def start_application():
    """Start the CyberSentinel application."""
    print("🚀 Starting CyberSentinel...")

    try:
        # Launch the application
        process = subprocess.Popen(
            [sys.executable, 'run_cybersentinel.py'],
            cwd=os.getcwd(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        print(f"✅ CyberSentinel launched (PID: {process.pid})")

        # Wait for application to start
        time.sleep(3)

        # Check if process is still running
        if process.poll() is None:
            print("✅ Application is running successfully!")

            # Try to bring window to front on Windows
            if os.name == 'nt':
                try:
                    import win32gui
                    import win32con

                    def callback(hwnd, extra):
                        title = win32gui.GetWindowText(hwnd)
                        if 'cybersentinel' in title.lower():
                            print(f"🎯 Found CyberSentinel window: {title}")
                            win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
                            win32gui.SetForegroundWindow(hwnd)
                            return False
                        return True

                    win32gui.EnumWindows(callback, None)
                    print("✅ Window brought to front")
                except ImportError:
                    print("ℹ️  Window activation requires manual Alt+Tab")

            return True
        else:
            stdout, stderr = process.communicate()
            print("❌ Application exited immediately")
            if stderr:
                print("Error:", stderr[:200])
            return False

    except Exception as e:
        print(f"❌ Failed to start: {e}")
        return False

def main():
    """Main launcher function."""
    print("🎯 CYBERSENTINEL AUTO-LAUNCHER")
    print("=" * 40)

    # Kill existing processes
    kill_existing_processes()

    # Start application
    if start_application():
        print("\n🎉 SUCCESS! CyberSentinel is now running!")
        print("\n📋 Check for:")
        print("   • Taskbar icon")
        print("   • Desktop window")
        print("   • Use Alt+Tab to switch")
        return True
    else:
        print("❌ Failed to start CyberSentinel")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
