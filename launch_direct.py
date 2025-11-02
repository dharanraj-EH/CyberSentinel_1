#!/usr/bin/env python3
"""
CyberSentinel Direct Launcher - No complications
"""
import sys
import os
from pathlib import Path

# Add cybersentinel to path
sys.path.insert(0, str(Path(__file__).parent / "cybersentinel"))

def main():
    """Launch CyberSentinel directly"""
    print("🚀 Launching CyberSentinel...")

    try:
        # Import everything we need
        from PyQt5.QtWidgets import QApplication
        from cybersentinel.gui.main_window import MainWindow

        # Create application
        app = QApplication(sys.argv)
        app.setApplicationName("CyberSentinel")
        app.setApplicationVersion("0.1.0")
        app.setOrganizationName("CyberSentinel")

        # Create and show main window
        main_window = MainWindow(auth_manager=None)
        main_window.show()

        print("✅ CyberSentinel started successfully!")
        print("🔍 Look for the 'CyberSentinel v0.1.0' window on your desktop")
        print("📋 Available tabs: Dashboard, Network Scanner, SSL/TLS Analyzer, Web Tests, Reports")

        # Start event loop
        app.exec_()

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
