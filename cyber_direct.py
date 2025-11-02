#!/usr/bin/env python3
"""
CyberSentinel - Direct GUI Launcher (No Authentication)
"""
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def main():
    print("🚀 Starting CyberSentinel GUI (Direct Mode)...")
    print("No authentication required - launching scanner interface directly")
    print()

    try:
        # Import PyQt5
        from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget,
                                   QWidget, QVBoxLayout, QLabel, QPushButton,
                                   QTextEdit, QProgressBar, QMessageBox)
        from PyQt5.QtCore import Qt, QTimer

        print("✓ PyQt5 imported successfully")

        # Create application
        app = QApplication(sys.argv)
        app.setApplicationName("CyberSentinel")
        app.setAttribute(Qt.AA_EnableHighDpiScaling, True)

        print("✓ QApplication created")

        # Import application modules
        from app.core.application import CyberSentinelApp
        from app.gui.main_window import CyberSentinelMainWindow

        print("✓ Application modules imported")

        # Initialize core application
        core_app = CyberSentinelApp()
        print("✓ Core application initialized")

        # Create main window (without authentication)
        main_window = CyberSentinelMainWindow(core_app)
        main_window.setWindowTitle("CyberSentinel - Vulnerability Scanner (Direct Mode)")
        main_window.show()
        main_window.raise_()  # Bring to front
        main_window.activateWindow()  # Activate window

        print("✓ Main scanner interface loaded")
        print("🎉 CyberSentinel GUI is running successfully!")
        print("   You can now perform vulnerability scans directly")

        # Start the application
        sys.exit(app.exec_())

    except ImportError as e:
        print(f"❌ Import Error: {e}")
        print("   Please install missing dependencies:")
        print("   pip install PyQt5 python-nmap requests cryptography")

        # Try to show error in GUI
        try:
            from PyQt5.QtWidgets import QApplication, QMessageBox
            if not QApplication.instance():
                app = QApplication(sys.argv)
            QMessageBox.critical(None, "Import Error",
                               f"Missing dependencies:\n\n{str(e)}\n\n"
                               "Please install: pip install PyQt5 python-nmap requests cryptography")
        except:
            pass

    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

        # Try to show error in GUI
        try:
            from PyQt5.QtWidgets import QApplication, QMessageBox
            if not QApplication.instance():
                app = QApplication(sys.argv)
            QMessageBox.critical(None, "CyberSentinel Error", f"Error: {str(e)}")
        except:
            pass

if __name__ == "__main__":
    main()
