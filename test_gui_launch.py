#!/usr/bin/env python3
"""
CyberSentinel GUI Test Launcher
"""
import sys
import os
from pathlib import Path

# Add cybersentinel to path
sys.path.insert(0, str(Path(__file__).parent / "cybersentinel"))

def test_basic_gui():
    """Test if basic PyQt5 GUI works"""
    print("🖥️  Testing PyQt5 GUI capabilities...")

    try:
        from PyQt5.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget, QPushButton
        from PyQt5.QtCore import Qt
        import sys

        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)

        # Create test window
        window = QWidget()
        window.setWindowTitle("CyberSentinel - GUI Test")
        window.setGeometry(200, 200, 500, 300)

        layout = QVBoxLayout()

        title = QLabel("🎯 CYBERSENTINEL GUI TEST")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #2c3e50; margin: 20px;")
        layout.addWidget(title)

        status = QLabel("✅ PyQt5 GUI is working correctly!")
        status.setAlignment(Qt.AlignCenter)
        status.setStyleSheet("font-size: 14px; color: #27ae60; margin: 10px;")
        layout.addWidget(status)

        info = QLabel("If you can see this window, CyberSentinel GUI will work.\nClose this window to launch the main application.")
        info.setAlignment(Qt.AlignCenter)
        info.setWordWrap(True)
        info.setStyleSheet("font-size: 12px; color: #7f8c8d; margin: 20px;")
        layout.addWidget(info)

        close_btn = QPushButton("Launch CyberSentinel")
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 14px;
                font-weight: bold;
                padding: 10px 20px;
                margin: 20px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
        """)
        close_btn.clicked.connect(window.close)
        layout.addWidget(close_btn)

        window.setLayout(layout)
        window.show()

        print("✅ Test window created - look for 'CyberSentinel - GUI Test' window")
        app.exec_()

        return True

    except Exception as e:
        return False

def launch_cybersentinel():
    """Launch the main CyberSentinel application"""
    print("🚀 Launching CyberSentinel...")

    try:
        # Import QApplication here
        from PyQt5.QtWidgets import QApplication

        # Import and launch main application
        from cybersentinel.gui.main_window import MainWindow

        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)
            app.setApplicationName("CyberSentinel")
            app.setApplicationVersion("0.1.0")

        # Create main window
        main_window = MainWindow(auth_manager=None)
        main_window.show()

        print("✅ CyberSentinel main window created and shown")
        print("🔍 Look for 'CyberSentinel v0.1.0' window")

        app.exec_()

    except Exception as e:
        print(f"❌ Failed to launch CyberSentinel: {e}")
        import traceback
        traceback.print_exc()
    print("🎯 CYBERSENTINEL LAUNCHER")
    print("=" * 30)

    # First test basic GUI
    if test_basic_gui():
        print("\n✅ GUI test passed, launching main application...")
        launch_cybersentinel()
    else:
        print("\n❌ GUI test failed - cannot launch CyberSentinel")
        input("Press Enter to exit...")
