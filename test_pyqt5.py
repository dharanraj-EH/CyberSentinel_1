#!/usr/bin/env python3
"""
Simple test script to check if PyQt5 imports work correctly.
"""
import sys
import os
sys.path.insert(0, '.')

try:
    from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QVBoxLayout, QFrame, QScrollArea, QSizePolicy
    from PyQt5.QtCore import Qt, QSize
    from PyQt5.QtGui import QPixmap, QIcon, QFont
    print("✓ All PyQt5 imports successful")

    # Test basic widget creation
    app = QApplication([])
    widget = QWidget()
    layout = QVBoxLayout(widget)

    label = QLabel("Test Label")
    layout.addWidget(label)

    print("✓ Basic widget creation successful")
    print("✓ PyQt5 is working correctly")

except ImportError as e:
    print(f"✗ Import error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"✗ Error: {e}")
    sys.exit(1)
