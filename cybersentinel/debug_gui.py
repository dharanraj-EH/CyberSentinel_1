import sys
import logging
from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtCore import Qt

print("Starting CyberSentinel...")
app = QApplication(sys.argv)
print("QApplication created")

try:
    from cybersentinel.gui.main_window import MainWindow
    print("Imported MainWindow")
    
    # Create and show main window
    mainWin = MainWindow()
    print("Created MainWindow instance")
    
    mainWin.show()
    print("Main window shown")
    
    # Show a test message box to verify GUI is working
    QMessageBox.information(None, "Test", "GUI is working!", QMessageBox.Ok)
    
    sys.exit(app.exec_())
except Exception as e:
    print(f"Error: {str(e)}")
    QMessageBox.critical(None, "Error", f"Failed to start CyberSentinel:\n{str(e)}")
