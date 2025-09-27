import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel

app = QApplication(sys.argv)
window = QMainWindow()
window.setWindowTitle('CyberSentinel Test')
window.setGeometry(100, 100, 800, 600)

# Add a label
label = QLabel('CyberSentinel is working!', window)
label.setStyleSheet('font-size: 24px; font-weight: bold;')
label.setGeometry(100, 100, 600, 50)

window.show()
sys.exit(app.exec_())
