from PyQt5.QtWidgets import QWidget, QLabel, QVBoxLayout

class ReportsTab(QWidget):
    """Minimal placeholder so the app can start. Replace with real implementation later."""
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Reports - Coming soon"))
