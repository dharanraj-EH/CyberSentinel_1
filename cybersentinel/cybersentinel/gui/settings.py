from PyQt5.QtWidgets import QDialog, QLabel, QVBoxLayout

class SettingsDialog(QDialog):
    """Minimal placeholder so the app can start. Replace with real implementation later."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Settings - Coming soon"))
