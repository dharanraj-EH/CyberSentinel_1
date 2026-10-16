"""Persisted local desktop preferences."""
from PyQt5.QtCore import QSettings
from PyQt5.QtWidgets import QDialog, QFormLayout, QSpinBox, QDialogButtonBox, QLabel
class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Assessment Preferences')
        self.settings = QSettings('CyberSentinel', 'Desktop')
        layout = QFormLayout(self)
        self.timeout = QSpinBox()
        self.timeout.setRange(1, 30)
        self.timeout.setValue(int(self.settings.value('request_timeout', 10)))
        self.timeout.setSuffix(' seconds')
        layout.addRow('HTTP request timeout', self.timeout)
        layout.addRow(QLabel('History is stored in the local workspace. Local AI uses Ollama.'))
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)
    def accept(self):
        self.settings.setValue('request_timeout', self.timeout.value())
        super().accept()
