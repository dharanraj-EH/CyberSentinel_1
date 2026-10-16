"""Editable assessment inventory and explicit exclusions."""
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit, QPushButton, QMessageBox


class AssetScopeTab(QWidget):
    def __init__(self, policy, parent=None):
        super().__init__(parent)
        self.policy = policy
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel('ASSET INVENTORY & SCOPE'))
        label = QLabel('Add assets you are authorized to assess, one per line: hostname, IP, small CIDR, or HTTP(S) origin.\nExclusions take precedence. Redirects stay within the original web origin. Network ranges are limited to 256 addresses.')
        label.setWordWrap(True)
        layout.addWidget(label)
        layout.addWidget(QLabel('Approved assets'))
        self.approved = QTextEdit()
        layout.addWidget(self.approved)
        layout.addWidget(QLabel('Excluded assets'))
        self.excluded = QTextEdit()
        layout.addWidget(self.excluded)
        save = QPushButton('Save assessment scope')
        save.clicked.connect(self.save)
        layout.addWidget(save)
        existing = policy.read()
        self.approved.setPlainText('\n'.join(existing['approved']))
        self.excluded.setPlainText('\n'.join(existing['excluded']))

    def save(self):
        try:
            approved = [line.strip() for line in self.approved.toPlainText().splitlines() if line.strip()]
            excluded = [line.strip() for line in self.excluded.toPlainText().splitlines() if line.strip()]
            self.policy.save(approved, excluded)
            QMessageBox.information(self, 'Assessment scope', 'Assessment scope saved.')
        except ValueError as error:
            QMessageBox.warning(self, 'Invalid scope', str(error))
