"""Live desktop overview backed by the local desktop workspace."""
import shutil
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QGroupBox, QTableWidget, QTableWidgetItem, QAbstractItemView
from PyQt5.QtGui import QFont
class DashboardTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 26, 26, 26)
        layout.setSpacing(20)
        eyebrow = QLabel('SECURITY OPERATIONS / OVERVIEW')
        eyebrow.setStyleSheet('color:#6bd8ca; font-weight:600;')
        layout.addWidget(eyebrow)
        title = QLabel('Understand your exposure.\nTrack what changes.')
        title.setStyleSheet('font-size:26pt;font-weight:700;')
        layout.addWidget(title)
        description = QLabel('Network, certificate and web configuration assessments in one local desktop workspace.')
        description.setWordWrap(True)
        layout.addWidget(description)
        cards = QHBoxLayout()
        self.summary = []
        for name in ['Saved assessments', 'Open workflow items', 'Assessment engines']:
            card = QGroupBox(name)
            body = QVBoxLayout(card)
            number = QLabel('—')
            number.setStyleSheet('font-size:24pt;color:#76dfd0;font-weight:700;')
            body.addWidget(number)
            self.summary.append(number)
            cards.addWidget(card)
        layout.addLayout(cards)
        actions = QHBoxLayout()
        for label, attr in [('Assess network','scanner_tab'), ('Inspect TLS','ssl_tab'), ('Review web configuration','web_tests_tab'), ('Manage scope','scope_tab')]:
            button = QPushButton(label)
            button.clicked.connect(lambda checked=False, attr=attr: self.window().tab_widget.setCurrentWidget(getattr(self.window(), attr)))
            actions.addWidget(button)
        layout.addLayout(actions)
        monitoring_row = QHBoxLayout()
        self.monitoring_summary = QLabel('Security Monitoring: no events imported')
        self.monitoring_summary.setWordWrap(True)
        monitoring_row.addWidget(self.monitoring_summary, 1)
        monitor_button = QPushButton('Investigate security events')
        monitor_button.clicked.connect(lambda: self.window().tab_widget.setCurrentWidget(self.window().monitoring_tab))
        monitoring_row.addWidget(monitor_button)
        layout.addLayout(monitoring_row)
        heading = QHBoxLayout()
        heading.addWidget(QLabel('RECENT ASSESSMENTS'))
        refresh = QPushButton('Refresh overview')
        refresh.clicked.connect(self.reload_recent_scans)
        heading.addWidget(refresh)
        layout.addLayout(heading)
        self.recent = QTableWidget(0, 4)
        self.recent.setHorizontalHeaderLabels(['Time (UTC)', 'Module', 'Target', 'Status'])
        self.recent.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.recent.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.recent.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.recent, 1)
        self.health = QLabel('Only assess approved assets. Findings include confidence and evidence; errors remain visible.')
        self.health.setWordWrap(True)
        layout.addWidget(self.health)
    def showEvent(self, event):
        super().showEvent(event)
        self.reload_recent_scans()
    def reload_recent_scans(self):
        workspace = getattr(self.window(), 'workspace', None)
        if workspace is None:
            return
        items = workspace.history()
        monitoring = getattr(self.window(), 'monitoring_tab', None)
        if monitoring:
            metrics = monitoring.service.metrics()
            self.monitoring_summary.setText(f"Security Monitoring: {metrics['events']} events | {metrics['alerts']} alerts | {metrics['open_incidents']} open incidents")
        self.summary[0].setText(str(len(items)))
        with workspace.connect() as db:
            count = db.execute("SELECT COUNT(*) FROM findings WHERE state IN ('Open','In progress','Fixed pending verification')").fetchone()[0]
        self.summary[1].setText(str(count))
        self.summary[2].setText('4' if shutil.which('nmap') else '3')
        self.health.setText('TCP Connect · TLS · Web configuration ready. ' + ('Nmap available.' if shutil.which('nmap') else 'Nmap optional engine not installed; use TCP Connect.'))
        self.recent.setRowCount(min(10, len(items)))
        for row, item in enumerate(items[:10]):
            for col, key in enumerate(('timestamp','module','target','status')):
                self.recent.setItem(row,col,QTableWidgetItem(item[key]))
        self.recent.resizeColumnsToContents()
