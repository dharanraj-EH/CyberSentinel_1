"""Desktop assessment history, remediation and local model advisory panels."""
import json
from pathlib import Path
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QTextEdit, QLineEdit, QTableWidget, QTableWidgetItem, QFileDialog, QMessageBox,
    QAbstractItemView)
from ..services.model_advisor import LocalIntelligence


class IntelligenceWorker(QThread):
    completed = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, model=None, assessment=None, parent=None):
        super().__init__(parent)
        self.model, self.assessment = model, assessment

    def run(self):
        try:
            service = LocalIntelligence()
            self.completed.emit(service.explain(self.model, self.assessment) if self.model else service.models())
        except Exception as error:
            self.failed.emit(str(error))


class AssessmentWorkspaceTab(QWidget):
    def __init__(self, workspace, parent=None):
        super().__init__(parent)
        self.workspace = workspace
        self.items = []
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel('ASSESSMENT WORKSPACE  /  History · Evidence · Remediation'))
        actions = QHBoxLayout()
        for title, callback in [('Refresh history', self.refresh), ('Compare previous', self.compare), ('Export assessment', self.export)]:
            button = QPushButton(title)
            button.clicked.connect(callback)
            actions.addWidget(button)
        layout.addLayout(actions)
        maintenance = QHBoxLayout()
        for title, callback in [('Combined target report', self.combined), ('Back up workspace', self.backup), ('Restore backup', self.restore)]:
            button = QPushButton(title)
            button.clicked.connect(callback)
            maintenance.addWidget(button)
        layout.addLayout(maintenance)
        self.history_table = QTableWidget(0, 4)
        self.history_table.setHorizontalHeaderLabels(['Time (UTC)', 'Module', 'Target', 'Status'])
        self.history_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.history_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.history_table.itemSelectionChanged.connect(self.select_assessment)
        layout.addWidget(self.history_table)
        self.findings = QComboBox()
        self.findings.currentIndexChanged.connect(self.select_finding)
        layout.addWidget(self.findings)
        edit = QHBoxLayout()
        self.owner = QLineEdit()
        self.owner.setPlaceholderText('Remediation owner')
        self.state = QComboBox()
        self.state.addItems(['Open', 'In progress', 'Fixed pending verification', 'False positive', 'Accepted risk'])
        edit.addWidget(self.owner)
        edit.addWidget(self.state)
        layout.addLayout(edit)
        self.note = QLineEdit()
        self.note.setPlaceholderText('Remediation notes / reason for false positive or accepted risk')
        layout.addWidget(self.note)
        save = QPushButton('Save remediation update')
        save.clicked.connect(self.save_workflow)
        layout.addWidget(save)
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        layout.addWidget(self.details)
        self.refresh()

    def refresh(self):
        self.items = self.workspace.history()
        self.history_table.setRowCount(len(self.items))
        for row, assessment in enumerate(self.items):
            for col, key in enumerate(('timestamp', 'module', 'target', 'status')):
                self.history_table.setItem(row, col, QTableWidgetItem(assessment[key]))
        self.history_table.resizeColumnsToContents()

    def current(self):
        row = self.history_table.currentRow()
        return self.items[row] if 0 <= row < len(self.items) else None

    def select_assessment(self):
        assessment = self.current()
        self.findings.clear()
        if assessment:
            for finding in assessment['findings']:
                self.findings.addItem(f"{finding['severity'].upper()} · {finding['title']}", finding)
            self.details.setPlainText(json.dumps(assessment, indent=2))

    def select_finding(self):
        finding = self.findings.currentData()
        if finding:
            record = self.workspace.workflow(finding['fingerprint'])
            self.owner.setText(record['owner'])
            self.state.setCurrentText(record['state'])
            self.note.setText(record['note'])

    def save_workflow(self):
        finding = self.findings.currentData()
        if finding:
            try:
                self.workspace.update(finding['fingerprint'], self.owner.text(), self.state.currentText(), self.note.text())
                self.details.setPlainText('Remediation update saved.\n' + json.dumps(finding, indent=2))
            except ValueError as error:
                QMessageBox.warning(self, 'Remediation', str(error))

    def compare(self):
        current = self.current()
        if not current:
            return
        previous = next((item for item in self.items if item['timestamp'] < current['timestamp'] and item['module'] == current['module'] and item['target'] == current['target']), None)
        self.details.setPlainText(json.dumps(self.workspace.compare(current, previous), indent=2) if previous else 'No earlier assessment for this target and module.')

    def export(self):
        current = self.current()
        if not current:
            return
        path, _ = QFileDialog.getSaveFileName(self, 'Export assessment', 'assessment.json', 'JSON (*.json)')
        if path:
            current = dict(current)
            current['remediation'] = {item['fingerprint']: self.workspace.workflow(item['fingerprint']) for item in current['findings']}
            Path(path).write_text(json.dumps(current, indent=2), encoding='utf-8')

    def combined(self):
        current = self.current()
        if current:
            try:
                directory = self.workspace.export_bundle(self.workspace.consolidated(current['target']))
                self.details.setPlainText('Combined JSON, HTML and PDF report generated:\n' + str(directory))
            except Exception as error:
                QMessageBox.warning(self, 'Combined report', str(error))

    def backup(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Back up workspace', 'cybersentinel-backup.zip', 'ZIP (*.zip)')
        if path:
            try:
                self.workspace.backup(path)
                self.details.setPlainText('Workspace backup created: ' + path)
            except Exception as error:
                QMessageBox.warning(self, 'Backup failed', str(error))

    def restore(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Restore workspace backup', '', 'ZIP (*.zip)')
        if path and QMessageBox.question(self, 'Restore workspace', 'Replace the local assessment history with the selected backup? Existing exported report files will be preserved.', QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes:
            try:
                monitoring = getattr(self.window(), 'monitoring_tab', None)
                if monitoring and monitoring.worker and monitoring.worker.isRunning():
                    raise ValueError('Cancel the active monitoring task and wait before restoring a backup.')
                if monitoring:
                    monitoring.stop_monitoring()
                self.workspace.restore(path)
                if monitoring:
                    monitoring.service.initialize()
                    monitoring.refresh()
                self.refresh()
                self.details.setPlainText('Workspace restored.')
            except Exception as error:
                QMessageBox.warning(self, 'Restore failed', str(error))


class LocalIntelligenceTab(QWidget):
    def __init__(self, workspace, parent=None):
        super().__init__(parent)
        self.workspace, self.worker = workspace, None
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel('LOCAL SECURITY INTELLIGENCE  /  AgentShield model integration'))
        description = QLabel('Select a saved assessment and an installed Ollama model. AI advice is separate from scanner evidence.\nThe selected redacted assessment is sent only to Ollama on this computer.')
        description.setWordWrap(True)
        layout.addWidget(description)
        self.models = QComboBox()
        layout.addWidget(self.models)
        self.assessments = QComboBox()
        layout.addWidget(self.assessments)
        self.refresh_button = QPushButton('Discover installed models and refresh assessments')
        self.refresh_button.clicked.connect(self.refresh)
        layout.addWidget(self.refresh_button)
        self.explain_button = QPushButton('Explain evidence and remediation')
        self.explain_button.clicked.connect(self.explain)
        layout.addWidget(self.explain_button)
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setPlainText('Start the local Ollama service used by AgentShield, then discover models. No model downloads are required.')
        layout.addWidget(self.output)

    def launch(self, model=None, assessment=None):
        if self.worker and self.worker.isRunning():
            return
        self.refresh_button.setEnabled(False)
        self.explain_button.setEnabled(False)
        self.worker = IntelligenceWorker(model, assessment, self)
        self.worker.completed.connect(self.completed)
        self.worker.failed.connect(lambda error: self.output.setPlainText('Local model unavailable: ' + error))
        self.worker.finished.connect(lambda: self.refresh_button.setEnabled(True))
        self.worker.finished.connect(lambda: self.explain_button.setEnabled(True))
        self.worker.start()

    def refresh(self):
        self.assessments.clear()
        for item in self.workspace.history():
            self.assessments.addItem(f"{item['module']} · {item['target']} · {item['timestamp']}", item)
        self.output.setPlainText('Discovering local models…')
        self.launch()

    def completed(self, result):
        if isinstance(result, list):
            self.models.clear()
            self.models.addItems(result)
            self.output.setPlainText(f'{len(result)} local models found. Select an assessment to continue.' if result else 'No models installed in Ollama.')
        else:
            self.output.setPlainText('AI ADVISORY — verify against the supplied evidence.\n\n' + result)

    def explain(self):
        if self.models.currentText() and self.assessments.currentData():
            self.output.setPlainText('Generating local advisory…')
            self.launch(self.models.currentText(), self.assessments.currentData())
        else:
            self.output.setPlainText('Discover an installed model and save an assessment first.')
