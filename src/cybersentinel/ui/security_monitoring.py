"""Native desktop event search, live sources, alerts and incident investigation."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event

from PyQt5.QtCore import Qt, QThread, QTimer
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QLabel, QLineEdit, QPushButton,
    QComboBox, QCheckBox, QSpinBox, QTextEdit, QTabWidget, QTableWidget,
    QTableWidgetItem, QAbstractItemView, QFileDialog, QMessageBox, QSplitter,
    QSystemTrayIcon, QApplication, QStyle, QGroupBox,
)
from ..services.security_monitor import SecurityMonitor
from ..services.model_advisor import LocalIntelligence
from .event_volume_chart import EventVolumeChart


def table(headers):
    widget = QTableWidget(0, len(headers))
    widget.setHorizontalHeaderLabels(headers)
    widget.setSelectionBehavior(QAbstractItemView.SelectRows)
    widget.setSelectionMode(QAbstractItemView.SingleSelection)
    widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
    widget.setAlternatingRowColors(True)
    widget.horizontalHeader().setStretchLastSection(True)
    return widget


def populate(widget, rows):
    widget.setRowCount(len(rows))
    for row, values in enumerate(rows):
        for column, value in enumerate(values):
            widget.setItem(row, column, QTableWidgetItem(str(value if value is not None else '')))
    widget.resizeColumnsToContents()


class MonitoringWorker(QThread):
    def __init__(self, task, parent=None):
        super().__init__(parent)
        self.task, self.cancelled = task, Event()
        self.result, self.error = None, None

    def stop(self):
        self.cancelled.set()

    def run(self):
        try:
            self.result = self.task(self.cancelled)
        except Exception as error:
            self.error = str(error)


class SecurityMonitoringTab(QWidget):
    def __init__(self, workspace, parent=None):
        super().__init__(parent)
        self.service = SecurityMonitor(workspace)
        self.worker, self.worker_title = None, ''
        self.event_page, self.event_rows, self.alert_rows, self.incident_rows = 0, [], [], []
        self.actions = []
        self.case_dirty = False
        self.advisories = {}
        layout = QVBoxLayout(self)
        title = QLabel('SECURITY MONITORING  /  Events · Detections · Investigations')
        title.setStyleSheet('font-size:15pt;font-weight:700;color:#6bdfd0;padding:6px;')
        layout.addWidget(title)
        self.metrics_label = QLabel()
        layout.addWidget(self.metrics_label)
        controls = QVBoxLayout()
        monitoring_options = QHBoxLayout()
        self.live = QCheckBox('Monitor watched files while this app is open')
        self.live.toggled.connect(self.toggle_monitoring)
        monitoring_options.addWidget(self.live)
        self.notify = QCheckBox('Desktop notifications for new alerts')
        monitoring_options.addWidget(self.notify)
        controls.addLayout(monitoring_options)
        monitoring_actions = QHBoxLayout()
        evaluate = self.button('Evaluate detection rules', self.evaluate)
        monitoring_actions.addWidget(evaluate)
        self.cancel = QPushButton('Cancel task')
        self.cancel.setEnabled(False)
        self.cancel.clicked.connect(self.cancel_task)
        monitoring_actions.addWidget(self.cancel)
        monitoring_actions.addStretch()
        controls.addLayout(monitoring_actions)
        layout.addLayout(controls)
        self.pages = QTabWidget()
        layout.addWidget(self.pages, 1)
        self.build_events()
        self.build_alerts()
        self.build_incidents()
        self.build_sources()
        self.build_rules()
        self.build_intelligence()
        self.build_analytics()
        self.status = QLabel('Import authorized logs to begin. Alerts are investigation candidates, not confirmed attacks.')
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.timer = QTimer(self)
        self.timer.setInterval(3000)
        self.timer.timeout.connect(self.poll)
        self.tray = QSystemTrayIcon(QApplication.windowIcon() if not QApplication.windowIcon().isNull() else QApplication.style().standardIcon(QStyle.SP_ComputerIcon), self)
        self.notify.toggled.connect(lambda checked: self.tray.setVisible(checked and QSystemTrayIcon.isSystemTrayAvailable()))
        self.refresh()

    def button(self, text, callback):
        button = QPushButton(text)
        button.clicked.connect(callback)
        self.actions.append(button)
        return button

    def task(self, title, callback):
        if self.worker is not None:
            self.status.setText('Wait for the current task or cancel it first.')
            return
        self.worker_title = title
        self.status.setText(title + '…')
        for action in self.actions:
            action.setEnabled(False)
        self.cancel.setEnabled(True)
        self.worker = MonitoringWorker(callback, self)
        self.worker.finished.connect(self.task_finished)
        self.worker.start()

    def task_finished(self):
        finished_worker = self.worker
        for action in self.actions:
            action.setEnabled(True)
        self.cancel.setEnabled(False)
        if self.worker.error:
            self.status.setText(self.worker_title + ': ' + self.worker.error)
        else:
            result = self.worker.result
            if isinstance(result, dict) and 'import' in result:
                imported = result['import']
                summary = f"{imported['status']}: read {imported['read']}, stored {imported['imported']}, duplicates {imported['duplicates']}, rejected {imported['rejected']}. See Log Sources for import errors."
            elif isinstance(result, dict) and 'advisory' in result:
                summary = 'Completed. Open the Local AI Advisory case tab; scanner evidence is unchanged.'
            else:
                summary = json.dumps(result, ensure_ascii=False)[:350]
            self.status.setText(self.worker_title + ': ' + summary)
            if isinstance(result, dict):
                detections = result.get('detections', result)
                if self.notify.isChecked() and detections.get('new_alerts', 0):
                    self.tray.showMessage('CyberSentinel security alerts', f"{detections['new_alerts']} new investigation candidates. Review Security Monitoring.", QSystemTrayIcon.Warning, 8000)
                if 'advisory' in result:
                    self.advisories[result['incident_id']] = result['advisory']
        self.refresh()
        self.worker = None
        finished_worker.deleteLater()

    def cancel_task(self):
        if self.worker:
            self.worker.stop()
            self.status.setText('Cancellation requested; already committed records are retained.')

    def build_events(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        imports = QHBoxLayout()
        self.import_asset = QLineEdit()
        self.import_asset.setPlaceholderText('Server asset / hostname (required)')
        self.import_asset.setToolTip('Use the server asset, not the remote client IP. Windows Computer fields take precedence.')
        self.import_format = QComboBox()
        for label, value in [('Auto detect', 'auto'), ('Apache/Nginx access', 'access'), ('Windows / structured JSON', 'json'), ('JSON lines', 'jsonl'), ('Windows XML', 'xml'), ('Windows CSV', 'csv'), ('Windows EVTX', 'evtx'), ('RFC 5424 syslog', 'syslog')]:
            self.import_format.addItem(label, value)
        imports.addWidget(self.import_asset)
        imports.addWidget(self.import_format)
        imports.addWidget(self.button('Import log export', self.import_log))
        layout.addLayout(imports)
        help = QLabel('Accepts common/combined access logs, Nginx JSON, and Windows XML/CSV/JSON/EVTX. Timestamps must include an offset. Import errors and duplicates are reported.')
        help.setWordWrap(True)
        layout.addWidget(help)
        filters = QFormLayout()
        self.query = QLineEdit()
        self.query.setPlaceholderText('Plain-text terms (AND); not Splunk SPL')
        self.filter_asset, self.filter_ip, self.filter_user = QLineEdit(), QLineEdit(), QLineEdit()
        self.filter_kind = QComboBox()
        self.filter_kind.addItems(['', 'http_request', 'login_failure', 'login_success', 'windows_event', 'syslog', 'firewall'])
        self.filter_start, self.filter_end = QLineEdit(), QLineEdit()
        for edit in (self.filter_start, self.filter_end):
            edit.setPlaceholderText('Optional ISO timestamp, e.g. 2026-10-14T00:00:00Z')
        filters.addRow('Search', self.query)
        row = QHBoxLayout()
        for label, edit in [('Asset', self.filter_asset), ('Source IP', self.filter_ip), ('User', self.filter_user), ('Kind', self.filter_kind)]:
            row.addWidget(QLabel(label))
            row.addWidget(edit)
        filters.addRow(row)
        row = QHBoxLayout()
        row.addWidget(self.filter_start)
        row.addWidget(self.filter_end)
        filters.addRow('UTC time range', row)
        layout.addLayout(filters)
        actions = QHBoxLayout()
        actions.addWidget(self.button('Search events', self.new_search))
        actions.addWidget(self.button('Previous page', lambda: self.change_page(-1)))
        actions.addWidget(self.button('Next page', lambda: self.change_page(1)))
        actions.addWidget(self.button('Export visible events (JSON)', self.export_events))
        self.event_count = QLabel()
        actions.addWidget(self.event_count)
        layout.addLayout(actions)
        self.events_table = table(['Time (UTC)', 'Asset', 'Source IP', 'User', 'Kind', 'Code/status', 'Request'])
        self.events_table.itemSelectionChanged.connect(self.event_selected)
        self.event_details = QTextEdit()
        self.event_details.setReadOnly(True)
        split = QSplitter(Qt.Vertical)
        split.addWidget(self.events_table)
        split.addWidget(self.event_details)
        split.setSizes([320, 120])
        layout.addWidget(split, 1)
        self.pages.addTab(page, 'Events & Search')

    def import_log(self):
        if not self.import_asset.text().strip():
            QMessageBox.warning(self, 'Asset required', 'Enter the server asset or hostname first.')
            return
        path, _ = QFileDialog.getOpenFileName(self, 'Import authorized log export', '', 'Logs (*.log *.txt *.json *.jsonl *.ndjson *.csv *.xml *.evtx);;All files (*)')
        if not path:
            return
        asset, format = self.import_asset.text().strip(), self.import_format.currentData()
        def run(cancelled):
            imported = self.service.import_file(path, asset, format, cancelled)
            detections = self.service.detect(cancelled) if not cancelled.is_set() else {}
            return {'import': imported, 'detections': detections}
        self.task('Import and detection', run)

    def new_search(self):
        self.event_page = 0
        self.search_events()

    def change_page(self, step):
        self.event_page = max(0, self.event_page + step)
        self.search_events()

    def search_events(self):
        try:
            result = self.service.search(self.query.text(), self.filter_asset.text().strip(), self.filter_ip.text().strip(),
                self.filter_user.text().strip(), self.filter_kind.currentText(), self.filter_start.text().strip(),
                self.filter_end.text().strip(), limit=250, offset=self.event_page * 250)
            self.event_rows = result['events']
            populate(self.events_table, [[item['occurred_at'], item['asset'], item['source_ip'], item['user'], item['event_kind'],
                                         item['event_code'] or item['status'], item['url']] for item in self.event_rows])
            self.event_count.setText(f"{result['total']} matches | Page {self.event_page + 1} | Up to 250 rows")
        except Exception as error:
            self.status.setText('Search failed: ' + str(error))

    def event_selected(self):
        row = self.events_table.currentRow()
        if 0 <= row < len(self.event_rows):
            self.event_details.setPlainText(json.dumps(self.event_rows[row], indent=2, ensure_ascii=False))

    def export_events(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Export visible event page', 'security_events.json', 'JSON (*.json)')
        if path:
            Path(path).write_text(json.dumps({'scope': 'Current visible event page only', 'events': self.event_rows}, indent=2), encoding='utf-8')

    def build_alerts(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(QLabel('Alerts retain their triggering event IDs. Re-evaluation deduplicates overlapping episodes; it does not declare attacks confirmed.'))
        self.alert_table = table(['Rule', 'Severity', 'Asset', 'Source IP', 'First event (UTC)', 'Last event (UTC)', 'Evidence count'])
        self.alert_table.itemSelectionChanged.connect(self.alert_selected)
        layout.addWidget(self.alert_table, 1)
        layout.addWidget(self.button('Open related incident', self.open_alert_incident))
        self.alert_details = QTextEdit()
        self.alert_details.setReadOnly(True)
        layout.addWidget(self.alert_details)
        self.pages.addTab(page, 'Alerts')

    def alert_selected(self):
        row = self.alert_table.currentRow()
        if 0 <= row < len(self.alert_rows):
            item = dict(self.alert_rows[row])
            item['data'] = json.loads(item['data'])
            self.alert_details.setPlainText(json.dumps(item, indent=2))

    def open_alert_incident(self):
        row = self.alert_table.currentRow()
        if not 0 <= row < len(self.alert_rows):
            return
        with self.service.workspace.connect() as db:
            linked = db.execute('SELECT incident_id FROM incident_alerts WHERE alert_id=?', (self.alert_rows[row]['id'],)).fetchone()
        if linked:
            self.pages.setCurrentIndex(2)
            for index, incident in enumerate(self.incident_rows):
                if incident['id'] == linked[0]:
                    self.incident_table.selectRow(index)
                    break

    def build_incidents(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        self.incident_table = table(['Asset', 'Source IP', 'Risk (0–100)', 'Rules', 'State', 'Owner', 'Last event (UTC)'])
        self.incident_table.itemSelectionChanged.connect(self.incident_selected)
        layout.addWidget(self.incident_table, 1)
        workflow = QHBoxLayout()
        self.incident_state = QComboBox()
        self.incident_state.addItems(['New', 'Investigating', 'Contained', 'Resolved', 'False positive'])
        self.incident_owner, self.incident_note = QLineEdit(), QLineEdit()
        self.incident_owner.setPlaceholderText('Analyst / owner')
        self.incident_note.setPlaceholderText('Investigation note / required resolution reason')
        self.incident_owner.textEdited.connect(lambda: setattr(self, 'case_dirty', True))
        self.incident_note.textEdited.connect(lambda: setattr(self, 'case_dirty', True))
        self.incident_state.activated.connect(lambda: setattr(self, 'case_dirty', True))
        workflow.addWidget(self.incident_state)
        workflow.addWidget(self.incident_owner)
        workflow.addWidget(self.incident_note, 1)
        workflow.addWidget(self.button('Save case update', self.save_incident))
        layout.addLayout(workflow)
        actions = QHBoxLayout()
        actions.addWidget(self.button('Triage checklist', lambda: self.playbook('triage')))
        actions.addWidget(self.button('Export evidence', self.export_incident))
        actions.addWidget(self.button('Local AI advice', self.explain_incident))
        actions.addWidget(self.button('Generate PDF/HTML report', self.incident_report))
        layout.addLayout(actions)
        self.case_pages = QTabWidget()
        self.timeline_table = table(['Time (UTC)', 'Source IP', 'User', 'Kind', 'Code/status', 'Request'])
        self.case_pages.addTab(self.timeline_table, 'Event Timeline')
        self.incident_evidence = QTextEdit()
        self.incident_evidence.setReadOnly(True)
        self.case_pages.addTab(self.incident_evidence, 'Evidence & Advisory')
        self.linked_assessments = QTextEdit()
        self.linked_assessments.setReadOnly(True)
        self.case_pages.addTab(self.linked_assessments, 'Linked Scan Findings')
        self.case_audit = QTextEdit()
        self.case_audit.setReadOnly(True)
        self.case_pages.addTab(self.case_audit, 'Case Audit')
        self.incident_ai = QTextEdit()
        self.incident_ai.setReadOnly(True)
        self.case_pages.addTab(self.incident_ai, 'Local AI Advisory')
        layout.addWidget(self.case_pages, 2)
        self.pages.addTab(page, 'Incidents')

    def current_incident(self):
        row = self.incident_table.currentRow()
        return self.incident_rows[row] if 0 <= row < len(self.incident_rows) else None

    def incident_selected(self):
        item = self.current_incident()
        if not item:
            return
        self.case_dirty = False
        detail = self.service.incident_detail(item['id'])
        self.incident_state.setCurrentText(item['state'])
        self.incident_owner.setText(item['owner'])
        self.incident_note.setText(item['note'])
        populate(self.timeline_table, [[event['occurred_at'], event['source_ip'], event['user'], event['event_kind'],
                                       event['event_code'] or event['status'], event['url']] for event in detail['timeline']])
        self.incident_evidence.setPlainText(json.dumps({'incident': item, 'alerts': detail['alerts'], 'note': detail['note']}, indent=2))
        self.linked_assessments.setPlainText(json.dumps(detail['linked_assessments'], indent=2) if detail['linked_assessments'] else 'No matching assessment asset. Use Asset Aliases for known hostname/IP equivalences, then refresh.')
        self.case_audit.setPlainText(json.dumps(detail['audit'], indent=2))
        self.incident_ai.setPlainText('AI ADVISORY — verify against evidence.\n\n' + self.advisories[item['id']] if item['id'] in self.advisories else 'No AI advice requested for this incident. Evidence and detection results remain independent of AI.')

    def save_incident(self):
        item = self.current_incident()
        if item:
            try:
                self.service.update_incident(item['id'], self.incident_state.currentText(), self.incident_owner.text(), self.incident_note.text())
                self.case_dirty = False
                self.refresh()
            except ValueError as error:
                self.status.setText(str(error))

    def playbook(self, name):
        item = self.current_incident()
        if item:
            self.status.setText(self.service.run_playbook(item['id'], name))
            self.case_dirty = False
            self.refresh()

    def export_incident(self):
        item = self.current_incident()
        if item:
            path, _ = QFileDialog.getSaveFileName(self, 'Export incident with timeline and linked scans', 'incident_' + item['id'][:8] + '.json', 'JSON (*.json)')
            if path:
                self.service.export_incident(item['id'], path)
                self.status.setText('Incident evidence exported.')

    def explain_incident(self):
        item = self.current_incident()
        model_tab = getattr(self.window(), 'intelligence_tab', None)
        model = model_tab.models.currentText() if model_tab else ''
        if not item or not model:
            self.status.setText('Select an incident and discover/select a model in Local Security Intelligence first.')
            return
        detail = self.service.incident_detail(item['id'])
        self.case_pages.setCurrentIndex(4)
        self.task('Local incident advisory', lambda cancelled: {'incident_id': item['id'], 'advisory': LocalIntelligence().explain(model, detail)})

    def incident_report(self):
        item = self.current_incident()
        if item:
            try:
                directory = self.service.export_incident_bundle(item['id'])
                self.status.setText('Incident JSON/HTML/PDF report saved: ' + str(directory))
                if hasattr(self.window(), 'reports_tab'):
                    self.window().reports_tab._load_reports()
            except Exception as error:
                self.status.setText('Incident report failed: ' + str(error))

    def build_sources(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        label = QLabel('Watch authorized local access-log or JSONL files. Polling runs only while this desktop app is open and monitoring is enabled. Checkpoints survive restarts; partial lines are deferred and rotation/truncation resets the source.')
        label.setWordWrap(True)
        layout.addWidget(label)
        form = QFormLayout()
        self.source_path, self.source_asset = QLineEdit(), QLineEdit()
        browse = QHBoxLayout()
        browse.addWidget(self.source_path)
        browse.addWidget(self.button('Browse', self.browse_source))
        form.addRow('Log file', browse)
        form.addRow('Server asset', self.source_asset)
        self.source_format = QComboBox()
        self.source_format.addItem('Apache/Nginx access', 'access')
        self.source_format.addItem('Structured JSON lines', 'jsonl')
        self.source_format.addItem('RFC 5424 syslog', 'syslog')
        form.addRow('Format', self.source_format)
        self.source_from_start = QCheckBox('Read existing content too (otherwise start at current end)')
        form.addRow(self.source_from_start)
        layout.addLayout(form)
        actions = QHBoxLayout()
        actions.addWidget(self.button('Register watched file', self.add_source))
        actions.addWidget(self.button('Enable/disable selected source', self.toggle_source))
        actions.addWidget(self.button('Poll sources now', self.poll))
        layout.addLayout(actions)
        self.source_table = table(['Enabled', 'Path', 'Asset', 'Checkpoint (bytes)', 'Last poll (UTC)', 'Error'])
        layout.addWidget(self.source_table, 1)
        self.import_history = QTextEdit()
        self.import_history.setReadOnly(True)
        layout.addWidget(self.import_history)
        self.pages.addTab(page, 'Log Sources')

    def browse_source(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Choose authorized live log file')
        if path:
            self.source_path.setText(path)

    def add_source(self):
        try:
            self.service.add_source(self.source_path.text(), self.source_asset.text(), self.source_format.currentData(), self.source_from_start.isChecked())
            self.refresh()
            self.status.setText('Source registered. Enable monitoring to collect new records.')
        except Exception as error:
            self.status.setText(str(error))

    def toggle_source(self):
        rows = self.service.sources()
        index = self.source_table.currentRow()
        if 0 <= index < len(rows):
            self.service.enable_source(rows[index]['id'], not rows[index]['enabled'])
            self.refresh()

    def toggle_monitoring(self, enabled):
        if enabled:
            self.timer.start()
            self.poll()
        else:
            self.timer.stop()

    def stop_monitoring(self):
        self.live.setChecked(False)
        self.timer.stop()
        self.tray.hide()
        if self.worker and self.worker.isRunning():
            self.worker.stop()

    def poll(self):
        if self.worker is not None:
            return
        def run(cancelled):
            result = self.service.poll_sources(cancelled)
            detections = self.service.detect(cancelled) if result['imported'] and not cancelled.is_set() else {}
            return {'poll': result, 'detections': detections}
        self.task('Source polling', run)

    def evaluate(self):
        self.task('Rule evaluation', lambda cancelled: self.service.detect(cancelled))

    def build_rules(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        self.rule_table = table(['Rule', 'Enabled', 'Threshold', 'Window (seconds)', 'Severity', 'Risk weight'])
        layout.addWidget(self.rule_table)
        self.rule_choice = QComboBox()
        for rule in self.service.rules():
            self.rule_choice.addItem(rule['name'], rule['id'])
        self.rule_choice.currentIndexChanged.connect(self.select_rule)
        self.rule_enabled = QCheckBox('Enabled')
        self.rule_threshold, self.rule_window = QSpinBox(), QSpinBox()
        self.rule_threshold.setRange(1, 100000)
        self.rule_window.setRange(1, 86400)
        form = QFormLayout()
        form.addRow('Detection', self.rule_choice)
        form.addRow(self.rule_enabled)
        form.addRow('Event threshold', self.rule_threshold)
        form.addRow('Time window (seconds)', self.rule_window)
        layout.addLayout(form)
        layout.addWidget(self.button('Save rule settings', self.save_rule))
        note = QLabel('Changes apply to the next evaluation. Existing evidence and alerts are retained for audit. Request-rate alerts use a fixed threshold, not a learned baseline. Risk scores are local rule weights, not attack probabilities.')
        note.setWordWrap(True)
        layout.addWidget(note)
        layout.addStretch()
        self.pages.addTab(page, 'Detection Rules')
        self.select_rule()

    def select_rule(self):
        rule = next((item for item in self.service.rules() if item['id'] == self.rule_choice.currentData()), None)
        if rule:
            self.rule_enabled.setChecked(rule['enabled'])
            self.rule_threshold.setValue(rule['threshold'])
            self.rule_window.setValue(rule['window'])

    def save_rule(self):
        self.service.configure_rule(self.rule_choice.currentData(), self.rule_enabled.isChecked(), self.rule_threshold.value(), self.rule_window.value())
        self.status.setText('Rule saved. Evaluate rules to apply it; historical alerts remain.')
        self.refresh()

    def build_intelligence(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        label = QLabel('Local indicator list: exact IP and domain matches only. No reputation feed is downloaded automatically. Domain matching uses observed asset/absolute request host, not URL paths or guessed DNS mappings.')
        label.setWordWrap(True)
        layout.addWidget(label)
        row = QHBoxLayout()
        self.indicator_type = QComboBox()
        self.indicator_type.addItems(['ip', 'domain'])
        self.indicator_value, self.indicator_label = QLineEdit(), QLineEdit()
        self.indicator_value.setPlaceholderText('Indicator value')
        self.indicator_label.setPlaceholderText('Source / label')
        for widget in (self.indicator_type, self.indicator_value, self.indicator_label):
            row.addWidget(widget)
        row.addWidget(self.button('Add indicator', self.add_indicator))
        row.addWidget(self.button('Remove selected', self.remove_indicator))
        layout.addLayout(row)
        layout.addWidget(self.button('Import local indicator list (JSON/CSV)', self.import_indicators))
        self.indicator_table = table(['Type', 'Value', 'Label'])
        layout.addWidget(self.indicator_table, 1)
        layout.addWidget(QLabel('ASSET ALIASES — explicit equivalence for scan/incident correlation'))
        row = QHBoxLayout()
        self.alias, self.alias_canonical = QLineEdit(), QLineEdit()
        self.alias.setPlaceholderText('Alias hostname or IP')
        self.alias_canonical.setPlaceholderText('Canonical asset used by events')
        row.addWidget(self.alias)
        row.addWidget(self.alias_canonical)
        row.addWidget(self.button('Save asset alias', self.save_alias))
        layout.addLayout(row)
        layout.addWidget(QLabel('Aliases apply to new imports and linked scan lookups. Existing event assets are not rewritten.'))
        self.pages.addTab(page, 'Threat Indicators & Assets')

    def add_indicator(self):
        try:
            self.service.add_indicator(self.indicator_type.currentText(), self.indicator_value.text(), self.indicator_label.text())
            self.refresh()
        except ValueError as error:
            self.status.setText(str(error))

    def remove_indicator(self):
        index = self.indicator_table.currentRow()
        rows = self.service.indicators()
        if 0 <= index < len(rows):
            self.service.remove_indicator(rows[index]['type'], rows[index]['value'])
            self.refresh()

    def import_indicators(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Import authorized threat indicator list', '', 'Indicator lists (*.json *.csv)')
        if path:
            self.task('Indicator import', lambda cancelled: self.service.import_indicators(path, cancelled))

    def save_alias(self):
        try:
            self.service.set_alias(self.alias.text(), self.alias_canonical.text())
            self.status.setText('Asset alias saved; existing events retain their original asset.')
        except ValueError as error:
            self.status.setText(str(error))

    def build_analytics(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(self.button('Refresh monitoring overview', self.refresh))
        self.volume_chart = EventVolumeChart()
        layout.addWidget(self.volume_chart)
        self.asset_counts = table(['Asset', 'Stored events'])
        self.kind_counts = table(['Event kind', 'Stored events'])
        distributions = QSplitter(Qt.Horizontal)
        distributions.addWidget(self.asset_counts)
        distributions.addWidget(self.kind_counts)
        layout.addWidget(distributions, 1)
        self.analytics = QTextEdit()
        self.analytics.setReadOnly(True)
        layout.addWidget(self.analytics, 1)
        self.pages.addTab(page, 'Monitoring Overview')

    def refresh(self):
        selected = self.current_incident()['id'] if hasattr(self, 'incident_table') and self.current_incident() else None
        draft = (self.incident_owner.text(), self.incident_state.currentText(), self.incident_note.text()) if selected and self.case_dirty else None
        metrics = self.service.metrics()
        self.metrics_label.setText('  |  '.join(f'{key.replace("_", " ").title()}: {value}' for key, value in metrics.items()))
        self.search_events()
        self.alert_rows = self.service.alerts()
        populate(self.alert_table, [[json.loads(item['data'])['title'], item['severity'], item['asset'], item['source_ip'], item['first_at'], item['last_at'], item['evidence_count']] for item in self.alert_rows])
        self.incident_rows = self.service.incidents()
        self.incident_table.blockSignals(True)
        populate(self.incident_table, [[item['asset'], item['source_ip'], item['risk_score'], item['rule_count'], item['state'], item['owner'], item['last_at']] for item in self.incident_rows])
        self.incident_table.blockSignals(False)
        if selected:
            for index, item in enumerate(self.incident_rows):
                if item['id'] == selected:
                    self.incident_table.selectRow(index)
                    self.incident_selected()
                    if draft:
                        self.incident_owner.setText(draft[0])
                        self.incident_state.setCurrentText(draft[1])
                        self.incident_note.setText(draft[2])
                        self.case_dirty = True
                    break
        sources = self.service.sources()
        populate(self.source_table, [[bool(item['enabled']), item['path'], item['asset'], item['offset'], item['last_poll'], item['error']] for item in sources])
        populate(self.rule_table, [[item['name'], item['enabled'], item['threshold'], item['window'], item['severity'], item['score']] for item in self.service.rules()])
        populate(self.indicator_table, [[item['type'], item['value'], item['label']] for item in self.service.indicators()])
        with self.service.workspace.connect() as db:
            imports = [dict(row) for row in db.execute('SELECT time,path,asset,data FROM log_imports ORDER BY time DESC LIMIT 10')]
            assets = [dict(row) for row in db.execute('SELECT asset,COUNT(*) events FROM security_events GROUP BY asset ORDER BY events DESC LIMIT 20')]
            kinds = [dict(row) for row in db.execute('SELECT event_kind,COUNT(*) events FROM security_events GROUP BY event_kind ORDER BY events DESC')]
            hourly = [dict(row) for row in db.execute('SELECT SUBSTR(occurred_at,1,13) hour,COUNT(*) events FROM security_events GROUP BY hour ORDER BY hour DESC LIMIT 24')]
        populate(self.asset_counts, [[item['asset'], item['events']] for item in assets])
        populate(self.kind_counts, [[item['event_kind'], item['events']] for item in kinds])
        if hourly:
            latest = datetime.fromisoformat(hourly[0]['hour'] + ':00:00+00:00')
            counts = {item['hour']: item['events'] for item in hourly}
            self.volume_chart.set_points([(hour.strftime('%Y-%m-%dT%H'), counts.get(hour.strftime('%Y-%m-%dT%H'), 0))
                                          for hour in [latest - timedelta(hours=offset) for offset in range(23, -1, -1)]])
        else:
            self.volume_chart.set_points([])
        self.import_history.setPlainText(json.dumps(imports, indent=2))
        self.analytics.setPlainText(json.dumps({'totals': metrics, 'top_assets': assets, 'event_kinds': kinds, 'recent_hourly_counts_utc': hourly,
            'storage': str(self.service.workspace.db_path), 'search_index': 'SQLite FTS5' if self.service.full_text else 'SQLite text search',
            'coverage': 'Local files and exports only. No remote collector, distributed cluster or always-on service.'}, indent=2))
