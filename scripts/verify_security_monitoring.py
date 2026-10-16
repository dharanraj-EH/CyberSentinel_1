"""End-to-end desktop verification using isolated, labelled synthetic log fixtures."""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from PyQt5.QtWidgets import QApplication
from cybersentinel.ui.main_window import MainWindow


def wait(app, worker):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            if not worker.isRunning():
                break
        except RuntimeError:  # The finished worker was released by the panel.
            break
        app.processEvents()
        time.sleep(.01)
    app.processEvents()
    try:
        running = worker.isRunning()
    except RuntimeError:
        running = False
    if running:
        worker.stop()
        worker.wait(5000)
        raise TimeoutError('Monitoring verification worker did not finish')
    assert not worker.error, worker.error


def main():
    output = Path('.artifacts/verification')
    output.mkdir(parents=True, exist_ok=True)
    app = QApplication.instance() or QApplication([])
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        log = root / 'synthetic_windows_events.json'
        records = [{'Id': 4625, 'TimeCreated': f'2026-10-14T12:00:0{index}Z', 'MachineName': 'fixture.example',
                    'EventData': {'TargetUserName': 'fixture_analyst', 'IpAddress': '192.0.2.5'}} for index in range(5)]
        records.append({'Id': 4624, 'TimeCreated': '2026-10-14T12:00:06Z', 'MachineName': 'fixture.example',
                        'EventData': {'TargetUserName': 'fixture_analyst', 'IpAddress': '192.0.2.5'}})
        log.write_text(json.dumps(records), encoding='utf-8')
        window = MainWindow(workspace_root=root)
        window.resize(1600, 1000)
        window.show()
        panel = window.monitoring_tab
        window.tab_widget.setCurrentWidget(panel)
        window.workspace.record('web', 'https://fixture.example/', {'headers': {'vulnerable': True, 'evidence': ['Synthetic missing-CSP fixture']}})
        panel.task('Synthetic verification import', lambda cancelled: {
            'import': panel.service.import_file(log, 'fixture.example', cancelled=cancelled),
            'detections': panel.service.detect(cancelled)})
        wait(app, panel.worker)
        panel.refresh()
        assert panel.service.metrics()['events'] == 6
        assert len(panel.service.alerts()) == 2
        assert len(panel.service.incidents()) == 1
        panel.filter_ip.setText('192.0.2.5')
        panel.new_search()
        assert len(panel.event_rows) == 6
        panel.status.setText('SYNTHETIC VERIFICATION FIXTURE — temporary workspace, not production activity')
        panel.pages.setCurrentIndex(0)
        app.processEvents()
        window.grab().save(str(output / 'monitoring-events.png'))
        panel.pages.setCurrentIndex(2)
        panel.incident_table.selectRow(0)
        app.processEvents()
        assert panel.timeline_table.rowCount() == 6
        assert 'Synthetic missing-CSP fixture' in panel.linked_assessments.toPlainText()
        window.grab().save(str(output / 'monitoring-incidents.png'))
        panel.pages.setCurrentIndex(6)
        app.processEvents()
        window.grab().save(str(output / 'monitoring-overview.png'))
        incident = panel.service.incidents()[0]
        report = panel.service.export_incident_bundle(incident['id'])
        assert (report / 'report.pdf').read_bytes().startswith(b'%PDF')
        panel.service.run_playbook(incident['id'], 'triage')
        assert panel.service.incidents()[0]['state'] == 'Investigating'
        result = {'scope': 'Synthetic fixtures in a temporary workspace only', 'events': 6, 'alerts': 2, 'incidents': 1,
                  'verified': ['background import', 'full-text/event filters', 'login correlation', 'timeline', 'scan links', 'incident PDF/HTML/JSON', 'triage checklist'],
                  'metrics': panel.service.metrics()}
        window.close()
    (output / 'security-monitoring.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
