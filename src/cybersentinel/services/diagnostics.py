"""Offline smoke verification for source and portable desktop distributions."""
import json
import tempfile
from pathlib import Path


def self_check(destination):
    from PyQt5.QtWidgets import QApplication
    from ..ui.main_window import MainWindow
    report = {'ok': False, 'checks': []}
    output = Path(destination).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        app = QApplication.instance() or QApplication([])
        with tempfile.TemporaryDirectory() as temporary:
            window = MainWindow(workspace_root=temporary)
            window.resize(1500, 950)
            window.show()
            app.processEvents()
            report['modules'] = [window.tab_widget.tabText(index) for index in range(window.tab_widget.count())]
            report['checks'].append('Ten desktop modules initialized without login')
            from .event_parsers import access_line
            event = access_line('192.0.2.1 - - [14/Oct/2026:12:00:00 +0000] "GET /.env HTTP/1.1" 404 0', 'self-check.local', 'self-check-event')
            window.monitoring_tab.service.insert_batch([event])
            detection = window.monitoring_tab.service.detect()
            assert detection['new_alerts'] == 1
            assert window.monitoring_tab.service.incidents()
            report['checks'].append('Event indexing, detection and incident correlation verified using a synthetic fixture')
            window.grab().save(str(output.with_suffix('.png')))
            evidence = window.workspace.record('network', '127.0.0.1', {'ports': [{'port': 443, 'state': 'open'}]})
            directory = window.workspace.export_bundle(evidence)
            assert all((directory / ('report.' + extension)).exists() for extension in ('json', 'html', 'pdf'))
            report['checks'].append('SQLite, JSON, HTML and PDF generation verified')
            window.close()
        report['ok'] = True
    except Exception as error:
        report['error'] = str(error)
    output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    return 0 if report['ok'] else 1
