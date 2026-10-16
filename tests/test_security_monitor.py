"""Detection, investigation, search and incremental collection behavior."""
import json
from datetime import datetime, timedelta, timezone
from threading import Event
import pytest
from cybersentinel.services.assessment_store import AssessmentWorkspace
from cybersentinel.services.security_monitor import SecurityMonitor
from cybersentinel.services.event_parsers import event


@pytest.fixture
def monitor(tmp_path):
    return SecurityMonitor(AssessmentWorkspace('fixture', tmp_path))


def make_event(index, seconds=0, **overrides):
    raw = {'occurred_at': (datetime(2026, 10, 14, tzinfo=timezone.utc) + timedelta(seconds=seconds)).isoformat(),
           'asset': 'server.example', 'source_ip': '192.0.2.5', 'user': 'alice', 'event_kind': 'login_failure', 'event_code': '4625'}
    raw.update(overrides)
    return event(raw, 'server.example', 'windows_export', str(index))


def test_failed_login_threshold_and_idempotent_re_evaluation(monitor):
    monitor.insert_batch([make_event(index, index) for index in range(4)])
    assert monitor.detect()['new_alerts'] == 0
    monitor.insert_batch([make_event(4, 4)])
    assert monitor.detect()['new_alerts'] == 1
    assert monitor.detect()['new_alerts'] == 0
    assert len(monitor.alerts()) == 1
    incident = monitor.incidents()[0]
    assert len(monitor.incident_detail(incident['id'])['timeline']) == 5


def test_failures_outside_window_or_on_other_asset_do_not_combine(monitor):
    monitor.insert_batch([make_event(index, index * 301) for index in range(5)])
    monitor.insert_batch([make_event(100 + index, index, asset=f'server{index}.example') for index in range(5)])
    assert monitor.detect()['new_alerts'] == 0


def test_success_after_failures_correlates_actual_windows_events(monitor):
    monitor.insert_batch([make_event(index, index) for index in range(5)] + [make_event(10, 6, event_kind='login_success', event_code='4624')])
    assert monitor.detect()['new_alerts'] == 2
    assert len(monitor.incidents()) == 1
    detail = monitor.incident_detail(monitor.incidents()[0]['id'])
    assert len(detail['timeline']) == 6
    assert detail['incident']['risk_score'] == 100
    assert detail['timeline'][-1]['event_kind'] == 'login_success'


def test_request_rate_and_encoded_url_patterns(monitor):
    monitor.configure_rule('request_rate', True, 3, 60)
    monitor.insert_batch([make_event(index, index, event_kind='http_request', event_code='', url='/normal', status=200) for index in range(3)])
    monitor.insert_batch([make_event(50, 4, event_kind='http_request', event_code='', url='/%252e%252e/etc/passwd', status=404)])
    monitor.detect()
    assert {item['rule_id'] for item in monitor.alerts()} == {'request_rate', 'suspicious_url'}
    assert all(not json.loads(item['data'])['confirmed_attack'] for item in monitor.alerts())


def test_import_duplicates_bad_lines_and_full_text_search(monitor, tmp_path):
    path = tmp_path / 'access.log'
    path.write_text('192.0.2.5 - - [14/Oct/2026:12:00:00 +0000] "GET /interesting HTTP/1.1" 200 0\nmalformed\n')
    first = monitor.import_file(path, 'server.example')
    assert first['imported'] == 1 and first['rejected'] == 1 and first['status'] == 'partial'
    assert monitor.import_file(path, 'server.example')['duplicates'] == 1
    assert monitor.search('interesting', source_ip='192.0.2.5')['total'] == 1
    assert monitor.search(asset='other.example')['total'] == 0
    assert monitor.search("' OR 1=1 --")['total'] == 0


def test_incident_links_scan_findings_and_retains_analyst_workflow(monitor):
    scan = monitor.workspace.record('web', 'https://server.example/', {'headers': {'vulnerable': True, 'evidence': ['Missing CSP']}})
    monitor.insert_batch([make_event(index, index) for index in range(5)])
    monitor.detect()
    incident = monitor.incidents()[0]
    detail = monitor.incident_detail(incident['id'])
    assert detail['linked_assessments'][0]['assessment_id'] == scan['id']
    with pytest.raises(ValueError):
        monitor.update_incident(incident['id'], 'Resolved', 'Analyst', '')
    monitor.update_incident(incident['id'], 'Investigating', 'Analyst', 'Reviewing evidence')
    monitor.detect()
    detail = monitor.incident_detail(incident['id'])
    assert detail['incident']['owner'] == 'Analyst'
    assert detail['incident']['state'] == 'Investigating'
    assert detail['audit'][-1]['note'] == 'Reviewing evidence'


def test_indicator_matching_aliases_and_disabled_rules(monitor):
    monitor.set_alias('192.0.2.20', 'server.example')
    monitor.workspace.record('network', '192.0.2.20', {'ports': [{'port': 22, 'state': 'open'}]})
    monitor.add_indicator('ip', '192.0.2.5', 'Test intelligence fixture')
    monitor.configure_rule('failed_logins', False, 5, 300)
    monitor.insert_batch([make_event(1, 0)])
    monitor.detect()
    assert monitor.alerts()[0]['rule_id'] == 'indicator_match'
    assert monitor.incident_detail(monitor.incidents()[0]['id'])['linked_assessments']


def test_live_checkpoint_partial_line_restart_and_truncation(monitor, tmp_path):
    path = tmp_path / 'live.log'
    line = '192.0.2.5 - - [14/Oct/2026:12:00:00 +0000] "GET /normal HTTP/1.1" 200 0'
    path.write_text(line)  # Not a complete record until its newline arrives.
    monitor.add_source(path, 'server.example', from_start=True)
    assert monitor.poll_sources()['imported'] == 0
    with path.open('a') as stream:
        stream.write('\n')
    assert monitor.poll_sources()['imported'] == 1
    assert SecurityMonitor(monitor.workspace).poll_sources()['imported'] == 0
    # Rewritten/truncated file with the same length is detected using the prefix anchor.
    path.write_text(line.replace('/normal', '/.env') + '\n')
    assert monitor.poll_sources()['imported'] == 1
    assert monitor.metrics()['events'] == 2


def test_import_then_watch_from_start_does_not_duplicate_events(monitor, tmp_path):
    path = tmp_path / 'access.log'
    path.write_text('192.0.2.5 - - [14/Oct/2026:12:00:00 +0000] "GET /normal HTTP/1.1" 200 0\n')
    assert monitor.import_file(path, 'server.example')['imported'] == 1
    monitor.add_source(path, 'server.example', from_start=True)
    assert monitor.poll_sources()['imported'] == 0
    assert monitor.metrics()['events'] == 1


def test_monitoring_tables_survive_workspace_backup_restore(monitor, tmp_path):
    monitor.insert_batch([make_event(index, index) for index in range(5)])
    monitor.detect()
    archive = tmp_path / 'monitor.zip'
    monitor.workspace.backup(archive)
    restored = AssessmentWorkspace('restored', tmp_path)
    restored.restore(archive)
    assert SecurityMonitor(restored).metrics()['events'] == 5
    assert SecurityMonitor(restored).incidents()


def test_cancelled_import_and_rule_validation(monitor, tmp_path):
    path = tmp_path / 'access.log'
    path.write_text('192.0.2.5 - - [14/Oct/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 0\n')
    cancelled = Event()
    cancelled.set()
    assert monitor.import_file(path, 'server.example', cancelled=cancelled)['status'] == 'cancelled'
    assert monitor.metrics()['events'] == 0
    with pytest.raises(ValueError):
        monitor.configure_rule('failed_logins', True, 0, 300)


def test_bom_crlf_access_import_and_live_watch_share_ids(monitor, tmp_path):
    path = tmp_path / 'windows_access.log'
    raw = '192.0.2.5 - - [14/Oct/2026:12:00:00 +0000] "GET /normal HTTP/1.1" 200 0\r\n'
    path.write_bytes(b'\xef\xbb\xbf' + (raw + raw.replace('/normal', '/second')).encode())
    assert monitor.import_file(path, 'server.example')['imported'] == 2
    monitor.add_source(path, 'server.example', from_start=True)
    assert monitor.poll_sources()['duplicates'] == 2


def test_unknown_identity_does_not_merge_unrelated_failures(monitor):
    monitor.insert_batch([make_event(index, index, source_ip='', user='') for index in range(10)])
    assert monitor.detect()['new_alerts'] == 0


def test_later_evidence_reopens_resolved_case(monitor):
    monitor.insert_batch([make_event(index, index) for index in range(5)])
    monitor.detect()
    incident_id = monitor.incidents()[0]['id']
    monitor.update_incident(incident_id, 'Resolved', 'Analyst', 'Validated legitimate test')
    monitor.insert_batch([make_event(10, 6)])
    monitor.detect()
    assert monitor.incident_detail(incident_id)['incident']['state'] == 'New'


def test_incident_report_and_safe_internal_playbook(monitor, tmp_path):
    monitor.insert_batch([make_event(index, index) for index in range(5)])
    monitor.detect()
    incident_id = monitor.incidents()[0]['id']
    report = monitor.export_incident_bundle(incident_id)
    assert (report / 'report.pdf').read_bytes().startswith(b'%PDF')
    data = json.loads((report / 'report.json').read_text())
    assert len(data['raw']['timeline']) == 5
    monitor.run_playbook(incident_id, 'triage')
    assert monitor.incidents()[0]['state'] == 'Investigating'
    assert 'Automatic containment was not performed' in monitor.incidents()[0]['note']


def test_indicator_bulk_import_reports_invalid_rows(monitor, tmp_path):
    path = tmp_path / 'indicators.json'
    path.write_text(json.dumps([{'type':'ip','value':'192.0.2.5','label':'Fixture'}, {'type':'ip','value':'not-an-ip'}]))
    result = monitor.import_indicators(path)
    assert result['accepted'] == 1 and result['rejected'] == 1 and result['errors']


def test_utc_time_filters_and_case_audit_export(monitor, tmp_path):
    monitor.insert_batch([make_event(index, index) for index in range(5)])
    assert monitor.search(start='2026-10-14T00:00:02Z', end='2026-10-14T00:00:03Z')['total'] == 2
    monitor.detect()
    incident_id = monitor.incidents()[0]['id']
    monitor.update_incident(incident_id, 'False positive', 'Analyst', 'Fixture verified')
    destination = tmp_path / 'incident.json'
    monitor.export_incident(incident_id, destination)
    assert json.loads(destination.read_text())['audit'][-1]['note'] == 'Fixture verified'


def test_overlapping_windows_exports_deduplicate_record_identity(monitor, tmp_path):
    record = {'Id':4625,'RecordId':123,'LogName':'Security','MachineName':'server.example',
              'TimeCreated':'2026-10-14T00:00:00Z','EventData':{'TargetUserName':'alice','IpAddress':'192.0.2.5'}}
    first, second = tmp_path / 'first.json', tmp_path / 'second.json'
    first.write_text(json.dumps([record]))
    second.write_text(json.dumps([record]))
    assert monitor.import_file(first, 'server.example')['imported'] == 1
    assert monitor.import_file(second, 'server.example')['duplicates'] == 1
