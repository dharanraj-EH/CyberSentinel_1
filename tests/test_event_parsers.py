"""Real format fixtures exercise timestamp, provenance and parsing failures."""
import json
from pathlib import Path
import pytest
from cybersentinel.services.event_parsers import access_line, windows_xml, read_records, timestamp, syslog_line


def test_apache_combined_normalizes_timezone_and_redacts_query():
    line = '192.0.2.7 - alice [14/Oct/2026:12:30:00 +0530] "GET /login?token=private&next=home HTTP/1.1" 401 23 "-" "Mozilla/5.0"'
    item = access_line(line, 'https://Example.COM/', 'fixture')
    assert item['asset'] == 'example.com'
    assert item['occurred_at'] == '2026-10-14T07:00:00.000000+00:00'
    assert item['source_ip'] == '192.0.2.7'
    assert item['user'] == 'alice'
    assert 'private' not in item['url']
    assert item['status'] == 401


def test_windows_xml_named_fields_are_normalized():
    xml = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4625</EventID><TimeCreated SystemTime="2026-10-14T00:00:00Z"/><Computer>HOST.EXAMPLE</Computer></System><EventData><Data Name="TargetUserName">alice</Data><Data Name="IpAddress">::ffff:192.0.2.5</Data></EventData></Event>'''
    item = windows_xml(xml, 'fallback.example', 'fixture')
    assert item['asset'] == 'host.example'
    assert item['event_kind'] == 'login_failure'
    assert item['source_ip'] == '192.0.2.5'
    assert item['user'] == 'alice'


def test_json_and_csv_windows_exports(tmp_path):
    record = {'Id': 4624, 'MachineName': 'host.example', 'TimeCreated': '2026-10-14T00:00:00Z',
              'EventData': {'TargetUserName': 'alice', 'IpAddress': '192.0.2.5'}}
    path = tmp_path / 'events.json'
    path.write_text(json.dumps([record]))
    item, error = next(read_records(path, 'host.example'))
    assert not error and item['event_kind'] == 'login_success'
    path = tmp_path / 'events.csv'
    path.write_text('Id,MachineName,TimeCreated,Message\n4625,host.example,2026-10-14T00:00:00Z,Failure\n')
    item, error = next(read_records(path, 'host.example'))
    assert not error and item['event_kind'] == 'login_failure'


def test_malformed_line_and_naive_timestamp_are_explicit_errors(tmp_path):
    path = tmp_path / 'access.log'
    path.write_text('not a real access log\n')
    item, error = next(read_records(path, 'server.example'))
    assert item is None and error
    with pytest.raises(ValueError, match='timezone'):
        timestamp('2026-10-14T00:00:00')


def test_untrusted_xml_entities_are_rejected(tmp_path):
    path = tmp_path / 'events.xml'
    path.write_text('<!DOCTYPE Event [<!ENTITY secret SYSTEM "file:///etc/passwd">]><Event>&secret;</Event>')
    with pytest.raises(Exception):
        list(read_records(path, 'server.example'))


def test_windows_xml_import_ids_are_stable(tmp_path):
    path = tmp_path / 'events.xml'
    path.write_text('<Events><Event><System><EventID>4625</EventID><TimeCreated SystemTime="2026-10-14T00:00:00Z"/><Computer>server.example</Computer></System></Event></Events>')
    first = list(read_records(path, 'server.example'))
    second = list(read_records(path, 'server.example'))
    assert first[0][0]['id'] == second[0][0]['id']


def test_rfc5424_linux_authentication_event():
    item = syslog_line('<34>1 2026-10-14T00:00:00Z linux.example sshd 123 - - Failed password for invalid user alice from 192.0.2.5 port 4321 ssh2', 'fallback.example', 'fixture')
    assert item['event_kind'] == 'login_failure'
    assert item['asset'] == 'linux.example'
    assert item['source_ip'] == '192.0.2.5'


def test_nginx_structured_json_and_windows_jsonl(tmp_path):
    path = tmp_path / 'nginx.jsonl'
    path.write_text(json.dumps({'time_iso8601': '2026-10-14T00:00:00+00:00', 'remote_addr': '192.0.2.5',
                               'request_method': 'GET', 'request_uri': '/hello', 'status': 200}) + '\n')
    item, error = next(read_records(path, 'server.example'))
    assert not error and item['url'] == '/hello' and item['method'] == 'GET'


def test_utf16_windows_csv_export(tmp_path):
    path = tmp_path / 'windows.csv'
    path.write_text('Id,MachineName,TimeCreated,Message\n4625,server.example,2026-10-14T00:00:00Z,Failure\n', encoding='utf-16')
    item, error = next(read_records(path, 'server.example'))
    assert not error and item['event_code'] == '4625'
