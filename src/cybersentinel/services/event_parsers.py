"""Bounded parsers for real Apache/Nginx and Windows event exports."""
import csv
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit

from defusedxml import ElementTree as SafeXML

MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_RECORDS = 100_000
MAX_LINE_BYTES = 256 * 1024
ACCESS = re.compile(r'^(?:(?P<vhost>\S+)\s+)?(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^]]+)\]\s+"(?P<request>(?:[^"\\]|\\.)*)"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)(?:\s+"(?P<ref>(?:[^"\\]|\\.)*)"\s+"(?P<agent>(?:[^"\\]|\\.)*)")?.*$')
SENSITIVE = re.compile(r'password|passwd|token|secret|authorization|cookie|api.?key', re.I)


def canonical_asset(value):
    value = str(value or '').strip().lower().rstrip('.')
    if not value:
        raise ValueError('An asset hostname or IP is required; client IP is not the server asset.')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        host = urlsplit(value if '://' in value else '//' + value).hostname
        if not host or not re.fullmatch(r'[\w.\-]+', host, re.UNICODE):
            raise ValueError('Invalid asset hostname or IP')
        return host.rstrip('.')


def timestamp(value):
    value = str(value or '').strip()
    if not value:
        raise ValueError('Missing event timestamp')
    match = re.fullmatch(r'/Date\((\d+)(?:[+-]\d{4})?\)/', value)
    if match:
        parsed = datetime.fromtimestamp(int(match[1]) / 1000, timezone.utc)
    else:
        try:
            parsed = datetime.strptime(value, '%d/%b/%Y:%H:%M:%S %z')
        except ValueError:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            raise ValueError('Timestamp needs an explicit timezone or UTC offset')
    return parsed.astimezone(timezone.utc).isoformat(timespec='microseconds')


def sanitize_url(value):
    parsed = urlsplit(str(value or '')[:8192])
    query = [(key, '[REDACTED]' if SENSITIVE.search(key) else val) for key, val in parse_qsl(parsed.query, keep_blank_values=True)]
    return urlunsplit((parsed.scheme, parsed.netloc.split('@')[-1], parsed.path, urlencode(query), ''))


def sanitize(value):
    if isinstance(value, dict):
        return {str(key): '[REDACTED]' if SENSITIVE.search(str(key)) else sanitize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        value = re.sub(r'(?i)(bearer\s+)[\w.\-]+', r'\1[REDACTED]', value[:65536])
        return re.sub(r'(?i)((?:password|passwd|token|secret|api_key)=)[^&\s"<>]+', r'\1[REDACTED]', value)
    return value


def event(data, asset, source_type, identity):
    code = str(data.get('event_code', ''))
    status = int(data.get('status') or 0)
    kind = data.get('event_kind') or ('login_failure' if code == '4625' else 'login_success' if code == '4624' else 'windows_event' if source_type.startswith('windows') else 'http_request')
    ip = str(data.get('source_ip', '') or '').strip()
    if ip in ('-', '::', ''):
        ip = ''
    elif ip.startswith('::ffff:'):
        ip = ip[7:]
    if ip:
        try:
            ip = str(ipaddress.ip_address(ip))
        except ValueError:
            raise ValueError('Invalid source IP')
    occurred_at = timestamp(data.get('occurred_at'))
    normalized_asset = canonical_asset(data.get('asset') or asset)
    details = data.get('details', {})
    if source_type.startswith('windows') and details.get('windows_record_id') and details.get('windows_channel'):
        identity = json.dumps(['windows', normalized_asset, details['windows_channel'], str(details['windows_record_id']), occurred_at])
    return {'id': hashlib.sha256(identity.encode()).hexdigest(),
            'occurred_at': occurred_at, 'asset': normalized_asset,
            'source_type': source_type, 'source_ip': ip, 'user': str(data.get('user') or '').strip('-')[:256],
            'event_kind': kind, 'event_code': code, 'method': str(data.get('method') or '')[:16],
            'url': sanitize_url(data.get('url', '')), 'status': status,
            'message': sanitize(str(data.get('message') or '')),
            'severity': 'medium' if kind == 'login_failure' else 'info',
            'details': sanitize(data.get('details', {}))}


def access_line(line, asset, identity):
    match = ACCESS.match(line.strip())
    if not match:
        raise ValueError('Not an Apache/Nginx common or combined access-log record')
    fields = match.groupdict()
    request = fields['request'].split(' ')
    return event({'occurred_at': fields['time'], 'source_ip': fields['ip'], 'user': fields['user'],
                  'method': request[0] if len(request) > 1 else '', 'url': request[1] if len(request) > 1 else '',
                  'status': fields['status'], 'message': 'HTTP access',
                  'details': {'bytes': fields['size'], 'user_agent': fields.get('agent') or '',
                              'referer': sanitize_url(fields.get('ref') or '')}}, asset, 'web_access', identity)


def syslog_line(line, asset, identity):
    """RFC 5424 syslog only; legacy timestamps without a year/offset are rejected."""
    match = re.match(r'^<\d{1,3}>1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$', line.strip())
    if not match:
        raise ValueError('Expected RFC 5424 syslog with an explicit ISO timestamp')
    time, host, application, process, message_id, message = match.groups()
    login = re.search(r'(Failed|Accepted) password for (?:invalid user )?(\S+) from ([0-9a-fA-F:.]+)', message)
    return event({'occurred_at': time, 'asset': host if host != '-' else asset,
                  'event_kind': 'login_failure' if login and login[1] == 'Failed' else 'login_success' if login else 'syslog',
                  'user': login[2] if login else '', 'source_ip': login[3] if login else '', 'message': message,
                  'details': {'application': application, 'process': process, 'message_id': message_id}}, asset, 'syslog_rfc5424', identity)


def windows_xml(text, asset, identity):
    root = SafeXML.fromstring(text)
    def find(name):
        return next((item for item in root.iter() if item.tag.split('}')[-1] == name), None)
    def content(name):
        item = find(name)
        return item.text if item is not None else ''
    created = find('TimeCreated')
    fields = {item.attrib.get('Name', ''): item.text or '' for item in root.iter() if item.tag.split('}')[-1] == 'Data'}
    fields['windows_record_id'] = content('EventRecordID')
    fields['windows_channel'] = content('Channel')
    return event({'occurred_at': created.attrib.get('SystemTime') if created is not None else '',
                  'asset': content('Computer') or asset, 'event_code': content('EventID'),
                  'source_ip': fields.get('IpAddress', ''), 'user': fields.get('TargetUserName', ''),
                  'message': content('Message') or 'Windows event ' + str(content('EventID')),
                  'details': fields}, asset, 'windows_xml', identity)


def structured(record, asset, identity):
    if isinstance(record.get('Xml'), str):
        return windows_xml(record['Xml'], asset, identity)
    fields = record.get('EventData', {}) or {}
    if isinstance(fields, str):
        fields = json.loads(fields)
    if not isinstance(fields, dict):
        raise ValueError('EventData must be a named field object')
    code = record.get('Id', record.get('EventID', record.get('event_code', '')))
    fields = dict(fields)
    if 'System' in record:
        system = record['System']
        code = system.get('EventID', code)
        created = system.get('TimeCreated', {})
        time = created.get('SystemTime') if isinstance(created, dict) else created
        host = system.get('Computer', asset)
        fields['windows_record_id'] = system.get('EventRecordID', '')
        fields['windows_channel'] = system.get('Channel', '')
    else:
        time = record.get('occurred_at') or record.get('TimeCreated') or record.get('time_iso8601') or record.get('@timestamp') or record.get('timestamp')
        host = record.get('asset') or record.get('MachineName') or record.get('Computer') or asset
        fields['windows_record_id'] = record.get('RecordId', record.get('EventRecordID', ''))
        fields['windows_channel'] = record.get('LogName', record.get('Channel', ''))
    return event({'occurred_at': time, 'asset': host, 'event_code': code,
                  'source_ip': record.get('source_ip') or record.get('remote_addr') or record.get('IpAddress') or fields.get('IpAddress', ''),
                  'user': record.get('user') or record.get('TargetUserName') or record.get('UserName') or fields.get('TargetUserName', ''),
                  'event_kind': record.get('event_kind'), 'method': record.get('method') or record.get('request_method', ''),
                  'url': record.get('url') or record.get('request_uri', ''), 'status': record.get('status', 0),
                  'message': record.get('Message') or record.get('message') or ('Windows event ' + str(code) if code else 'HTTP access'),
                  'details': fields}, asset, 'windows_export' if code else 'web_json', identity)


def read_records(path, asset, format='auto', cancelled=None):
    """Yield (event, error) so malformed records are never silently discarded."""
    path = Path(path).resolve()
    if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError('Choose a regular log file no larger than 128 MB')
    canonical_asset(asset)
    stat = path.stat()
    identity = f'{path}:{stat.st_dev}:{stat.st_ino}:0'
    kind = path.suffix.lower() if format == 'auto' else '.' + format
    if kind == '.evtx':
        from Evtx.Evtx import Evtx
        with Evtx(str(path)) as log:
            records = ((index, 'xml', record.xml()) for index, record in enumerate(log.records()))
            yield from convert(records, asset, identity, cancelled)
        return
    if kind == '.xml':
        records = ((index, 'xml_element', element) for index, (_, element) in enumerate(SafeXML.iterparse(str(path), events=('end',))) if element.tag.split('}')[-1] == 'Event')
        yield from convert(records, asset, identity, cancelled)
        return
    with path.open('rb') as binary:
        prefix = binary.read(3)
    encoding = 'utf-16' if prefix.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig'
    with path.open(encoding=encoding, errors='strict', newline='') as stream:
        if kind == '.csv':
            records = ((index, 'json', record) for index, record in enumerate(csv.DictReader(stream)))
        elif kind == '.json':
            data = json.load(stream)
            data = data.get('events', data) if isinstance(data, dict) and 'events' in data else data
            data = data if isinstance(data, list) else [data]
            records = ((index, 'json', record) for index, record in enumerate(data))
        else:
            def lines():
                position = 0
                with path.open('rb') as binary:
                    bom_size = 3 if binary.read(3) == b'\xef\xbb\xbf' else 0
                for line in stream:
                    offset = position
                    position += len(line.encode('utf-8')) + bom_size
                    bom_size = 0
                    if line.strip():
                        yield offset, 'json_line' if kind in ('.jsonl', '.ndjson') else 'syslog' if kind == '.syslog' else 'access', line
            records = lines()
        yield from convert(records, asset, identity, cancelled)


def convert(records, asset, identity, cancelled):
    for count, (position, kind, raw) in enumerate(records):
        if count >= MAX_RECORDS:
            raise ValueError('Import exceeds 100,000 records; split the export into smaller files')
        if cancelled and cancelled.is_set():
            raise InterruptedError('Import cancelled; already committed events are retained')
        try:
            if isinstance(raw, str) and len(raw.encode('utf-8')) > MAX_LINE_BYTES:
                raise ValueError('Record exceeds 256 KB')
            key = f'{identity}:{position}:' + hashlib.sha256(str(raw).encode()).hexdigest()
            if kind == 'access':
                result = access_line(raw, asset, key)
            elif kind == 'syslog':
                result = syslog_line(raw, asset, key)
            elif kind in ('xml', 'xml_element'):
                if kind == 'xml_element':
                    import xml.etree.ElementTree as XML
                    raw = XML.tostring(raw, encoding='unicode')
                    # Stable identity across imports; Element repr contains a memory address.
                    key = f'{identity}:{position}:' + hashlib.sha256(raw.encode()).hexdigest()
                result = windows_xml(raw, asset, key)
            else:
                result = structured(json.loads(raw) if kind == 'json_line' else raw, asset, key)
            yield result, None
        except (ValueError, TypeError, KeyError, AttributeError) as error:
            yield None, {'record': position + 1, 'error': str(error)}
