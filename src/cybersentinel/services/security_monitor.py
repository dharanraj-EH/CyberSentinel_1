"""Local event indexing, deterministic detections and incident correlation."""
import hashlib
import ipaddress
import json
import sqlite3
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from threading import Event
from urllib.parse import unquote, urlsplit
from uuid import uuid4

from .event_parsers import read_records, canonical_asset, access_line, syslog_line, structured, sanitize, MAX_LINE_BYTES

RULES = [
    {'id': 'failed_logins', 'name': 'Repeated authentication failures', 'enabled': True, 'threshold': 5, 'window': 300, 'severity': 'high', 'score': 50},
    {'id': 'request_rate', 'name': 'High request rate (fixed threshold)', 'enabled': True, 'threshold': 100, 'window': 60, 'severity': 'medium', 'score': 30},
    {'id': 'suspicious_url', 'name': 'Suspicious request patterns', 'enabled': True, 'threshold': 1, 'window': 300, 'severity': 'medium', 'score': 30},
    {'id': 'success_after_failures', 'name': 'Successful logon after repeated failures', 'enabled': True, 'threshold': 5, 'window': 300, 'severity': 'high', 'score': 70},
    {'id': 'indicator_match', 'name': 'Local threat-indicator match', 'enabled': True, 'threshold': 1, 'window': 300, 'severity': 'high', 'score': 60},
]


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds')


def epoch(value):
    return datetime.fromisoformat(value).timestamp()


class SecurityMonitor:
    def __init__(self, workspace):
        self.workspace = workspace
        self.initialize()

    def initialize(self):
        with self.workspace.connect() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.executescript('''
                CREATE TABLE IF NOT EXISTS security_events(
                    id TEXT PRIMARY KEY, occurred_at TEXT NOT NULL, asset TEXT NOT NULL,
                    source_type TEXT, source_ip TEXT, user TEXT, event_kind TEXT, event_code TEXT,
                    status INTEGER, url TEXT, data TEXT NOT NULL, imported_at TEXT);
                CREATE INDEX IF NOT EXISTS security_time ON security_events(occurred_at);
                CREATE INDEX IF NOT EXISTS security_asset ON security_events(asset,occurred_at);
                CREATE INDEX IF NOT EXISTS security_ip ON security_events(source_ip,occurred_at);
                CREATE INDEX IF NOT EXISTS security_kind ON security_events(event_kind,occurred_at);
                CREATE TABLE IF NOT EXISTS security_rules(id TEXT PRIMARY KEY,data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS security_alerts(
                    id TEXT PRIMARY KEY, rule_id TEXT, entity TEXT, asset TEXT, source_ip TEXT,
                    first_at TEXT,last_at TEXT,severity TEXT,score INTEGER,data TEXT);
                CREATE INDEX IF NOT EXISTS alert_entity ON security_alerts(rule_id,entity,first_at,last_at);
                CREATE TABLE IF NOT EXISTS alert_events(alert_id TEXT,event_id TEXT,PRIMARY KEY(alert_id,event_id));
                CREATE TABLE IF NOT EXISTS security_incidents(
                    id TEXT PRIMARY KEY,entity TEXT,asset TEXT,source_ip TEXT,first_at TEXT,last_at TEXT,
                    state TEXT DEFAULT 'New',owner TEXT DEFAULT '',note TEXT DEFAULT '');
                CREATE TABLE IF NOT EXISTS incident_alerts(incident_id TEXT,alert_id TEXT,PRIMARY KEY(incident_id,alert_id));
                CREATE TABLE IF NOT EXISTS incident_audit(id INTEGER PRIMARY KEY,incident_id TEXT,time TEXT,action TEXT,note TEXT);
                CREATE TABLE IF NOT EXISTS log_sources(id TEXT PRIMARY KEY,path TEXT UNIQUE,asset TEXT,format TEXT,
                    offset INTEGER DEFAULT 0,identity TEXT DEFAULT '',generation INTEGER DEFAULT 0,
                    anchor TEXT DEFAULT '',enabled INTEGER DEFAULT 1,last_poll TEXT,error TEXT DEFAULT '');
                CREATE TABLE IF NOT EXISTS threat_indicators(type TEXT,value TEXT,label TEXT,PRIMARY KEY(type,value));
                CREATE TABLE IF NOT EXISTS asset_aliases(alias TEXT PRIMARY KEY,canonical TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS log_imports(id TEXT PRIMARY KEY,time TEXT,path TEXT,asset TEXT,data TEXT);
            ''')
            for rule in RULES:
                db.execute('INSERT OR IGNORE INTO security_rules VALUES(?,?)', (rule['id'], json.dumps(rule)))
            try:
                db.execute('CREATE VIRTUAL TABLE IF NOT EXISTS security_search USING fts5(event_id UNINDEXED, content)')
                self.full_text = True
            except sqlite3.OperationalError:
                self.full_text = False

    def resolve_asset(self, asset):
        asset = canonical_asset(asset)
        with self.workspace.connect() as db:
            row = db.execute('SELECT canonical FROM asset_aliases WHERE alias=?', (asset,)).fetchone()
        return row[0] if row else asset

    def set_alias(self, alias, canonical):
        alias, canonical = canonical_asset(alias), canonical_asset(canonical)
        with self.workspace.connect() as db:
            db.execute('INSERT OR REPLACE INTO asset_aliases VALUES(?,?)', (alias, canonical))
        # Event assets are resolved at import; mapping changes are prospective.

    def insert_batch(self, events):
        added = 0
        with self.workspace.connect() as db:
            for item in events:
                item = dict(item)
                row = db.execute('SELECT canonical FROM asset_aliases WHERE alias=?', (item['asset'],)).fetchone()
                if row:
                    item['asset'] = row[0]
                data = json.dumps(item, ensure_ascii=False)
                cursor = db.execute('INSERT OR IGNORE INTO security_events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                    (item['id'], item['occurred_at'], item['asset'], item['source_type'], item['source_ip'], item['user'],
                     item['event_kind'], item['event_code'], item['status'], item['url'], data, utcnow()))
                if cursor.rowcount:
                    added += 1
                    if self.full_text:
                        db.execute('INSERT INTO security_search VALUES(?,?)', (item['id'], data + ' ' + unquote(unquote(item['url']))))
        return added

    def import_file(self, path, asset, format='auto', cancelled=None, progress=None):
        asset = canonical_asset(asset)
        result = {'read': 0, 'imported': 0, 'duplicates': 0, 'rejected': 0, 'errors': [], 'status': 'completed'}
        batch = []
        try:
            for item, error in read_records(path, asset, format, cancelled):
                result['read'] += 1
                if error:
                    result['rejected'] += 1
                    if len(result['errors']) < 50:
                        result['errors'].append(error)
                else:
                    batch.append(item)
                if len(batch) >= 500:
                    added = self.insert_batch(batch)
                    result['imported'] += added
                    result['duplicates'] += len(batch) - added
                    batch.clear()
                    if progress:
                        progress(f"Read {result['read']} records; stored {result['imported']}")
        except Exception as error:
            result['status'] = 'cancelled' if isinstance(error, InterruptedError) else 'partial'
            result['errors'].append({'error': str(error)})
        if batch:
            added = self.insert_batch(batch)
            result['imported'] += added
            result['duplicates'] += len(batch) - added
        if result['rejected'] and result['status'] == 'completed':
            result['status'] = 'partial'
        with self.workspace.connect() as db:
            db.execute('INSERT INTO log_imports VALUES(?,?,?,?,?)', (uuid4().hex, utcnow(), str(Path(path).resolve()), asset, json.dumps(result)))
            db.execute('INSERT INTO audit(timestamp,action,detail) VALUES(?,?,?)', (utcnow(), 'security_log_import', json.dumps(result)))
        return result

    def search(self, text='', asset='', source_ip='', user='', kind='', start='', end='', limit=250, offset=0):
        conditions, parameters = [], []
        for column, value in [('asset', asset), ('source_ip', source_ip), ('user', user), ('event_kind', kind)]:
            if value:
                conditions.append('e.' + column + '=?')
                parameters.append(self.resolve_asset(value) if column == 'asset' else value)
        for operator, value in [('>=', start), ('<=', end)]:
            if value:
                from .event_parsers import timestamp
                conditions.append('e.occurred_at' + operator + '?')
                parameters.append(timestamp(value))
        join = ''
        if text.strip():
            if self.full_text:
                join = ' JOIN security_search ON security_search.event_id=e.id '
                conditions.append('security_search MATCH ?')
                parameters.append(' AND '.join('"' + term.replace('"', '""') + '"' for term in text.split()[:20]))
            else:
                conditions.append("e.data LIKE ? ESCAPE '\\'")
                parameters.append('%' + text.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%')
        where = ' WHERE ' + ' AND '.join(conditions) if conditions else ''
        with self.workspace.connect() as db:
            total = db.execute('SELECT COUNT(*) FROM security_events e ' + join + where, parameters).fetchone()[0]
            rows = db.execute('SELECT e.data FROM security_events e ' + join + where + ' ORDER BY e.occurred_at DESC,e.id LIMIT ? OFFSET ?',
                              parameters + [min(max(int(limit), 1), 1000), max(int(offset), 0)]).fetchall()
        return {'total': total, 'events': [json.loads(row[0]) for row in rows]}

    def rules(self):
        with self.workspace.connect() as db:
            return [json.loads(row[0]) for row in db.execute('SELECT data FROM security_rules ORDER BY id')]

    def configure_rule(self, rule_id, enabled, threshold, window):
        if not 1 <= int(threshold) <= 100_000 or not 1 <= int(window) <= 86400:
            raise ValueError('Threshold must be 1–100000 and window 1–86400 seconds')
        rule = next((rule for rule in self.rules() if rule['id'] == rule_id), None)
        if not rule:
            raise ValueError('Unknown detection rule')
        rule.update(enabled=bool(enabled), threshold=int(threshold), window=int(window))
        with self.workspace.connect() as db:
            db.execute('UPDATE security_rules SET data=? WHERE id=?', (json.dumps(rule), rule_id))
            db.execute('INSERT INTO audit(timestamp,action,detail) VALUES(?,?,?)', (utcnow(), 'detection_rule_updated', json.dumps(rule)))

    def add_indicator(self, type, value, label):
        value = value.strip().lower()
        if type == 'ip':
            value = str(ipaddress.ip_address(value))
        elif type == 'domain':
            value = canonical_asset(value)
        else:
            raise ValueError('Supported indicators: ip and domain')
        with self.workspace.connect() as db:
            db.execute('INSERT OR REPLACE INTO threat_indicators VALUES(?,?,?)', (type, value, label[:256]))

    def indicators(self):
        with self.workspace.connect() as db:
            return [dict(row) for row in db.execute('SELECT * FROM threat_indicators ORDER BY type,value')]

    def remove_indicator(self, type, value):
        with self.workspace.connect() as db:
            db.execute('DELETE FROM threat_indicators WHERE type=? AND value=?', (type, value))

    def import_indicators(self, path, cancelled=None):
        import csv
        path = Path(path)
        if not path.is_file() or path.stat().st_size > 2_000_000:
            raise ValueError('Choose a JSON/CSV indicator list no larger than 2 MB')
        with path.open(encoding='utf-8-sig', newline='') as stream:
            rows = list(csv.DictReader(stream)) if path.suffix.lower() == '.csv' else json.load(stream)
        if not isinstance(rows, list) or len(rows) > 10000:
            raise ValueError('Indicator list must contain at most 10,000 objects with type, value and label')
        result = {'accepted': 0, 'rejected': 0, 'errors': []}
        for index, row in enumerate(rows):
            if cancelled and cancelled.is_set():
                raise InterruptedError('Indicator import cancelled; accepted entries are retained')
            try:
                self.add_indicator(row['type'], row['value'], row.get('label', str(path.name)))
                result['accepted'] += 1
            except (ValueError, TypeError, KeyError) as error:
                result['rejected'] += 1
                if len(result['errors']) < 50:
                    result['errors'].append({'row': index + 1, 'error': str(error)})
        with self.workspace.connect() as db:
            db.execute('INSERT INTO audit(timestamp,action,detail) VALUES(?,?,?)', (utcnow(), 'indicator_import', json.dumps(result)))
        return result

    def detect(self, cancelled=None, progress=None):
        cancelled = cancelled or Event()
        rules = {rule['id']: rule for rule in self.rules() if rule['enabled']}
        indicators = {(item['type'], item['value']): item['label'] for item in self.indicators()}
        buckets, candidates, recent_failures = defaultdict(deque), {}, defaultdict(deque)
        processed = 0
        started = time.monotonic()
        # Read transaction is closed before detections are written.
        with self.workspace.connect() as db:
            for row in db.execute('SELECT data FROM security_events ORDER BY occurred_at,id'):
                if cancelled.is_set():
                    raise InterruptedError('Detection cancelled; previous alerts are retained')
                if time.monotonic() - started > 120:
                    raise TimeoutError('Detection exceeded the two-minute local processing budget; imported events and previous alerts are retained')
                item = json.loads(row[0])
                processed += 1
                now = epoch(item['occurred_at'])
                entity = item['asset'] + '|' + (item['source_ip'] or 'user:' + item['user'] or 'unknown')
                identity = entity + '|' + item['user']
                applicable = []
                failure = item['event_kind'] == 'login_failure' or (item['status'] == 401 and any(part in item['url'].lower() for part in ('login', 'signin', 'auth')))
                if failure and (item['source_ip'] or item['user']):
                    applicable.append(('failed_logins', identity, 'Repeated failed authentication observations'))
                    recent_failures[identity].append(item)
                if item['event_kind'] == 'http_request' and item['source_ip']:
                    applicable.append(('request_rate', entity, 'Request count exceeds the configured fixed threshold; traffic may be legitimate'))
                url = unquote(unquote(item['url'])).lower()
                patterns = [name for name, pattern in [
                    ('path traversal', r'\.\./'), ('script-like input', r'<script\b|javascript:|onerror\s*='),
                    ('SQL-like input', r'\bunion\s+select\b|\bor\s+1\s*=\s*1\b'),
                    ('sensitive path', r'/(?:\.env(?:[/?]|$)|\.git/|etc/passwd)')]
                    if __import__('re').search(pattern, url)]
                if patterns:
                    applicable.append(('suspicious_url', entity, 'Candidate request patterns: ' + ', '.join(patterns) + '; exploitation is not established'))
                matches = []
                if ('ip', item['source_ip']) in indicators:
                    matches.append(item['source_ip'])
                domains = [urlsplit(item['url']).hostname, item['asset']]
                for domain in domains:
                    if domain and ('domain', domain.lower()) in indicators:
                        matches.append(domain)
                if matches:
                    applicable.append(('indicator_match', entity, 'Matched local indicator: ' + ', '.join(matches)))
                success_rule = rules.get('success_after_failures')
                if success_rule and (identity in recent_failures or item['event_kind'] == 'login_success'):
                    failures = recent_failures[identity]
                    while failures and now - epoch(failures[0]['occurred_at']) > success_rule['window']:
                        failures.popleft()
                    if item['event_kind'] == 'login_success' and len(failures) >= success_rule['threshold']:
                        self._candidate(candidates, success_rule, identity, [*failures, item], 'Successful logon after repeated failures; investigate whether access was legitimate')
                for rule_id, group, explanation in applicable:
                    rule = rules.get(rule_id)
                    if not rule:
                        continue
                    bucket = buckets[(rule_id, group)]
                    bucket.append(item)
                    while bucket and now - epoch(bucket[0]['occurred_at']) > rule['window']:
                        bucket.popleft()
                    if len(bucket) >= rule['threshold']:
                        self._candidate(candidates, rule, group, list(bucket), explanation)
                if progress and processed % 5000 == 0:
                    progress(f'Correlating {processed} events…')
                if processed % 5000 == 0:
                    max_window = max((rule['window'] for rule in rules.values()), default=300)
                    for key in [key for key, queue in buckets.items() if not queue or now - epoch(queue[-1]['occurred_at']) > max_window]:
                        del buckets[key]
                    for key in [key for key, queue in recent_failures.items() if not queue or now - epoch(queue[-1]['occurred_at']) > max_window]:
                        del recent_failures[key]
        new_alerts = 0
        with self.workspace.connect() as db:
            for candidate in candidates.values():
                if cancelled.is_set():
                    raise InterruptedError('Detection cancelled')
                new_alerts += self._persist_candidate(db, candidate)
            db.execute('INSERT INTO audit(timestamp,action,detail) VALUES(?,?,?)', (utcnow(), 'security_detection_run', json.dumps({'processed': processed, 'new_alerts': new_alerts})))
        return {'events_evaluated': processed, 'new_alerts': new_alerts, 'candidate_episodes': len(candidates)}

    @staticmethod
    def _candidate(candidates, rule, group, items, explanation):
        # Coalesce overlapping windows within this evaluation, retaining actual evidence.
        key = (rule['id'], group)
        current = candidates.get(key)
        if current and epoch(items[0]['occurred_at']) <= epoch(current['last_at']) + rule['window']:
            current['events'].update({item['id']: item for item in items})
            current['last_at'] = max(current['last_at'], items[-1]['occurred_at'])
        else:
            if current:
                candidates[(rule['id'], group, current['first_at'])] = current
            candidates[key] = {'rule': rule, 'entity': group, 'asset': items[0]['asset'], 'source_ip': items[0]['source_ip'],
                               'first_at': items[0]['occurred_at'], 'last_at': items[-1]['occurred_at'],
                               'events': {item['id']: item for item in items}, 'explanation': explanation}

    def _persist_candidate(self, db, candidate):
        rule = candidate['rule']
        existing = db.execute('SELECT * FROM security_alerts WHERE rule_id=? AND entity=? ORDER BY last_at DESC', (rule['id'], candidate['entity'])).fetchall()
        existing = next((row for row in existing if epoch(candidate['first_at']) <= epoch(row['last_at']) + rule['window'] and epoch(candidate['last_at']) >= epoch(row['first_at']) - rule['window']), None)
        alert_id = existing['id'] if existing else uuid4().hex
        first = min(candidate['first_at'], existing['first_at']) if existing else candidate['first_at']
        last = max(candidate['last_at'], existing['last_at']) if existing else candidate['last_at']
        data = {'title': rule['name'], 'explanation': candidate['explanation'], 'threshold': rule['threshold'],
                'window_seconds': rule['window'], 'rule_snapshot': rule, 'confirmed_attack': False}
        if existing:
            original = json.loads(existing['data'])
            original['latest_evaluation'] = data
            data = original
        db.execute('INSERT OR REPLACE INTO security_alerts VALUES(?,?,?,?,?,?,?,?,?,?)',
                   (alert_id, rule['id'], candidate['entity'], candidate['asset'], candidate['source_ip'], first, last, rule['severity'], rule['score'], json.dumps(data)))
        for event_id in candidate['events']:
            db.execute('INSERT OR IGNORE INTO alert_events VALUES(?,?)', (alert_id, event_id))
        linked = db.execute('SELECT incident_id FROM incident_alerts WHERE alert_id=?', (alert_id,)).fetchone()
        if linked:
            incident_id = linked[0]
            db.execute('UPDATE security_incidents SET first_at=MIN(first_at,?),last_at=MAX(last_at,?) WHERE id=?', (first, last, incident_id))
            if existing and last > existing['last_at']:
                reopened = db.execute("UPDATE security_incidents SET state='New' WHERE id=? AND state IN ('Resolved','False positive')", (incident_id,))
                if reopened.rowcount:
                    db.execute('INSERT INTO incident_audit(incident_id,time,action,note) VALUES(?,?,?,?)', (incident_id, utcnow(), 'reopened', 'New later event evidence added to this alert'))
        else:
            entity = candidate['asset'] + '|' + (candidate['source_ip'] or candidate['entity'].split('|')[-1])
            incidents = db.execute('SELECT * FROM security_incidents WHERE entity=? ORDER BY last_at DESC', (entity,)).fetchall()
            incident = next((row for row in incidents if epoch(first) <= epoch(row['last_at']) + 900 and epoch(last) >= epoch(row['first_at']) - 900), None)
            incident_id = incident['id'] if incident else uuid4().hex
            if incident:
                db.execute('UPDATE security_incidents SET first_at=MIN(first_at,?),last_at=MAX(last_at,?) WHERE id=?', (first, last, incident_id))
            else:
                db.execute('INSERT INTO security_incidents(id,entity,asset,source_ip,first_at,last_at) VALUES(?,?,?,?,?,?)', (incident_id, entity, candidate['asset'], candidate['source_ip'], first, last))
                db.execute('INSERT INTO incident_audit(incident_id,time,action,note) VALUES(?,?,?,?)', (incident_id, utcnow(), 'created', 'Detection candidate; analyst verification required'))
            db.execute('INSERT OR IGNORE INTO incident_alerts VALUES(?,?)', (incident_id, alert_id))
        return 0 if existing else 1

    def alerts(self):
        with self.workspace.connect() as db:
            return [dict(row) for row in db.execute('SELECT a.*,COUNT(e.event_id) evidence_count FROM security_alerts a LEFT JOIN alert_events e ON e.alert_id=a.id GROUP BY a.id ORDER BY a.last_at DESC')]

    def incidents(self):
        with self.workspace.connect() as db:
            rows = db.execute('SELECT * FROM security_incidents ORDER BY last_at DESC').fetchall()
            results = []
            for row in rows:
                item = dict(row)
                scores = db.execute('SELECT a.rule_id,MAX(a.score) score FROM incident_alerts i JOIN security_alerts a ON a.id=i.alert_id WHERE i.incident_id=? GROUP BY a.rule_id', (item['id'],)).fetchall()
                item['risk_score'] = min(100, sum(score['score'] for score in scores))
                item['rule_count'] = len(scores)
                results.append(item)
            return results

    def incident_detail(self, incident_id):
        incident = next((item for item in self.incidents() if item['id'] == incident_id), None)
        if not incident:
            raise ValueError('Unknown incident')
        with self.workspace.connect() as db:
            events = db.execute('SELECT DISTINCT e.data FROM incident_alerts i JOIN alert_events a ON a.alert_id=i.alert_id JOIN security_events e ON e.id=a.event_id WHERE i.incident_id=? ORDER BY e.occurred_at,e.id', (incident_id,)).fetchall()
            audit = [dict(row) for row in db.execute('SELECT time,action,note FROM incident_audit WHERE incident_id=? ORDER BY time,id', (incident_id,))]
            alerts = [dict(row) for row in db.execute('SELECT a.* FROM incident_alerts i JOIN security_alerts a ON a.id=i.alert_id WHERE i.incident_id=? ORDER BY a.first_at', (incident_id,))]
        linked = []
        for assessment in self.workspace.history():
            try:
                matched = self.resolve_asset(assessment['target']) == self.resolve_asset(incident['asset'])
            except ValueError:
                matched = False
            if matched:
                linked.append({'assessment_id': assessment['id'], 'module': assessment['module'], 'timestamp': assessment['timestamp'],
                               'status': assessment['status'], 'findings': assessment['findings']})
        return {'incident': incident, 'alerts': alerts, 'timeline': [json.loads(row[0]) for row in events],
                'audit': audit, 'linked_assessments': linked,
                'note': 'Asset links provide context, not proof that a weakness was exploited. Risk is a deterministic local rule score, not a probability.'}

    def update_incident(self, incident_id, state, owner, note):
        if state not in ('New', 'Investigating', 'Contained', 'Resolved', 'False positive'):
            raise ValueError('Invalid incident state')
        if state in ('Resolved', 'False positive', 'Contained') and not note.strip():
            raise ValueError('A reason or verification note is required for this state')
        with self.workspace.connect() as db:
            cursor = db.execute('UPDATE security_incidents SET state=?,owner=?,note=? WHERE id=?', (state, owner[:256], sanitize(note), incident_id))
            if not cursor.rowcount:
                raise ValueError('Unknown incident')
            db.execute('INSERT INTO incident_audit(incident_id,time,action,note) VALUES(?,?,?,?)', (incident_id, utcnow(), state, sanitize(note)))

    def metrics(self):
        with self.workspace.connect() as db:
            return {'events': db.execute('SELECT COUNT(*) FROM security_events').fetchone()[0],
                    'alerts': db.execute('SELECT COUNT(*) FROM security_alerts').fetchone()[0],
                    'open_incidents': db.execute("SELECT COUNT(*) FROM security_incidents WHERE state NOT IN ('Resolved','False positive')").fetchone()[0],
                    'sources': db.execute('SELECT COUNT(*) FROM log_sources WHERE enabled=1').fetchone()[0]}

    def add_source(self, path, asset, format='access', from_start=False):
        path = Path(path).resolve()
        if not path.is_file() or format not in ('access', 'jsonl', 'syslog'):
            raise ValueError('Live sources support access logs, RFC 5424 syslog or JSONL files')
        asset = canonical_asset(asset)
        stat = path.stat()
        offset = 0 if from_start else stat.st_size
        size = min(offset, 4096)
        with path.open('rb') as stream:
            if stream.read(2) in (b'\xff\xfe', b'\xfe\xff'):
                raise ValueError('Live sources require UTF-8. Import UTF-16 Windows exports as snapshots instead.')
            stream.seek(0)
            anchor = json.dumps({'size': size, 'sha': hashlib.sha256(stream.read(size)).hexdigest()})
        with self.workspace.connect() as db:
            if db.execute('SELECT id FROM log_sources WHERE path=?', (str(path),)).fetchone():
                raise ValueError('This file is already registered; enable or disable its existing source')
            db.execute('INSERT INTO log_sources(id,path,asset,format,offset,identity,anchor) VALUES(?,?,?,?,?,?,?)',
                       (uuid4().hex, str(path), asset, format, offset, f'{stat.st_dev}:{stat.st_ino}', anchor))

    def sources(self):
        with self.workspace.connect() as db:
            return [dict(row) for row in db.execute('SELECT * FROM log_sources ORDER BY path')]

    def enable_source(self, source_id, enabled):
        with self.workspace.connect() as db:
            db.execute('UPDATE log_sources SET enabled=? WHERE id=?', (int(bool(enabled)), source_id))

    def poll_sources(self, cancelled=None):
        results = {'imported': 0, 'duplicates': 0, 'rejected': 0, 'errors': [], 'sources': 0}
        for source in self.sources():
            if not source['enabled']:
                continue
            if cancelled and cancelled.is_set():
                break
            path = Path(source['path'])
            offset, generation = source['offset'], source['generation']
            batch, rejected = [], []
            try:
                stat = path.stat()
                identity = f'{stat.st_dev}:{stat.st_ino}'
                anchor = json.loads(source['anchor']) if source['anchor'] else {'size': 0, 'sha': hashlib.sha256(b'').hexdigest()}
                with path.open('rb') as stream:
                    changed = hashlib.sha256(stream.read(anchor['size'])).hexdigest() != anchor['sha']
                    if identity != source['identity'] or stat.st_size < offset or changed:
                        offset, generation = 0, generation + 1
                    stream.seek(offset)
                    budget = 0
                    while budget < 4 * 1024 * 1024:
                        if cancelled and cancelled.is_set():
                            break
                        position = stream.tell()
                        line = stream.readline(MAX_LINE_BYTES + 1)
                        if not line:
                            break
                        if len(line) > MAX_LINE_BYTES:
                            raise ValueError('Live record exceeds 256 KB; source paused at this record')
                        if not line.endswith(b'\n'):
                            break  # Do not checkpoint an incomplete last record.
                        budget += len(line)
                        offset = stream.tell()
                        if not line.strip():
                            continue
                        try:
                            raw = line.decode('utf-8-sig')
                            key = f'{path}:{identity}:{generation}:{position}:' + hashlib.sha256(raw.encode()).hexdigest()
                            if source['format'] == 'access':
                                item = access_line(raw, source['asset'], key)
                            elif source['format'] == 'syslog':
                                item = syslog_line(raw, source['asset'], key)
                            else:
                                item = structured(json.loads(raw), source['asset'], key)
                            batch.append(item)
                        except (ValueError, TypeError, UnicodeError) as error:
                            rejected.append({'byte_offset': position, 'error': str(error)})
                    size = min(offset, 4096)
                    stream.seek(0)
                    anchor = json.dumps({'size': size, 'sha': hashlib.sha256(stream.read(size)).hexdigest()})
                added = self.insert_batch(batch)
                results['imported'] += added
                results['duplicates'] += len(batch) - added
                results['rejected'] += len(rejected)
                with self.workspace.connect() as db:
                    db.execute('UPDATE log_sources SET offset=?,identity=?,generation=?,anchor=?,last_poll=?,error=? WHERE id=?',
                               (offset, identity, generation, anchor, utcnow(), json.dumps(rejected[:10]) if rejected else '', source['id']))
                results['sources'] += 1
            except Exception as error:
                results['errors'].append({'source': str(path), 'error': str(error)})
                with self.workspace.connect() as db:
                    db.execute('UPDATE log_sources SET last_poll=?,error=? WHERE id=?', (utcnow(), str(error), source['id']))
        return results

    def export_incident(self, incident_id, destination):
        Path(destination).write_text(json.dumps(self.incident_detail(incident_id), indent=2, ensure_ascii=False), encoding='utf-8')

    def export_incident_bundle(self, incident_id):
        detail = self.incident_detail(incident_id)
        incident = detail['incident']
        findings = []
        for alert in detail['alerts']:
            data = json.loads(alert['data'])
            findings.append({'fingerprint': alert['id'], 'title': data['title'], 'severity': alert['severity'],
                             'confidence': 'rule match; attack unconfirmed', 'status': incident['state'],
                             'evidence': {'explanation': data['explanation'], 'first_event': alert['first_at'],
                                          'last_event': alert['last_at'], 'risk_weight': alert['score']},
                             'recommendation': 'Validate the event timeline, source identity and linked scan context; document the investigation outcome.'})
        return self.workspace.export_bundle({'id': 'incident_' + incident_id, 'timestamp': utcnow(), 'module': 'incident',
            'target': incident['asset'], 'status': incident['state'], 'findings': findings, 'raw': detail})

    def run_playbook(self, incident_id, playbook):
        """Internal analyst workflows only: no remote actions or shell execution."""
        detail = self.incident_detail(incident_id)
        item = detail['incident']
        if playbook == 'triage':
            note = 'Triage checklist: verify event provenance and timezone; review timeline; confirm source IP/user; inspect linked scan evidence; document disposition. Automatic containment was not performed.'
            self.update_incident(incident_id, 'Investigating', item['owner'], note)
            return note
        if playbook == 'evidence':
            directory = self.workspace.root / 'incident_exports'
            directory.mkdir(exist_ok=True)
            destination = directory / (incident_id + '.json')
            self.export_incident(incident_id, destination)
            return 'Evidence exported to ' + str(destination)
        raise ValueError('Unknown playbook')
