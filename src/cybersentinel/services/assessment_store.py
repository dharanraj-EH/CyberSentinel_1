"""Per-user assessment history and persistent remediation workflow."""
import hashlib
import json
import sqlite3
from contextlib import contextmanager, closing
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


def redact(value):
    if isinstance(value, dict):
        return {key: '[REDACTED]' if any(word in key.lower() for word in ('password', 'cookie', 'authorization', 'secret', 'token')) else redact(item)
                for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def normalize(module, target, data):
    findings = []
    if module == 'network':
        for port in data.get('ports', []):
            if port.get('state') == 'open':
                findings.append({'title': f"{port.get('host', target)}: Open {port.get('protocol', 'tcp')} port {port['port']}",
                                 'severity': 'info', 'confidence': 'high', 'evidence': port,
                                 'recommendation': 'Verify this service is needed and access is restricted.',
                                 'status': 'observed'})
    elif module == 'web':
        for check, result in data.items():
            if isinstance(result, dict) and (result.get('vulnerable') or result.get('error')):
                findings.append({'title': check.replace('_', ' ').title(), 'severity': result.get('severity', 'info'),
                                 'confidence': result.get('confidence', 'unknown'),
                                 'evidence': result.get('evidence', result.get('error', result.get('details'))),
                                 'recommendation': result.get('recommendation', 'Resolve the check failure and reassess.'),
                                 'status': 'error' if result.get('error') else 'needs_review'})
    else:
        for result in data.get('vulnerabilities', []):
            findings.append({'title': result.get('title', result.get('name', result.get('type', 'TLS configuration finding'))),
                             'severity': result.get('severity', 'info'), 'confidence': 'medium', 'evidence': result,
                             'recommendation': result.get('recommendation', result.get('remediation', 'Review TLS configuration.')),
                             'status': 'needs_review'})
    for finding in findings:
        finding['fingerprint'] = hashlib.sha256(f"{module}:{target}:{finding['title']}".encode()).hexdigest()[:24]
    return findings


class AssessmentWorkspace:
    def __init__(self, user_id, root=None):
        self.root = Path(root or Path.home() / '.cybersentinel' / 'workspaces') / str(user_id)
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / 'assessments.db'
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS assessments(id TEXT PRIMARY KEY, timestamp TEXT, module TEXT, target TEXT, status TEXT, data TEXT);
                CREATE TABLE IF NOT EXISTS findings(fingerprint TEXT PRIMARY KEY, owner TEXT DEFAULT '', state TEXT DEFAULT 'Open', note TEXT DEFAULT '', updated TEXT);
                CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, timestamp TEXT, action TEXT, detail TEXT);
            ''')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.db_path)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def record(self, module, target, raw, status='completed'):
        data = redact(raw)
        findings = normalize(module, target, data)
        if status != 'cancelled' and (data.get('error') or any(isinstance(item, dict) and item.get('error') for item in data.values())):
            status = 'partial'
        if module == 'tls' and any(item.get('error') for item in data.get('protocols', {}).values()):
            status = 'partial'
        assessment = {'id': uuid4().hex, 'timestamp': datetime.now(timezone.utc).isoformat(),
                      'module': module, 'target': target, 'status': status, 'findings': findings, 'raw': data}
        with self.connect() as db:
            db.execute('INSERT INTO assessments VALUES(?,?,?,?,?,?)',
                       (assessment['id'], assessment['timestamp'], module, target, status, json.dumps(assessment)))
            for finding in findings:
                db.execute('INSERT OR IGNORE INTO findings(fingerprint) VALUES(?)', (finding['fingerprint'],))
            db.execute('INSERT INTO audit(timestamp,action,detail) VALUES(?,?,?)',
                       (assessment['timestamp'], 'assessment_recorded', assessment['id']))
        return assessment

    def history(self):
        with self.connect() as db:
            return [json.loads(row['data']) for row in db.execute('SELECT data FROM assessments ORDER BY timestamp DESC')]

    def workflow(self, fingerprint):
        with self.connect() as db:
            row = db.execute('SELECT * FROM findings WHERE fingerprint=?', (fingerprint,)).fetchone()
            return dict(row) if row else {'owner': '', 'state': 'Open', 'note': ''}

    def update(self, fingerprint, owner, state, note):
        if state not in ('Open', 'In progress', 'Fixed pending verification', 'False positive', 'Accepted risk'):
            raise ValueError('Invalid workflow state')
        if state in ('False positive', 'Accepted risk') and not note.strip():
            raise ValueError('A reason is required for this state.')
        with self.connect() as db:
            now = datetime.now(timezone.utc).isoformat()
            db.execute('UPDATE findings SET owner=?,state=?,note=?,updated=? WHERE fingerprint=?',
                       (owner, state, note, now, fingerprint))
            db.execute('INSERT INTO audit(timestamp,action,detail) VALUES(?,?,?)', (now, 'workflow_updated', fingerprint + ':' + state))

    def compare(self, current, previous):
        if (current['module'], current['target']) != (previous['module'], previous['target']):
            raise ValueError('Compare assessments of the same target and module.')
        before = {item['fingerprint'] for item in previous['findings']}
        after = {item['fingerprint'] for item in current['findings']}
        complete = current['status'] == previous['status'] == 'completed'
        return {'new': sorted(after - before), 'unchanged': sorted(after & before),
                'not_observed' if complete else 'unverified_missing': sorted(before - after),
                'note': 'Absence requires remediation verification; it is not automatic proof of a fix.'}

    def consolidated(self, target):
        """Combine the most recent result per module for one hostname."""
        from urllib.parse import urlsplit
        def host(value):
            return urlsplit(value if '://' in value else '//' + value).hostname
        selected = {}
        for item in self.history():
            if host(item['target']) == host(target) and item['module'] not in selected:
                selected[item['module']] = item
        findings = []
        for module, item in selected.items():
            findings.extend({**finding, 'source_module': module} for finding in item['findings'])
        return {'id': uuid4().hex, 'timestamp': datetime.now(timezone.utc).isoformat(), 'module': 'unified',
                'target': target, 'status': 'completed' if selected and all(item['status'] == 'completed' for item in selected.values()) else 'partial',
                'findings': findings, 'raw': selected,
                'coverage': 'Latest available module results; timestamps differ. Missing modules were not assessed.'}

    def backup(self, destination):
        """Create a consistent SQLite snapshot and report archive without credentials."""
        import tempfile
        import zipfile
        with tempfile.TemporaryDirectory() as temporary:
            snapshot = Path(temporary) / 'assessments.db'
            with self.connect() as source, closing(sqlite3.connect(snapshot)) as target:
                source.backup(target)
            with zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED) as archive:
                archive.write(snapshot, 'assessments.db')
                if (self.root / 'scope.json').exists():
                    archive.write(self.root / 'scope.json', 'scope.json')
                for path in (self.root / 'reports').rglob('*'):
                    if path.is_file():
                        archive.write(path, path.relative_to(self.root).as_posix())

    def restore(self, source):
        """Validate the archive before replacing local assessment history."""
        import tempfile
        import zipfile
        import shutil
        with tempfile.TemporaryDirectory() as temporary, zipfile.ZipFile(source) as archive:
            staging = Path(temporary)
            if 'assessments.db' not in archive.namelist():
                raise ValueError('Not a CyberSentinel workspace backup')
            if sum(entry.file_size for entry in archive.infolist()) > 200_000_000:
                raise ValueError('Backup exceeds the 200 MB restore limit')
            for entry in archive.infolist():
                path = Path(entry.filename)
                if path.is_absolute() or '..' in path.parts or ':' in entry.filename or '\\' in entry.filename:
                    raise ValueError('Unsafe backup path')
                if entry.filename not in ('assessments.db', 'scope.json') and not entry.filename.startswith('reports/'):
                    raise ValueError('Unexpected backup content')
                resolved = (staging / path).resolve()
                if not resolved.is_relative_to(staging.resolve()):
                    raise ValueError('Backup path escapes staging')
                archive.extract(entry, staging)
            with closing(sqlite3.connect(staging / 'assessments.db')) as db:
                if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                    raise ValueError('Backup database is damaged')
                for table in ('assessments', 'findings', 'audit'):
                    db.execute('SELECT * FROM ' + table + ' LIMIT 1')
            if (staging / 'scope.json').exists():
                policy = json.loads((staging / 'scope.json').read_text())
                from .asset_scope import ScopePolicy
                for entry in policy['approved'] + policy['excluded']:
                    ScopePolicy.parse(entry)
            # Merge report files; unrelated local exports are preserved.
            shutil.copy2(staging / 'assessments.db', self.db_path)
            if (staging / 'scope.json').exists():
                shutil.copy2(staging / 'scope.json', self.root / 'scope.json')
            if (staging / 'reports').exists():
                shutil.copytree(staging / 'reports', self.root / 'reports', dirs_exist_ok=True)

    def export_bundle(self, assessment):
        """Generate matching JSON, escaped HTML and PDF from common evidence."""
        import html
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        directory = self.root / 'reports' / assessment['module'] / assessment['id']
        directory.mkdir(parents=True, exist_ok=True)
        payload = dict(assessment)
        payload['remediation'] = {item['fingerprint']: self.workflow(item['fingerprint']) for item in assessment['findings']}
        (directory / 'report.json').write_text(json.dumps(payload, indent=2), encoding='utf-8')
        sections = [('<h1>CyberSentinel Assessment</h1>'),
                    '<p>' + html.escape(f"{assessment['target']} · {assessment['module']} · {assessment['timestamp']}") + '</p>',
                    '<p>Status: ' + html.escape(assessment['status']) + '. Results cover only checks performed.</p>']
        styles = getSampleStyleSheet()
        story = [Paragraph('CyberSentinel Assessment', styles['Title']),
                 Paragraph(html.escape(assessment['target']), styles['Heading2']),
                 Paragraph(html.escape(f"Module: {assessment['module']} | Status: {assessment['status']} | UTC: {assessment['timestamp']}"), styles['BodyText']), Spacer(1, 16)]
        for finding in assessment['findings']:
            title = html.escape(f"{finding['severity'].upper()} — {finding['title']}")
            evidence = html.escape(json.dumps(finding['evidence'], ensure_ascii=False))
            recommendation = html.escape(finding['recommendation'])
            sections.append(f'<h2>{title}</h2><p>Confidence: {html.escape(finding["confidence"])}</p><pre>{evidence}</pre><p>{recommendation}</p>')
            story.extend([Paragraph(title, styles['Heading2']), Paragraph(evidence, styles['BodyText']),
                          Paragraph('Remediation: ' + recommendation, styles['BodyText']), Spacer(1, 12)])
        if not assessment['findings']:
            story.append(Paragraph('No findings recorded. This does not establish the absence of vulnerabilities.', styles['BodyText']))
        (directory / 'report.html').write_text('<!doctype html><meta charset="utf-8"><title>CyberSentinel Assessment</title><style>body{font:16px system-ui;max-width:1000px;margin:40px auto;color:#172b40}h1,h2{color:#125f68}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#eef4f7;padding:16px}</style>' + ''.join(sections), encoding='utf-8')
        SimpleDocTemplate(str(directory / 'report.pdf'), title='CyberSentinel Assessment').build(story)
        return directory
