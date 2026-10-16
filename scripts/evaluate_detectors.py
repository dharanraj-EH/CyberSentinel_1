"""Reproducible synthetic heuristic benchmark; never contacts external targets."""
import html
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from urllib.parse import urlsplit, parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from cybersentinel.services.web_assessment import WebSecurityTester


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        route = urlsplit(self.path)
        query = parse_qs(route.query).get('q', [''])[0]
        body = '<html><title>Fixture</title></html>'
        status = 200
        if route.path == '/sql-candidate' and "'" in query:
            status, body = 500, 'SQL syntax error'
        if route.path == '/reflect':
            body = query
        if route.path == '/encoded':
            body = html.escape(query)
        if route.path == '/csrf-review':
            body = '<form method="POST"><input name="name"></form>'
        if route.path == '/csrf-token':
            body = '<form method="POST"><input name="csrf_token" value="fixture"></form>'
        self.send_response(status)
        self.send_header('Content-Type', 'text/html')
        if route.path == '/headers-present':
            self.send_header('Content-Security-Policy', "default-src 'self'")
            self.send_header('Referrer-Policy', 'strict-origin')
            self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(body.encode())


def main():
    server = ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
    Thread(target=server.serve_forever, daemon=True).start()
    cases = [('headers', '/headers-present', False), ('headers', '/headers-missing', True),
             ('sql_injection', '/sql-candidate?q=hello', True), ('sql_injection', '/sql-safe?q=hello', False),
             ('reflected_xss', '/reflect?q=hello', True), ('reflected_xss', '/encoded?q=hello', False),
             ('csrf', '/csrf-review', True), ('csrf', '/csrf-token', False)]
    outcomes = []
    started = time.perf_counter()
    try:
        for check, route, expected in cases:
            check_start = time.perf_counter()
            try:
                result = WebSecurityTester().assess(check, f'http://127.0.0.1:{server.server_port}' + route)
                outcomes.append({'check': check, 'fixture': route.split('?')[0], 'expected_review': expected,
                                 'observed_review': result['vulnerable'], 'confidence': result['confidence'],
                                 'duration_ms': round((time.perf_counter() - check_start) * 1000, 2)})
            except Exception as error:
                outcomes.append({'check': check, 'expected_review': expected, 'error': str(error)})
    finally:
        server.shutdown()
        server.server_close()
    eligible = [item for item in outcomes if 'error' not in item]
    tp = sum(item['expected_review'] and item['observed_review'] for item in eligible)
    fp = sum(not item['expected_review'] and item['observed_review'] for item in eligible)
    fn = sum(item['expected_review'] and not item['observed_review'] for item in eligible)
    tn = sum(not item['expected_review'] and not item['observed_review'] for item in eligible)
    report = {'scope': 'Eight synthetic loopback fixtures; measures heuristic review flags, not exploit detection or production accuracy.',
              'true_positive': tp, 'false_positive': fp, 'false_negative': fn, 'true_negative': tn,
              'errors': len(outcomes) - len(eligible), 'precision': tp / (tp + fp) if tp + fp else None,
              'recall': tp / (tp + fn) if tp + fn else None,
              'duration_seconds': round(time.perf_counter() - started, 3), 'cases': outcomes}
    destination = Path('.artifacts/verification')
    destination.mkdir(parents=True, exist_ok=True)
    (destination / 'detector-evaluation.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({key: value for key, value in report.items() if key != 'cases'}, indent=2))
    return 1 if report['errors'] or fp or fn else 0


if __name__ == '__main__':
    raise SystemExit(main())
