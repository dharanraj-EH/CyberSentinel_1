"""Real local HTTP fixtures exercise safe, vulnerable and inconclusive checks."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import urlsplit, parse_qs
import pytest
import requests
from cybersentinel.services.web_assessment import WebSecurityTester


@pytest.fixture
def server():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            path = urlsplit(self.path)
            if path.path == '/redirect':
                self.send_response(302)
                self.send_header('Location', 'http://outside.invalid/')
                self.end_headers()
                return
            probe = parse_qs(path.query).get('q', [''])[0]
            if path.path == '/sql' and "'" in probe:
                self.send_response(500)
                body = 'SQL syntax error'
            else:
                self.send_response(200)
                body = 'Hello' if path.path == '/safe' else probe
            self.send_header('Content-Type', 'text/html')
            if path.path == '/safe':
                self.send_header('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'")
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.send_header('Referrer-Policy', 'strict-origin')
            self.end_headers()
            self.wfile.write(body.encode())
    instance = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = Thread(target=instance.serve_forever, daemon=True)
    worker.start()
    yield 'http://127.0.0.1:' + str(instance.server_port)
    instance.shutdown()
    instance.server_close()


def test_safe_headers_no_finding(server):
    result = WebSecurityTester().assess('headers', server + '/safe')
    assert result['status'] == 'no_finding'


def test_missing_headers_are_observations(server):
    result = WebSecurityTester().assess('headers', server + '/missing')
    assert result['status'] == 'needs_review'
    assert len(result['evidence']) == 3


def test_redirect_cannot_escape_scope(server):
    with pytest.raises(ValueError, match='outside'):
        WebSecurityTester().fetch(server + '/redirect', follow_redirects=True)


def test_http_500_is_sql_candidate_evidence(server):
    result = WebSecurityTester().assess('sql_injection', server + '/sql?q=hello')
    assert result['vulnerable']
    assert result['confidence'] == 'low'
    assert result['status'] == 'needs_review'


def test_html_reflection_is_not_confirmed_xss(server):
    result = WebSecurityTester().assess('reflected_xss', server + '/reflect?q=hello')
    assert result['vulnerable']
    assert 'script execution not tested' in result['details']


def test_scope_applies_to_every_request(server):
    tester = WebSecurityTester()
    tester.fetch(server + '/safe')
    with pytest.raises(ValueError):
        tester.fetch('http://outside.invalid/')
