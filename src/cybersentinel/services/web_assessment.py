"""Bounded, same-origin configuration assessment used by the desktop UI."""
import time
from threading import Event
from urllib.parse import urlsplit, urljoin, parse_qs, urlencode, urlunsplit
import re

import requests
from bs4 import BeautifulSoup


def origin(url):
    parsed = urlsplit(url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Use an HTTP(S) URL without embedded credentials.')
    return parsed.scheme, parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == 'https' else 80)


class WebSecurityTester:
    """Read-only checks. Findings are observations, not exploit confirmation."""
    def __init__(self, cancel_event=None):
        self.cancel_event = cancel_event or Event()
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers['User-Agent'] = 'CyberSentinel/0.2 Desktop Assessment'
        self.scope = None
        self.count = 0
        self.last_request = 0
        self.started = time.monotonic()

    def fetch(self, url, timeout=10, verify_ssl=True, follow_redirects=False, method='GET', tolerate_http_errors=False):
        if self.scope is None:
            self.scope = origin(url)
        for _ in range(6):
            if origin(url) != self.scope:
                raise ValueError('Destination is outside the approved origin.')
            if self.cancel_event.is_set():
                raise RuntimeError('Assessment cancelled')
            if time.monotonic() - self.started > 180:
                raise TimeoutError('Web assessment exceeded the desktop time budget')
            if self.count >= 50:
                raise RuntimeError('Assessment request budget exhausted')
            if self.cancel_event.wait(max(0, .15 - (time.monotonic() - self.last_request))):
                raise RuntimeError('Assessment cancelled')
            self.count += 1
            self.last_request = time.monotonic()
            response = self.session.request(method, url, timeout=min(timeout, 30), verify=verify_ssl,
                                            allow_redirects=False, stream=True)
            try:
                if 300 <= response.status_code < 400:
                    if not follow_redirects:
                        raise RuntimeError('Redirect encountered; enable same-origin redirects to assess the destination.')
                    url = urljoin(url, response.headers.get('Location', ''))
                    continue
                chunks, size = [], 0
                for chunk in response.iter_content(16384):
                    if self.cancel_event.is_set():
                        raise RuntimeError('Assessment cancelled')
                    if time.monotonic() - self.started > 180:
                        raise TimeoutError('Web assessment exceeded the desktop time budget')
                    size += len(chunk)
                    if size > 2_000_000:
                        raise RuntimeError('Response exceeds the 2 MB assessment limit')
                    chunks.append(chunk)
                response._content = b''.join(chunks)
                if not tolerate_http_errors:
                    response.raise_for_status()
                return response
            finally:
                response.close()
        raise RuntimeError('Redirect limit exceeded')

    def assess(self, check, url, **options):
        method = 'OPTIONS' if check == 'http_methods' else 'GET'
        response = self.fetch(url, method=method, tolerate_http_errors=check in ('sql_injection', 'reflected_xss'), **options)
        headers = response.headers
        evidence, recommendation = [], ''
        confidence, severity = 'high', 'low'
        if check in ('sql_injection', 'reflected_xss'):
            parsed = urlsplit(url)
            parameters = parse_qs(parsed.query, keep_blank_values=True)
            if not parameters:
                raise ValueError('Active query checks require an explicit URL query parameter; forms are not submitted.')
            marker = 'CyberSentinelProbe42'
            payload = "'" if check == 'sql_injection' else '<span data-cybersentinel="' + marker + '">' + marker + '</span>'
            sql_errors = re.compile(r'(SQL syntax|unclosed quotation mark|ORA-\d{5}|SQLSTATE\[[^\]]+\]|SQLite error)', re.I)
            baseline_errors = set(sql_errors.findall(response.text))
            for parameter in list(parameters)[:8]:
                changed = dict(parameters)
                changed[parameter] = [payload]
                candidate = urlunsplit(parsed._replace(query=urlencode(changed, doseq=True)))
                tested = self.fetch(candidate, tolerate_http_errors=True, **options)
                if check == 'sql_injection':
                    new_errors = set(sql_errors.findall(tested.text)) - baseline_errors
                    if new_errors:
                        evidence.append('Parameter ' + parameter + ': new database error signature ' + ', '.join(sorted(new_errors)))
                elif payload in tested.text and 'text/html' in tested.headers.get('Content-Type', '').lower():
                    evidence.append('Parameter ' + parameter + ': unencoded HTML marker reflected; script execution not tested.')
            confidence, severity = 'low', 'medium'
            recommendation = 'Manually validate the candidate finding in a controlled environment. Use parameterized SQL and context-aware output encoding.'
        elif check == 'headers':
            missing = [name for name in ('Content-Security-Policy', 'X-Content-Type-Options', 'Referrer-Policy') if not headers.get(name)]
            evidence = ['Missing header: ' + name for name in missing]
            recommendation = 'Configure appropriate browser security headers for this application.'
        elif check == 'cors':
            # A wildcard alone is not proof of an exploitable CORS policy.
            evidence = ['Wildcard CORS with credentials advertised'] if headers.get('Access-Control-Allow-Origin') == '*' and headers.get('Access-Control-Allow-Credentials', '').lower() == 'true' else []
            confidence = 'medium'
            recommendation = 'Review CORS on authenticated endpoints and use explicit trusted origins.'
        elif check == 'clickjacking':
            evidence = ['No framing policy observed'] if not headers.get('X-Frame-Options') and 'frame-ancestors' not in headers.get('Content-Security-Policy', '').lower() else []
            recommendation = 'Set a suitable CSP frame-ancestors policy.'
        elif check == 'csrf':
            soup = BeautifulSoup(response.text, 'html.parser')
            for form in soup.find_all('form'):
                if form.get('method', 'get').lower() == 'post' and not any('csrf' in field.get('name', '').lower() or 'authenticity' in field.get('name', '').lower() for field in form.find_all('input')):
                    evidence.append('POST form without a recognizable anti-CSRF token; other defenses are untested.')
            confidence, severity = 'low', 'medium'
            recommendation = 'Review state-changing routes for token validation, SameSite and Origin checks.'
        elif check in ('csp', 'xss'):
            evidence = ['No Content-Security-Policy observed; this does not confirm XSS.'] if not headers.get('Content-Security-Policy') else []
            recommendation = 'Deploy and validate an application-specific Content Security Policy.'
        elif check == 'hsts':
            evidence = ['HTTPS is not used'] if urlsplit(response.url).scheme != 'https' else (['Missing HSTS header'] if not headers.get('Strict-Transport-Security') else [])
            recommendation = 'Serve over HTTPS and configure HSTS after verifying HTTPS coverage.'
        elif check == 'cookies':
            for cookie in response.cookies:
                if not cookie.secure or not cookie.has_nonstandard_attr('HttpOnly'):
                    evidence.append('Cookie ' + cookie.name + ' lacks Secure or HttpOnly; value redacted.')
            recommendation = 'Set appropriate Secure, HttpOnly and SameSite cookie attributes.'
        elif check == 'http_methods':
            methods = set(headers.get('Allow', '').upper().replace(',', ' ').split())
            evidence = ['Advertised methods require review: ' + ', '.join(sorted(methods & {'TRACE', 'PUT', 'DELETE'}))] if methods & {'TRACE', 'PUT', 'DELETE'} else []
            confidence = 'low'
            recommendation = 'Restrict methods to those needed; validate authorization on write endpoints.'
        elif check == 'directory_listing':
            soup = BeautifulSoup(response.text, 'html.parser')
            title = soup.title.get_text().strip() if soup.title else ''
            evidence = ['Directory index title observed: ' + title[:160]] if title.lower().startswith('index of /') else []
            recommendation = 'Disable directory indexes where they are not explicitly required.'
        elif check == 'server_info':
            evidence = [name + ': ' + headers[name] for name in ('Server', 'X-Powered-By') if headers.get(name)]
            severity = 'info'
            recommendation = 'Review unnecessary software-version disclosure.'
        else:
            raise ValueError('Unsupported assessment check: ' + check)
        return {'vulnerable': bool(evidence), 'status': 'needs_review' if evidence else 'no_finding',
                'severity': severity if evidence else 'info', 'confidence': confidence,
                'details': '\n'.join(evidence) or 'No issue observed by this limited check.',
                'evidence': evidence, 'recommendation': recommendation, 'url': response.url,
                'http_status': response.status_code}

    def __getattr__(self, name):
        if name.startswith('test_'):
            return lambda url, **options: self.assess(name[5:], url, **options)
        raise AttributeError(name)
