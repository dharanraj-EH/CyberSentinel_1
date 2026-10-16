"""Exercise real scanner transports against temporary loopback fixtures only."""
import json
import socket
import ssl
import tempfile
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cybersentinel.scanner.tcp_scanner import SocketScanner
from cybersentinel.scanner.tls_scanner import SSLScanner
from cybersentinel.scanner.nmap_engine import NmapScanner
from cybersentinel.services.web_assessment import WebSecurityTester


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def handle(self):
        try:
            super().handle()
        except (ConnectionResetError, BrokenPipeError):
            pass
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'<html><title>Local assessment fixture</title></html>')


def main():
    results = {}
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        web = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        Thread(target=web.serve_forever, daemon=True).start()
        port = web.server_port
        results['tcp'] = SocketScanner(timeout=.5).scan('127.0.0.1', [port])
        results['web'] = WebSecurityTester().assess('headers', f'http://127.0.0.1:{port}')
        scanner = NmapScanner()
        if scanner._check_nmap_installed():
            results['nmap'] = scanner.scan('127.0.0.1', str(port), arguments='-sT -T3 -n', output_xml=str(root / 'nmap.xml'), timeout=20)
        web.shutdown()
        web.server_close()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
        now = datetime.now(timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=10)).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), False).sign(key, hashes.SHA256()))
        (root / 'cert.pem').write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        (root / 'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        tls = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(root / 'cert.pem', root / 'key.pem')
        tls.socket = context.wrap_socket(tls.socket, server_side=True)
        Thread(target=tls.serve_forever, daemon=True).start()
        results['tls'] = SSLScanner(timeout=2).scan('localhost', tls.server_port, ['TLSv1.2', 'TLSv1.3']).to_dict()
        tls.shutdown()
        tls.server_close()
    assert results['tcp']['ports'][0]['state'] == 'open'
    assert results['web']['status'] == 'needs_review'
    assert not results['tls']['error'], results['tls']['error']
    assert results['tls']['protocols']['TLSv1.2']['supported']
    output = Path('.artifacts/verification')
    output.mkdir(parents=True, exist_ok=True)
    (output / 'local-assessments.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    print('Real loopback TCP, HTTP, TLS and optional Nmap checks passed.')


if __name__ == '__main__':
    main()
