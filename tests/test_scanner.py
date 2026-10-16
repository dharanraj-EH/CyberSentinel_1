"""Network scanner regression tests; no external targets are contacted."""
from io import StringIO
from threading import Event
from unittest.mock import MagicMock, patch
import socket
import pytest
from cybersentinel.scanner.nmap_engine import NmapScanner
from cybersentinel.scanner.tcp_scanner import SocketScanner


def scanner():
    with patch.object(NmapScanner, '_check_nmap_installed', return_value=True):
        return NmapScanner()


def test_xml_parses_cpe_children(tmp_path):
    xml = tmp_path / 'scan.xml'
    xml.write_text('<nmaprun><host><status state="up"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"><cpe>cpe:/a:apache:http_server:2.4</cpe></service></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>')
    result = scanner()._parse_nmap_xml(str(xml))
    assert result['hosts'][0]['ports'][0]['service']['cpe'] == ['cpe:/a:apache:http_server:2.4']


@pytest.mark.parametrize('target', ['--script=unsafe', 'host another', 'https://example.com'])
def test_rejects_invalid_targets(target):
    with pytest.raises(ValueError):
        scanner().scan(target)


def test_rejects_arbitrary_nmap_options():
    instance = scanner()
    with patch.object(instance, '_check_nmap_installed', return_value=True):
        with pytest.raises(ValueError):
            instance.scan('localhost', arguments='--script=/tmp/arbitrary.nse')


def test_nonzero_exit_never_returns_success():
    process = MagicMock()
    process.stdout = StringIO('permission denied\n')
    process.returncode = 1
    process.poll.return_value = 1
    instance = scanner()
    with patch.object(instance, '_check_nmap_installed', return_value=True), patch('subprocess.Popen', return_value=process):
        with pytest.raises(RuntimeError, match='Nmap failed'):
            instance.scan('localhost', stream=True, on_output=lambda line: None)


def test_tcp_connect_local_listener():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        port = listener.getsockname()[1]
        result = SocketScanner(timeout=.2).scan('127.0.0.1', [port])
    assert result['status'] == 'completed'
    assert result['ports'][0]['state'] == 'open'


def test_cancelled_socket_does_not_connect():
    cancelled = Event()
    cancelled.set()
    with patch('socket.socket') as sock:
        assert SocketScanner(cancel_event=cancelled)._check_port('127.0.0.1', 80) == (False, None)
        sock.assert_not_called()
