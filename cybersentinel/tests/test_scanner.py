"""
Tests for the scanner module.
"""

import unittest
from unittest.mock import patch, MagicMock
import socket
from pathlib import Path

# Import the modules to test
from cybersentinel.scanner.nmap_wrapper import NmapScanner
from cybersentinel.scanner.socket_scanner import SocketScanner


class TestNmapScanner(unittest.TestCase):
    """Test cases for the NmapScanner class."""

    def setUp(self):
        """Set up test fixtures."""
        self.scanner = NmapScanner()

    @patch('cybersentinel.scanner.nmap_wrapper.nmap.PortScanner')
    def test_scan_ports(self, mock_port_scanner):
        """Test scanning ports with Nmap."""
        # Mock the Nmap PortScanner
        mock_scanner = MagicMock()
        mock_port_scanner.return_value = mock_scanner
        
        # Mock the scan results
        mock_scanner.scan.return_value = {
            'scan': {
                '127.0.0.1': {
                    'status': {'state': 'up', 'reason': 'localhost-response'},
                    'tcp': {
                        80: {'state': 'open', 'name': 'http', 'product': 'nginx', 'version': '1.19.5'},
                        443: {'state': 'open', 'name': 'https', 'product': 'OpenSSL', 'version': '1.1.1'}
                    }
                }
            }
        }
        
        # Test the scan
        results = self.scanner.scan('127.0.0.1', '80,443')
        
        # Assertions
        self.assertIn('127.0.0.1', results)
        self.assertIn('tcp', results['127.0.0.1'])
        self.assertIn(80, results['127.0.0.1']['tcp'])
        self.assertEqual(results['127.0.0.1']['tcp'][80]['state'], 'open')


class TestSocketScanner(unittest.TestCase):
    """Test cases for the SocketScanner class."""

    def setUp(self):
        """Set up test fixtures."""
        self.scanner = SocketScanner()

    @patch('socket.socket')
    def test_scan_port_open(self, mock_socket):
        """Test scanning an open port."""
        # Mock the socket connection
        mock_socket.return_value.connect_ex.return_value = 0
        
        # Test the scan
        result = self.scanner.scan('127.0.0.1', [80])
        
        # Assertions
        self.assertEqual(len(result['ports']), 1)
        self.assertEqual(result['ports'][0]['port'], 80)
        self.assertEqual(result['ports'][0]['state'], 'open')

    @patch('socket.socket')
    def test_scan_port_closed(self, mock_socket):
        """Test scanning a closed port."""
        # Mock the socket connection
        mock_socket.return_value.connect_ex.return_value = 1
        
        # Test the scan
        result = self.scanner.scan('127.0.0.1', [9999])
        
        # Assertions
        self.assertEqual(len(result['ports']), 1)
        self.assertEqual(result['ports'][0]['port'], 9999)
        self.assertEqual(result['ports'][0]['state'], 'closed')


class TestSSLScanner(unittest.TestCase):
    """Test cases for the SSLScanner class."""

    @patch('ssl.create_default_context')
    @patch('socket.create_connection')
    def test_ssl_cert_check(self, mock_connect, mock_ssl_context):
        """Test SSL certificate checking."""
        # Mock SSL context and connection
        mock_ssl_context.return_value.wrap_socket.return_value.getpeercert.return_value = {
            'subject': ((('commonName', 'example.com'),),),
            'issuer': ((('organizationName', 'Example CA'),),),
            'notBefore': 'Jan  1 00:00:00 2023 GMT',
            'notAfter': 'Dec 31 23:59:59 2023 GMT',
            'version': 3,
            'serialNumber': '1234567890ABCDEF',
            'subjectAltName': [('DNS', 'example.com')]
        }
        
        # Import here to avoid ssl module patching issues
        from cybersentinel.scanner.ssl_tests import SSLScanner
        
        # Test the SSL scan
        scanner = SSLScanner()
        result = scanner.scan('example.com', 443)
        
        # Assertions
        self.assertIsNotNone(result.certificate)
        self.assertEqual(result.certificate['subject']['commonName'], 'example.com')
        self.assertEqual(result.certificate['issuer']['organizationName'], 'Example CA')


if __name__ == '__main__':
    unittest.main()
