"""
SSL/TLS scanner for CyberSentinel.

This module provides functionality to scan and analyze SSL/TLS configurations
of remote servers, including certificate validation, protocol support, and
cipher suite analysis.
"""

import socket
import ssl
import datetime
import concurrent.futures
from typing import Dict, List, Optional, Tuple, Union
import logging
import ipaddress
from pathlib import Path
import json
from enum import Enum

logger = logging.getLogger(__name__)

class SSLScanResult:
    """Container for SSL/TLS scan results."""
    
    def __init__(self, target: str, port: int = 443):
        self.target = target
        self.port = port
        self.ip = None
        self.hostname = None
        self.certificate = None
        self.protocols = {}
        self.ciphers = {}
        self.vulnerabilities = []
        self.start_time = None
        self.end_time = None
        self.error = None
    
    def to_dict(self) -> Dict:
        """Convert the scan results to a dictionary."""
        return {
            'target': self.target,
            'ip': self.ip,
            'hostname': self.hostname,
            'port': self.port,
            'certificate': self.certificate,
            'protocols': self.protocols,
            'ciphers': self.ciphers,
            'vulnerabilities': self.vulnerabilities,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration': (self.end_time - self.start_time).total_seconds() if self.end_time and self.start_time else None,
            'error': self.error
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert the scan results to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

class ProtocolVersion(Enum):
    """SSL/TLS protocol versions."""
    SSLv2 = "SSLv2"
    SSLv3 = "SSLv3"
    TLSv1_0 = "TLSv1.0"
    TLSv1_1 = "TLSv1.1"
    TLSv1_2 = "TLSv1.2"
    TLSv1_3 = "TLSv1.3"

class SSLScanner:
    """SSL/TLS scanner for analyzing server configurations."""
    
    # Known weak ciphers
    WEAK_CIPHERS = [
        'NULL', 'EXP', 'RC4', 'DES', '3DES', 'MD5', 'ANON', 'ADH', 'AECDH', 'CBC',
        'CAMELLIA', 'SEED', 'IDEA', 'PSK', 'SRP', 'KRB5', 'ARIA', 'CHACHA20', 'GCM',
        'CCM', 'POLY1305', 'SHA1', 'SHA256', 'SHA384', 'SHA512', 'AES128', 'AES256',
        'CAMELLIA128', 'CAMELLIA256', 'ARIA128', 'ARIA256', 'CHACHA20-POLY1305',
        'AES128-GCM-SHA256', 'AES256-GCM-SHA384', 'CHACHA20-POLY1305-SHA256'
    ]
    
    # Known vulnerable ciphers
    VULNERABLE_CIPHERS = [
        'SSL_RSA_WITH_RC4_128_MD5', 'SSL_RSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA',
        'TLS_RSA_WITH_AES_256_CBC_SHA', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
        'TLS_DHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'
    ]
    
    def __init__(self, timeout: float = 5.0, max_workers: int = 10):
        """Initialize the SSL/TLS scanner.
        
        Args:
            timeout: Socket connection timeout in seconds.
            max_workers: Maximum number of concurrent workers for scanning.
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.ciphers_info = self._load_ciphers_info()
    
    def scan(
        self,
        target: str,
        port: int = 443,
        protocols: Optional[List[str]] = None,
        check_vulnerabilities: bool = True
    ) -> SSLScanResult:
        """Perform an SSL/TLS scan on the target.
        
        Args:
            target: Target hostname or IP address.
            port: Target port (default: 443).
            protocols: List of protocols to check (e.g., ['TLSv1.2', 'TLSv1.3']).
                     If None, checks all supported protocols.
            check_vulnerabilities: Whether to check for known vulnerabilities.
            
        Returns:
            SSLScanResult object containing the scan results.
        """
        result = SSLScanResult(target, port)
        result.start_time = datetime.datetime.now()
        
        try:
            # Resolve the target to an IP address
            try:
                ipaddress.ip_address(target)
                result.ip = target
                result.hostname = self._reverse_lookup(target) or target
            except ValueError:
                # Not a valid IP, try to resolve hostname
                try:
                    result.ip = socket.gethostbyname(target)
                    result.hostname = target
                except socket.gaierror as e:
                    raise ValueError(f"Could not resolve hostname: {target}") from e
            
            # Check certificate
            result.certificate = self._check_certificate(result.hostname, port)
            
            # Check supported protocols
            if protocols is None:
                protocols = [p.value for p in ProtocolVersion]
            
            # Test each protocol version
            for protocol in protocols:
                try:
                    supported, ciphers = self._check_protocol(
                        result.hostname,
                        port,
                        protocol
                    )
                    result.protocols[protocol] = {
                        'supported': supported,
                        'ciphers': ciphers
                    }
                    
                    # Add to ciphers dictionary
                    for cipher in ciphers:
                        if cipher['name'] not in result.ciphers:
                            result.ciphers[cipher['name']] = cipher
                except Exception as e:
                    logger.error(f"Error checking protocol {protocol}: {e}")
                    result.protocols[protocol] = {
                        'supported': False,
                        'error': str(e)
                    }
            
            # Check for vulnerabilities if requested
            if check_vulnerabilities:
                result.vulnerabilities = self._check_vulnerabilities(result)
            
            result.end_time = datetime.datetime.now()
            return result
            
        except Exception as e:
            result.error = str(e)
            logger.error(f"SSL scan failed: {e}", exc_info=True)
            return result
    
    def _check_certificate(
        self,
        hostname: str,
        port: int
    ) -> Dict:
        """Check the SSL/TLS certificate of the target.
        
        Args:
            hostname: Target hostname.
            port: Target port.
            
        Returns:
            Dictionary containing certificate information.
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((hostname, port), self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Get certificate expiration
                    not_before = datetime.datetime.strptime(
                        cert['notBefore'],
                        '%b %d %H:%M:%S %Y %Z'
                    )
                    not_after = datetime.datetime.strptime(
                        cert['notAfter'],
                        '%b %d %H:%M:%S %Y %Z'
                    )
                    
                    # Check if certificate is expired or will expire soon
                    now = datetime.datetime.now()
                    expires_in = (not_after - now).days
                    is_expired = now > not_after
                    is_expiring_soon = 0 < expires_in <= 30  # 30 days threshold
                    
                    # Get subject and issuer information
                    subject = {k: v for k, v in cert['subject']}
                    issuer = {k: v for k, v in cert['issuer']}
                    
                    # Get SANs (Subject Alternative Names)
                    san = []
                    for ext in cert.get('subjectAltName', []):
                        san.append(f"{ext[0]}: {ext[1]}")
                    
                    return {
                        'subject': subject,
                        'issuer': issuer,
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': not_before.isoformat(),
                        'not_after': not_after.isoformat(),
                        'expires_in_days': expires_in,
                        'is_expired': is_expired,
                        'is_expiring_soon': is_expiring_soon,
                        'signature_algorithm': cert.get('signature_algorithm', ''),
                        'subject_alt_name': san,
                        'ocsp': cert.get('OCSP', []),
                        'ca_issuers': cert.get('caIssuers', []),
                        'cipher': {
                            'name': cipher[0],
                            'version': cipher[1],
                            'bits': cipher[2]
                        },
                        'tls_version': ssock.version(),
                        'compression': ssock.compression()
                    }
                    
        except ssl.SSLError as e:
            if 'CERTIFICATE_VERIFY_FAILED' in str(e):
                # Certificate verification failed, try to get it anyway without verification
                return self._get_unverified_certificate(hostname, port)
            raise
        except Exception as e:
            logger.error(f"Error checking certificate: {e}")
            return {'error': str(e)}
    
    def _get_unverified_certificate(
        self,
        hostname: str,
        port: int
    ) -> Dict:
        """Get certificate information without verification.
        
        Args:
            hostname: Target hostname.
            port: Target port.
            
        Returns:
            Dictionary containing certificate information.
        """
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Get certificate expiration
                    not_before = datetime.datetime.strptime(
                        cert['notBefore'],
                        '%b %d %H:%M:%S %Y %Z'
                    )
                    not_after = datetime.datetime.strptime(
                        cert['notAfter'],
                        '%b %d %H:%M:%S %Y %Z'
                    )
                    
                    # Check if certificate is expired or will expire soon
                    now = datetime.datetime.now()
                    expires_in = (not_after - now).days
                    is_expired = now > not_after
                    is_expiring_soon = 0 < expires_in <= 30  # 30 days threshold
                    
                    # Get subject and issuer information
                    subject = {k: v for k, v in cert['subject']}
                    issuer = {k: v for k, v in cert['issuer']}
                    
                    # Get SANs (Subject Alternative Names)
                    san = []
                    for ext in cert.get('subjectAltName', []):
                        san.append(f"{ext[0]}: {ext[1]}")
                    
                    return {
                        'subject': subject,
                        'issuer': issuer,
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': not_before.isoformat(),
                        'not_after': not_after.isoformat(),
                        'expires_in_days': expires_in,
                        'is_expired': is_expired,
                        'is_expiring_soon': is_expiring_soon,
                        'signature_algorithm': cert.get('signature_algorithm', ''),
                        'subject_alt_name': san,
                        'ocsp': cert.get('OCSP', []),
                        'ca_issuers': cert.get('caIssuers', []),
                        'cipher': {
                            'name': cipher[0],
                            'version': cipher[1],
                            'bits': cipher[2]
                        },
                        'tls_version': ssock.version(),
                        'compression': ssock.compression(),
                        'verification_error': 'Certificate verification failed (untrusted/self-signed)',
                        'verified': False
                    }
                    
        except Exception as e:
            logger.error(f"Error getting unverified certificate: {e}")
            return {'error': str(e), 'verified': False}
    
    def _check_protocol(
        self,
        hostname: str,
        port: int,
        protocol: str
    ) -> Tuple[bool, List[Dict]]:
        """Check if a specific protocol version is supported.
        
        Args:
            hostname: Target hostname.
            port: Target port.
            protocol: Protocol version to check (e.g., 'TLSv1.2').
            
        Returns:
            Tuple of (is_supported, list_of_supported_ciphers)
        """
        try:
            # Map protocol string to ssl.PROTOCOL_* constant
            protocol_map = {
                'SSLv2': ssl.PROTOCOL_SSLv2,
                'SSLv3': ssl.PROTOCOL_SSLv3,
                'TLSv1.0': ssl.PROTOCOL_TLSv1,
                'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
                'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
                'TLSv1.3': ssl.PROTOCOL_TLS
            }
            
            if protocol not in protocol_map:
                raise ValueError(f"Unsupported protocol: {protocol}")
            
            # Skip SSLv2/3 if not available
            if (protocol == 'SSLv2' and not hasattr(ssl, 'PROTOCOL_SSLv2')) or \
               (protocol == 'SSLv3' and not hasattr(ssl, 'PROTOCOL_SSLv3')):
                return False, []
            
            context = ssl.SSLContext(protocol_map[protocol])
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False
            
            # Get list of ciphers for this protocol
            ciphers = self._get_ciphers_for_protocol(protocol)
            
            # Test each cipher
            supported_ciphers = []
            
            for cipher in ciphers:
                try:
                    context.set_ciphers(cipher['name'])
                    with socket.create_connection((hostname, port), self.timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            # If we get here, the cipher is supported
                            cipher_info = cipher.copy()
                            cipher_info['supported'] = True
                            supported_ciphers.append(cipher_info)
                except (ssl.SSLError, socket.error, ConnectionError):
                    # Cipher not supported
                    pass
                except Exception as e:
                    logger.debug(f"Error testing cipher {cipher['name']}: {e}")
            
            return len(supported_ciphers) > 0, supported_ciphers
            
        except Exception as e:
            logger.error(f"Error checking protocol {protocol}: {e}")
            raise
    
    def _get_ciphers_for_protocol(self, protocol: str) -> List[Dict]:
        """Get a list of ciphers for a specific protocol.
        
        Args:
            protocol: Protocol version (e.g., 'TLSv1.2').
            
        Returns:
            List of cipher dictionaries.
        """
        # This is a simplified list; in a real implementation, you'd want a more
        # comprehensive list of ciphers for each protocol
        common_ciphers = [
            'AES256-SHA256', 'AES128-SHA256', 'AES256-SHA', 'AES128-SHA',
            'CAMELLIA256-SHA', 'CAMELLIA128-SHA', 'DES-CBC3-SHA', 'RC4-SHA',
            'RC4-MD5', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_AES_128_GCM_SHA256', 'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES128-GCM-SHA256', 'DHE-RSA-AES256-GCM-SHA384',
            'DHE-RSA-AES128-GCM-SHA256', 'DHE-DSS-AES256-GCM-SHA384',
            'DHE-DSS-AES128-GCM-SHA256', 'ECDHE-RSA-AES256-SHA384',
            'ECDHE-ECDSA-AES256-SHA384', 'ECDHE-RSA-AES128-SHA256',
            'ECDHE-ECDSA-AES128-SHA256', 'DHE-RSA-AES256-SHA256',
            'DHE-DSS-AES256-SHA256', 'DHE-RSA-AES128-SHA256',
            'DHE-DSS-AES128-SHA256', 'ECDH-RSA-AES256-GCM-SHA384',
            'ECDH-ECDSA-AES256-GCM-SHA384', 'ECDH-RSA-AES128-GCM-SHA256',
            'ECDH-ECDSA-AES128-GCM-SHA256', 'AES256-GCM-SHA384',
            'AES128-GCM-SHA256', 'AES256-SHA256', 'AES128-SHA256',
            'CAMELLIA256-SHA256', 'CAMELLIA128-SHA256', 'ECDHE-RSA-AES256-SHA',
            'ECDHE-ECDSA-AES256-SHA', 'ECDHE-RSA-AES128-SHA',
            'ECDHE-ECDSA-AES128-SHA', 'DHE-RSA-AES256-SHA',
            'DHE-DSS-AES256-SHA', 'DHE-RSA-AES128-SHA', 'DHE-DSS-AES128-SHA',
            'ECDH-RSA-AES256-SHA', 'ECDH-ECDSA-AES256-SHA',
            'ECDH-RSA-AES128-SHA', 'ECDH-ECDSA-AES128-SHA', 'AES256-SHA',
            'AES128-SHA', 'CAMELLIA256-SHA', 'CAMELLIA128-SHA', 'DES-CBC3-MD5',
            'SEED-SHA', 'IDEA-CBC-SHA', 'RC2-CBC-MD5', 'RC4-MD5', 'RC4-SHA',
            'DES-CBC-SHA', 'DES-CBC3-SHA', 'EDH-RSA-DES-CBC3-SHA',
            'EDH-DSS-DES-CBC3-SHA', 'EXP-EDH-RSA-DES-CBC-SHA',
            'EXP-EDH-DSS-DES-CBC-SHA', 'EXP-DES-CBC-SHA', 'EXP-RC2-CBC-MD5',
            'EXP-RC4-MD5', 'EXP-RC2-CBC-MD5', 'EXP-RC4-MD5', 'NULL-SHA',
            'NULL-MD5', 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV',
            'TLS_FALLBACK_SCSV'
        ]
        
        # Filter ciphers based on protocol
        # This is a simplified filter; in a real implementation, you'd want to
        # properly map ciphers to protocols based on IANA assignments
        if protocol in ['SSLv2', 'SSLv3']:
            return [{'name': c, 'bits': 0, 'security': 'insecure'} 
                   for c in common_ciphers if 'SSL' in c or 'NULL' in c or 'EXP' in c]
        elif protocol in ['TLSv1.0', 'TLSv1.1']:
            return [{'name': c, 'bits': 0, 'security': 'weak'} 
                   for c in common_ciphers if 'TLS' not in c or 'TLSv1' in c]
        else:  # TLSv1.2, TLSv1.3
            return [{'name': c, 'bits': 0, 'security': 'strong'} 
                   for c in common_ciphers if 'TLS' in c or 'AES' in c or 'CHACHA20' in c]
    
    def _check_vulnerabilities(self, result: SSLScanResult) -> List[Dict]:
        """Check for known SSL/TLS vulnerabilities.
        
        Args:
            result: SSLScanResult object containing scan results.
            
        Returns:
            List of vulnerabilities found.
        """
        vulnerabilities = []
        
        # Check for expired or soon-to-expire certificate
        if 'certificate' in result and result.certificate and 'is_expired' in result.certificate:
            if result.certificate['is_expired']:
                vulnerabilities.append({
                    'id': 'cert_expired',
                    'severity': 'high',
                    'name': 'Expired Certificate',
                    'description': 'The SSL/TLS certificate has expired.',
                    'remediation': 'Renew the certificate as soon as possible.'
                })
            elif result.certificate.get('is_expiring_soon', False):
                vulnerabilities.append({
                    'id': 'cert_expiring_soon',
                    'severity': 'medium',
                    'name': 'Certificate Expiring Soon',
                    'description': f"The SSL/TLS certificate will expire in {result.certificate.get('expires_in_days', 0)} days.",
                    'remediation': 'Renew the certificate before it expires.'
                })
        
        # Check for self-signed certificates
        if 'certificate' in result and result.certificate and 'verified' in result.certificate and not result.certificate['verified']:
            vulnerabilities.append({
                'id': 'self_signed_cert',
                'severity': 'medium',
                'name': 'Self-Signed Certificate',
                'description': 'The server is using a self-signed or untrusted certificate.',
                'remediation': 'Obtain a certificate from a trusted certificate authority (CA).'
            })
        
        # Check for weak protocols
        weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
        for proto in weak_protocols:
            if proto in result.protocols and result.protocols[proto].get('supported', False):
                vulnerabilities.append({
                    'id': f'weak_protocol_{proto.lower()}',
                    'severity': 'high' if proto in ['SSLv2', 'SSLv3'] else 'medium',
                    'name': f'Weak Protocol: {proto}',
                    'description': f'The server supports the weak or deprecated {proto} protocol.',
                    'remediation': f'Disable {proto} and use TLS 1.2 or higher.'
                })
        
        # Check for weak ciphers
        if hasattr(result, 'ciphers'):
            for cipher_name, cipher_info in result.ciphers.items():
                if any(weak in cipher_name for weak in self.WEAK_CIPHERS):
                    vulnerabilities.append({
                        'id': f'weak_cipher_{cipher_name.lower().replace("-", "_")}',
                        'severity': 'high' if 'NULL' in cipher_name or 'EXP' in cipher_name else 'medium',
                        'name': f'Weak Cipher: {cipher_name}',
                        'description': f'The server supports the weak or insecure {cipher_name} cipher.',
                        'remediation': 'Disable weak ciphers and use strong, modern ciphers only.'
                    })
                
                if cipher_name in self.VULNERABLE_CIPHERS:
                    vulnerabilities.append({
                        'id': f'vulnerable_cipher_{cipher_name.lower().replace("-", "_")}',
                        'severity': 'critical',
                        'name': f'Vulnerable Cipher: {cipher_name}',
                        'description': f'The server supports the vulnerable {cipher_name} cipher.',
                        'remediation': f'Immediately disable the {cipher_name} cipher as it is known to be vulnerable to attacks.'
                    })
        
        # Check for common vulnerabilities
        if 'TLSv1.2' in result.protocols and result.protocols['TLSv1.2'].get('supported', False):
            # Check for POODLE (CVE-2014-3566)
            if any('CBC' in cipher and 'SHA' in cipher for cipher in result.protocols['TLSv1.2'].get('ciphers', [])):
                vulnerabilities.append({
                    'id': 'poodle_tls',
                    'severity': 'high',
                    'name': 'POODLE (CVE-2014-3566)',
                    'description': 'The server is vulnerable to the POODLE attack (CVE-2014-3566) which could allow man-in-the-middle attackers to obtain sensitive information.',
                    'remediation': 'Disable SSLv3 and CBC cipher suites in TLS 1.0-1.2.'
                })
            
            # Check for BEAST (CVE-2011-3389)
            if any('CBC' in cipher['name'] for cipher in result.protocols['TLSv1.2'].get('ciphers', [])):
                vulnerabilities.append({
                    'id': 'beast',
                    'severity': 'medium',
                    'name': 'BEAST (CVE-2011-3389)',
                    'description': 'The server is vulnerable to the BEAST attack (CVE-2011-3389) which could allow man-in-the-middle attackers to obtain sensitive information.',
                    'remediation': 'Disable CBC cipher suites in TLS 1.0-1.2 or enable TLS 1.3.'
                })
        
        # Check for Heartbleed (CVE-2014-0160)
        if 'TLSv1.2' in result.protocols and result.protocols['TLSv1.2'].get('supported', False):
            if any('heartbeat' in cipher['name'].lower() for cipher in result.protocols['TLSv1.2'].get('ciphers', [])):
                vulnerabilities.append({
                    'id': 'heartbleed',
                    'severity': 'critical',
                    'name': 'Heartbleed (CVE-2014-0160)',
                    'description': 'The server is vulnerable to the Heartbleed bug (CVE-2014-0160) which could allow attackers to obtain sensitive information from memory.',
                    'remediation': 'Upgrade OpenSSL to version 1.0.1g or later and reissue all certificates.'
                })
        
        return vulnerabilities
    
    def _load_ciphers_info(self) -> Dict:
        """Load information about ciphers from a local database.
        
        Returns:
            Dictionary containing cipher information.
        """
        # In a real implementation, this would load cipher information from a file
        # or database. For now, we'll return an empty dictionary.
        return {}
    
    def _reverse_lookup(self, ip: str) -> Optional[str]:
        """Perform a reverse DNS lookup.
        
        Args:
            ip: IP address to look up.
            
        Returns:
            Hostname if found, None otherwise.
        """
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return None

# Example usage
if __name__ == "__main__":
    import argparse
    import json
    
    # Set up argument parsing
    parser = argparse.ArgumentParser(description='SSL/TLS Scanner')
    parser.add_argument('target', help='Target hostname or IP address')
    parser.add_argument('-p', '--port', type=int, default=443,
                        help='Target port (default: 443)')
    parser.add_argument('-t', '--timeout', type=float, default=5.0,
                        help='Connection timeout in seconds (default: 5.0)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('-o', '--output', help='Output file for JSON results')
    
    args = parser.parse_args()
    
    # Set up logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create a scanner instance
    scanner = SSLScanner(timeout=args.timeout)
    
    # Run the scan
    print(f"Scanning {args.target}:{args.port}...\n")
    
    try:
        result = scanner.scan(args.target, args.port)
        
        # Print summary
        print("=== Scan Results ===")
        print(f"Target: {result.target} ({result.ip})")
        print(f"Hostname: {result.hostname}")
        print(f"Port: {result.port}")
        print(f"Status: {result.status}")
        
        if result.certificate:
            print("\n=== Certificate Information ===")
            cert = result.certificate
            print(f"Subject: {cert.get('subject', {}).get('commonName', 'N/A')}")
            print(f"Issuer: {cert.get('issuer', {}).get('organizationName', 'N/A')}")
            print(f"Valid From: {cert.get('not_before', 'N/A')}")
            print(f"Valid Until: {cert.get('not_after', 'N/A')}")
            print(f"Expires In: {cert.get('expires_in_days', 'N/A')} days")
            print(f"Signature Algorithm: {cert.get('signature_algorithm', 'N/A')}")
            
            if 'subject_alt_name' in cert and cert['subject_alt_name']:
                print("\nSubject Alternative Names:")
                for san in cert['subject_alt_name']:
                    print(f"  - {san}")
        
        # Print supported protocols
        print("\n=== Supported Protocols ===")
        for proto, info in result.protocols.items():
            status = "SUPPORTED" if info.get('supported', False) else "NOT SUPPORTED"
            print(f"{proto}: {status}")
            
            if info.get('ciphers'):
                print(f"  Ciphers ({len(info['ciphers'])}):")
                for cipher in info['ciphers']:
                    print(f"    - {cipher['name']} ({cipher.get('security', 'unknown')})")
        
        # Print vulnerabilities
        if result.vulnerabilities:
            print("\n=== Vulnerabilities ===")
            for i, vuln in enumerate(result.vulnerabilities, 1):
                print(f"\n{i}. {vuln['name']} ({vuln['severity'].upper()})")
                print(f"   Description: {vuln['description']}")
                print(f"   Remediation: {vuln['remediation']}")
        else:
            print("\nNo vulnerabilities found.")
        
        # Save results to file if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(result.to_dict(), f, indent=2)
            print(f"\nResults saved to {args.output}")
        
    except Exception as e:
        print(f"\nError: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
