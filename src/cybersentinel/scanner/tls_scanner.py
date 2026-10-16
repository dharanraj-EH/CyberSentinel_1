"""
SSL/TLS scanner for CyberSentinel.

This module provides functionality to scan and analyze SSL/TLS configurations
of remote servers, including certificate validation, protocol support, and
cipher suite analysis.
"""

import socket
from threading import Event
import ssl
import datetime
import concurrent.futures
from typing import Dict, List, Optional, Tuple, Union, Any
import logging
import ipaddress
from pathlib import Path
import json
from enum import Enum
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import ExtensionOID

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
        # Obsolete/weak or anonymous/export ciphers
        'NULL', 'EXP', 'RC4', 'DES', '3DES', 'MD5', 'ANON', 'ADH', 'AECDH',
        # Non-AEAD CBC suites are considered weaker compared to GCM/CHACHA20
        'CBC',
        # Legacy algorithms rarely used today
        'CAMELLIA', 'SEED', 'IDEA', 'RC2',
        # SHA1 in cipher name indicates non-AEAD HMAC-SHA1
        'SHA1'
    ]
    
    # Known vulnerable ciphers
    VULNERABLE_CIPHERS = [
        'SSL_RSA_WITH_RC4_128_MD5', 'SSL_RSA_WITH_RC4_128_SHA', 'TLS_RSA_WITH_AES_128_CBC_SHA',
        'TLS_RSA_WITH_AES_256_CBC_SHA', 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
        'TLS_DHE_RSA_WITH_AES_256_CBC_SHA', 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'
    ]
    
    def __init__(self, timeout: float = 5.0, max_workers: int = 10, cancel_event=None):
        """Initialize the SSL/TLS scanner.
        
        Args:
            timeout: Socket connection timeout in seconds.
            max_workers: Maximum number of concurrent workers for scanning.
        """
        self.cancel_event = cancel_event or Event()
        self.timeout = timeout
        self.max_workers = max_workers
        self.ciphers_info = self._load_ciphers_info()
    
    def _load_ciphers_info(self) -> Dict[str, Any]:
        """Load cipher suite information and classifications.
        
        Returns:
            Dictionary containing cipher information and security classifications.
        """
        return {
            'weak_ciphers': [
                'NULL', 'aNULL', 'eNULL', 'EXPORT', 'DES', '3DES', 'MD5', 'PSK',
                'SRP', 'KRB5', 'RC4', 'RC2', 'IDEA', 'SEED', 'ADH', 'AECDH'
            ],
            'medium_ciphers': [
                'AES128', 'CAMELLIA128', 'ARIA128'
            ],
            'strong_ciphers': [
                'AES256', 'CAMELLIA256', 'ARIA256', 'CHACHA20', 'POLY1305'
            ],
            'weak_protocols': [
                'SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'
            ],
            'secure_protocols': [
                'TLSv1.2', 'TLSv1.3'
            ]
        }
    
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
        result.start_time = datetime.datetime.now(datetime.timezone.utc)
        
        try:
            # Resolve the target to an IP address
            try:
                ipaddress.ip_address(target)
                result.ip = target
                result.hostname = target
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
                if self.cancel_event.is_set():
                    raise RuntimeError('Assessment cancelled')
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
                        'supported': None,
                        'error': str(e)
                    }
            
            # Check for vulnerabilities if requested
            if check_vulnerabilities:
                result.vulnerabilities = self._check_vulnerabilities(result)
            
            result.end_time = datetime.datetime.now(datetime.timezone.utc)
            return result
            
        except Exception as e:
            result.end_time = datetime.datetime.now(datetime.timezone.utc)
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
                    der = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()

                    cert = x509.load_der_x509_certificate(der, default_backend())
                    now = datetime.datetime.now(datetime.timezone.utc)
                    not_before = cert.not_valid_before_utc
                    not_after = cert.not_valid_after_utc
                    expires_in = (not_after - now).days
                    is_expired = now > not_after
                    is_expiring_soon = 0 < expires_in <= 30

                    subject_dict = {attr.oid._name: attr.value for attr in cert.subject}
                    issuer_dict = {attr.oid._name: attr.value for attr in cert.issuer}

                    # SANs
                    san_list: List[str] = []
                    hostname_matches = False
                    try:
                        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
                        dns_names = san.get_values_for_type(x509.DNSName)
                        ip_names = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
                        san_list = [*dns_names, *ip_names]
                        # simple match
                        for name in dns_names:
                            if _hostname_matches(hostname, name):
                                hostname_matches = True
                                break
                        if not hostname_matches and hostname in ip_names:
                            hostname_matches = True
                    except x509.ExtensionNotFound:
                        san_list = []

                    # Public key details
                    pubkey = cert.public_key()
                    key_type = type(pubkey).__name__
                    key_size = getattr(pubkey, 'key_size', None)
                    if isinstance(pubkey, ec.EllipticCurvePublicKey):
                        key_type = f"EC ({pubkey.curve.name})"
                        key_size = pubkey.key_size
                    elif isinstance(pubkey, rsa.RSAPublicKey):
                        key_type = "RSA"
                    sig_hash = getattr(cert.signature_hash_algorithm, 'name', None)

                    is_self_signed = cert.issuer == cert.subject

                    return {
                        'subject': subject_dict,
                        'issuer': issuer_dict,
                        'version': getattr(cert, 'version', None).name if getattr(cert, 'version', None) else None,
                        'serial_number': format(cert.serial_number, 'x').upper(),
                        'not_before': not_before.isoformat(),
                        'not_after': not_after.isoformat(),
                        'expires_in_days': expires_in,
                        'is_expired': is_expired,
                        'is_expiring_soon': is_expiring_soon,
                        'signature_algorithm': sig_hash or '',
                        'subject_alt_name': san_list,
                        'ocsp': [],
                        'ca_issuers': [],
                        'public_key_type': key_type,
                        'key_size': key_size,
                        'tls_version': ssock.version(),
                        'cipher': {
                            'name': cipher[0],
                            'version': cipher[1],
                            'bits': cipher[2]
                        },
                        'verified': True,
                        'self_signed': bool(is_self_signed),
                        'hostname_matches': bool(hostname_matches) if san_list else True,
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
                    der = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    cert = x509.load_der_x509_certificate(der, default_backend())

                    now = datetime.datetime.now(datetime.timezone.utc)
                    not_before = cert.not_valid_before_utc
                    not_after = cert.not_valid_after_utc
                    expires_in = (not_after - now).days
                    is_expired = now > not_after
                    is_expiring_soon = 0 < expires_in <= 30

                    subject_dict = {attr.oid._name: attr.value for attr in cert.subject}
                    issuer_dict = {attr.oid._name: attr.value for attr in cert.issuer}

                    san_list: List[str] = []
                    try:
                        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
                        dns_names = san.get_values_for_type(x509.DNSName)
                        ip_names = [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
                        san_list = [*dns_names, *ip_names]
                    except x509.ExtensionNotFound:
                        pass

                    pubkey = cert.public_key()
                    key_type = type(pubkey).__name__
                    key_size = getattr(pubkey, 'key_size', None)
                    if isinstance(pubkey, ec.EllipticCurvePublicKey):
                        key_type = f"EC ({pubkey.curve.name})"
                        key_size = pubkey.key_size
                    elif isinstance(pubkey, rsa.RSAPublicKey):
                        key_type = "RSA"
                    sig_hash = getattr(cert.signature_hash_algorithm, 'name', None)
                    is_self_signed = cert.issuer == cert.subject

                    return {
                        'subject': subject_dict,
                        'issuer': issuer_dict,
                        'version': getattr(cert, 'version', None).name if getattr(cert, 'version', None) else None,
                        'serial_number': format(cert.serial_number, 'x').upper(),
                        'not_before': not_before.isoformat(),
                        'not_after': not_after.isoformat(),
                        'expires_in_days': expires_in,
                        'is_expired': is_expired,
                        'is_expiring_soon': is_expiring_soon,
                        'signature_algorithm': sig_hash or '',
                        'subject_alt_name': san_list,
                        'ocsp': [],
                        'ca_issuers': [],
                        'public_key_type': key_type,
                        'key_size': key_size,
                        'tls_version': ssock.version(),
                        'cipher': {
                            'name': cipher[0],
                            'version': cipher[1],
                            'bits': cipher[2]
                        },
                        'verification_error': 'Certificate verification failed (untrusted/self-signed)',
                        'verified': False,
                        'self_signed': bool(is_self_signed),
                        'hostname_matches': None,
                    }

        except Exception as e:
            logger.error(f"Error getting unverified certificate: {e}")
            return {'error': str(e), 'verified': False}
    
    def _check_protocol(self, hostname, port, protocol):
        versions = {'TLSv1.0': getattr(ssl.TLSVersion, 'TLSv1', None),
                    'TLSv1.1': getattr(ssl.TLSVersion, 'TLSv1_1', None),
                    'TLSv1.2': ssl.TLSVersion.TLSv1_2,
                    'TLSv1.3': getattr(ssl.TLSVersion, 'TLSv1_3', None)}
        if protocol not in versions or versions[protocol] is None:
            raise RuntimeError('Protocol cannot be tested by the local TLS runtime')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = versions[protocol]
        context.maximum_version = versions[protocol]
        if protocol in ('TLSv1.0', 'TLSv1.1'):
            context.set_ciphers('ALL:@SECLEVEL=0')
        try:
            with socket.create_connection((hostname, port), self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as connection:
                    negotiated = connection.version()
                    if negotiated != protocol:
                        raise RuntimeError('Unexpected negotiated protocol: ' + str(negotiated))
                    name, _, bits = connection.cipher()
                    return True, [{'name': name, 'bits': bits, 'protocol': negotiated,
                                   'supported': True, 'coverage': 'negotiated sample; not exhaustive'}]
        except ssl.SSLError as error:
            reason = str(error).upper()
            if any(value in reason for value in ('NO_CIPHERS_AVAILABLE', 'NO_PROTOCOLS_AVAILABLE', 'UNSUPPORTED_PROTOCOL')):
                raise RuntimeError('Local runtime cannot test this protocol: ' + str(error)) from error
            if 'TLSV1_ALERT_PROTOCOL_VERSION' in reason:
                return False, []
            raise RuntimeError('Handshake failed; protocol support is inconclusive: ' + str(error)) from error

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
        if result.certificate and 'is_expired' in result.certificate:
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
        
        # Check for self-signed/unverified certificates
        if result.certificate and ('verified' in result.certificate) and not result.certificate['verified']:
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
                
        # Check for common vulnerabilities
        if 'TLSv1.2' in result.protocols and result.protocols['TLSv1.2'].get('supported', False):
            # Check for POODLE (in TLS context, misconfiguration leading to CBC issues is rare; treat as informational check)
            if any(('CBC' in c.get('name','')) and ('SHA' in c.get('name','')) for c in result.protocols['TLSv1.2'].get('ciphers', [])):
                vulnerabilities.append({
                    'id': 'poodle_tls',
                    'severity': 'medium',
                    'name': 'CBC ciphers in TLS 1.2',
                    'description': 'CBC ciphers detected under TLS 1.2. Consider preferring AEAD ciphers (GCM/CHACHA20-POLY1305).',
                    'remediation': 'Prefer TLS 1.2 AEAD ciphers or TLS 1.3 where possible.'
                })
            
            # Check for BEAST (relevant to TLS 1.0 clients, but flag if CBC offered)
            if any('CBC' in c.get('name','') for c in result.protocols.get('TLSv1.0', {}).get('ciphers', []) if result.protocols.get('TLSv1.0',{}).get('supported',False)):
                vulnerabilities.append({
                    'id': 'beast',
                    'severity': 'medium',
                    'name': 'BEAST (CVE-2011-3389) risk',
                    'description': 'CBC cipher suites offered under TLS 1.0 can expose BEAST risk for legacy clients.',
                    'remediation': 'Disable TLS 1.0 or ensure clients use 1/n-1 splitting mitigations; prefer TLS 1.2+.'
                })
        
        # Certificate-specific vulnerabilities (signature/hash, key size, SAN, hostname)
        cert = result.certificate or {}
        if cert:
            sig = str(cert.get('signature_algorithm') or '').lower()
            if sig in ('md2', 'md4', 'md5'):
                vulnerabilities.append({
                    'id': 'weak_signature_md5',
                    'severity': 'high',
                    'name': f'Weak signature algorithm ({sig.upper()})',
                    'description': f'The certificate is signed using the weak hash algorithm {sig.upper()}.',
                    'remediation': 'Reissue the certificate using SHA-256 or stronger (e.g., SHA-256/384).'
                })
            elif sig == 'sha1':
                vulnerabilities.append({
                    'id': 'weak_signature_sha1',
                    'severity': 'medium',
                    'name': 'Weak signature algorithm (SHA-1)',
                    'description': 'The certificate is signed using SHA-1 which is deprecated.',
                    'remediation': 'Reissue the certificate using SHA-256 or stronger.'
                })

            pk_type = str(cert.get('public_key_type') or '')
            key_size = cert.get('key_size') or 0
            if 'RSA' in pk_type and key_size and key_size < 2048:
                vulnerabilities.append({
                    'id': 'weak_rsa_key',
                    'severity': 'high',
                    'name': f'Weak RSA key size ({key_size} bits)',
                    'description': 'RSA key size is smaller than 2048 bits.',
                    'remediation': 'Generate a new RSA key with at least 2048 bits (preferably 3072+).'
                })
            if pk_type.startswith('EC') and key_size and key_size < 224:
                vulnerabilities.append({
                    'id': 'weak_ec_key',
                    'severity': 'medium',
                    'name': f'Weak EC key size ({key_size} bits)',
                    'description': 'Elliptic Curve key size is smaller than recommended.',
                    'remediation': 'Use curves like P-256, P-384, or P-521.'
                })

            san = cert.get('subject_alt_name', [])
            if san == []:
                vulnerabilities.append({
                    'id': 'missing_san',
                    'severity': 'low',
                    'name': 'Certificate missing SAN',
                    'description': 'The certificate does not contain a Subject Alternative Name (SAN) extension.',
                    'remediation': 'Include SAN entries (DNS/IP) in the certificate per current standards.'
                })

            if cert.get('hostname_matches') is False:
                vulnerabilities.append({
                    'id': 'hostname_mismatch',
                    'severity': 'high',
                    'name': 'Hostname mismatch',
                    'description': 'The hostname does not match any certificate SANs or CN.',
                    'remediation': 'Reissue the certificate for the correct hostname(s).'
                })

        return vulnerabilities

# --- helpers ---
def _hostname_matches(host: str, pattern: str) -> bool:
    """Basic wildcard hostname match to evaluate SAN patterns like *.example.com"""
    host = host.lower()
    pattern = pattern.lower()
    if pattern.startswith('*.'):
        # wildcard matches one level
        suffix = pattern[1:]
        return host.endswith(suffix) and host.count('.') >= pattern.count('.')
    return host == pattern

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
