"""
Web vulnerability scanner for SQL injection, XSS, and CSRF detection.

This module provides functionality to scan for common web vulnerabilities
including SQL injection, Cross-Site Scripting (XSS), and Cross-Site Request
Forgery (CSRF) vulnerabilities.
"""

import re
import json
import logging
import requests
from typing import Dict, List, Optional, Tuple, Union, Any
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from http.cookies import SimpleCookie

logger = logging.getLogger(__name__)

class WebVulnerabilityScanner:
    """
    Scanner for detecting web application vulnerabilities including
    SQL injection, XSS, and CSRF.
    """
    
    # Common SQL injection test patterns
    SQLI_TEST_PAYLOADS = [
        "' OR '1'='1",
        '" OR "1"="1',
        "' OR 1=1 --",
        '" OR 1=1 --',
        "' OR 'a'='a",
        '" OR "a"="a"',
        "' OR 1=1#",
        '" OR 1=1#',
        "' OR 1=1; --",
        '" OR 1=1; --',
        "' OR 'x'='x",
        '" OR "x"="x"',
        "' OR 'a'='a' OR ''='",
        '" OR "a"="a" OR ""="',
    ]
    
    # Common XSS test payloads
    XSS_TEST_PAYLOADS = [
        "<script>alert('XSS')</script>",
        '"><script>alert("XSS")</script>',
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<iframe src='javascript:alert(\"XSS\")'>",
        "javascript:alert('XSS')",
        "<a href='javascript:alert(\"XSS\")'>click</a>",
        "<img src='x' onerror=alert('XSS')>",
        "<div onmouseover='alert(\"XSS\")'>hover me</div>",
    ]
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = True):
        """
        Initialize the web vulnerability scanner.
        
        Args:
            timeout: Request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        })
    
    def scan(self, url: str, check_sqli: bool = True, check_xss: bool = True, 
             check_csrf: bool = True) -> Dict[str, Any]:
        """
        Scan a URL for web vulnerabilities.
        
        Args:
            url: The URL to scan.
            check_sqli: Whether to check for SQL injection vulnerabilities.
            check_xss: Whether to check for XSS vulnerabilities.
            check_csrf: Whether to check for CSRF vulnerabilities.
            
        Returns:
            Dictionary containing scan results.
        """
        results = {
            'url': url,
            'vulnerabilities': [],
            'forms': [],
            'cookies': {},
            'headers': {},
            'secure_headers': {},
            'timestamp': None,
            'elapsed': 0
        }
        
        try:
            # Initial request to get base page
            response = self._make_request('GET', url)
            if not response:
                results['error'] = 'Failed to fetch the target URL'
                return results
            
            # Parse the response
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract forms
            forms = self._extract_forms(soup, response.url)
            results['forms'] = forms
            
            # Extract cookies and headers
            results['cookies'] = dict(self.session.cookies)
            results['headers'] = dict(response.headers)
            
            # Check for security headers
            results['secure_headers'] = self._check_security_headers(response)
            
            # Check for robots.txt and sitemap.xml
            robots_url = urljoin(url, '/robots.txt')
            robots_response = self._make_request('GET', robots_url)
            if robots_response and robots_response.status_code == 200:
                results['robots_txt'] = robots_response.text
            
            sitemap_url = urljoin(url, '/sitemap.xml')
            sitemap_response = self._make_request('GET', sitemap_url)
            if sitemap_response and sitemap_response.status_code == 200:
                results['sitemap'] = True
            
            # Check for .git directory exposure
            git_url = urljoin(url, '/.git/HEAD')
            git_response = self._make_request('GET', git_url)
            if git_response and git_response.status_code == 200 and 'ref:' in git_response.text:
                results['git_exposed'] = True
            
            # Check for common vulnerabilities
            vulnerabilities = []
            
            if check_sqli:
                sqli_vulns = self.test_sql_injection(url, forms)
                vulnerabilities.extend(sqli_vulns)
            
            if check_xss:
                xss_vulns = self.test_xss(url, forms)
                vulnerabilities.extend(xss_vulns)
            
            if check_csrf:
                csrf_vulns = self.test_csrf(url, forms)
                vulnerabilities.extend(csrf_vulns)
            
            results['vulnerabilities'] = vulnerabilities
            results['timestamp'] = response.headers.get('Date')
            results['elapsed'] = response.elapsed.total_seconds()
            
        except Exception as e:
            logger.error(f"Error during web vulnerability scan: {str(e)}", exc_info=True)
            results['error'] = str(e)
        
        return results
    
    def _make_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Make an HTTP request with error handling.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: URL to request
            **kwargs: Additional arguments to pass to requests.request()
            
        Returns:
            Response object or None if request failed
        """
        try:
            response = self.session.request(
                method=method,
                url=url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                **kwargs
            )
            return response
        except requests.RequestException as e:
            logger.warning(f"Request failed: {str(e)}")
            return None
    
    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """
        Extract forms from a BeautifulSoup object.
        
        Args:
            soup: BeautifulSoup object containing the HTML
            base_url: Base URL for resolving relative form actions
            
        Returns:
            List of form dictionaries
        """
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').upper(),
                'inputs': [],
                'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
                'attributes': {k: v for k, v in form.attrs.items()}
            }
            
            # Resolve relative URLs in form action
            if form_data['action']:
                form_data['action'] = urljoin(base_url, form_data['action'])
            else:
                form_data['action'] = base_url
            
            # Extract input fields
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_type = input_tag.get('type', 'text')
                input_name = input_tag.get('name')
                input_value = input_tag.get('value', '')
                
                if input_tag.name == 'select':
                    # Handle dropdown/select elements
                    options = [opt.get('value', '') for opt in input_tag.find_all('option')]
                    input_data = {
                        'type': 'select',
                        'name': input_name,
                        'value': input_value,
                        'options': options
                    }
                elif input_tag.name == 'textarea':
                    # Handle textarea elements
                    input_data = {
                        'type': 'textarea',
                        'name': input_name,
                        'value': input_value
                    }
                else:
                    # Handle regular input elements
                    input_data = {
                        'type': input_type,
                        'name': input_name,
                        'value': input_value
                    }
                
                # Skip buttons and submit inputs
                if input_type in ['submit', 'button', 'image']:
                    continue
                    
                form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        
        return forms
    
    def _check_security_headers(self, response: requests.Response) -> Dict:
        """
        Check for important security headers.
        
        Args:
            response: Response object to check headers from
            
        Returns:
            Dictionary of security headers and their status
        """
        headers = response.headers
        security_headers = {
            'strict_transport_security': {
                'header': 'Strict-Transport-Security',
                'present': 'Strict-Transport-Security' in headers,
                'value': headers.get('Strict-Transport-Security', '')
            },
            'x_frame_options': {
                'header': 'X-Frame-Options',
                'present': 'X-Frame-Options' in headers,
                'value': headers.get('X-Frame-Options', '')
            },
            'x_xss_protection': {
                'header': 'X-XSS-Protection',
                'present': 'X-XSS-Protection' in headers,
                'value': headers.get('X-XSS-Protection', '')
            },
            'x_content_type_options': {
                'header': 'X-Content-Type-Options',
                'present': 'X-Content-Type-Options' in headers,
                'value': headers.get('X-Content-Type-Options', '')
            },
            'content_security_policy': {
                'header': 'Content-Security-Policy',
                'present': 'Content-Security-Policy' in headers,
                'value': headers.get('Content-Security-Policy', '')
            },
            'referrer_policy': {
                'header': 'Referrer-Policy',
                'present': 'Referrer-Policy' in headers,
                'value': headers.get('Referrer-Policy', '')
            },
            'permissions_policy': {
                'header': 'Permissions-Policy',
                'present': 'Permissions-Policy' in headers,
                'value': headers.get('Permissions-Policy', '')
            },
            'cross_origin_embedder_policy': {
                'header': 'Cross-Origin-Embedder-Policy',
                'present': 'Cross-Origin-Embedder-Policy' in headers,
                'value': headers.get('Cross-Origin-Embedder-Policy', '')
            },
            'cross_origin_opener_policy': {
                'header': 'Cross-Origin-Opener-Policy',
                'present': 'Cross-Origin-Opener-Policy' in headers,
                'value': headers.get('Cross-Origin-Opener-Policy', '')
            },
            'cross_origin_resource_policy': {
                'header': 'Cross-Origin-Resource-Policy',
                'present': 'Cross-Origin-Resource-Policy' in headers,
                'value': headers.get('Cross-Origin-Resource-Policy', '')
            }
        }
        
        return security_headers
    
    def test_sql_injection(self, url: str, forms: List[Dict] = None) -> List[Dict]:
        """
        Test for SQL injection vulnerabilities.
        
        Args:
            url: URL to test
            forms: List of forms to test (if None, will be extracted from the page)
            
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        try:
            # Test URL parameters
            parsed_url = urlparse(url)
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query, keep_blank_values=True)
                
                for param in query_params:
                    for payload in self.SQLI_TEST_PAYLOADS:
                        # Create a copy of the query parameters
                        test_params = query_params.copy()
                        test_params[param] = [payload]
                        
                        # Rebuild the URL with the test parameter
                        test_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed_url._replace(query=test_query))
                        
                        # Make the request
                        response = self._make_request('GET', test_url)
                        if not response:
                            continue
                        
                        # Check for common SQL error messages
                        error_messages = [
                            'SQL syntax', 'MySQL server', 'ORA-', 'PostgreSQL',
                            'SQLite', 'syntax error', 'unclosed', 'unterminated',
                            'syntax error at or near', 'unterminated quoted string',
                            'quoted string not properly terminated', 'unexpected end of SQL command',
                            'SQL command not properly ended', 'unterminated quoted string',
                            'syntax error in your SQL', 'SQL query failed', 'DB2 SQL error',
                            'SQLite/JDBCDriver', 'Microsoft Access Driver', 'ODBC Microsoft Access',
                            'SQL Server Driver', 'SQLException', 'MySQL Error', 'PostgreSql Error',
                            'SQLite Exception', 'syntax error at or near', 'unterminated quoted string',
                            'syntax error or access violation', 'syntax error or missing operator',
                            'warning: mysql_', 'Microsoft OLE DB Provider for SQL Server',
                            'Incorrect syntax near', 'Sintaxis incorrecta cerca de',
                            'Syntax error in string in query expression', 'Unclosed quotation mark',
                            'Unclosed quote', 'Unterminated string constant', 'SQLite.Exception',
                            'SQL error', 'SQLite/JDBC', 'PostgreSQL query failed', 'MySQL Error:'
                        ]
                        
                        # Check if any error message is in the response
                        if any(error.lower() in response.text.lower() for error in error_messages if error):
                            finding = {
                                'type': 'sql_injection',
                                'severity': 'high',
                                'parameter': param,
                                'payload': payload,
                                'url': test_url,
                                'evidence': 'SQL error message found in response'
                            }
                            findings.append(finding)
                            break  # No need to test more payloads for this parameter
            
            # Test form inputs if provided
            if forms is None:
                response = self._make_request('GET', url)
                if response:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    forms = self._extract_forms(soup, url)
            
            for form in forms:
                for input_field in form.get('inputs', []):
                    if input_field['type'] in ['hidden', 'submit', 'button']:
                        continue
                    
                    for payload in self.SQLI_TEST_PAYLOADS:
                        # Prepare form data
                        form_data = {}
                        for field in form['inputs']:
                            if field['name'] == input_field['name']:
                                form_data[field['name']] = payload
                            else:
                                form_data[field['name']] = field.get('value', '')
                        
                        # Submit the form
                        if form['method'].upper() == 'GET':
                            response = self._make_request(
                                'GET',
                                form['action'],
                                params=form_data
                            )
                        else:
                            response = self._make_request(
                                'POST',
                                form['action'],
                                data=form_data
                            )
                        
                        if not response:
                            continue
                        
                        # Check for SQL errors in the response
                        error_messages = [
                            'SQL syntax', 'MySQL server', 'ORA-', 'PostgreSQL',
                            'SQLite', 'syntax error', 'unclosed', 'unterminated',
                            'syntax error at or near', 'unterminated quoted string',
                            'quoted string not properly terminated', 'unexpected end of SQL command',
                            'SQL command not properly ended', 'unterminated quoted string',
                            'syntax error in your SQL', 'SQL query failed', 'DB2 SQL error',
                            'SQLite/JDBCDriver', 'Microsoft Access Driver', 'ODBC Microsoft Access',
                            'SQL Server Driver', 'SQLException', 'MySQL Error', 'PostgreSql Error',
                            'SQLite Exception', 'syntax error at or near', 'unterminated quoted string',
                            'syntax error or access violation', 'syntax error or missing operator',
                            'warning: mysql_', 'Microsoft OLE DB Provider for SQL Server',
                            'Incorrect syntax near', 'Sintaxis incorrecta cerca de',
                            'Syntax error in string in query expression', 'Unclosed quotation mark',
                            'Unclosed quote', 'Unterminated string constant', 'SQLite.Exception',
                            'SQL error', 'SQLite/JDBC', 'PostgreSQL query failed', 'MySQL Error:'
                        ]
                        
                        if any(error.lower() in response.text.lower() for error in error_messages if error):
                            finding = {
                                'type': 'sql_injection',
                                'severity': 'high',
                                'parameter': input_field['name'],
                                'payload': payload,
                                'form_action': form['action'],
                                'form_method': form['method'],
                                'evidence': 'SQL error message found in response'
                            }
                            findings.append(finding)
                            break  # No need to test more payloads for this field
        
        except Exception as e:
            logger.error(f"Error during SQL injection testing: {str(e)}", exc_info=True)
        
        return findings
    
    def test_xss(self, url: str, forms: List[Dict] = None) -> List[Dict]:
        """
        Test for Cross-Site Scripting (XSS) vulnerabilities.
        
        Args:
            url: URL to test
            forms: List of forms to test (if None, will be extracted from the page)
            
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        try:
            # Test URL parameters
            parsed_url = urlparse(url)
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query, keep_blank_values=True)
                
                for param in query_params:
                    for payload in self.XSS_TEST_PAYLOADS:
                        # Create a copy of the query parameters
                        test_params = query_params.copy()
                        test_params[param] = [payload]
                        
                        # Rebuild the URL with the test parameter
                        test_query = urlencode(test_params, doseq=True)
                        test_url = urlunparse(parsed_url._replace(query=test_query))
                        
                        # Make the request
                        response = self._make_request('GET', test_url)
                        if not response:
                            continue
                        
                        # Check if the payload is reflected in the response
                        if payload in response.text:
                            # Check if the payload is properly encoded/escaped
                            is_vulnerable = True
                            
                            # Check for common XSS filtering/encoding
                            if '&lt;script&gt;' in response.text or '&lt;/script&gt;' in response.text:
                                is_vulnerable = False
                            
                            if is_vulnerable:
                                finding = {
                                    'type': 'reflected_xss',
                                    'severity': 'high',
                                    'parameter': param,
                                    'payload': payload,
                                    'url': test_url,
                                    'evidence': 'XSS payload reflected in response without proper encoding'
                                }
                                findings.append(finding)
                                break  # No need to test more payloads for this parameter
            
            # Test form inputs if provided
            if forms is None:
                response = self._make_request('GET', url)
                if response:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    forms = self._extract_forms(soup, url)
            
            for form in forms:
                for input_field in form.get('inputs', []):
                    if input_field['type'] in ['hidden', 'submit', 'button']:
                        continue
                    
                    for payload in self.XSS_TEST_PAYLOADS:
                        # Prepare form data
                        form_data = {}
                        for field in form['inputs']:
                            if field['name'] == input_field['name']:
                                form_data[field['name']] = payload
                            else:
                                form_data[field['name']] = field.get('value', '')
                        
                        # Submit the form
                        if form['method'].upper() == 'GET':
                            response = self._make_request(
                                'GET',
                                form['action'],
                                params=form_data
                            )
                        else:
                            response = self._make_request(
                                'POST',
                                form['action'],
                                data=form_data
                            )
                        
                        if not response:
                            continue
                        
                        # Check if the payload is reflected in the response
                        if payload in response.text:
                            # Check if the payload is properly encoded/escaped
                            is_vulnerable = True
                            
                            # Check for common XSS filtering/encoding
                            if '&lt;script&gt;' in response.text or '&lt;/script&gt;' in response.text:
                                is_vulnerable = False
                            
                            if is_vulnerable:
                                finding = {
                                    'type': 'stored_xss',
                                    'severity': 'high',
                                    'parameter': input_field['name'],
                                    'payload': payload,
                                    'form_action': form['action'],
                                    'form_method': form['method'],
                                    'evidence': 'XSS payload reflected in response without proper encoding'
                                }
                                findings.append(finding)
                                break  # No need to test more payloads for this field
        
        except Exception as e:
            logger.error(f"Error during XSS testing: {str(e)}", exc_info=True)
        
        return findings
    
    def test_csrf(self, url: str, forms: List[Dict] = None) -> List[Dict]:
        """
        Test for Cross-Site Request Forgery (CSRF) vulnerabilities.
        
        Args:
            url: URL to test
            forms: List of forms to test (if None, will be extracted from the page)
            
        Returns:
            List of vulnerability findings
        """
        findings = []
        
        try:
            # Get forms if not provided
            if forms is None:
                response = self._make_request('GET', url)
                if response:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    forms = self._extract_forms(soup, url)
            
            for form in forms:
                # Skip GET forms (CSRF is typically not applicable to GET requests)
                if form['method'].upper() == 'GET':
                    continue
                
                # Check for anti-CSRF tokens
                has_csrf_token = False
                csrf_tokens = []
                
                for input_field in form.get('inputs', []):
                    input_name = input_field.get('name', '').lower()
                    input_value = input_field.get('value', '')
                    
                    # Common CSRF token names
                    csrf_token_names = ['csrf', 'csrf_token', 'csrf-token', 'csrftoken', 'authenticity_token', 'token']
                    
                    if any(token in input_name for token in csrf_token_names) or \
                       (len(input_value) > 16 and not input_value.isalnum()):
                        has_csrf_token = True
                        csrf_tokens.append({
                            'name': input_field.get('name'),
                            'value': input_value
                        })
                
                # Check if the form has a SameSite cookie attribute
                has_samesite_cookie = False
                for cookie in self.session.cookies:
                    if hasattr(cookie, 'get_nonstandard_attr') and cookie.get_nonstandard_attr('samesite'):
                        has_samesite_cookie = True
                        break
                
                # Check for Origin/Referer header validation
                origin_header = self.session.headers.get('Origin', '')
                referer_header = self.session.headers.get('Referer', '')
                
                # Determine if the form is vulnerable
                is_vulnerable = True
                evidence = []
                
                if has_csrf_token:
                    is_vulnerable = False
                    evidence.append('CSRF token found in form')
                
                if has_samesite_cookie:
                    is_vulnerable = False
                    evidence.append('SameSite cookie attribute found')
                
                if origin_header and origin_header != urlparse(url).netloc:
                    is_vulnerable = False
                    evidence.append('Origin header validation detected')
                
                if referer_header and urlparse(referer_header).netloc != urlparse(url).netloc:
                    is_vulnerable = False
                    evidence.append('Referer header validation detected')
                
                if is_vulnerable:
                    finding = {
                        'type': 'csrf',
                        'severity': 'medium',
                        'form_action': form['action'],
                        'form_method': form['method'],
                        'evidence': 'No CSRF protection detected. ' + ' '.join(evidence) if evidence else 'No CSRF protection detected.',
                        'recommendation': 'Implement CSRF tokens, SameSite cookie attribute, and/or Origin/Referer header validation.'
                    }
                    findings.append(finding)
        
        except Exception as e:
            logger.error(f"Error during CSRF testing: {str(e)}", exc_info=True)
        
        return findings

# Example usage
if __name__ == "__main__":
    import argparse
    import json
    
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Web Vulnerability Scanner')
    parser.add_argument('url', help='URL to scan')
    parser.add_argument('--sql', action='store_true', help='Test for SQL injection')
    parser.add_argument('--xss', action='store_true', help='Test for XSS')
    parser.add_argument('--csrf', action='store_true', help='Test for CSRF')
    parser.add_argument('--all', action='store_true', help='Run all tests')
    parser.add_argument('-o', '--output', help='Output file for results (JSON)')
    args = parser.parse_args()
    
    # Determine which tests to run
    test_sql = args.sql or args.all or (not args.xss and not args.csrf)
    test_xss = args.xss or args.all or (not args.sql and not args.csrf)
    test_csrf = args.csrf or args.all or (not args.sql and not args.xss)
    
    # Run the scanner
    scanner = WebVulnerabilityScanner()
    results = scanner.scan(
        args.url,
        check_sqli=test_sql,
        check_xss=test_xss,
        check_csrf=test_csrf
    )
    
    # Print or save results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {args.output}")
    else:
        print(json.dumps(results, indent=2))
