"""
Web vulnerability scanner module for CyberSentinel.

This module provides functionality to scan for common web vulnerabilities
including SQL injection, XSS, CSRF, and other web application security issues.
"""

from .sql_xss_csrf import WebVulnerabilityScanner
# Backward-compat alias expected by gui.web_tests_tab
WebSecurityTester = WebVulnerabilityScanner

__all__ = ['WebVulnerabilityScanner', 'WebSecurityTester']
