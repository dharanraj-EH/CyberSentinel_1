"""
CVE (Common Vulnerabilities and Exposures) matcher for CyberSentinel.

This module provides functionality to match software versions against known
vulnerabilities from the NVD (National Vulnerability Database).
"""

from .cve_matcher import CVEMatcher, CVEDatabase

__all__ = ['CVEMatcher', 'CVEDatabase']
