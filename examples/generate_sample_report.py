#!/usr/bin/env python3
"""
Example script to demonstrate report generation in CyberSentinel.
"""
import os
import sys
import time
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.parent)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from app.core.report_generator import ReportGenerator

def generate_sample_report():
    """Generate a sample report with test data."""
    # Sample scan data
    scan_data = {
        "scan_id": "SCAN-2023-001",
        "target": "example.com",
        "scan_type": "full",
        "status": "completed",
        "start_time": time.time() - 3600,  # 1 hour ago
        "end_time": time.time(),
        "findings": [
            {
                "name": "TLS 1.0/1.1 Enabled",
                "severity": "High",
                "description": "The server supports TLS 1.0 and/or 1.1, which are considered insecure and should be disabled.",
                "target": "example.com:443",
                "port": 443,
                "protocol": "tcp",
                "service": "https",
                "cvss": 7.5,
                "cve": "CVE-2021-33831",
                "evidence": "TLS 1.0 and 1.1 protocols were detected during the SSL/TLS handshake.",
                "recommendation": "Disable TLS 1.0 and 1.1, and use TLS 1.2 or later.",
                "references": [
                    "https://datatracker.ietf.org/doc/rfc8996/",
                    "https://nvd.nist.gov/vuln/detail/CVE-2021-33831"
                ]
            },
            {
                "name": "Missing Security Headers",
                "severity": "Medium",
                "description": "Important security headers are missing from the HTTP responses.",
                "target": "http://example.com",
                "port": 80,
                "protocol": "tcp",
                "service": "http",
                "cvss": 5.3,
                "evidence": "Missing headers: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Content-Security-Policy.",
                "recommendation": "Add the following security headers to all HTTP responses:\n"
                                "- X-Content-Type-Options: nosniff\n"
                                "- X-Frame-Options: DENY\n"
                                "- X-XSS-Protection: 1; mode=block\n"
                                "- Content-Security-Policy: default-src 'self'",
                "references": [
                    "https://owasp.org/www-project-secure-headers/",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"
                ]
            },
            {
                "name": "Outdated WordPress Version",
                "severity": "Critical",
                "description": "The WordPress installation is outdated and contains known vulnerabilities.",
                "target": "http://example.com/wordpress",
                "port": 80,
                "protocol": "tcp",
                "service": "http",
                "cvss": 9.8,
                "cve": "CVE-2022-21661",
                "evidence": "WordPress version 5.8.1 detected (latest is 6.0+).",
                "recommendation": "Update WordPress to the latest version immediately.",
                "references": [
                    "https://wordpress.org/support/wordpress-version/version-6-0/",
                    "https://nvd.nist.gov/vuln/detail/CVE-2022-21661"
                ]
            },
            {
                "name": "Directory Listing Enabled",
                "severity": "Low",
                "description": "Directory listing is enabled, which may expose sensitive information.",
                "target": "http://example.com/images/",
                "port": 80,
                "protocol": "tcp",
                "service": "http",
                "cvss": 3.5,
                "evidence": "Directory listing is enabled for /images/.",
                "recommendation": "Disable directory listing in the web server configuration.",
                "references": [
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Review_Webserver_Metafiles_for_Information_Leak"
                ]
            }
        ]
    }

    # Configuration for the report generator
    config = {
        'company_name': 'Acme Security',
        'company_website': 'https://acme-security.example.com',
        'company_contact': 'security@acme.example.com'
    }

    # Initialize the report generator
    report_gen = ReportGenerator(config)

    # Generate reports in different formats
    try:
        # HTML Report
        html_report = report_gen.generate_report(
            scan_data,
            report_format='html',
            options={
                'include_exec_summary': True,
                'include_methodology': True,
                'include_findings': True,
                'include_recommendations': True
            }
        )
        print(f"HTML report generated: {html_report}")

        # PDF Report
        pdf_report = report_gen.generate_report(
            scan_data,
            report_format='pdf',
            options={
                'include_exec_summary': True,
                'include_methodology': True,
                'include_findings': True,
                'include_recommendations': True
            }
        )
        print(f"PDF report generated: {pdf_report}")

        # JSON Report
        json_report = report_gen.generate_report(
            scan_data,
            report_format='json',
            options={
                'include_exec_summary': True,
                'include_methodology': True,
                'include_findings': True,
                'include_recommendations': True
            }
        )
        print(f"JSON report generated: {json_report}")

        # Generate just the executive summary
        exec_summary = report_gen.generate_executive_summary(
            scan_data,
            output_format='text'
        )
        print("\nExecutive Summary:")
        print("-" * 50)
        print(exec_summary)

    except Exception as e:
        print(f"Error generating report: {e}", file=sys.stderr)
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(generate_sample_report())
