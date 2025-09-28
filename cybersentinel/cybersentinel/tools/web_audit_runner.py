"""
Web audit runner for CyberSentinel.

Runs 4 checks (Security Headers, SQLi, XSS, CSRF) against one or more URLs
and generates JSON, HTML, and PDF reports under:
  %USERPROFILE%\.cybersentinel\reports\web_audit\<target>_<timestamp>

Usage:
  python -m cybersentinel.tools.web_audit_runner --urls <url1> <url2> ...
  python -m cybersentinel.tools.web_audit_runner  # runs with a default demo set
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from ..web_tests import WebSecurityTester  # alias to WebVulnerabilityScanner
from ..reporting.json_report import JSONReportGenerator
from ..reporting.pdf_report import PDFReportGenerator

# HTML is optional; we handle ImportError gracefully at runtime
try:
    from ..reporting.html_report import HTMLReportGenerator
    HAS_HTML = True
except Exception:  # ImportError or template errors
    HTMLReportGenerator = None  # type: ignore
    HAS_HTML = False


DEFAULT_URLS = [
    "http://testphp.vulnweb.com/",
    "https://demo.testfire.net/",
    "https://juice-shop.herokuapp.com/#/",
    "https://www.hackthissite.org/",
    "https://httpbin.org/",
]


def _slugify_host(url: str) -> str:
    p = urlparse(url)
    host = p.netloc or p.path.replace("/", "_")
    return host.replace(":", "-").replace(" ", "_") or "target"


def _now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


def _build_findings_from_scan(scan: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    # 1) Vulnerabilities from scanner
    for v in scan.get("vulnerabilities", []):
        vtype = str(v.get("type", "unknown"))
        sev = str(v.get("severity", "info")).lower()
        title_map = {
            "sql_injection": "SQL Injection",
            "reflected_xss": "Reflected XSS",
            "stored_xss": "Stored XSS",
            "csrf": "Cross-Site Request Forgery (CSRF)",
        }
        title = title_map.get(vtype, vtype.replace("_", " ").title())
        evidence = v.get("evidence") or json.dumps(v, indent=2, ensure_ascii=False)

        findings.append(
            {
                "id": f"WEB-{len(findings)+1:03d}",
                "title": title,
                "severity": sev or "info",
                "description": f"Detected {title} condition during automated testing.",
                "impact": "Potential compromise of application integrity, confidentiality or availability.",
                "recommendation": _recommendation_for_type(vtype),
                "evidence": str(evidence),
                "references": [],
            }
        )

    # 2) Missing/weak security headers -> findings
    sh = scan.get("secure_headers", {}) or {}
    header_specs: List[Tuple[str, str, str, str]] = [
        # (field_key, human title, severity, recommendation)
        (
            "x_frame_options",
            "Missing X-Frame-Options",
            "medium",
            "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN' to mitigate clickjacking.",
        ),
        (
            "x_content_type_options",
            "Missing X-Content-Type-Options",
            "low",
            "Set X-Content-Type-Options to 'nosniff' to prevent MIME sniffing.",
        ),
        (
            "content_security_policy",
            "Missing Content-Security-Policy",
            "medium",
            "Define a strict Content-Security-Policy to mitigate XSS and data injection.",
        ),
        (
            "x_xss_protection",
            "Missing X-XSS-Protection",
            "low",
            "Optionally set X-XSS-Protection for legacy browsers; prefer strong CSP for modern mitigation.",
        ),
        (
            "referrer_policy",
            "Missing Referrer-Policy",
            "low",
            "Define Referrer-Policy (e.g., 'no-referrer' or 'strict-origin-when-cross-origin').",
        ),
        (
            "permissions_policy",
            "Missing Permissions-Policy",
            "low",
            "Define Permissions-Policy (e.g., camera=(), geolocation=()) to restrict features.",
        ),
        (
            "cross_origin_opener_policy",
            "Missing Cross-Origin-Opener-Policy",
            "low",
            "Set COOP (e.g., 'same-origin') to isolate browsing context groups.",
        ),
        (
            "cross_origin_embedder_policy",
            "Missing Cross-Origin-Embedder-Policy",
            "low",
            "Set COEP (e.g., 'require-corp') to opt into cross-origin isolation.",
        ),
        (
            "cross_origin_resource_policy",
            "Missing Cross-Origin-Resource-Policy",
            "low",
            "Set CORP (e.g., 'same-origin') for resource sharing restrictions.",
        ),
    ]

    # Special handling for HSTS: only applicable on HTTPS
    p = urlparse(scan.get("url") or "")
    if p.scheme.lower() == "https":
        header_specs.insert(
            0,
            (
                "strict_transport_security",
                "Missing Strict-Transport-Security (HSTS)",
                "medium",
                "Enable HSTS to enforce HTTPS and prevent downgrade attacks.",
            ),
        )

    for key, title, sev, rec in header_specs:
        meta = sh.get(key) or {}
        present = bool(meta.get("present"))
        if not present:
            findings.append(
                {
                    "id": f"WEB-{len(findings)+1:03d}",
                    "title": title,
                    "severity": sev,
                    "description": f"Security header '{meta.get('header', key)}' was not present in the response.",
                    "impact": "Missing security headers can increase exposure to well-known web attacks.",
                    "recommendation": rec,
                    "evidence": f"Header value: {meta.get('value', '')!r}",
                    "references": [],
                }
            )

    return findings


def _recommendation_for_type(vuln_type: str) -> str:
    if vuln_type == "sql_injection":
        return "Use parameterized queries/ORMs, input validation, and least-privileged DB accounts."
    if vuln_type in ("reflected_xss", "stored_xss"):
        return "Implement output encoding, a strict Content Security Policy, and input validation."
    if vuln_type == "csrf":
        return "Implement anti-CSRF tokens, SameSite cookies, and Origin/Referer validation."
    return "Follow secure coding best practices and relevant OWASP recommendations."


def _severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for f in findings:
        sev = str(f.get("severity", "unknown")).lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def build_report_payload(url: str, scan: Dict[str, Any]) -> Dict[str, Any]:
    findings = _build_findings_from_scan(scan)
    payload: Dict[str, Any] = {
        "scan_id": f"web-{_slugify_host(url)}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        "target": url,
        "scan_type": "web_audit",
        "timestamp": _now_iso(),
        "parameters": {
            "tests": ["security_headers", "sqli", "xss", "csrf"],
            "timeout": scan.get("timeout", 10),
            "verify_ssl": scan.get("verify_ssl", True),
        },
        "findings": findings,
        "summary": {
            "total_findings": len(findings),
            "severity_counts": _severity_counts(findings),
        },
    }
    return payload


def generate_reports(scan_payload: Dict[str, Any], out_dir: Path) -> Dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)

    paths: Dict[str, str] = {}

    # JSON
    json_path = out_dir / "report.json"
    JSONReportGenerator(pretty_print=True, indent=2).generate(scan_payload, json_path)
    paths["json"] = str(json_path)

    # HTML (optional)
    if HAS_HTML and HTMLReportGenerator is not None:
        try:
            html_path = out_dir / "report.html"
            HTMLReportGenerator().generate(scan_payload, html_path)
            paths["html"] = str(html_path)
        except Exception as e:
            print(f"[warn] HTML report generation failed: {e}")
    else:
        print("[warn] HTML report generation unavailable (jinja2/templates missing)")

    # PDF
    pdf_path = out_dir / "report.pdf"
    PDFReportGenerator(title="CyberSentinel Web Audit Report", author="CyberSentinel").generate(
        scan_payload, pdf_path
    )
    paths["pdf"] = str(pdf_path)

    return paths


def run_for_url(url: str, reports_root: Path) -> Dict[str, Any]:
    print(f"\n=== Running web audit for: {url} ===")
    scanner = WebSecurityTester(timeout=10, verify_ssl=True)
    scan = scanner.scan(url, check_sqli=True, check_xss=True, check_csrf=True)

    payload = build_report_payload(url, scan)

    # Output directory
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    out_dir = reports_root / "web_audit" / f"{_slugify_host(url)}_{ts}"

    paths = generate_reports(payload, out_dir)

    counts = payload["summary"]["severity_counts"]
    print(
        f"Findings: total={payload['summary']['total_findings']} | "
        f"Critical={counts.get('critical',0)} High={counts.get('high',0)} "
        f"Medium={counts.get('medium',0)} Low={counts.get('low',0)} Info={counts.get('info',0)}"
    )
    print("Saved:")
    for k, v in paths.items():
        print(f"  - {k.upper()}: {v}")

    return {"url": url, "summary": payload["summary"], "paths": paths}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="CyberSentinel Web Audit Runner (4 checks)")
    parser.add_argument(
        "--urls",
        nargs="*",
        default=DEFAULT_URLS,
        help="List of URLs to test",
    )
    parser.add_argument(
        "--reports-root",
        default=str(Path.home() / ".cybersentinel" / "reports"),
        help="Root directory to save reports",
    )
    args = parser.parse_args(argv)

    reports_root = Path(args.reports_root)
    reports_root.mkdir(parents=True, exist_ok=True)

    results = []
    for url in args.urls:
        try:
            results.append(run_for_url(url, reports_root))
        except Exception as e:
            print(f"[error] Failed for {url}: {e}")

    # Summary JSON print
    print("\n=== Batch Summary ===")
    print(json.dumps(results, indent=2))
    print(f"Reports saved under: {reports_root / 'web_audit'}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
