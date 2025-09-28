# CyberSentinel

A comprehensive vulnerability scanner with a modern GUI, inspired by Nessus and OpenVAS.

## Features

- Port and service scanning with Nmap integration (live output stream, parsed XML)
- SSL/TLS security analysis (certificate details, protocol/cipher checks, vuln findings)
- Software version assessment with CVE database lookup (planned)
- Web application security testing (headers, SQLi, XSS, CSRF)
- Professional reporting: PDF, HTML, JSON
- Dashboard with Recent Scans and quick actions
- Reports browser to open/delete saved reports
- User-friendly GUI built with PyQt5
- Port presets: Well-known, Registered, Dynamic/Ephemeral, All

## Requirements

- Python 3.9+
- Nmap (for advanced scanning features)
- See `cybersentinel/requirements.txt` for pinned Python dependencies

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/cybersentinel.git
   cd cybersentinel
   ```

2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   # Windows
   .\venv\Scripts\activate
   pip install --no-cache-dir -r cybersentinel/requirements.txt
   ```

3. Install Nmap (required for port scanning):
   - Windows: Download from https://nmap.org/download.html
   - Linux: `sudo apt-get install nmap`
   - macOS: `brew install nmap`

## Usage

Run the GUI application:

```bash
python -m cybersentinel.cybersentinel.gui_main
```

Alternative (if PYTHONPATH issues):

```bash
python -c "import sys; sys.path.insert(0, '.'); import cybersentinel.cybersentinel.gui_main as g; g.main()"
```

### Tabs overview
- **Dashboard**: Welcome, quick actions, and Recent Scans.
- **Network Scanner**: Nmap/socket scans, live output, tables for Ports/Hosts, Topology, Host Details, and executed command.
- **SSL/TLS Analyzer**: Shows certificate subject/issuer, validity, key size/type, TLS version, cipher, SANs, verification/hostname match, protocols/ciphers, and a Vulnerabilities table with remediation.
- **Web Tests**: Security headers, SQLi, XSS, CSRF checks with progress, results, and details.
- **Reports**: Browses saved reports and opens JSON/HTML/PDF. You can refresh, open folder, or delete.

### Reports location
Reports are saved under the user's home directory:

- Windows: `%USERPROFILE%\.cybersentinel\reports\`
- Linux/macOS: `~/.cybersentinel/reports/`

Categories:
- `network/<target>_<timestamp>/report.{json,html,pdf}` (plus `nmap_output.txt`)
- `web_audit/<target>_<timestamp>/report.{json,html,pdf}`

### Troubleshooting
- If you see `ModuleNotFoundError: No module named 'cryptography'`:
  ```bash
  pip install --no-cache-dir cryptography==41.0.0
  ```
- If PDF generation fails, ensure ReportLab is installed:
  ```bash
  pip install --no-cache-dir reportlab==4.1.0
  ```
- HTML report generation requires Jinja2 and bundled templates. If templates are missing, HTML report is skipped.

## License

MIT License - See LICENSE file for details
