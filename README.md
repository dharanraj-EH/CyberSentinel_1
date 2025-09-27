# CyberSentinel

A comprehensive vulnerability scanner with a modern GUI, inspired by Nessus and OpenVAS.

## Features

- Port and service scanning with Nmap integration
- SSL/TLS security analysis
- Software version assessment with CVE database lookup
- Web application security testing
- Professional reporting (PDF, HTML, JSON)
- User-friendly GUI built with PyQt5

## Requirements

- Python 3.8+
- Nmap (for advanced scanning features)
- See `requirements.txt` for Python dependencies

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/cybersentinel.git
   cd cybersentinel
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Install Nmap (required for port scanning):
   - Windows: Download from https://nmap.org/download.html
   - Linux: `sudo apt-get install nmap`
   - macOS: `brew install nmap`

## Usage

```bash
python main.py
```

## License

MIT License - See LICENSE file for details
