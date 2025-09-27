# CyberSentinel

A comprehensive, user-friendly vulnerability scanner with a modern GUI, designed for security professionals and system administrators.

## Features

- **Port & Service Scanning**: Nmap integration with socket-based fallback
- **SSL/TLS Analysis**: Certificate validation, protocol support, and vulnerability detection
- **Web Application Testing**: SQLi, XSS, CSRF, and security header analysis
- **CVE Matching**: Automatic vulnerability detection using NVD database
- **Professional Reporting**: PDF and HTML reports with executive summaries
- **Modern GUI**: Responsive interface with real-time progress updates

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
python -m cybersentinel.gui_main
```

## Project Structure

```
cybersentinel/
├── cybersentinel/         # Main package
│   ├── gui/              # GUI components
│   ├── scanner/          # Port and service scanning
│   ├── web_tests/        # Web application tests
│   ├── cve/              # CVE matching and analysis
│   ├── reporting/        # Report generation
│   └── utils/            # Utility functions
└── tests/                # Unit tests
```

## License

MIT License - See [LICENSE](LICENSE) for details.
