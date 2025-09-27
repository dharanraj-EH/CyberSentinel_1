# Development Guide for CyberSentinel

This guide provides instructions for setting up a development environment for CyberSentinel.

## Prerequisites

- Python 3.8 or higher
- Git
- Nmap (for full functionality)

## Setting Up the Development Environment

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/cybersentinel.git
   cd cybersentinel
   ```

2. **Create and activate a virtual environment**
   ```bash
   # Linux/macOS
   python -m venv venv
   source venv/bin/activate
   
   # Windows
   python -m venv venv
   .\venv\Scripts\activate
   ```

3. **Install development dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -e .
   ```

## Running Tests

Run the test suite with pytest:

```bash
pytest tests/ -v
```

For test coverage report:

```bash
pytest --cov=cybersentinel tests/
```

## NVD API Key

To enable CVE lookups, you'll need an NVD API key:

1. Get an API key from the [NVD API Key Request](https://nvd.nist.gov/developers/request-an-api-key) page.
2. Create a `.env` file in the project root:
   ```
   NVD_API_KEY=your_api_key_here
   ```

## Scan History

Scan history is stored in the following locations:

- **Linux/macOS**: `~/.cybersentinel/scans/`
- **Windows**: `%APPDATA%\CyberSentinel\scans\`

## Logs

Application logs can be found in:

- **Linux/macOS**: `~/.cybersentinel/logs/cybersentinel.log`
- **Windows**: `%APPDATA%\CyberSentinel\logs\cybersentinel.log`

## Packaging with PyInstaller

To create a standalone executable:

1. Install PyInstaller:
   ```bash
   pip install pyinstaller
   ```

2. Build the executable:
   ```bash
   pyinstaller --windowed --name CyberSentinel --icon=assets/icon.ico cybersentinel/gui_main.py
   ```

The executable will be created in the `dist/CyberSentinel` directory.

## Code Style

- Follow PEP 8 style guide
- Use type hints for all function signatures
- Keep lines under 100 characters
- Use docstrings for all public modules, classes, and functions

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
