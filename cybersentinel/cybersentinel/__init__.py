"""
CyberSentinel - A comprehensive vulnerability scanner with a modern GUI.

This package provides tools for network and web application security scanning,
including port scanning, service detection, SSL/TLS analysis, and web vulnerability
testing.
"""

__version__ = "0.1.0"
__author__ = "Your Name"
__email__ = "your.email@example.com"
__license__ = "MIT"

import logging
import sys
from pathlib import Path

# Configure logging
def setup_logging():
    """Configure application-wide logging."""
    log_dir = Path.home() / ".cybersentinel" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    
    log_file = log_dir / "cybersentinel.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler(sys.stderr)
        ]
    )

# Initialize logging when the package is imported
setup_logging()
logger = logging.getLogger(__name__)
logger.info(f"CyberSentinel v{__version__} initialized")
