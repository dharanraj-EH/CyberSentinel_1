#!/usr/bin/env python3
"""
CyberSentinel - A comprehensive vulnerability scanner with a modern GUI.
"""
import sys
import os
import logging

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt5.QtWidgets import QApplication
from app.gui.main_window import CyberSentinelMainWindow
from app.core.application import CyberSentinelApp

def setup_logging():
    """Configure application logging."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('cybersentinel.log'),
            logging.StreamHandler()
        ]
    )

def main():
    """Main entry point for the application."""
    # Set up logging
    setup_logging()
    logger = logging.getLogger(__name__)
    
    try:
        # Initialize Qt application
        app = QApplication(sys.argv)
        app.setApplicationName("CyberSentinel")
        app.setApplicationVersion("1.0.0")
        
        # Initialize application core
        core_app = CyberSentinelApp()
        
        # Initialize and show main window
        main_window = CyberSentinelMainWindow(core_app)
        main_window.show()
        
        # Start the application event loop
        sys.exit(app.exec_())
        
    except Exception as e:
        logger.critical(f"Fatal error: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
