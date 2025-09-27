"""
Main entry point for the CyberSentinel GUI application.
"""
import sys
import logging
from pathlib import Path
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox, QSplashScreen
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QPixmap, QIcon

# Import local modules
from .gui.main_window import MainWindow
from . import __version__, logger

class CyberSentinelApp(QApplication):
    """Main application class for CyberSentinel."""
    
    def __init__(self, argv):
        super().__init__(argv)
        self.setApplicationName("CyberSentinel")
        self.setApplicationVersion(__version__)
        self.setOrganizationName("CyberSentinel")
        self.setStyle('Fusion')  # Use Fusion style for a modern look
        
        # Set application icon if available
        try:
            from .utils.resource_loader import get_resource_path
            icon_path = get_resource_path("icons/app_icon.png")
            if icon_path.exists():
                self.setWindowIcon(QIcon(str(icon_path)))
        except ImportError:
            logger.warning("Could not load application icon")
        
        # Create and show splash screen
        self.splash = self._create_splash_screen()
        if self.splash:
            self.splash.show()
            QTimer.singleShot(2000, self._init_ui)  # Show splash for 2 seconds
        else:
            self._init_ui()
    
    def _create_splash_screen(self):
        """Create and return a splash screen if resources are available."""
        try:
            from .utils.resource_loader import get_resource_path
            splash_path = get_resource_path("images/splash.png")
            if splash_path.exists():
                pixmap = QPixmap(str(splash_path))
                return QSplashScreen(pixmap, Qt.WindowStaysOnTopHint)
        except (ImportError, Exception) as e:
            logger.debug(f"Could not create splash screen: {e}")
        return None
    
    def _init_ui(self):
        """Initialize the main UI components."""
        try:
            self.main_window = MainWindow()
            self.main_window.show()
            
            if self.splash:
                self.splash.finish(self.main_window)
                self.splash.deleteLater()
                self.splash = None
                
        except Exception as e:
            logger.critical(f"Failed to initialize UI: {e}", exc_info=True)
            QMessageBox.critical(
                None,
                "Initialization Error",
                f"Failed to initialize the application: {e}\n\n"
                "Please check the logs for more information."
            )
            self.quit()

def main():
    """Main entry point for the application."""
    try:
        # Set up high DPI scaling for better display on high-resolution screens
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
        
        app = CyberSentinelApp(sys.argv)
        return app.exec_()
    except Exception as e:
        logger.critical(f"Unhandled exception: {e}", exc_info=True)
        QMessageBox.critical(
            None,
            "Fatal Error",
            f"A critical error occurred: {e}\n\n"
            "The application will now exit. Please check the logs for details."
        )
        return 1

if __name__ == "__main__":
    sys.exit(main())
