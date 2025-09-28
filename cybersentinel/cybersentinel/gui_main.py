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
from .gui.auth_dialogs import LoginDialog, RegistrationDialog
from .auth.auth_manager import AuthManager
from . import __version__, logger

class CyberSentinelApp(QApplication):
    """Main application class for CyberSentinel."""
    
    def __init__(self, argv):
        super().__init__(argv)
        self.setApplicationName("CyberSentinel")
        self.setApplicationVersion(__version__)
        self.setOrganizationName("CyberSentinel")
        self.setStyle('Fusion')  # Use Fusion style for a modern look
        
        # Initialize authentication manager
        self.auth_manager = AuthManager()
        
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
            # Hide splash screen first
            if self.splash:
                self.splash.hide()
            
            # Show authentication dialog
            if not self._authenticate_user():
                self.quit()
                return
            
            # Create and show main window
            self.main_window = MainWindow(self.auth_manager)
            self.main_window.show()
            
            if self.splash:
                self.splash.finish(self.main_window)
                self.splash.deleteLater()
                self.splash = None
                
        except Exception as e:
            import traceback
            logger.critical(f"Failed to initialize UI: {e}", exc_info=True)
            logger.critical(f"Full traceback: {traceback.format_exc()}")
            QMessageBox.critical(
                None,
                "Initialization Error",
                f"Failed to initialize the application: {e}\n\n"
                "Please check the logs for more information."
            )
            self.quit()
    
    def _authenticate_user(self) -> bool:
        """Show authentication dialog and authenticate user.
        
        Returns:
            True if user authenticated successfully, False otherwise.
        """
        try:
            # Show login dialog first
            login_dialog = LoginDialog(self.auth_manager)
            
            # Add registration button to login dialog
            register_button = login_dialog.findChild(object, "register_button")
            if not register_button:
                from PyQt5.QtWidgets import QPushButton
                register_button = QPushButton("New User? Register Here")
                register_button.setObjectName("register_button")
                register_button.setStyleSheet("""
                    QPushButton {
                        background-color: #3498db;
                        color: white;
                        border: none;
                        border-radius: 5px;
                        font-weight: bold;
                        padding: 8px 16px;
                        margin: 5px;
                    }
                    QPushButton:hover {
                        background-color: #2980b9;
                    }
                """)
                register_button.clicked.connect(lambda: self._show_registration(login_dialog))
                
                # Add to login dialog layout
                layout = login_dialog.layout()
                if layout:
                    layout.addWidget(register_button)
            
            result = login_dialog.exec_()
            
            if result == login_dialog.Accepted:
                if self.auth_manager.is_logged_in():
                    user = self.auth_manager.get_current_user()
                    logger.info(f"User authenticated: {user.username}")
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            QMessageBox.critical(
                None,
                "Authentication Error",
                f"An error occurred during authentication: {e}"
            )
            return False
    
    def _show_registration(self, parent_dialog):
        """Show registration dialog."""
        try:
            parent_dialog.hide()
            registration_dialog = RegistrationDialog(self.auth_manager)
            result = registration_dialog.exec_()
            
            if result == registration_dialog.Accepted:
                # Registration successful, show login again
                QMessageBox.information(
                    None,
                    "Registration Complete",
                    "Account created successfully! Please log in with your new credentials."
                )
            
            # Show login dialog again
            parent_dialog.show()
            
        except Exception as e:
            logger.error(f"Registration dialog error: {e}")
            QMessageBox.critical(
                None,
                "Registration Error",
                f"An error occurred during registration: {e}"
            )

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
