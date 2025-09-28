"""
Authentication dialogs for CyberSentinel.
"""

import re
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QLabel, QLineEdit,
    QPushButton, QMessageBox, QGroupBox, QCheckBox, QFrame, QTextEdit,
    QTabWidget, QWidget, QProgressBar
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QPixmap, QIcon
import logging

from ..auth.auth_manager import AuthManager

logger = logging.getLogger(__name__)


class AuthWorker(QThread):
    """Worker thread for authentication operations."""
    
    auth_completed = pyqtSignal(bool, str)  # success, message
    
    def __init__(self, auth_manager: AuthManager, operation: str, **kwargs):
        super().__init__()
        self.auth_manager = auth_manager
        self.operation = operation
        self.kwargs = kwargs
    
    def run(self):
        """Run the authentication operation."""
        try:
            if self.operation == "register":
                success, message = self.auth_manager.register_user(
                    self.kwargs['username'],
                    self.kwargs['email'],
                    self.kwargs['full_name'],
                    self.kwargs['password']
                )
            elif self.operation == "login":
                success, message = self.auth_manager.login(
                    self.kwargs['username_or_email'],
                    self.kwargs['password']
                )
            else:
                success, message = False, "Unknown operation"
            
            self.auth_completed.emit(success, message)
            
        except Exception as e:
            logger.error(f"Auth worker error: {e}")
            self.auth_completed.emit(False, f"Error: {str(e)}")


class RegistrationDialog(QDialog):
    """User registration dialog."""
    
    def __init__(self, auth_manager: AuthManager, parent=None):
        super().__init__(parent)
        self.auth_manager = auth_manager
        self.auth_worker = None
        self.setWindowTitle("CyberSentinel - User Registration")
        self.setFixedSize(450, 600)
        self.setModal(True)
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the UI components."""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Header
        header_label = QLabel("Create Your Account")
        header_font = QFont()
        header_font.setPointSize(18)
        header_font.setBold(True)
        header_label.setFont(header_font)
        header_label.setAlignment(Qt.AlignCenter)
        header_label.setStyleSheet("color: #2c3e50; margin-bottom: 10px;")
        layout.addWidget(header_label)
        
        subtitle_label = QLabel("Join CyberSentinel to access advanced security scanning tools")
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_label.setStyleSheet("color: #7f8c8d; margin-bottom: 20px;")
        layout.addWidget(subtitle_label)
        
        # Registration form
        form_group = QGroupBox("Registration Details")
        form_layout = QFormLayout(form_group)
        form_layout.setSpacing(12)
        
        # Full name
        self.full_name_input = QLineEdit()
        self.full_name_input.setPlaceholderText("Enter your full name")
        self.full_name_input.setMinimumHeight(35)
        form_layout.addRow("Full Name:", self.full_name_input)
        
        # Username
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Choose a username (min. 3 characters)")
        self.username_input.setMinimumHeight(35)
        self.username_input.textChanged.connect(self._validate_username)
        form_layout.addRow("Username:", self.username_input)
        
        # Username validation label
        self.username_validation = QLabel()
        self.username_validation.setStyleSheet("color: #e74c3c; font-size: 11px;")
        form_layout.addRow("", self.username_validation)
        
        # Email
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Enter your email address")
        self.email_input.setMinimumHeight(35)
        self.email_input.textChanged.connect(self._validate_email)
        form_layout.addRow("Email:", self.email_input)
        
        # Email validation label
        self.email_validation = QLabel()
        self.email_validation.setStyleSheet("color: #e74c3c; font-size: 11px;")
        form_layout.addRow("", self.email_validation)
        
        # Password
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Create a password (min. 6 characters)")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setMinimumHeight(35)
        self.password_input.textChanged.connect(self._validate_password)
        form_layout.addRow("Password:", self.password_input)
        
        # Password validation label
        self.password_validation = QLabel()
        self.password_validation.setStyleSheet("color: #e74c3c; font-size: 11px;")
        form_layout.addRow("", self.password_validation)
        
        # Confirm password
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setPlaceholderText("Confirm your password")
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input.setMinimumHeight(35)
        self.confirm_password_input.textChanged.connect(self._validate_confirm_password)
        form_layout.addRow("Confirm Password:", self.confirm_password_input)
        
        # Confirm password validation label
        self.confirm_password_validation = QLabel()
        self.confirm_password_validation.setStyleSheet("color: #e74c3c; font-size: 11px;")
        form_layout.addRow("", self.confirm_password_validation)
        
        layout.addWidget(form_group)
        
        # Terms and conditions
        self.terms_checkbox = QCheckBox("I agree to the Terms of Service and Privacy Policy")
        self.terms_checkbox.setStyleSheet("margin: 10px 0;")
        layout.addWidget(self.terms_checkbox)
        
        # Progress bar (hidden initially)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.register_button = QPushButton("Create Account")
        self.register_button.setMinimumHeight(40)
        self.register_button.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
            }
        """)
        self.register_button.clicked.connect(self._register)
        
        cancel_button = QPushButton("Cancel")
        cancel_button.setMinimumHeight(40)
        cancel_button.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                border: none;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
        """)
        cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(cancel_button)
        button_layout.addWidget(self.register_button)
        layout.addLayout(button_layout)
        
        # Login link
        login_layout = QHBoxLayout()
        login_layout.addStretch()
        login_label = QLabel("Already have an account?")
        login_link = QPushButton("Sign In")
        login_link.setFlat(True)
        login_link.setStyleSheet("color: #3498db; text-decoration: underline; border: none;")
        login_link.clicked.connect(self._show_login)
        login_layout.addWidget(login_label)
        login_layout.addWidget(login_link)
        login_layout.addStretch()
        layout.addLayout(login_layout)
    
    def _validate_username(self):
        """Validate username input."""
        username = self.username_input.text()
        if len(username) < 3 and username:
            self.username_validation.setText("Username must be at least 3 characters long")
        elif not re.match(r'^[a-zA-Z0-9_]+$', username) and username:
            self.username_validation.setText("Username can only contain letters, numbers, and underscores")
        else:
            self.username_validation.setText("")
    
    def _validate_email(self):
        """Validate email input."""
        email = self.email_input.text()
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email) and email:
            self.email_validation.setText("Please enter a valid email address")
        else:
            self.email_validation.setText("")
    
    def _validate_password(self):
        """Validate password input."""
        password = self.password_input.text()
        if len(password) < 6 and password:
            self.password_validation.setText("Password must be at least 6 characters long")
        else:
            self.password_validation.setText("")
        
        # Also validate confirm password if it has content
        if self.confirm_password_input.text():
            self._validate_confirm_password()
    
    def _validate_confirm_password(self):
        """Validate confirm password input."""
        password = self.password_input.text()
        confirm_password = self.confirm_password_input.text()
        if password != confirm_password and confirm_password:
            self.confirm_password_validation.setText("Passwords do not match")
        else:
            self.confirm_password_validation.setText("")
    
    def _is_form_valid(self) -> bool:
        """Check if the form is valid."""
        # Check all fields are filled
        if not all([
            self.full_name_input.text().strip(),
            self.username_input.text().strip(),
            self.email_input.text().strip(),
            self.password_input.text(),
            self.confirm_password_input.text()
        ]):
            return False
        
        # Check validation messages are empty
        if any([
            self.username_validation.text(),
            self.email_validation.text(),
            self.password_validation.text(),
            self.confirm_password_validation.text()
        ]):
            return False
        
        # Check terms accepted
        if not self.terms_checkbox.isChecked():
            return False
        
        return True
    
    def _register(self):
        """Handle registration."""
        if not self._is_form_valid():
            QMessageBox.warning(self, "Validation Error", 
                              "Please fill all fields correctly and accept the terms.")
            return
        
        # Disable form and show progress
        self._set_form_enabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        
        # Start registration in background thread
        self.auth_worker = AuthWorker(
            self.auth_manager,
            "register",
            username=self.username_input.text().strip(),
            email=self.email_input.text().strip(),
            full_name=self.full_name_input.text().strip(),
            password=self.password_input.text()
        )
        self.auth_worker.auth_completed.connect(self._on_registration_complete)
        self.auth_worker.start()
    
    def _on_registration_complete(self, success: bool, message: str):
        """Handle registration completion."""
        self.progress_bar.setVisible(False)
        self._set_form_enabled(True)
        
        if success:
            QMessageBox.information(self, "Registration Successful", message)
            self.accept()
        else:
            QMessageBox.warning(self, "Registration Failed", message)
    
    def _set_form_enabled(self, enabled: bool):
        """Enable or disable form controls."""
        self.full_name_input.setEnabled(enabled)
        self.username_input.setEnabled(enabled)
        self.email_input.setEnabled(enabled)
        self.password_input.setEnabled(enabled)
        self.confirm_password_input.setEnabled(enabled)
        self.terms_checkbox.setEnabled(enabled)
        self.register_button.setEnabled(enabled)
    
    def _show_login(self):
        """Show login dialog."""
        self.reject()
        login_dialog = LoginDialog(self.auth_manager, self.parent())
        login_dialog.exec_()


class LoginDialog(QDialog):
    """User login dialog."""
    
    def __init__(self, auth_manager: AuthManager, parent=None):
        super().__init__(parent)
        self.auth_manager = auth_manager
        self.auth_worker = None
        self.setWindowTitle("CyberSentinel - Sign In")
        self.setFixedSize(400, 350)
        self.setModal(True)
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the UI components."""
        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Header
        header_label = QLabel("Welcome Back")
        header_font = QFont()
        header_font.setPointSize(18)
        header_font.setBold(True)
        header_label.setFont(header_font)
        header_label.setAlignment(Qt.AlignCenter)
        header_label.setStyleSheet("color: #2c3e50; margin-bottom: 10px;")
        layout.addWidget(header_label)
        
        subtitle_label = QLabel("Sign in to your CyberSentinel account")
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_label.setStyleSheet("color: #7f8c8d; margin-bottom: 20px;")
        layout.addWidget(subtitle_label)
        
        # Login form
        form_group = QGroupBox("Sign In")
        form_layout = QFormLayout(form_group)
        form_layout.setSpacing(15)
        
        # Username or email
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username or email address")
        self.username_input.setMinimumHeight(35)
        form_layout.addRow("Username/Email:", self.username_input)
        
        # Password
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setMinimumHeight(35)
        self.password_input.returnPressed.connect(self._login)
        form_layout.addRow("Password:", self.password_input)
        
        layout.addWidget(form_group)
        
        # Progress bar (hidden initially)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.login_button = QPushButton("Sign In")
        self.login_button.setMinimumHeight(40)
        self.login_button.setStyleSheet("""
            QPushButton {
                background-color: #27ae60;
                color: white;
                border: none;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #229954;
            }
            QPushButton:disabled {
                background-color: #bdc3c7;
            }
        """)
        self.login_button.clicked.connect(self._login)
        
        cancel_button = QPushButton("Cancel")
        cancel_button.setMinimumHeight(40)
        cancel_button.setStyleSheet("""
            QPushButton {
                background-color: #95a5a6;
                color: white;
                border: none;
                border-radius: 5px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #7f8c8d;
            }
        """)
        cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(cancel_button)
        button_layout.addWidget(self.login_button)
        layout.addLayout(button_layout)
        
        # Registration link
        register_layout = QHBoxLayout()
        register_layout.addStretch()
        register_label = QLabel("Don't have an account?")
        register_link = QPushButton("Create Account")
        register_link.setFlat(True)
        register_link.setStyleSheet("color: #3498db; text-decoration: underline; border: none;")
        register_link.clicked.connect(self._show_registration)
        register_layout.addWidget(register_label)
        register_layout.addWidget(register_link)
        register_layout.addStretch()
        layout.addLayout(register_layout)
        
        # Set focus to username input
        self.username_input.setFocus()
    
    def _login(self):
        """Handle login."""
        username_or_email = self.username_input.text().strip()
        password = self.password_input.text()
        
        if not username_or_email or not password:
            QMessageBox.warning(self, "Input Error", 
                              "Please enter both username/email and password.")
            return
        
        # Disable form and show progress
        self._set_form_enabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        
        # Start login in background thread
        self.auth_worker = AuthWorker(
            self.auth_manager,
            "login",
            username_or_email=username_or_email,
            password=password
        )
        self.auth_worker.auth_completed.connect(self._on_login_complete)
        self.auth_worker.start()
    
    def _on_login_complete(self, success: bool, message: str):
        """Handle login completion."""
        self.progress_bar.setVisible(False)
        self._set_form_enabled(True)
        
        if success:
            QMessageBox.information(self, "Login Successful", message)
            self.accept()
        else:
            QMessageBox.warning(self, "Login Failed", message)
            self.password_input.clear()
            self.password_input.setFocus()
    
    def _set_form_enabled(self, enabled: bool):
        """Enable or disable form controls."""
        self.username_input.setEnabled(enabled)
        self.password_input.setEnabled(enabled)
        self.login_button.setEnabled(enabled)
    
    def _show_registration(self):
        """Show registration dialog."""
        self.reject()
        registration_dialog = RegistrationDialog(self.auth_manager, self.parent())
        registration_dialog.exec_()


class AuthenticationDialog(QDialog):
    """Main authentication dialog with tabs for login and registration."""
    
    def __init__(self, auth_manager: AuthManager, parent=None):
        super().__init__(parent)
        self.auth_manager = auth_manager
        self.setWindowTitle("CyberSentinel - Authentication")
        self.setFixedSize(500, 650)
        self.setModal(True)
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the UI components."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Create tab widget
        tab_widget = QTabWidget()
        
        # Login tab
        login_widget = QWidget()
        login_dialog = LoginDialog(self.auth_manager)
        login_layout = QVBoxLayout(login_widget)
        login_layout.addWidget(login_dialog)
        tab_widget.addTab(login_widget, "Sign In")
        
        # Registration tab
        register_widget = QWidget()
        register_dialog = RegistrationDialog(self.auth_manager)
        register_layout = QVBoxLayout(register_widget)
        register_layout.addWidget(register_dialog)
        tab_widget.addTab(register_widget, "Create Account")
        
        layout.addWidget(tab_widget)
        
        # Connect dialog acceptance
        login_dialog.accepted.connect(self.accept)
        register_dialog.accepted.connect(self.accept)
