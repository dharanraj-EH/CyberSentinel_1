"""
Settings widget for CyberSentinel GUI.
"""
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTabWidget, QFormLayout, QCheckBox,
    QSpinBox, QDoubleSpinBox, QFileDialog, QMessageBox,
    QComboBox, QGroupBox, QScrollArea, QTableWidget,
    QTableWidgetItem, QHeaderView, QInputDialog
)
from PyQt5.QtCore import Qt, pyqtSignal
import json
import os
from pathlib import Path

class SettingsWidget(QWidget):
    """Widget for managing application settings."""
    
    settings_changed = pyqtSignal(dict)  # Emitted when settings are saved
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.settings = {}
        self.init_ui()
        self.load_settings()
    
    def init_ui(self):
        """Initialize the user interface."""
        main_layout = QVBoxLayout(self)
        
        # Create a scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Create tabs
        self.general_tab = self.create_general_tab()
        self.scan_tab = self.create_scan_tab()
        self.reporting_tab = self.create_reporting_tab()
        self.integrations_tab = self.create_integrations_tab()
        self.about_tab = self.create_about_tab()
        
        # Add tabs to tab widget
        self.tab_widget.addTab(self.general_tab, "General")
        self.tab_widget.addTab(self.scan_tab, "Scanning")
        self.tab_widget.addTab(self.reporting_tab, "Reporting")
        self.tab_widget.addTab(self.integrations_tab, "Integrations")
        self.tab_widget.addTab(self.about_tab, "About")
        
        # Add tab widget to layout
        scroll_layout.addWidget(self.tab_widget)
        
        # Add buttons
        button_layout = QHBoxLayout()
        
        self.save_btn = QPushButton("Save Settings")
        self.save_btn.clicked.connect(self.save_settings)
        
        self.reset_btn = QPushButton("Reset to Defaults")
        self.reset_btn.clicked.connect(self.reset_to_defaults)
        
        button_layout.addStretch()
        button_layout.addWidget(self.reset_btn)
        button_layout.addWidget(self.save_btn)
        
        # Set up scroll content
        scroll.setWidget(scroll_content)
        
        # Add widgets to main layout
        main_layout.addWidget(scroll)
        main_layout.addLayout(button_layout)
        
        # Apply styles
        self.apply_styles()
    
    def create_general_tab(self) -> QWidget:
        """Create the General settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Appearance group
        appearance_group = QGroupBox("Appearance")
        appearance_layout = QFormLayout()
        
        # Theme selection
        self.theme_combo = QComboBox()
        self.theme_combo.addItem("System Default", "system")
        self.theme_combo.addItem("Light", "light")
        self.theme_combo.addItem("Dark", "dark")
        
        # Font size
        self.font_size = QSpinBox()
        self.font_size.setRange(8, 24)
        self.font_size.setValue(10)
        
        # Add widgets to layout
        appearance_layout.addRow("Theme:", self.theme_combo)
        appearance_layout.addRow("Font Size:", self.font_size)
        
        appearance_group.setLayout(appearance_layout)
        
        # Updates group
        updates_group = QGroupBox("Updates")
        updates_layout = QVBoxLayout()
        
        self.check_updates = QCheckBox("Check for updates on startup")
        self.check_updates.setChecked(True)
        
        self.auto_update = QCheckBox("Automatically download and install updates")
        self.auto_update.setChecked(False)
        
        updates_layout.addWidget(self.check_updates)
        updates_layout.addWidget(self.auto_update)
        updates_group.setLayout(updates_layout)
        
        # Add groups to layout
        layout.addWidget(appearance_group)
        layout.addWidget(updates_group)
        layout.addStretch()
        
        return tab
    
    def create_scan_tab(self) -> QWidget:
        """Create the Scanning settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Nmap settings group
        nmap_group = QGroupBox("Nmap Settings")
        nmap_layout = QFormLayout()
        
        # Nmap path
        self.nmap_path = QLineEdit()
        self.nmap_browse_btn = QPushButton("Browse...")
        self.nmap_browse_btn.clicked.connect(self.browse_nmap_path)
        
        nmap_path_layout = QHBoxLayout()
        nmap_path_layout.addWidget(self.nmap_path)
        nmap_path_layout.addWidget(self.nmap_browse_btn)
        
        # Nmap timing template
        self.nmap_timing = QComboBox()
        self.nmap_timing.addItem("Paranoid (0)", 0)
        self.nmap_timing.addItem("Sneaky (1)", 1)
        self.nmap_timing.addItem("Polite (2)", 2)
        self.nmap_timing.addItem("Normal (3)", 3)
        self.nmap_timing.addItem("Aggressive (4)", 4)
        self.nmap_timing.addItem("Insane (5)", 5)
        self.nmap_timing.setCurrentIndex(3)  # Default to Normal
        
        # Add widgets to layout
        nmap_layout.addRow("Nmap Path:", nmap_path_layout)
        nmap_layout.addRow("Default Timing Template:", self.nmap_timing)
        
        nmap_group.setLayout(nmap_layout)
        
        # Scan options group
        scan_options_group = QGroupBox("Default Scan Options")
        scan_options_layout = QVBoxLayout()
        
        # Default scan options
        self.service_scan = QCheckBox("Service version detection (-sV)")
        self.os_detection = QCheckBox("OS detection (-O)")
        self.script_scan = QCheckBox("Script scanning (-sC)")
        self.aggressive_scan = QCheckBox("Aggressive scan (-A)")
        
        # Default ports
        self.default_ports = QLineEdit("1-1024,3000-5000,8000-10000")
        
        # Add widgets to layout
        scan_options_layout.addWidget(self.service_scan)
        scan_options_layout.addWidget(self.os_detection)
        scan_options_layout.addWidget(self.script_scan)
        scan_options_layout.addWidget(self.aggressive_scan)
        
        scan_options_form = QFormLayout()
        scan_options_form.addRow("Default Ports:", self.default_ports)
        
        scan_options_group.setLayout(scan_options_layout)
        
        # Add groups to layout
        layout.addWidget(nmap_group)
        layout.addWidget(scan_options_group)
        layout.addLayout(scan_options_form)
        layout.addStretch()
        
        return tab
    
    def create_reporting_tab(self) -> QWidget:
        """Create the Reporting settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Report settings group
        report_group = QGroupBox("Report Settings")
        report_layout = QVBoxLayout()
        
        # Report options
        self.auto_generate = QCheckBox("Automatically generate reports after scan")
        self.auto_open = QCheckBox("Open report after generation")
        self.include_timestamp = QCheckBox("Include timestamp in report filename")
        
        # Default report format
        self.default_format = QComboBox()
        self.default_format.addItem("PDF", "pdf")
        self.default_format.addItem("HTML", "html")
        self.default_format.addItem("JSON", "json")
        
        # Default report location
        self.report_location = QLineEdit()
        self.report_browse_btn = QPushButton("Browse...")
        self.report_browse_btn.clicked.connect(self.browse_report_location)
        
        report_location_layout = QHBoxLayout()
        report_location_layout.addWidget(self.report_location)
        report_location_layout.addWidget(self.report_browse_btn)
        
        # Add widgets to layout
        report_layout.addWidget(self.auto_generate)
        report_layout.addWidget(self.auto_open)
        report_layout.addWidget(self.include_timestamp)
        
        report_form = QFormLayout()
        report_form.addRow("Default Format:", self.default_format)
        report_form.addRow("Default Location:", report_location_layout)
        
        report_group.setLayout(report_layout)
        
        # Company information group
        company_group = QGroupBox("Company Information")
        company_layout = QFormLayout()
        
        # Company details
        self.company_name = QLineEdit()
        self.company_logo = QLineEdit()
        self.company_logo_browse = QPushButton("Browse...")
        self.company_logo_browse.clicked.connect(self.browse_company_logo)
        
        logo_layout = QHBoxLayout()
        logo_layout.addWidget(self.company_logo)
        logo_layout.addWidget(self.company_logo_browse)
        
        self.company_website = QLineEdit()
        self.company_contact = QLineEdit()
        
        # Add widgets to layout
        company_layout.addRow("Company Name:", self.company_name)
        company_layout.addRow("Logo:", logo_layout)
        company_layout.addRow("Website:", self.company_website)
        company_layout.addRow("Contact:", self.company_contact)
        
        company_group.setLayout(company_layout)
        
        # Add groups to layout
        layout.addWidget(report_group)
        layout.addLayout(report_form)
        layout.addWidget(company_group)
        layout.addStretch()
        
        return tab
    
    def create_integrations_tab(self) -> QWidget:
        """Create the Integrations settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Vulnerability databases group
        vuln_db_group = QGroupBox("Vulnerability Databases")
        vuln_db_layout = QVBoxLayout()
        
        # NVD API key
        self.nvd_api_key = QLineEdit()
        self.nvd_api_key.setEchoMode(QLineEdit.Password)
        self.nvd_api_key_show = QPushButton("Show")
        self.nvd_api_key_show.setCheckable(True)
        self.nvd_api_key_show.toggled.connect(
            lambda checked: self.nvd_api_key.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)
        )
        
        nvd_api_key_layout = QHBoxLayout()
        nvd_api_key_layout.addWidget(self.nvd_api_key)
        nvd_api_key_layout.addWidget(self.nvd_api_key_show)
        
        # Add widgets to layout
        vuln_db_form = QFormLayout()
        vuln_db_form.addRow("NVD API Key:", nvd_api_key_layout)
        
        vuln_db_group.setLayout(vuln_db_form)
        
        # Export integrations group
        export_group = QGroupBox("Export Integrations")
        export_layout = QVBoxLayout()
        
        # Jira integration
        jira_group = QGroupBox("Jira")
        jira_group.setCheckable(True)
        jira_group.setChecked(False)
        jira_layout = QFormLayout()
        
        self.jira_url = QLineEdit()
        self.jira_username = QLineEdit()
        self.jira_api_token = QLineEdit()
        self.jira_api_token.setEchoMode(QLineEdit.Password)
        self.jira_project = QLineEdit()
        
        jira_layout.addRow("URL:", self.jira_url)
        jira_layout.addRow("Username:", self.jira_username)
        jira_layout.addRow("API Token:", self.jira_api_token)
        jira_layout.addRow("Project Key:", self.jira_project)
        
        jira_group.setLayout(jira_layout)
        
        # Add widgets to layout
        export_layout.addWidget(jira_group)
        export_group.setLayout(export_layout)
        
        # Add groups to layout
        layout.addWidget(vuln_db_group)
        layout.addWidget(export_group)
        layout.addStretch()
        
        return tab
    
    def create_about_tab(self) -> QWidget:
        """Create the About tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Application information
        about_text = """
        <h1>CyberSentinel</h1>
        <p>Version 1.0.0</p>
        <p>A comprehensive vulnerability scanner with a modern GUI.</p>
        <p>© 2023 CyberSentinel. All rights reserved.</p>
        
        <h2>License</h2>
        <p>MIT License</p>
        
        <h2>Credits</h2>
        <p>Developed by Your Name</p>
        <p>Icons by <a href="https://icons8.com">Icons8</a></p>
        
        <h2>Third-Party Libraries</h2>
        <ul>
            <li>PyQt5 - GUI Framework</li>
            <li>python-nmap - Nmap integration</li>
            <li>requests - HTTP requests</li>
            <li>cryptography - SSL/TLS analysis</li>
            <li>reportlab - PDF report generation</li>
        </ul>
        """
        
        about_label = QLabel(about_text)
        about_label.setOpenExternalLinks(True)
        about_label.setWordWrap(True)
        
        # Add to layout
        layout.addWidget(about_label)
        layout.addStretch()
        
        return tab
    
    def browse_nmap_path(self):
        """Open a file dialog to select the Nmap executable."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Nmap Executable", "", "Executable Files (*.exe);;All Files (*)"
        )
        
        if file_path:
            self.nmap_path.setText(file_path)
    
    def browse_report_location(self):
        """Open a directory dialog to select the default report location."""
        dir_path = QFileDialog.getExistingDirectory(
            self, "Select Default Report Location"
        )
        
        if dir_path:
            self.report_location.setText(dir_path)
    
    def browse_company_logo(self):
        """Open a file dialog to select a company logo."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Company Logo", "", 
            "Image Files (*.png *.jpg *.jpeg *.bmp);;All Files (*)"
        )
        
        if file_path:
            self.company_logo.setText(file_path)
    
    def load_settings(self):
        """Load settings from the configuration file."""
        # Default settings
        self.settings = {
            'general': {
                'theme': 'system',
                'font_size': 10,
                'check_updates': True,
                'auto_update': False
            },
            'scanning': {
                'nmap_path': 'nmap',
                'timing_template': 3,
                'service_scan': True,
                'os_detection': False,
                'script_scan': False,
                'aggressive_scan': False,
                'default_ports': '1-1024,3000-5000,8000-10000'
            },
            'reporting': {
                'auto_generate': True,
                'auto_open': True,
                'include_timestamp': True,
                'default_format': 'pdf',
                'report_location': str(Path.home() / 'CyberSentinel' / 'reports'),
                'company': {
                    'name': '',
                    'logo': '',
                    'website': '',
                    'contact': ''
                }
            },
            'integrations': {
                'nvd_api_key': '',
                'jira': {
                    'enabled': False,
                    'url': '',
                    'username': '',
                    'api_token': '',
                    'project': ''
                }
            }
        }
        
        # Try to load settings from file
        config_path = self.get_config_path()
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    loaded_settings = json.load(f)
                    self.settings.update(loaded_settings)
            except Exception as e:
                QMessageBox.warning(
                    self, 
                    "Settings Error", 
                    f"Failed to load settings: {str(e)}. Using default settings."
                )
        
        # Update UI with loaded settings
        self.update_ui_from_settings()
    
    def save_settings(self):
        """Save settings to the configuration file."""
        # Update settings from UI
        self.update_settings_from_ui()
        
        # Create config directory if it doesn't exist
        config_path = self.get_config_path()
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            # Save settings to file
            with open(config_path, 'w') as f:
                json.dump(self.settings, f, indent=2)
            
            # Emit signal that settings have changed
            self.settings_changed.emit(self.settings)
            
            QMessageBox.information(
                self, 
                "Settings Saved", 
                "Settings have been saved successfully."
            )
        except Exception as e:
            QMessageBox.critical(
                self, 
                "Save Error", 
                f"Failed to save settings: {str(e)}"
            )
    
    def reset_to_defaults(self):
        """Reset all settings to their default values."""
        reply = QMessageBox.question(
            self,
            "Confirm Reset",
            "Are you sure you want to reset all settings to their default values?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Reset settings to defaults
            self.settings = {}
            self.load_settings()
            
            # Update UI
            self.update_ui_from_settings()
            
            QMessageBox.information(
                self, 
                "Settings Reset", 
                "All settings have been reset to their default values."
            )
    
    def update_ui_from_settings(self):
        """Update the UI with the current settings."""
        # General tab
        self.theme_combo.setCurrentIndex(
            self.theme_combo.findData(self.settings['general']['theme'])
        )
        self.font_size.setValue(self.settings['general']['font_size'])
        self.check_updates.setChecked(self.settings['general']['check_updates'])
        self.auto_update.setChecked(self.settings['general']['auto_update'])
        
        # Scan tab
        self.nmap_path.setText(self.settings['scanning']['nmap_path'])
        self.nmap_timing.setCurrentIndex(
            self.nmap_timing.findData(self.settings['scanning']['timing_template'])
        )
        self.service_scan.setChecked(self.settings['scanning']['service_scan'])
        self.os_detection.setChecked(self.settings['scanning']['os_detection'])
        self.script_scan.setChecked(self.settings['scanning']['script_scan'])
        self.aggressive_scan.setChecked(self.settings['scanning']['aggressive_scan'])
        self.default_ports.setText(self.settings['scanning']['default_ports'])
        
        # Reporting tab
        self.auto_generate.setChecked(self.settings['reporting']['auto_generate'])
        self.auto_open.setChecked(self.settings['reporting']['auto_open'])
        self.include_timestamp.setChecked(self.settings['reporting']['include_timestamp'])
        self.default_format.setCurrentIndex(
            self.default_format.findData(self.settings['reporting']['default_format'])
        )
        self.report_location.setText(self.settings['reporting']['report_location'])
        
        # Company information
        self.company_name.setText(self.settings['reporting']['company']['name'])
        self.company_logo.setText(self.settings['reporting']['company']['logo'])
        self.company_website.setText(self.settings['reporting']['company']['website'])
        self.company_contact.setText(self.settings['reporting']['company']['contact'])
        
        # Integrations tab
        self.nvd_api_key.setText(self.settings['integrations']['nvd_api_key'])
        
        # Jira integration
        jira_settings = self.settings['integrations']['jira']
        jira_group = self.integrations_tab.findChild(QGroupBox, "Jira")
        if jira_group:
            jira_group.setChecked(jira_settings['enabled'])
            
            jira_url = jira_group.findChild(QLineEdit, "jira_url")
            if jira_url:
                jira_url.setText(jira_settings['url'])
            
            jira_username = jira_group.findChild(QLineEdit, "jira_username")
            if jira_username:
                jira_username.setText(jira_settings['username'])
            
            jira_api_token = jira_group.findChild(QLineEdit, "jira_api_token")
            if jira_api_token:
                jira_api_token.setText(jira_settings['api_token'])
            
            jira_project = jira_group.findChild(QLineEdit, "jira_project")
            if jira_project:
                jira_project.setText(jira_settings['project'])
    
    def update_settings_from_ui(self):
        """Update the settings dictionary from the UI."""
        # General tab
        self.settings['general']['theme'] = self.theme_combo.currentData()
        self.settings['general']['font_size'] = self.font_size.value()
        self.settings['general']['check_updates'] = self.check_updates.isChecked()
        self.settings['general']['auto_update'] = self.auto_update.isChecked()
        
        # Scan tab
        self.settings['scanning']['nmap_path'] = self.nmap_path.text()
        self.settings['scanning']['timing_template'] = self.nmap_timing.currentData()
        self.settings['scanning']['service_scan'] = self.service_scan.isChecked()
        self.settings['scanning']['os_detection'] = self.os_detection.isChecked()
        self.settings['scanning']['script_scan'] = self.script_scan.isChecked()
        self.settings['scanning']['aggressive_scan'] = self.aggressive_scan.isChecked()
        self.settings['scanning']['default_ports'] = self.default_ports.text()
        
        # Reporting tab
        self.settings['reporting']['auto_generate'] = self.auto_generate.isChecked()
        self.settings['reporting']['auto_open'] = self.auto_open.isChecked()
        self.settings['reporting']['include_timestamp'] = self.include_timestamp.isChecked()
        self.settings['reporting']['default_format'] = self.default_format.currentData()
        self.settings['reporting']['report_location'] = self.report_location.text()
        
        # Company information
        self.settings['reporting']['company'] = {
            'name': self.company_name.text(),
            'logo': self.company_logo.text(),
            'website': self.company_website.text(),
            'contact': self.company_contact.text()
        }
        
        # Integrations tab
        self.settings['integrations']['nvd_api_key'] = self.nvd_api_key.text()
        
        # Jira integration
        jira_group = self.integrations_tab.findChild(QGroupBox, "Jira")
        if jira_group:
            self.settings['integrations']['jira'] = {
                'enabled': jira_group.isChecked(),
                'url': jira_group.findChild(QLineEdit, "jira_url").text() if jira_group.findChild(QLineEdit, "jira_url") else "",
                'username': jira_group.findChild(QLineEdit, "jira_username").text() if jira_group.findChild(QLineEdit, "jira_username") else "",
                'api_token': jira_group.findChild(QLineEdit, "jira_api_token").text() if jira_group.findChild(QLineEdit, "jira_api_token") else "",
                'project': jira_group.findChild(QLineEdit, "jira_project").text() if jira_group.findChild(QLineEdit, "jira_project") else ""
            }
    
    def get_config_path(self) -> Path:
        """Get the path to the configuration file."""
        config_dir = Path.home() / ".cybersentinel"
        return config_dir / "config.json"
    
    def apply_styles(self):
        """Apply custom styles to the widget."""
        self.setStyleSheet("""
            QGroupBox {
                border: 1px solid #3a7cce;
                border-radius: 5px;
                margin-top: 1em;
                padding-top: 10px;
            }
            
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px 0 3px;
            }
            
            QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QTextEdit {
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 5px;
            }
            
            QPushButton {
                background-color: #3a7cce;
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 4px;
            }
            
            QPushButton:hover {
                background-color: #2c6cb3;
            }
            
            QPushButton:disabled {
                background-color: #cccccc;
            }
            
            QTabWidget::pane {
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 10px;
            }
            
            QTabBar::tab {
                background: #f8f9fa;
                border: 1px solid #dee2e6;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                padding: 8px 16px;
                margin-right: 2px;
            }
            
            QTabBar::tab:selected {
                background: white;
                border-bottom: 1px solid white;
                margin-bottom: -1px;
            }
            
            QCheckBox {
                spacing: 5px;
            }
            
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
            }
        """)
