"""
Scan widget for CyberSentinel GUI.
"""
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QFormLayout,
    QLineEdit, QComboBox, QPushButton, QProgressBar, QTextEdit,
    QLabel, QSpinBox, QCheckBox, QTabWidget, QScrollArea
)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer

class ScanWidget(QWidget):
    """Widget for configuring and starting scans."""
    
    # Signals
    start_scan_signal = pyqtSignal(str, str, dict)  # target, scan_type, options
    stop_scan_signal = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scan_in_progress = False
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        main_layout = QVBoxLayout(self)
        
        # Create a scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        
        # Target section
        target_group = QGroupBox("Target")
        target_layout = QFormLayout()
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("example.com, 192.168.1.1, 192.168.1.0/24")
        target_layout.addRow("Target:", self.target_input)
        
        target_group.setLayout(target_layout)
        
        # Scan type selection
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItem("Quick Scan", "quick")
        self.scan_type_combo.addItem("Full Scan", "full")
        self.scan_type_combo.addItem("Port Scan", "port")
        self.scan_type_combo.addItem("Vulnerability Scan", "vulnerability")
        self.scan_type_combo.addItem("Web Application Scan", "web")
        self.scan_type_combo.addItem("SSL/TLS Scan", "ssl")
        
        # Advanced options
        self.advanced_options = QGroupBox("Advanced Options")
        self.advanced_options.setCheckable(True)
        self.advanced_options.setChecked(False)
        
        advanced_layout = QFormLayout()
        
        # Port range
        self.port_range = QLineEdit("1-1024")
        advanced_layout.addRow("Ports:", self.port_range)
        
        # Scan speed
        self.scan_speed = QComboBox()
        self.scan_speed.addItem("Paranoid (0)", 0)
        self.scan_speed.addItem("Sneaky (1)", 1)
        self.scan_speed.addItem("Polite (2)", 2)
        self.scan_speed.addItem("Normal (3)", 3)
        self.scan_speed.addItem("Aggressive (4)", 4)
        self.scan_speed.addItem("Insane (5)", 5)
        self.scan_speed.setCurrentIndex(3)  # Default to Normal
        advanced_layout.addRow("Scan Speed:", self.scan_speed)
        
        # Additional options
        self.service_version = QCheckBox("Service version detection")
        self.service_version.setChecked(True)
        advanced_layout.addRow(self.service_version)
        
        self.os_detection = QCheckBox("OS detection")
        advanced_layout.addRow(self.os_detection)
        
        self.script_scan = QCheckBox("Script scanning")
        advanced_layout.addRow(self.script_scan)
        
        self.advanced_options.setLayout(advanced_layout)
        
        # Scan button
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.toggle_scan)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        # Log output
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setPlaceholderText("Scan output will appear here...")
        
        # Add widgets to layout
        scroll_layout.addWidget(QLabel("Scan Type:"))
        scroll_layout.addWidget(self.scan_type_combo)
        scroll_layout.addSpacing(10)
        scroll_layout.addWidget(target_group)
        scroll_layout.addSpacing(10)
        scroll_layout.addWidget(self.advanced_options)
        scroll_layout.addStretch()
        
        # Set the scroll content
        scroll.setWidget(scroll_content)
        
        # Add to main layout
        main_layout.addWidget(scroll)
        main_layout.addWidget(self.scan_button)
        main_layout.addWidget(self.progress_bar)
        main_layout.addWidget(QLabel("Scan Output:"))
        main_layout.addWidget(self.log_output)
        
        # Set layout
        self.setLayout(main_layout)
        
        # Apply styles
        self.apply_styles()
    
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
            
            QTextEdit, QLineEdit, QComboBox, QSpinBox {
                padding: 5px;
                border: 1px solid #3a7cce;
                border-radius: 3px;
                background-color: #f8f9fa;
            }
            
            QPushButton {
                background-color: #3a7cce;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            
            QPushButton:hover {
                background-color: #2c6cb3;
            }
            
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """)
    
    def toggle_scan(self):
        """Toggle between starting and stopping a scan."""
        if self.scan_in_progress:
            self.stop_scan_signal.emit()
        else:
            self.start_scan()
    
    def start_scan(self):
        """Start a new scan."""
        target = self.target_input.text().strip()
        if not target:
            self.log("Error: Please enter a target to scan.", "error")
            return
        
        # Get scan type
        scan_type = self.scan_type_combo.currentData()
        
        # Prepare scan options
        options = {
            'ports': self.port_range.text(),
            'intensity': self.scan_speed.currentData(),
            'service_version': self.service_version.isChecked(),
            'os_detection': self.os_detection.isChecked(),
            'script_scan': self.script_scan.isChecked(),
        }
        
        # Clear previous logs
        self.log_output.clear()
        
        # Emit signal to start the scan
        self.start_scan_signal.emit(target, scan_type, options)
    
    def set_scan_in_progress(self, in_progress):
        """Update the UI to reflect the scan status."""
        self.scan_in_progress = in_progress
        
        if in_progress:
            self.scan_button.setText("Stop Scan")
            self.scan_button.setStyleSheet("""
                QPushButton {
                    background-color: #dc3545;
                    color: white;
                }
                QPushButton:hover {
                    background-color: #c82333;
                }
            """)
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
        else:
            self.scan_button.setText("Start Scan")
            self.scan_button.setStyleSheet("""
                QPushButton {
                    background-color: #3a7cce;
                    color: white;
                }
                QPushButton:hover {
                    background-color: #2c6cb3;
                }
            """)
            self.progress_bar.setVisible(False)
            self.progress_bar.setValue(0)
        
        # Disable/enable controls
        self.target_input.setEnabled(not in_progress)
        self.scan_type_combo.setEnabled(not in_progress)
        self.advanced_options.setEnabled(not in_progress)
    
    def update_progress(self, value):
        """Update the progress bar."""
        self.progress_bar.setValue(value)
    
    def log(self, message, level="info"):
        """Add a message to the log output."""
        if level == "error":
            formatted_message = f'<span style="color: #dc3545;">{message}</span>'
        elif level == "warning":
            formatted_message = f'<span style="color: #ffc107;">{message}</span>'
        elif level == "success":
            formatted_message = f'<span style="color: #28a745;">{message}</span>'
        else:
            formatted_message = f'<span>{message}</span>'
        
        self.log_output.append(formatted_message)
        
        # Auto-scroll to bottom
        scrollbar = self.log_output.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
