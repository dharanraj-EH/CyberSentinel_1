"""
Dashboard tab for the CyberSentinel application.
"""
from typing import Dict, List, Any

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame,
    QScrollArea, QSizePolicy
)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QPixmap, QIcon, QFont

from ..utils.resource_loader import load_icon

class DashboardTab(QWidget):
    """Dashboard tab showing an overview of the application and recent scans."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the UI components."""
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)
        
        # Welcome section
        welcome_section = self._create_welcome_section()
        main_layout.addWidget(welcome_section)
        
        # Quick actions section
        quick_actions = self._create_quick_actions()
        main_layout.addWidget(quick_actions)
        
        # Recent scans section
        recent_scans = self._create_recent_scans()
        main_layout.addWidget(recent_scans)
        
        # Status section
        status_section = self._create_status_section()
        main_layout.addWidget(status_section)
        
        # Add stretch to push everything to the top
        main_layout.addStretch()
    
    def _create_welcome_section(self) -> QFrame:
        """Create the welcome section."""
        frame = QFrame()
        frame.setFrameShape(QFrame.StyledPanel)
        frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Logo and title
        logo_label = QLabel()
        logo_pixmap = QPixmap()
        # Try to load the logo, use a placeholder if not found
        icon = load_icon("app_icon.png")
        if icon:
            logo_pixmap = icon.pixmap(64, 64)
        logo_label.setPixmap(logo_pixmap)
        
        title_label = QLabel("CyberSentinel")
        title_font = QFont()
        title_font.setPointSize(24)
        title_font.setBold(True)
        title_label.setFont(title_font)
        
        subtitle_label = QLabel("Comprehensive Vulnerability Scanner")
        subtitle_font = QFont()
        subtitle_font.setPointSize(12)
        subtitle_label.setFont(subtitle_font)
        
        # Create a vertical layout for the title and subtitle
        title_layout = QVBoxLayout()
        title_layout.addWidget(title_label)
        title_layout.addWidget(subtitle_label)
        
        # Add widgets to the main layout
        layout.addWidget(logo_label, 0, Qt.AlignLeft | Qt.AlignTop)
        layout.addSpacing(20)
        layout.addLayout(title_layout, 1)
        
        return frame
    
    def _create_quick_actions(self) -> QFrame:
        """Create the quick actions section."""
        frame = QFrame()
        frame.setFrameShape(QFrame.StyledPanel)
        frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Section title
        title = QLabel("Quick Actions")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        
        # Buttons layout
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(15)
        
        # New Scan button
        new_scan_btn = self._create_action_button("New Scan", "scanner.svg")
        new_scan_btn.clicked.connect(self._on_new_scan)
        
        # SSL Analyzer button
        ssl_btn = self._create_action_button("SSL Analyzer", "ssl.svg")
        ssl_btn.clicked.connect(self._on_ssl_analyzer)
        
        # Web Tests button
        web_tests_btn = self._create_action_button("Web Tests", "web.svg")
        web_tests_btn.clicked.connect(self._on_web_tests)
        
        # Reports button
        reports_btn = self._create_action_button("Reports", "reports.svg")
        reports_btn.clicked.connect(self._on_reports)
        
        # Add buttons to layout
        buttons_layout.addWidget(new_scan_btn)
        buttons_layout.addWidget(ssl_btn)
        buttons_layout.addWidget(web_tests_btn)
        buttons_layout.addWidget(reports_btn)
        buttons_layout.addStretch()
        
        # Add widgets to main layout
        layout.addWidget(title)
        layout.addSpacing(10)
        layout.addLayout(buttons_layout)
        
        return frame
    
    def _create_recent_scans(self) -> QFrame:
        """Create the recent scans section."""
        frame = QFrame()
        frame.setFrameShape(QFrame.StyledPanel)
        frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Section title
        title = QLabel("Recent Scans")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        
        # Scroll area for scan items
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.NoFrame)
        
        # Container widget for scan items
        container = QWidget()
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.setSpacing(10)
        
        # Add sample scan items (in a real app, these would be loaded from the database)
        sample_scans = [
            {"target": "example.com", "date": "2023-09-27", "status": "Completed", "findings": 5},
            {"target": "192.168.1.1/24", "date": "2023-09-26", "status": "Completed", "findings": 12},
            {"target": "https://test-site.com", "date": "2023-09-25", "status": "Failed", "findings": 0},
        ]
        
        for scan in sample_scans:
            scan_item = self._create_scan_item(scan)
            container_layout.addWidget(scan_item)
        
        # Add stretch to push items to the top
        container_layout.addStretch()
        
        # Set the container as the scroll area's widget
        scroll_area.setWidget(container)
        
        # Add widgets to main layout
        layout.addWidget(title)
        layout.addSpacing(10)
        layout.addWidget(scroll_area)
        
        return frame
    
    def _create_status_section(self) -> QFrame:
        """Create the status section."""
        frame = QFrame()
        frame.setFrameShape(QFrame.StyledPanel)
        frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Section title
        title = QLabel("System Status")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title.setFont(title_font)
        
        # Status items
        status_layout = QHBoxLayout()
        status_layout.setSpacing(30)
        
        # Scanner status
        scanner_status = self._create_status_item("Scanner", "Ready", "success")
        # Database status
        db_status = self._create_status_item("Database", "Connected", "success")
        # Updates status
        updates_status = self._create_status_item("Updates", "Available", "warning")
        # License status
        license_status = self._create_status_item("License", "Active", "success")
        
        # Add status items to layout
        status_layout.addWidget(scanner_status)
        status_layout.addWidget(db_status)
        status_layout.addWidget(updates_status)
        status_layout.addWidget(license_status)
        status_layout.addStretch()
        
        # Add widgets to main layout
        layout.addWidget(title)
        layout.addSpacing(10)
        layout.addLayout(status_layout)
        
        return frame
    
    def _create_action_button(self, text: str, icon_name: str) -> QPushButton:
        """Create a styled action button with an icon."""
        button = QPushButton(text)
        button.setIcon(load_icon(icon_name) or QIcon())
        button.setIconSize(QSize(24, 24))
        button.setMinimumHeight(50)
        button.setStyleSheet("""
            QPushButton {
                text-align: left;
                padding: 10px;
                border: 1px solid #d0d0d0;
                border-radius: 5px;
                background-color: #f8f9fa;
            }
            QPushButton:hover {
                background-color: #e9ecef;
                border-color: #adb5bd;
            }
            QPushButton:pressed {
                background-color: #dee2e6;
            }
        """)
        return button
    
    def _create_scan_item(self, scan_data: Dict[str, Any]) -> QFrame:
        """Create a scan item widget for the recent scans list."""
        frame = QFrame()
        frame.setFrameShape(QFrame.StyledPanel)
        frame.setStyleSheet("""
            QFrame {
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 10px;
                background-color: #f8f9fa;
            }
            QFrame:hover {
                background-color: #e9ecef;
                border-color: #adb5bd;
            }
        """)
        
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Target
        target_label = QLabel(f"<b>Target:</b> {scan_data['target']}")
        target_label.setStyleSheet("font-size: 12px;")
        
        # Date
        date_label = QLabel(f"<b>Date:</b> {scan_data['date']}")
        date_label.setStyleSheet("font-size: 12px;")
        
        # Status
        status_style = "color: #28a745;"  # Default to success (green)
        if scan_data['status'].lower() == 'failed':
            status_style = "color: #dc3545;"  # Red for failed
        elif scan_data['status'].lower() == 'in progress':
            status_style = "color: #ffc107;"  # Yellow for in progress
            
        status_label = QLabel(f"<b>Status:</b> <span style='{status_style}'>{scan_data['status']}</span>")
        status_label.setStyleSheet("font-size: 12px;")
        
        # Findings
        findings_label = QLabel(f"<b>Findings:</b> {scan_data['findings']}")
        findings_label.setStyleSheet("font-size: 12px;")
        
        # Add widgets to layout
        layout.addWidget(target_label, 2)
        layout.addWidget(date_label, 1)
        layout.addWidget(status_label, 1)
        layout.addWidget(findings_label, 1)
        
        # View button
        view_btn = QPushButton("View")
        view_btn.setStyleSheet("""
            QPushButton {
                padding: 2px 8px;
                border: 1px solid #0d6efd;
                border-radius: 4px;
                background-color: #0d6efd;
                color: white;
                font-size: 12px;
            }
            QPushButton:hover {
                background-color: #0b5ed7;
                border-color: #0a58ca;
            }
            QPushButton:pressed {
                background-color: #0a58ca;
                border-color: #0a53be;
            }
        """)
        view_btn.setCursor(Qt.PointingHandCursor)
        view_btn.clicked.connect(lambda: self._on_view_scan(scan_data))
        
        layout.addWidget(view_btn)
        
        return frame
    
    def _create_status_item(self, title: str, status: str, status_type: str) -> QFrame:
        """Create a status indicator item."""
        frame = QFrame()
        frame.setFrameShape(QFrame.StyledPanel)
        frame.setStyleSheet("""
            QFrame {
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 10px;
                background-color: #f8f9fa;
            }
        """)
        
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Title
        title_label = QLabel(title)
        title_label.setStyleSheet("font-weight: bold; font-size: 12px;")
        
        # Status indicator
        status_color = {
            "success": "#28a745",
            "warning": "#ffc107",
            "error": "#dc3545",
            "info": "#17a2b8"
        }.get(status_type.lower(), "#6c757d")
        
        status_label = QLabel(status)
        status_label.setStyleSheet(f"color: {status_color}; font-size: 14px; font-weight: bold;")
        
        # Add widgets to layout
        layout.addWidget(title_label)
        layout.addWidget(status_label)
        
        return frame
    
    # Event handlers
    def _on_new_scan(self):
        """Handle New Scan button click."""
        # This will be connected to the main window's new scan action
        if self.parent() and hasattr(self.parent(), 'new_scan_action'):
            self.parent().new_scan_action.trigger()
    
    def _on_ssl_analyzer(self):
        """Handle SSL Analyzer button click."""
        # This will switch to the SSL Analyzer tab
        if self.parent() and hasattr(self.parent(), 'tab_widget'):
            self.parent().tab_widget.setCurrentIndex(
                self.parent().tabs["ssl"]
            )
    
    def _on_web_tests(self):
        """Handle Web Tests button click."""
        # This will switch to the Web Tests tab
        if self.parent() and hasattr(self.parent(), 'tab_widget'):
            self.parent().tab_widget.setCurrentIndex(
                self.parent().tabs["web_tests"]
            )
    
    def _on_reports(self):
        """Handle Reports button click."""
        # This will switch to the Reports tab
        if self.parent() and hasattr(self.parent(), 'tab_widget'):
            self.parent().tab_widget.setCurrentIndex(
                self.parent().tabs["reports"]
            )
    
    def _on_view_scan(self, scan_data):
        """Handle View button click on a scan item."""
        # TODO: Implement view scan details
        print(f"Viewing scan: {scan_data}")
