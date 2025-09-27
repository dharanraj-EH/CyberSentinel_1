"""
Main window for the CyberSentinel application.
"""
import logging
from typing import Dict, Any, Optional

from PyQt5.QtWidgets import (
    QMainWindow, QTabWidget, QStatusBar, QAction, QMessageBox, QFileDialog
)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QKeySequence, QIcon

from .. import __version__, logger
from ..utils.resource_loader import load_icon, load_stylesheet
from .dashboard import DashboardTab
from .scanner_tab import ScannerTab
from .ssl_analyzer import SSLAnalyzerTab
from .web_tests import WebTestsTab
from .reports import ReportsTab
from .settings import SettingsDialog
from .reports import ReportsTab
from .settings import SettingsDialog

class MainWindow(QMainWindow):
    """Main application window."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"CyberSentinel v{__version__}")
        self.setMinimumSize(1024, 768)
        
        # Initialize UI components
        self._init_ui()
        self._create_actions()
        self._create_menus()
        self._create_toolbars()
        self._create_statusbar()
        
        # Apply stylesheet
        self._apply_styles()
        
        # Initialize tabs
        self._init_tabs()
        
        # Restore window state
        self._load_settings()
    
    def _init_ui(self):
        """Initialize the main UI components."""
        # Create central widget and main layout
        self.tab_widget = QTabWidget()
        self.tab_widget.setDocumentMode(True)
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.tabCloseRequested.connect(self._close_tab)
        
        self.setCentralWidget(self.tab_widget)
    
    def _init_tabs(self):
        """Initialize the main tabs."""
        # Create main tabs
        self.tabs = {}
        
        # Dashboard tab
        self.dashboard_tab = DashboardTab()
        self.tabs["dashboard"] = self.tab_widget.addTab(
            self.dashboard_tab, 
            load_icon("dashboard.svg") or QIcon(), 
            "Dashboard"
        )
        
        # Scanner tab
        self.scanner_tab = ScannerTab()
        self.tabs["scanner"] = self.tab_widget.addTab(
            self.scanner_tab,
            load_icon("scanner.svg") or QIcon(),
            "Network Scanner"
        )
        
        # SSL Analyzer tab
        self.ssl_tab = SSLAnalyzerTab()
        self.tabs["ssl"] = self.tab_widget.addTab(
            self.ssl_tab,
            load_icon("ssl.svg") or QIcon(),
            "SSL/TLS Analyzer"
        )
        
        # Web Tests tab
        self.web_tests_tab = WebTestsTab()
        self.tabs["web_tests"] = self.tab_widget.addTab(
            self.web_tests_tab,
            load_icon("web.svg") or QIcon(),
            "Web Tests"
        )
        
        # Reports tab
        self.reports_tab = ReportsTab()
        self.tabs["reports"] = self.tab_widget.addTab(
            self.reports_tab,
            load_icon("reports.svg") or QIcon(),
            "Reports"
        )
        
        # Note: Tabs manage their own internal signals; connections to non-existent
        # tab-level signals have been removed to avoid runtime errors.
    
    def _create_actions(self):
        """Create the main menu actions."""
        # File menu actions
        self.new_scan_action = QAction("&New Scan", self)
        self.new_scan_action.setShortcut(QKeySequence.New)
        self.new_scan_action.setStatusTip("Start a new scan")
        self.new_scan_action.triggered.connect(self._new_scan)
        
        self.open_action = QAction("&Open...", self)
        self.open_action.setShortcut(QKeySequence.Open)
        self.open_action.setStatusTip("Open a saved scan")
        self.open_action.triggered.connect(self._open_scan)
        
        self.save_action = QAction("&Save", self)
        self.save_action.setShortcut(QKeySequence.Save)
        self.save_action.setStatusTip("Save current scan")
        self.save_action.triggered.connect(self._save_scan)
        
        self.save_as_action = QAction("Save &As...", self)
        self.save_as_action.setShortcut(QKeySequence.SaveAs)
        self.save_as_action.setStatusTip("Save current scan as...")
        self.save_as_action.triggered.connect(self._save_scan_as)
        
        self.exit_action = QAction("E&xit", self)
        self.exit_action.setShortcut(QKeySequence.Quit)
        self.exit_action.setStatusTip("Exit the application")
        self.exit_action.triggered.connect(self.close)
        
        # Edit menu actions
        self.preferences_action = QAction("&Preferences...", self)
        self.preferences_action.setStatusTip("Edit application preferences")
        self.preferences_action.triggered.connect(self._show_preferences)
        
        # View menu actions
        self.toggle_toolbar_action = QAction("&Toolbar", self, checkable=True)
        self.toggle_toolbar_action.setStatusTip("Toggle toolbar visibility")
        self.toggle_toolbar_action.setChecked(True)
        self.toggle_toolbar_action.triggered.connect(self._toggle_toolbar)
        
        self.toggle_statusbar_action = QAction("Status &Bar", self, checkable=True)
        self.toggle_statusbar_action.setStatusTip("Toggle status bar visibility")
        self.toggle_statusbar_action.setChecked(True)
        self.toggle_statusbar_action.triggered.connect(self._toggle_statusbar)
        
        # Help menu actions
        self.about_action = QAction("&About", self)
        self.about_action.setStatusTip("Show the application's About box")
        self.about_action.triggered.connect(self._about)
        
        self.about_qt_action = QAction("About &Qt", self)
        self.about_qt_action.setStatusTip("Show the Qt library's About box")
        # Use QMessageBox.aboutQt to avoid direct QApplication reference
        self.about_qt_action.triggered.connect(lambda: QMessageBox.aboutQt(self))
    
    def _create_menus(self):
        """Create the main menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("&File")
        file_menu.addAction(self.new_scan_action)
        file_menu.addSeparator()
        file_menu.addAction(self.open_action)
        file_menu.addAction(self.save_action)
        file_menu.addAction(self.save_as_action)
        file_menu.addSeparator()
        file_menu.addAction(self.exit_action)
        
        # Edit menu
        edit_menu = menubar.addMenu("&Edit")
        edit_menu.addAction(self.preferences_action)
        
        # View menu
        view_menu = menubar.addMenu("&View")
        view_menu.addAction(self.toggle_toolbar_action)
        view_menu.addAction(self.toggle_statusbar_action)
        
        # Help menu
        help_menu = menubar.addMenu("&Help")
        help_menu.addAction(self.about_action)
        help_menu.addAction(self.about_qt_action)
    
    def _create_toolbars(self):
        """Create the main toolbar."""
        self.toolbar = self.addToolBar("Main Toolbar")
        self.toolbar.setIconSize(QSize(24, 24))
        
        # Add actions to toolbar
        self.toolbar.addAction(self.new_scan_action)
        self.toolbar.addAction(self.open_action)
        self.toolbar.addAction(self.save_action)
        self.toolbar.addSeparator()
        
        # Add scan actions
        self.toolbar.addAction("Start Scan", self._start_scan)
        self.toolbar.addAction("Stop Scan", self._stop_scan)
        self.toolbar.addSeparator()
        
        # Add report actions
        self.toolbar.addAction("Generate Report", self._generate_report)
    
    def _create_statusbar(self):
        """Create the status bar."""
        self.statusBar().showMessage("Ready")
    
    def _apply_styles(self):
        """Apply styles to the application."""
        # Load and apply the main stylesheet
        style = load_stylesheet("main.qss")
        if style:
            self.setStyleSheet(style)
    
    def _load_settings(self):
        """Load application settings."""
        # TODO: Implement settings loading
        pass
    
    def _save_settings(self):
        """Save application settings."""
        # TODO: Implement settings saving
        pass
    
    def closeEvent(self, event):
        """Handle window close event."""
        # TODO: Check for unsaved changes
        self._save_settings()
        event.accept()
    
    # Slots
    def _new_scan(self):
        """Start a new scan."""
        # TODO: Implement new scan
        pass
    
    def _open_scan(self):
        """Open a saved scan."""
        # TODO: Implement open scan
        pass
    
    def _save_scan(self):
        """Save the current scan."""
        # TODO: Implement save scan
        pass
    
    def _save_scan_as(self):
        """Save the current scan with a new name."""
        # TODO: Implement save scan as
        pass
    
    def _show_preferences(self):
        """Show the preferences dialog."""
        dialog = SettingsDialog(self)
        if dialog.exec_() == SettingsDialog.Accepted:
            # Apply preferences
            pass
    
    def _toggle_toolbar(self, visible):
        """Toggle toolbar visibility."""
        self.toolbar.setVisible(visible)
    
    def _toggle_statusbar(self, visible):
        """Toggle status bar visibility."""
        self.statusBar().setVisible(visible)
    
    def _start_scan(self):
        """Start the current scan."""
        # TODO: Implement start scan
        pass
    
    def _stop_scan(self):
        """Stop the current scan."""
        # TODO: Implement stop scan
        pass
    
    def _generate_report(self):
        """Generate a report for the current scan."""
        # TODO: Implement report generation
        pass
    
    def _about(self):
        """Show the About dialog."""
        QMessageBox.about(
            self,
            "About CyberSentinel",
            f"<h2>CyberSentinel v{__version__}</h2>"
            "<p>A comprehensive vulnerability scanner with a modern GUI.</p>"
            "<p>Copyright © 2023 Your Name. All rights reserved.</p>"
            "<p>Licensed under the MIT License.</p>"
            "<p>This software is provided 'as-is', without any express or "
            "implied warranty.</p>"
        )
    
    def _close_tab(self, index):
        """Close a tab."""
        # Don't close the main tabs
        if index < len(self.tabs):
            return
        
        # Close the tab
        widget = self.tab_widget.widget(index)
        widget.deleteLater()
        self.tab_widget.removeTab(index)
    
    # Signal handlers
    def _on_scan_completed(self, results):
        """Handle scan completion."""
        # TODO: Handle scan results
        self.statusBar().showMessage("Scan completed", 5000)
    
    def _on_analysis_completed(self, results):
        """Handle SSL/TLS analysis completion."""
        # TODO: Handle analysis results
        self.statusBar().showMessage("SSL/TLS analysis completed", 5000)
    
    def _on_test_completed(self, results):
        """Handle web test completion."""
        # TODO: Handle test results
        self.statusBar().showMessage("Web test completed", 5000)
