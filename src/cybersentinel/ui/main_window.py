"""
Main window for the CyberSentinel application.
"""
import logging
from typing import Dict, Any, Optional

from PyQt5.QtWidgets import (
    QMainWindow, QTabWidget, QStatusBar, QAction, QMessageBox, QFileDialog, QWidget, QHBoxLayout, QVBoxLayout, QLabel, QListWidget
)
from PyQt5.QtCore import Qt, QSize, QSettings
from PyQt5.QtGui import QKeySequence, QIcon

from .. import __version__, logger
from ..utils.resource_loader import load_icon, load_stylesheet
from .security_overview import DashboardTab
from .vulnerability_intelligence import VulnerabilityIntelligenceTab
from .asset_scope import AssetScopeTab
from ..services.asset_scope import ScopePolicy
from .assessment_workspace import AssessmentWorkspaceTab, LocalIntelligenceTab
from ..services.assessment_store import AssessmentWorkspace
from pathlib import Path
import json
from .network_assessment import ScannerTab
from .tls_assessment import SSLAnalyzerTab
from .web_assessment import WebTestsTab
from .report_library import ReportsTab
from .preferences import SettingsDialog
from .security_monitoring import SecurityMonitoringTab

class MainWindow(QMainWindow):
    """Main application window."""
    
    def __init__(self, parent=None, workspace_root=None):
        super().__init__(parent)
        user_id = 'local'
        self.workspace = AssessmentWorkspace(user_id, workspace_root) if workspace_root else AssessmentWorkspace(user_id)
        self.scope_policy = ScopePolicy(self.workspace.root)
        self.settings = QSettings('CyberSentinel', 'Desktop')
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
        self.tab_widget.setUsesScrollButtons(True)
        self.tab_widget.tabBar().hide()
        self.navigation.addItems([self.tab_widget.tabText(index) for index in range(self.tab_widget.count())])
        self.navigation.setCurrentRow(0)
        self.navigation.currentRowChanged.connect(self.tab_widget.setCurrentIndex)
        self.tab_widget.currentChanged.connect(self.navigation.setCurrentRow)
        self.tab_widget.tabBar().setExpanding(False)
        self.toolbar.setObjectName('assessmentToolbar')
        
        # Restore window state
        self._load_settings()
    
    def _init_ui(self):
        """Initialize the main UI components."""
        # Create central widget and main layout
        self.tab_widget = QTabWidget()
        self.tab_widget.setDocumentMode(True)
        self.tab_widget.setTabsClosable(False)
        self.tab_widget.tabCloseRequested.connect(self._close_tab)
        
        container = QWidget()
        content = QHBoxLayout(container)
        content.setContentsMargins(0, 0, 0, 0)
        sidebar = QWidget()
        sidebar.setFixedWidth(310)
        side = QVBoxLayout(sidebar)
        brand = QLabel('CYBERSENTINEL')
        brand.setStyleSheet('font-size: 16pt; font-weight: 700; color: #6bdfd0; padding: 16px 4px;')
        side.addWidget(brand)
        side.addWidget(QLabel('DESKTOP SECURITY OPERATIONS'))
        self.navigation = QListWidget()
        self.navigation.setStyleSheet('QListWidget{border:0;background:#101827;} QListWidget::item{padding:16px 8px;border-radius:5px;} QListWidget::item:selected{background:#24445e;color:#77e3d4;}')
        side.addWidget(self.navigation)
        side.addWidget(QLabel(f'LOCAL WORKSPACE  /  v{__version__}'))
        content.addWidget(sidebar)
        content.addWidget(self.tab_widget, 1)
        self.setCentralWidget(container)
    
    def _init_tabs(self):
        """Initialize the main tabs."""
        # Create main tabs
        self.tabs = {}
        
        # Dashboard tab
        self.dashboard_tab = DashboardTab()
        self.tabs["dashboard"] = self.tab_widget.addTab(
            self.dashboard_tab, 
            load_icon("dashboard.svg") or QIcon(), 
            "Security Overview"
        )
        
        # Scanner tab
        self.scanner_tab = ScannerTab()
        self.tabs["scanner"] = self.tab_widget.addTab(
            self.scanner_tab,
            load_icon("scanner.svg") or QIcon(),
            "Network Exposure Assessment"
        )
        
        # SSL Analyzer tab
        self.ssl_tab = SSLAnalyzerTab()
        self.tabs["ssl"] = self.tab_widget.addTab(
            self.ssl_tab,
            load_icon("ssl.svg") or QIcon(),
            "TLS & Certificate Assurance"
        )
        
        # Web Tests tab
        self.web_tests_tab = WebTestsTab()
        self.tabs["web_tests"] = self.tab_widget.addTab(
            self.web_tests_tab,
            load_icon("web.svg") or QIcon(),
            "Web Configuration Assessment"
        )
        
        # Reports tab
        self.reports_tab = ReportsTab()
        self.tabs["reports"] = self.tab_widget.addTab(
            self.reports_tab,
            load_icon("reports.svg") or QIcon(),
            "Report Library"
        )
        
        self.cve_tab = VulnerabilityIntelligenceTab(self.workspace)
        self.tab_widget.addTab(self.cve_tab, 'Vulnerability Intelligence')
        self.scope_tab = AssetScopeTab(self.scope_policy)
        self.tab_widget.addTab(self.scope_tab, 'Asset Inventory & Scope')
        self.reports_tab.reports_root = self.workspace.root / 'reports'
        self.reports_tab._load_reports()
        self.workspace_tab = AssessmentWorkspaceTab(self.workspace)
        self.tab_widget.addTab(self.workspace_tab, 'Assessment Workspace')
        self.intelligence_tab = LocalIntelligenceTab(self.workspace)
        self.tab_widget.addTab(self.intelligence_tab, 'Local Security Intelligence')
        self.monitoring_tab = SecurityMonitoringTab(self.workspace)
        self.tab_widget.addTab(self.monitoring_tab, 'Security Monitoring')
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
        self.statusBar().showMessage('Ready | Local desktop workspace')

    def _apply_styles(self):
        from .theme import DESKTOP_STYLE
        self.setStyleSheet(DESKTOP_STYLE)
    

    def _load_settings(self):
        geometry = self.settings.value('geometry')
        if geometry:
            self.restoreGeometry(geometry)
    

    def _save_settings(self):
        self.settings.setValue('geometry', self.saveGeometry())
    

    def closeEvent(self, event):
        from PyQt5.QtCore import QThread
        self.monitoring_tab.stop_monitoring()
        workers = []
        for tab, attr in ((self.scanner_tab, 'scan_worker'), (self.ssl_tab, 'scan_worker'),
                          (self.web_tests_tab, 'test_worker'), (self.intelligence_tab, 'worker'), (self.cve_tab, 'worker'), (self.monitoring_tab, 'worker')):
            worker = getattr(tab, attr, None)
            if worker and worker.isRunning():
                workers.append(worker)
        if workers:
            for worker in workers:
                if hasattr(worker, 'stop'):
                    worker.stop()
            self.statusBar().showMessage('Waiting for active tasks to finish cancellation. Close again when idle.')
            event.ignore()
            return
        self._save_settings()
        event.accept()
    

    def _new_scan(self):
        self.tab_widget.setCurrentWidget(self.scanner_tab)
        self.scanner_tab.target_input.setFocus()
    

    def _open_scan(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Open network assessment', '', 'JSON (*.json)')
        if path:
            try:
                data = json.loads(Path(path).read_text(encoding='utf-8'))
                data = data.get('raw', data)
                if not isinstance(data, dict) or not isinstance(data.get('ports'), list):
                    raise ValueError('Select a network assessment with a ports list.')
                self.scanner_tab.scan_results = data
                self.scanner_tab.display_results(data)
                self.tab_widget.setCurrentWidget(self.scanner_tab)
            except Exception as error:
                QMessageBox.warning(self, 'Open assessment', str(error))
    

    def _save_scan(self):
        widget = self.tab_widget.currentWidget()
        if hasattr(widget, 'save_results'):
            widget.save_results()
        elif widget is self.workspace_tab:
            widget.export()
        else:
            self.statusBar().showMessage('Select an assessment module or the workspace to export.', 5000)
    

    def _save_scan_as(self):
        self._save_scan()
    

    def _show_preferences(self):
        """Show the preferences dialog."""
        dialog = SettingsDialog(self)
        if dialog.exec_() == SettingsDialog.Accepted:
            self.web_tests_tab.timeout.setValue(int(self.settings.value("request_timeout", 10)))
    
    def _toggle_toolbar(self, visible):
        """Toggle toolbar visibility."""
        self.toolbar.setVisible(visible)
    
    def _toggle_statusbar(self, visible):
        """Toggle status bar visibility."""
        self.statusBar().setVisible(visible)
    
    def _start_scan(self):
        if not self.authorize_assessment():
            return
        widget = self.tab_widget.currentWidget()
        callback = getattr(widget, 'start_scan', None) or getattr(widget, 'start_tests', None)
        if callback:
            callback()
        else:
            self._new_scan()
    

    def _stop_scan(self):
        widget = self.tab_widget.currentWidget()
        callback = getattr(widget, 'stop_scan', None) or getattr(widget, 'stop_tests', None)
        if callback:
            callback()
    

    def _generate_report(self):
        self.workspace_tab.refresh()
        self.tab_widget.setCurrentWidget(self.workspace_tab)
    

    def _about(self):
        """Show the About dialog."""
        QMessageBox.about(
            self,
            "About CyberSentinel",
            (
                f"<h2>CyberSentinel v{__version__}</h2>"
                "<p>A comprehensive vulnerability scanner with a modern GUI.</p>"
                "<p><b>M DHARAN RAJ · Final Year Project</b></p>"
                "<p>Licensed under the MIT License.</p>"
                "<p>This software is provided 'as-is', without any express or implied warranty.</p>"
            )
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
    
    def authorize_assessment(self, target=None):
        if target:
            try:
                if not self.scope_policy.permits(target):
                    raise ValueError('Target is outside your approved scope. Add the authorized asset in Asset Inventory & Scope.')
            except ValueError as error:
                QMessageBox.warning(self, 'Assessment scope', str(error))
                return False
        return True

    def record_assessment(self, module, target, data):
        assessment = self.workspace.record(module, target, data, status=data.get('status', 'completed'))
        try:
            self.workspace.export_bundle(assessment)
            self.reports_tab._load_reports()
        except Exception as error:
            self.statusBar().showMessage('Evidence saved; report export failed: ' + str(error), 10000)
        self.workspace_tab.refresh()
        self.dashboard_tab.reload_recent_scans()
        self.statusBar().showMessage('Assessment saved to your workspace.', 5000)
