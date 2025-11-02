"""
Main window for CyberSentinel GUI.
"""
import logging
from typing import Optional
from pathlib import Path

from PyQt5.QtWidgets import (
    QMainWindow, QTabWidget, QStatusBar, QMessageBox, QFileDialog
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject
from PyQt5.QtGui import QIcon

from ..core.application import CyberSentinelApp
from .scan_widget import ScanWidget
from .results_widget import ResultsWidget
from .report_widget import ReportWidget
from .settings_widget import SettingsWidget

class ScanWorker(QObject):
    """Worker thread for running scans in the background."""
    
    scan_started = pyqtSignal(str)  # scan_id
    scan_progress = pyqtSignal(str, int)  # message, progress
    scan_completed = pyqtSignal(str, dict)  # scan_id, results
    scan_error = pyqtSignal(str, str)  # scan_id, error_message
    
    def __init__(self, app: CyberSentinelApp):
        super().__init__()
        self.app = app
        self.scan_id = None
        self.target = None
        self.scan_type = None
        self.options = None
    
    def run_scan(self, target: str, scan_type: str, options: dict):
        """Start a new scan."""
        self.target = target
        self.scan_type = scan_type
        self.options = options
        
        try:
            # Start the scan
            self.scan_id = self.app.start_scan(target, scan_type, options)
            self.scan_started.emit(self.scan_id)
            
            # TODO: Implement progress tracking
            # For now, we'll just emit progress updates at 25%, 50%, 75%, 100%
            for progress in [25, 50, 75, 100]:
                QThread.msleep(500)  # Simulate work
                self.scan_progress.emit(f"Scan in progress... {progress}%", progress)
            
            # Get the final results
            results = self.app.get_scan_status(self.scan_id)
            self.scan_completed.emit(self.scan_id, results)
            
        except Exception as e:
            self.scan_error.emit(self.scan_id, str(e))

class CyberSentinelMainWindow(QMainWindow):
    """Main window for CyberSentinel application."""
    
    def __init__(self, app: CyberSentinelApp):
        super().__init__()
        self.app = app
        self.logger = logging.getLogger(__name__)
        self.scan_worker = None
        self.scan_thread = None
        
        # Set window title
        self.setWindowTitle("CyberSentinel - Vulnerability Scanner")
        
        self.setMinimumSize(1024, 768)
        
        # Set application icon
        self._set_window_icon()
        
        # Initialize UI
        self._init_ui()
        
        # Connect signals
        self._connect_signals()
    
    def _set_window_icon(self):
        """Set the application window icon."""
        # Try to load the icon from the resources directory
        icon_path = Path(__file__).parent.parent / "resources" / "icon.png"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))
    
    def _init_ui(self):
        """Initialize the user interface."""
        # Create the main tab widget
        self.tab_widget = QTabWidget()
        
        # Create tabs
        self.scan_tab = ScanWidget()
        self.results_tab = ResultsWidget()
        self.report_tab = ReportWidget()
        self.settings_tab = SettingsWidget()
        
        # Add tabs to the tab widget
        self.tab_widget.addTab(self.scan_tab, "Scan")
        self.tab_widget.addTab(self.results_tab, "Results")
        self.tab_widget.addTab(self.report_tab, "Reports")
        self.tab_widget.addTab(self.settings_tab, "Settings")
        
        # Set the central widget
        self.setCentralWidget(self.tab_widget)
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
    
    def _connect_signals(self):
        """Connect signals and slots."""
        # Connect scan tab signals
        self.scan_tab.start_scan_signal.connect(self._on_start_scan)
        self.scan_tab.stop_scan_signal.connect(self._on_stop_scan)
    
    def _on_start_scan(self, target: str, scan_type: str, options: dict):
        """Handle start scan button click."""
        try:
            # Validate input
            if not target.strip():
                QMessageBox.warning(self, "Input Error", "Please enter a target to scan.")
                return
            
            # Disable UI elements
            self.scan_tab.set_scan_in_progress(True)
            self.status_bar.showMessage(f"Starting {scan_type} scan on {target}...")
            
            # Create worker and thread
            self.scan_worker = ScanWorker(self.app)
            self.scan_thread = QThread()
            
            # Move worker to the thread
            self.scan_worker.moveToThread(self.scan_thread)
            
            # Connect signals
            self.scan_worker.scan_started.connect(self._on_scan_started)
            self.scan_worker.scan_progress.connect(self._on_scan_progress)
            self.scan_worker.scan_completed.connect(self._on_scan_completed)
            self.scan_worker.scan_error.connect(self._on_scan_error)
            
            # Start the thread
            self.scan_thread.started.connect(
                lambda: self.scan_worker.run_scan(target, scan_type, options)
            )
            self.scan_thread.start()
            
        except Exception as e:
            self.logger.error(f"Error starting scan: {str(e)}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Failed to start scan: {str(e)}")
            self.scan_tab.set_scan_in_progress(False)
    
    def _on_stop_scan(self):
        """Handle stop scan button click."""
        if self.scan_worker and self.scan_worker.scan_id:
            if self.app.stop_scan(self.scan_worker.scan_id):
                self.status_bar.showMessage("Scan stopped by user")
            else:
                self.status_bar.showMessage("Failed to stop scan")
    
    def _on_scan_started(self, scan_id: str):
        """Handle scan started signal."""
        self.status_bar.showMessage(f"Scan started (ID: {scan_id})")
    
    def _on_scan_progress(self, message: str, progress: int):
        """Handle scan progress signal."""
        self.status_bar.showMessage(f"{message} ({progress}%)")
        # Update progress bar in scan tab
        self.scan_tab.update_progress(progress)
    
    def _on_scan_completed(self, scan_id: str, results: dict):
        """Handle scan completed signal."""
        try:
            # Clean up thread
            if self.scan_thread:
                self.scan_thread.quit()
                self.scan_thread.wait()
                self.scan_thread = None
            
            # Update UI
            self.scan_tab.set_scan_in_progress(False)
            self.status_bar.showMessage("Scan completed successfully")
            
            # Show results
            self.results_tab.display_results(results)
            self.tab_widget.setCurrentWidget(self.results_tab)
            
            # Enable report generation
            self.report_tab.set_scan_id(scan_id)
            
        except Exception as e:
            self.logger.error(f"Error handling scan completion: {str(e)}", exc_info=True)
            QMessageBox.critical(self, "Error", f"Failed to process scan results: {str(e)}")
    
    def _on_scan_error(self, scan_id: str, error_message: str):
        """Handle scan error signal."""
        # Clean up thread
        if self.scan_thread:
            self.scan_thread.quit()
            self.scan_thread.wait()
            self.scan_thread = None
        
        # Update UI
        self.scan_tab.set_scan_in_progress(False)
        
        # Show error message
        QMessageBox.critical(self, "Scan Error", f"Scan failed: {error_message}")
        self.status_bar.showMessage(f"Scan failed: {error_message}")
    
    def closeEvent(self, event):
        """Handle window close event."""
        # Stop any running scans
        if self.scan_worker and self.scan_worker.scan_id:
            self.app.stop_scan(self.scan_worker.scan_id)
        
        # Clean up threads
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.quit()
            self.scan_thread.wait()
        
        event.accept()
