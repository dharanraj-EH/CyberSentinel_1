"""
Scanner tab for the CyberSentinel application.
"""
import logging
from typing import Dict, List, Any, Optional

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QComboBox, QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar,
    QMessageBox, QGroupBox, QCheckBox, QFormLayout, QSpinBox, QSplitter,
    QTextEdit, QFileDialog, QTabWidget, QStyle, QApplication
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize, QTimer
from PyQt5.QtGui import QTextCursor, QIcon

from ..scanner.nmap_wrapper import NmapScanner
from ..scanner.socket_scanner import SocketScanner
from ..utils.resource_loader import load_icon

logger = logging.getLogger(__name__)

# Missing import used in save_results()
import json

class ScanWorker(QThread):
    """Worker thread for running scans in the background."""
    
    # Signals for communication with the main thread
    progress_updated = pyqtSignal(int, str)
    scan_completed = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, target: str, scan_type: str, options: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.target = target
        self.scan_type = scan_type
        self.options = options
        self._is_running = True
    
    def run(self):
        """Run the scan in a separate thread."""
        try:
            self.progress_updated.emit(0, "Initializing scan...")
            
            # Initialize the appropriate scanner
            if self.scan_type == "nmap":
                scanner = NmapScanner()
                self.progress_updated.emit(10, "Starting Nmap scan...")
                results = scanner.scan(self.target, self.options.get("ports", "1-1024"))
            else:
                scanner = SocketScanner()
                self.progress_updated.emit(10, "Starting socket scan...")
                results = scanner.scan(self.target, self.options.get("ports", [80, 443, 8080, 22, 21, 25, 110, 143, 443, 993, 995, 3306, 3389]))
            
            self.progress_updated.emit(90, "Processing results...")
            self.scan_completed.emit(results)
            self.progress_updated.emit(100, "Scan completed successfully!")
            
        except Exception as e:
            logger.error(f"Scan failed: {e}", exc_info=True)
            self.error_occurred.emit(str(e))
        finally:
            self._is_running = False
    
    def stop(self):
        """Stop the scan."""
        self._is_running = False
        self.terminate()
        self.wait()
        self.progress_updated.emit(0, "Scan stopped by user.")


class ScannerTab(QWidget):
    """Tab for performing network scans."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scan_worker = None
        self.scan_results = {}
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the UI components."""
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Create a splitter for resizable panels
        splitter = QSplitter(Qt.Vertical)
        
        # Top panel: Scan controls
        top_panel = QWidget()
        top_layout = QVBoxLayout(top_panel)
        top_layout.setContentsMargins(0, 0, 0, 0)
        
        # Target input
        target_group = QGroupBox("Scan Target")
        target_layout = QHBoxLayout(target_group)
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter IP address or hostname (e.g., 192.168.1.1 or example.com)")
        self.target_input.setMinimumWidth(300)
        
        scan_button = QPushButton("Start Scan")
        scan_button.setIcon(load_icon("search.svg") or QApplication.style().standardIcon(QStyle.SP_MediaPlay))
        scan_button.clicked.connect(self.start_scan)
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.setIcon(load_icon("stop.svg") or QApplication.style().standardIcon(QStyle.SP_MediaStop))
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_scan)
        
        target_layout.addWidget(QLabel("Target:"))
        target_layout.addWidget(self.target_input, 1)
        target_layout.addWidget(scan_button)
        target_layout.addWidget(self.stop_button)
        
        # Scan options
        options_group = QGroupBox("Scan Options")
        options_layout = QFormLayout(options_group)
        
        # Scanner type
        self.scanner_type = QComboBox()
        self.scanner_type.addItem("Nmap (recommended)", "nmap")
        self.scanner_type.addItem("Built-in Socket Scanner", "socket")
        
        # Port range
        self.port_range = QLineEdit("1-1024")
        self.port_range.setToolTip("Ports to scan (e.g., 80,443,8080 or 1-1000)")
        
        # Scan type
        self.scan_type = QComboBox()
        self.scan_type.addItem("Quick Scan", "quick")
        self.scan_type.addItem("Full Scan", "full")
        self.scan_type.addItem("Service Detection", "service")
        self.scan_type.addItem("OS Detection", "os")
        
        # Timing template
        self.timing = QComboBox()
        self.timing.addItem("Paranoid (0)", 0)
        self.timing.addItem("Sneaky (1)", 1)
        self.timing.addItem("Polite (2)", 2)
        self.timing.addItem("Normal (3)", 3)
        self.timing.addItem("Aggressive (4)", 4)
        self.timing.addItem("Insane (5)", 5)
        self.timing.setCurrentIndex(3)  # Default to Normal
        
        # Additional options
        self.service_scan = QCheckBox("Service version detection")
        self.os_detection = QCheckBox("OS detection")
        self.aggressive_scan = QCheckBox("Aggressive scan")
        self.script_scan = QCheckBox("NSE script scan")
        self.script_args = QLineEdit()
        self.script_args.setPlaceholderText("Script arguments (e.g., vuln,default,safe)")
        self.script_args.setEnabled(False)
        
        # Connect signals
        self.script_scan.stateChanged.connect(lambda state: self.script_args.setEnabled(state == Qt.Checked))
        
        # Add options to layout
        options_layout.addRow("Scanner:", self.scanner_type)
        options_layout.addRow("Ports:", self.port_range)
        options_layout.addRow("Scan Type:", self.scan_type)
        options_layout.addRow("Timing:", self.timing)
        options_layout.addRow(self.service_scan)
        options_layout.addRow(self.os_detection)
        options_layout.addRow(self.aggressive_scan)
        options_layout.addRow(self.script_scan)
        options_layout.addRow("Script Args:", self.script_args)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("Ready")
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        
        # Add widgets to top panel
        top_layout.addWidget(target_group)
        top_layout.addWidget(options_group)
        top_layout.addWidget(self.progress_bar)
        
        # Bottom panel: Results
        bottom_panel = QTabWidget()
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["Port", "Protocol", "State", "Service", "Version"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.verticalHeader().setVisible(False)
        
        # Output console
        self.output_console = QTextEdit()
        self.output_console.setReadOnly(True)
        self.output_console.setFontFamily("Courier")
        self.output_console.setLineWrapMode(QTextEdit.NoWrap)
        
        # Add tabs
        bottom_panel.addTab(self.results_table, "Results")
        bottom_panel.addTab(self.output_console, "Output")
        
        # Add panels to splitter
        splitter.addWidget(top_panel)
        splitter.addWidget(bottom_panel)
        
        # Set initial sizes
        splitter.setSizes([200, 400])
        
        # Add splitter to main layout
        main_layout.addWidget(splitter)
    
    def start_scan(self):
        """Start the scan with the current settings."""
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter a target to scan.")
            return
        
        # Prepare scan options
        options = {
            "ports": self.port_range.text(),
            "scan_type": self.scan_type.currentData(),
            "timing": self.timing.currentData(),
            "service_scan": self.service_scan.isChecked(),
            "os_detection": self.os_detection.isChecked(),
            "aggressive": self.aggressive_scan.isChecked(),
            "script_scan": self.script_scan.isChecked(),
            "script_args": self.script_args.text() if self.script_scan.isChecked() else ""
        }
        
        # Clear previous results
        self.results_table.setRowCount(0)
        self.output_console.clear()
        self.append_output(f"Starting {self.scanner_type.currentText()} scan on {target}...\n")
        
        # Update UI
        self.target_input.setEnabled(False)
        self.stop_button.setEnabled(True)
        
        # Create and start the worker thread
        self.scan_worker = ScanWorker(
            target=target,
            scan_type=self.scanner_type.currentData(),
            options=options
        )
        
        # Connect signals
        self.scan_worker.progress_updated.connect(self.update_progress)
        self.scan_worker.scan_completed.connect(self.on_scan_completed)
        self.scan_worker.error_occurred.connect(self.on_scan_error)
        
        # Start the scan
        self.scan_worker.start()
    
    def stop_scan(self):
        """Stop the current scan."""
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.stop()
            self.append_output("\nScan stopped by user.")
            self.progress_bar.setValue(0)
            self.progress_bar.setFormat("Scan stopped")
            self.stop_button.setEnabled(False)
            self.target_input.setEnabled(True)
    
    def update_progress(self, value: int, message: str):
        """Update the progress bar and status message."""
        self.progress_bar.setValue(value)
        self.progress_bar.setFormat(message)
        self.append_output(f"[STATUS] {message}")
    
    def on_scan_completed(self, results: Dict):
        """Handle scan completion."""
        try:
            self.scan_results = results
            self.display_results(results)
            self.append_output("\nScan completed successfully!")
        except Exception as e:
            logger.error(f"Error processing scan results: {e}", exc_info=True)
            self.append_output(f"\nError processing results: {e}")
        finally:
            self.progress_bar.setValue(100)
            self.progress_bar.setFormat("Scan completed")
            self.stop_button.setEnabled(False)
            self.target_input.setEnabled(True)
    
    def on_scan_error(self, error: str):
        """Handle scan errors."""
        self.append_output(f"\nError: {error}")
        self.progress_bar.setFormat("Scan failed")
        self.stop_button.setEnabled(False)
        self.target_input.setEnabled(True)
        QMessageBox.critical(self, "Scan Error", f"An error occurred during the scan:\n{error}")
    
    def display_results(self, results: Dict):
        """Display the scan results in the table."""
        try:
            if not results or "ports" not in results or not results["ports"]:
                self.append_output("No open ports found.")
                return
            
            # Clear existing rows
            self.results_table.setRowCount(0)
            
            # Add results to the table
            for port_info in results["ports"]:
                if port_info.get("state") == "open":
                    row = self.results_table.rowCount()
                    self.results_table.insertRow(row)
                    
                    self.results_table.setItem(row, 0, QTableWidgetItem(str(port_info.get("port", ""))))
                    self.results_table.setItem(row, 1, QTableWidgetItem(port_info.get("protocol", "tcp").upper()))
                    self.results_table.setItem(row, 2, QTableWidgetItem(port_info.get("state", "").title()))
                    self.results_table.setItem(row, 3, QTableWidgetItem(port_info.get("service", "unknown")))
                    self.results_table.setItem(row, 4, QTableWidgetItem(port_info.get("version", "")))
            
            # Resize columns to content
            self.results_table.resizeColumnsToContents()
            
            # Show summary
            open_ports = len([p for p in results.get("ports", []) if p.get("state") == "open"])
            self.append_output(f"\nScan complete. Found {open_ports} open ports.")
            
        except Exception as e:
            logger.error(f"Error displaying results: {e}", exc_info=True)
            self.append_output(f"\nError displaying results: {e}")
    
    def append_output(self, text: str):
        """Append text to the output console."""
        self.output_console.moveCursor(QTextCursor.End)
        self.output_console.insertPlainText(text + "\n")
        self.output_console.moveCursor(QTextCursor.End)
    
    def save_results(self):
        """Save the scan results to a file."""
        if not self.scan_results:
            QMessageBox.information(self, "No Results", "No scan results to save.")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Scan Results",
            "",
            "JSON Files (*.json);;Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(self.scan_results, f, indent=2)
                
                self.append_output(f"\nResults saved to: {file_path}")
                QMessageBox.information(self, "Success", f"Results saved to:\n{file_path}")
                
            except Exception as e:
                logger.error(f"Error saving results: {e}", exc_info=True)
                QMessageBox.critical(self, "Error", f"Failed to save results:\n{e}")
