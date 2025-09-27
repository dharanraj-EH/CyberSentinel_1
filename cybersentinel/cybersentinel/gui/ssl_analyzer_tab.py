"""
SSL/TLS Analyzer tab for the CyberSentinel application.
"""
import logging
import socket
import ssl
import datetime
from typing import Dict, List, Any, Optional, Tuple

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar,
    QMessageBox, QGroupBox, QFormLayout, QTabWidget, QTextEdit,
    QTreeWidget, QTreeWidgetItem, QComboBox, QSpinBox, QSplitter,
    QStyle, QApplication, QFileDialog
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt5.QtGui import QTextCursor, QIcon, QFont

from ..scanner.ssl_tests import SSLScanner, SSLScanResult
from ..utils.resource_loader import load_icon

logger = logging.getLogger(__name__)

class SSLScanWorker(QThread):
    """Worker thread for running SSL/TLS scans in the background."""
    
    # Signals for communication with the main thread
    progress_updated = pyqtSignal(int, str)
    scan_completed = pyqtSignal(SSLScanResult)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, target: str, port: int, protocols: List[str], parent=None):
        super().__init__(parent)
        self.target = target
        self.port = port
        self.protocols = protocols
        self._is_running = True
    
    def run(self):
        """Run the SSL/TLS scan in a separate thread."""
        try:
            self.progress_updated.emit(0, "Initializing SSL/TLS scan...")
            
            # Initialize the SSL scanner
            scanner = SSLScanner()
            
            # Run the scan
            self.progress_updated.emit(30, f"Scanning {self.target}:{self.port}...")
            result = scanner.scan(self.target, self.port, self.protocols)
            
            self.progress_updated.emit(90, "Processing results...")
            self.scan_completed.emit(result)
            self.progress_updated.emit(100, "Scan completed successfully!")
            
        except Exception as e:
            logger.error(f"SSL scan failed: {e}", exc_info=True)
            self.error_occurred.emit(str(e))
        finally:
            self._is_running = False
    
    def stop(self):
        """Stop the scan."""
        self._is_running = False
        self.terminate()
        self.wait()
        self.progress_updated.emit(0, "Scan stopped by user.")


class SSLAnalyzerTab(QWidget):
    """Tab for analyzing SSL/TLS configurations."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scan_worker = None
        self.scan_result = None
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
        target_group = QGroupBox("SSL/TLS Scan Target")
        target_layout = QHBoxLayout(target_group)
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter hostname or IP address")
        
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(443)
        
        scan_button = QPushButton("Start Scan")
        scan_button.setIcon(load_icon("search.svg") or QApplication.style().standardIcon(QStyle.SP_MediaPlay))
        scan_button.clicked.connect(self.start_scan)
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.setIcon(load_icon("stop.svg") or QApplication.style().standardIcon(QStyle.SP_MediaStop))
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_scan)
        
        target_layout.addWidget(QLabel("Target:"))
        target_layout.addWidget(self.target_input, 1)
        target_layout.addWidget(QLabel("Port:"))
        target_layout.addWidget(self.port_input)
        target_layout.addWidget(scan_button)
        target_layout.addWidget(self.stop_button)
        
        # Protocol selection
        protocol_group = QGroupBox("Protocols to Test")
        protocol_layout = QHBoxLayout(protocol_group)
        
        self.protocol_ssl2 = QCheckBox("SSLv2")
        self.protocol_ssl3 = QCheckBox("SSLv3")
        self.protocol_tls10 = QCheckBox("TLS 1.0")
        self.protocol_tls11 = QCheckBox("TLS 1.1")
        self.protocol_tls12 = QCheckBox("TLS 1.2")
        self.protocol_tls13 = QCheckBox("TLS 1.3")
        
        # Set default protocols
        self.protocol_tls10.setChecked(True)
        self.protocol_tls11.setChecked(True)
        self.protocol_tls12.setChecked(True)
        self.protocol_tls13.setChecked(True)
        
        protocol_layout.addWidget(self.protocol_ssl2)
        protocol_layout.addWidget(self.protocol_ssl3)
        protocol_layout.addWidget(self.protocol_tls10)
        protocol_layout.addWidget(self.protocol_tls11)
        protocol_layout.addWidget(self.protocol_tls12)
        protocol_layout.addWidget(self.protocol_tls13)
        protocol_layout.addStretch()
        
        # Scan options
        options_group = QGroupBox("Scan Options")
        options_layout = QFormLayout(options_group)
        
        self.check_certificate = QCheckBox("Check certificate validity")
        self.check_certificate.setChecked(True)
        
        self.check_ciphers = QCheckBox("Check cipher suites")
        self.check_ciphers.setChecked(True)
        
        self.check_vulnerabilities = QCheckBox("Check for known vulnerabilities")
        self.check_vulnerabilities.setChecked(True)
        
        options_layout.addRow(self.check_certificate)
        options_layout.addRow(self.check_ciphers)
        options_layout.addRow(self.check_vulnerabilities)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("Ready")
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        
        # Add widgets to top panel
        top_layout.addWidget(target_group)
        top_layout.addWidget(protocol_group)
        top_layout.addWidget(options_group)
        top_layout.addWidget(self.progress_bar)
        
        # Bottom panel: Results
        bottom_panel = QTabWidget()
        
        # Certificate tab
        self.cert_tab = QWidget()
        cert_layout = QFormLayout(self.cert_tab)
        
        self.cert_subject = QLabel("-")
        self.cert_issuer = QLabel("-")
        self.cert_valid_from = QLabel("-")
        self.cert_valid_to = QLabel("-")
        self.cert_days_left = QLabel("-")
        self.cert_serial = QLabel("-")
        self.cert_sig_algorithm = QLabel("-")
        self.cert_key_size = QLabel("-")
        
        cert_layout.addRow("Subject:", self.cert_subject)
        cert_layout.addRow("Issuer:", self.cert_issuer)
        cert_layout.addRow("Valid From:", self.cert_valid_from)
        cert_layout.addRow("Valid To:", self.cert_valid_to)
        cert_layout.addRow("Days Left:", self.cert_days_left)
        cert_layout.addRow("Serial Number:", self.cert_serial)
        cert_layout.addRow("Signature Algorithm:", self.cert_sig_algorithm)
        cert_layout.addRow("Key Size:", self.cert_key_size)
        
        # Protocols tab
        self.protocols_tab = QWidget()
        protocols_layout = QVBoxLayout(self.protocols_tab)
        
        self.protocols_table = QTableWidget()
        self.protocols_table.setColumnCount(3)
        self.protocols_table.setHorizontalHeaderLabels(["Protocol", "Supported", "Cipher Suites"])
        self.protocols_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.protocols_table.horizontalHeader().setStretchLastSection(True)
        self.protocols_table.verticalHeader().setVisible(False)
        
        protocols_layout.addWidget(self.protocols_table)
        
        # Vulnerabilities tab
        self.vulns_tab = QWidget()
        vulns_layout = QVBoxLayout(self.vulns_tab)
        
        self.vulns_table = QTableWidget()
        self.vulns_table.setColumnCount(4)
        self.vulns_table.setHorizontalHeaderLabels(["Severity", "Vulnerability", "Description", "Solution"])
        self.vulns_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.vulns_table.horizontalHeader().setStretchLastSection(True)
        self.vulns_table.verticalHeader().setVisible(False)
        
        vulns_layout.addWidget(self.vulns_table)
        
        # Output console
        self.output_console = QTextEdit()
        self.output_console.setReadOnly(True)
        self.output_console.setFontFamily("Courier")
        self.output_console.setLineWrapMode(QTextEdit.NoWrap)
        
        # Add tabs
        bottom_panel.addTab(self.cert_tab, "Certificate")
        bottom_panel.addTab(self.protocols_tab, "Protocols & Ciphers")
        bottom_panel.addTab(self.vulns_tab, "Vulnerabilities")
        bottom_panel.addTab(self.output_console, "Output")
        
        # Add panels to splitter
        splitter.addWidget(top_panel)
        splitter.addWidget(bottom_panel)
        
        # Set initial sizes
        splitter.setSizes([200, 400])
        
        # Add splitter to main layout
        main_layout.addWidget(splitter)
    
    def start_scan(self):
        """Start the SSL/TLS scan with the current settings."""
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter a target to scan.")
            return
        
        # Get selected protocols
        protocols = []
        if self.protocol_ssl2.isChecked():
            protocols.append("SSLv2")
        if self.protocol_ssl3.isChecked():
            protocols.append("SSLv3")
        if self.protocol_tls10.isChecked():
            protocols.append("TLSv1.0")
        if self.protocol_tls11.isChecked():
            protocols.append("TLSv1.1")
        if self.protocol_tls12.isChecked():
            protocols.append("TLSv1.2")
        if self.protocol_tls13.isChecked():
            protocols.append("TLSv1.3")
        
        if not protocols:
            QMessageBox.warning(self, "Input Error", "Please select at least one protocol to test.")
            return
        
        # Clear previous results
        self.clear_results()
        self.append_output(f"Starting SSL/TLS scan on {target}:{self.port_input.value()}...\n")
        
        # Update UI
        self.target_input.setEnabled(False)
        self.port_input.setEnabled(False)
        self.stop_button.setEnabled(True)
        
        # Create and start the worker thread
        self.scan_worker = SSLScanWorker(
            target=target,
            port=self.port_input.value(),
            protocols=protocols
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
            self.port_input.setEnabled(True)
    
    def update_progress(self, value: int, message: str):
        """Update the progress bar and status message."""
        self.progress_bar.setValue(value)
        self.progress_bar.setFormat(message)
        self.append_output(f"[STATUS] {message}")
    
    def on_scan_completed(self, result: SSLScanResult):
        """Handle scan completion."""
        try:
            self.scan_result = result
            self.display_results(result)
            self.append_output("\nSSL/TLS scan completed successfully!")
        except Exception as e:
            logger.error(f"Error processing SSL scan results: {e}", exc_info=True)
            self.append_output(f"\nError processing results: {e}")
        finally:
            self.progress_bar.setValue(100)
            self.progress_bar.setFormat("Scan completed")
            self.stop_button.setEnabled(False)
            self.target_input.setEnabled(True)
            self.port_input.setEnabled(True)
    
    def on_scan_error(self, error: str):
        """Handle scan errors."""
        self.append_output(f"\nError: {error}")
        self.progress_bar.setFormat("Scan failed")
        self.stop_button.setEnabled(False)
        self.target_input.setEnabled(True)
        self.port_input.setEnabled(True)
        QMessageBox.critical(self, "Scan Error", f"An error occurred during the scan:\n{error}")
    
    def clear_results(self):
        """Clear all result fields."""
        # Clear certificate info
        self.cert_subject.setText("-")
        self.cert_issuer.setText("-")
        self.cert_valid_from.setText("-")
        self.cert_valid_to.setText("-")
        self.cert_days_left.setText("-")
        self.cert_serial.setText("-")
        self.cert_sig_algorithm.setText("-")
        self.cert_key_size.setText("-")
        
        # Clear protocols table
        self.protocols_table.setRowCount(0)
        
        # Clear vulnerabilities table
        self.vulns_table.setRowCount(0)
        
        # Clear output console
        self.output_console.clear()
    
    def display_results(self, result: SSLScanResult):
        """Display the scan results in the UI."""
        try:
            # Display certificate information
            if result.certificate:
                self.display_certificate_info(result.certificate)
            
            # Display protocol and cipher information
            if result.protocols:
                self.display_protocols_info(result.protocols)
            
            # Display vulnerabilities
            if result.vulnerabilities:
                self.display_vulnerabilities(result.vulnerabilities)
            
            # Show summary
            self.append_output("\nSSL/TLS scan complete.")
            
        except Exception as e:
            logger.error(f"Error displaying SSL scan results: {e}", exc_info=True)
            self.append_output(f"\nError displaying results: {e}")
    
    def display_certificate_info(self, cert_info: Dict):
        """Display certificate information."""
        try:
            # Subject
            if 'subject' in cert_info:
                subject = ", ".join([f"{k}={v}" for k, v in cert_info['subject'].items()])
                self.cert_subject.setText(subject)
            
            # Issuer
            if 'issuer' in cert_info:
                issuer = ", ".join([f"{k}={v}" for k, v in cert_info['issuer'].items()])
                self.cert_issuer.setText(issuer)
            
            # Validity period
            if 'not_before' in cert_info:
                self.cert_valid_from.setText(str(cert_info['not_before']))
            if 'not_after' in cert_info:
                self.cert_valid_to.setText(str(cert_info['not_after']))
            
            # Days left
            if 'expires_in_days' in cert_info:
                days = cert_info['expires_in_days']
                self.cert_days_left.setText(f"{days} days")
                
                # Highlight if certificate is expired or expiring soon
                if days < 0:
                    self.cert_days_left.setStyleSheet("color: red; font-weight: bold;")
                    self.append_output("[WARNING] Certificate has expired!")
                elif days < 30:
                    self.cert_days_left.setStyleSheet("color: orange; font-weight: bold;")
                    self.append_output(f"[WARNING] Certificate expires in {days} days!")
                else:
                    self.cert_days_left.setStyleSheet("")
            
            # Other certificate details
            if 'serial_number' in cert_info:
                self.cert_serial.setText(str(cert_info['serial_number']))
            if 'signature_algorithm' in cert_info:
                self.cert_sig_algorithm.setText(str(cert_info['signature_algorithm']))
            if 'key_size' in cert_info:
                self.cert_key_size.setText(f"{cert_info['key_size']} bits")
            
            # Check for self-signed certificate
            if cert_info.get('self_signed', False):
                self.append_output("[WARNING] Certificate is self-signed!")
            
            # Check for weak key size
            if 'key_size' in cert_info and cert_info['key_size'] < 2048:
                self.append_output(f"[WARNING] Weak key size: {cert_info['key_size']} bits (recommended: 2048+)")
            
        except Exception as e:
            logger.error(f"Error displaying certificate info: {e}", exc_info=True)
            self.append_output(f"Error displaying certificate info: {e}")
    
    def display_protocols_info(self, protocols: Dict):
        """Display protocol and cipher information."""
        try:
            self.protocols_table.setRowCount(0)
            
            for protocol, info in protocols.items():
                row = self.protocols_table.rowCount()
                self.protocols_table.insertRow(row)
                
                # Protocol name
                self.protocols_table.setItem(row, 0, QTableWidgetItem(protocol))
                
                # Supported status
                status = "Yes" if info.get('supported', False) else "No"
                self.protocols_table.setItem(row, 1, QTableWidgetItem(status))
                
                # Cipher suites
                ciphers = info.get('ciphers', [])
                cipher_names = [c.get('name', '') for c in ciphers if c.get('supported', False)]
                self.protocols_table.setItem(row, 2, QTableWidgetItem(", ".join(cipher_names)))
                
                # Highlight insecure protocols
                if protocol in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'] and info.get('supported', False):
                    for col in range(3):
                        item = self.protocols_table.item(row, col)
                        if item:
                            item.setBackground(Qt.red)
                            item.setForeground(Qt.white)
                            item.setToolTip("This protocol is considered insecure and should be disabled.")
            
            # Resize columns to content
            self.protocols_table.resizeColumnsToContents()
            
        except Exception as e:
            logger.error(f"Error displaying protocols info: {e}", exc_info=True)
            self.append_output(f"Error displaying protocols info: {e}")
    
    def display_vulnerabilities(self, vulnerabilities: List[Dict]):
        """Display vulnerability information."""
        try:
            self.vulns_table.setRowCount(0)
            
            for vuln in vulnerabilities:
                row = self.vulns_table.rowCount()
                self.vulns_table.insertRow(row)
                
                # Severity with color coding
                severity = vuln.get('severity', 'info').capitalize()
                severity_item = QTableWidgetItem(severity)
                
                # Set background color based on severity
                if severity.lower() == 'critical':
                    severity_item.setBackground(Qt.darkRed)
                    severity_item.setForeground(Qt.white)
                elif severity.lower() == 'high':
                    severity_item.setBackground(Qt.red)
                    severity_item.setForeground(Qt.white)
                elif severity.lower() == 'medium':
                    severity_item.setBackground(Qt.yellow)
                elif severity.lower() == 'low':
                    severity_item.setBackground(Qt.cyan)
                
                self.vulns_table.setItem(row, 0, severity_item)
                
                # Vulnerability name
                self.vulns_table.setItem(row, 1, QTableWidgetItem(vuln.get('name', 'Unknown')))
                
                # Description
                self.vulns_table.setItem(row, 2, QTableWidgetItem(vuln.get('description', 'No description available.')))
                
                # Solution
                self.vulns_table.setItem(row, 3, QTableWidgetItem(vuln.get('solution', 'No solution provided.')))
            
            # Resize columns to content
            self.vulns_table.resizeColumnsToContents()
            
        except Exception as e:
            logger.error(f"Error displaying vulnerabilities: {e}", exc_info=True)
            self.append_output(f"Error displaying vulnerabilities: {e}")
    
    def append_output(self, text: str):
        """Append text to the output console."""
        self.output_console.moveCursor(QTextCursor.End)
        self.output_console.insertPlainText(text + "\n")
        self.output_console.moveCursor(QTextCursor.End)
    
    def save_results(self):
        """Save the scan results to a file."""
        if not self.scan_result:
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
                    # Convert SSLScanResult to dict if needed
                    if hasattr(self.scan_result, 'to_dict'):
                        json.dump(self.scan_result.to_dict(), f, indent=2)
                    else:
                        json.dump(self.scan_result, f, indent=2)
                
                self.append_output(f"\nResults saved to: {file_path}")
                QMessageBox.information(self, "Success", f"Results saved to:\n{file_path}")
                
            except Exception as e:
                logger.error(f"Error saving results: {e}", exc_info=True)
                QMessageBox.critical(self, "Error", f"Failed to save results:\n{e}")
