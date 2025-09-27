"""
Web Tests tab for the CyberSentinel application.
"""
import logging
import json
import requests
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Any, Optional, Tuple

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar,
    QMessageBox, QGroupBox, QFormLayout, QTabWidget, QTextEdit,
    QTreeWidget, QTreeWidgetItem, QComboBox, QCheckBox, QSplitter,
    QStyle, QApplication, QFileDialog, QListWidget, QListWidgetItem
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize, QUrl
from PyQt5.QtGui import QTextCursor, QIcon, QDesktopServices

from ..web_tests import WebSecurityTester
from ..utils.resource_loader import load_icon

logger = logging.getLogger(__name__)

class WebTestWorker(QThread):
    """Worker thread for running web security tests in the background."""
    
    # Signals for communication with the main thread
    progress_updated = pyqtSignal(int, str)
    test_completed = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, url: str, tests: List[str], options: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.url = url
        self.tests = tests
        self.options = options
        self._is_running = True
    
    def run(self):
        """Run the web security tests in a separate thread."""
        try:
            self.progress_updated.emit(0, "Initializing web security tests...")
            
            # Initialize the web security tester
            tester = WebSecurityTester()
            
            # Run the selected tests
            results = {}
            total_tests = len(self.tests)
            
            for i, test_name in enumerate(self.tests):
                if not self._is_running:
                    break
                
                self.progress_updated.emit(
                    int((i / total_tests) * 100),
                    f"Running {test_name.replace('_', ' ').title()} test..."
                )
                
                try:
                    # Run the test and store the results
                    test_method = getattr(tester, f"test_{test_name}", None)
                    if test_method:
                        result = test_method(self.url, **self.options)
                        results[test_name] = result
                        
                        # Log the result
                        status = "PASSED" if result.get('vulnerable', False) is False else "FAILED"
                        self.progress_updated.emit(
                            int(((i + 1) / total_tests) * 100),
                            f"{test_name.replace('_', ' ').title()}: {status}"
                        )
                    
                except Exception as e:
                    logger.error(f"Error running {test_name} test: {e}", exc_info=True)
                    results[test_name] = {
                        'vulnerable': False,
                        'error': str(e),
                        'details': f"Error running test: {e}"
                    }
            
            if self._is_running:
                self.test_completed.emit(results)
                self.progress_updated.emit(100, "All tests completed successfully!")
            
        except Exception as e:
            logger.error(f"Web security tests failed: {e}", exc_info=True)
            self.error_occurred.emit(str(e))
        finally:
            self._is_running = False
    
    def stop(self):
        """Stop the tests."""
        self._is_running = False
        self.terminate()
        self.wait()
        self.progress_updated.emit(0, "Tests stopped by user.")


class WebTestsTab(QWidget):
    """Tab for running web security tests."""
    
    # Available web security tests
    AVAILABLE_TESTS = [
        ('headers', "Security Headers", "Check for missing security headers"),
        ('cors', "CORS Misconfiguration", "Check for CORS misconfigurations"),
        ('clickjacking', "Clickjacking", "Check for clickjacking vulnerabilities"),
        ('csrf', "CSRF Protection", "Check for CSRF protection"),
        ('xss', "XSS Protection", "Check for XSS protection headers"),
        ('hsts', "HSTS", "Check for HTTP Strict Transport Security"),
        ('csp', "Content Security Policy", "Check Content Security Policy"),
        ('cookies', "Cookie Security", "Check cookie security flags"),
        ('http_methods', "HTTP Methods", "Check allowed HTTP methods"),
        ('directory_listing', "Directory Listing", "Check for directory listing"),
        ('server_info', "Server Information", "Gather server information")
    ]
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.test_worker = None
        self.test_results = {}
        self._init_ui()
    
    def _init_ui(self):
        """Initialize the UI components."""
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Create a splitter for resizable panels
        splitter = QSplitter(Qt.Vertical)
        
        # Top panel: Test controls
        top_panel = QWidget()
        top_layout = QVBoxLayout(top_panel)
        top_layout.setContentsMargins(0, 0, 0, 0)
        
        # URL input
        url_group = QGroupBox("Test Target")
        url_layout = QHBoxLayout(url_group)
        
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        
        test_button = QPushButton("Run Tests")
        test_button.setIcon(load_icon("search.svg") or QApplication.style().standardIcon(QStyle.SP_MediaPlay))
        test_button.clicked.connect(self.start_tests)
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.setIcon(load_icon("stop.svg") or QApplication.style().standardIcon(QStyle.SP_MediaStop))
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_tests)
        
        url_layout.addWidget(QLabel("URL:"))
        url_layout.addWidget(self.url_input, 1)
        url_layout.addWidget(test_button)
        url_layout.addWidget(self.stop_button)
        
        # Test selection
        tests_group = QGroupBox("Select Tests")
        tests_layout = QVBoxLayout(tests_group)
        
        # Create checkboxes for each test
        self.test_checkboxes = {}
        for test_id, test_name, test_desc in self.AVAILABLE_TESTS:
            checkbox = QCheckBox(f"{test_name} - {test_desc}")
            checkbox.setChecked(True)
            self.test_checkboxes[test_id] = checkbox
            tests_layout.addWidget(checkbox)
        
        # Select all/none buttons
        btn_layout = QHBoxLayout()
        select_all_btn = QPushButton("Select All")
        select_all_btn.clicked.connect(self.select_all_tests)
        select_none_btn = QPushButton("Select None")
        select_none_btn.clicked.connect(self.deselect_all_tests)
        
        btn_layout.addWidget(select_all_btn)
        btn_layout.addWidget(select_none_btn)
        btn_layout.addStretch()
        
        tests_layout.addLayout(btn_layout)
        
        # Test options
        options_group = QGroupBox("Test Options")
        options_layout = QFormLayout(options_group)
        
        self.follow_redirects = QCheckBox("Follow redirects")
        self.follow_redirects.setChecked(True)
        
        self.verify_ssl = QCheckBox("Verify SSL certificate")
        self.verify_ssl.setChecked(True)
        
        self.timeout = QSpinBox()
        self.timeout.setRange(1, 300)
        self.timeout.setValue(10)
        self.timeout.setSuffix(" seconds")
        
        options_layout.addRow(self.follow_redirects)
        options_layout.addRow(self.verify_ssl)
        options_layout.addRow("Request timeout:", self.timeout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("Ready")
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        
        # Add widgets to top panel
        top_layout.addWidget(url_group)
        top_layout.addWidget(tests_group)
        top_layout.addWidget(options_group)
        top_layout.addWidget(self.progress_bar)
        
        # Bottom panel: Results
        bottom_panel = QTabWidget()
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["Test", "Status", "Severity", "Details"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.itemDoubleClicked.connect(self.show_test_details)
        
        # Details panel
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setFontFamily("Courier")
        
        # Output console
        self.output_console = QTextEdit()
        self.output_console.setReadOnly(True)
        self.output_console.setFontFamily("Courier")
        self.output_console.setLineWrapMode(QTextEdit.NoWrap)
        
        # Add tabs
        bottom_panel.addTab(self.results_table, "Results")
        bottom_panel.addTab(self.details_text, "Details")
        bottom_panel.addTab(self.output_console, "Output")
        
        # Add panels to splitter
        splitter.addWidget(top_panel)
        splitter.addWidget(bottom_panel)
        
        # Set initial sizes
        splitter.setSizes([300, 400])
        
        # Add splitter to main layout
        main_layout.addWidget(splitter)
    
    def select_all_tests(self):
        """Select all available tests."""
        for checkbox in self.test_checkboxes.values():
            checkbox.setChecked(True)
    
    def deselect_all_tests(self):
        """Deselect all tests."""
        for checkbox in self.test_checkboxes.values():
            checkbox.setChecked(False)
    
    def get_selected_tests(self) -> List[str]:
        """Get the list of selected test IDs."""
        return [test_id for test_id, checkbox in self.test_checkboxes.items() 
                if checkbox.isChecked()]
    
    def start_tests(self):
        """Start the selected web security tests."""
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter a URL to test.")
            return
        
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            self.url_input.setText(url)
        
        # Get selected tests
        selected_tests = self.get_selected_tests()
        if not selected_tests:
            QMessageBox.warning(self, "Input Error", "Please select at least one test to run.")
            return
        
        # Clear previous results
        self.clear_results()
        self.append_output(f"Starting web security tests for {url}...\n")
        
        # Update UI
        self.url_input.setEnabled(False)
        self.stop_button.setEnabled(True)
        
        # Prepare test options
        options = {
            'follow_redirects': self.follow_redirects.isChecked(),
            'verify_ssl': self.verify_ssl.isChecked(),
            'timeout': self.timeout.value()
        }
        
        # Create and start the worker thread
        self.test_worker = WebTestWorker(
            url=url,
            tests=selected_tests,
            options=options
        )
        
        # Connect signals
        self.test_worker.progress_updated.connect(self.update_progress)
        self.test_worker.test_completed.connect(self.on_tests_completed)
        self.test_worker.error_occurred.connect(self.on_test_error)
        
        # Start the tests
        self.test_worker.start()
    
    def stop_tests(self):
        """Stop the current tests."""
        if self.test_worker and self.test_worker.isRunning():
            self.test_worker.stop()
            self.append_output("\nTests stopped by user.")
            self.progress_bar.setValue(0)
            self.progress_bar.setFormat("Tests stopped")
            self.stop_button.setEnabled(False)
            self.url_input.setEnabled(True)
    
    def update_progress(self, value: int, message: str):
        """Update the progress bar and status message."""
        self.progress_bar.setValue(value)
        self.progress_bar.setFormat(message)
        self.append_output(f"[STATUS] {message}")
    
    def on_tests_completed(self, results: Dict):
        """Handle test completion."""
        try:
            self.test_results = results
            self.display_results(results)
            self.append_output("\nAll tests completed!")
            
            # Show summary
            total_tests = len(results)
            passed_tests = sum(1 for r in results.values() if not r.get('vulnerable', True))
            failed_tests = total_tests - passed_tests
            
            summary = f"\n=== Test Summary ===\n"
            summary += f"Total Tests: {total_tests}\n"
            summary += f"Passed: {passed_tests}\n"
            summary += f"Failed: {failed_tests}\n"
            
            if failed_tests > 0:
                summary += "\nVulnerabilities found! Please review the results."
            else:
                summary += "\nNo vulnerabilities found!"
            
            self.append_output(summary)
            
        except Exception as e:
            logger.error(f"Error processing test results: {e}", exc_info=True)
            self.append_output(f"\nError processing results: {e}")
        finally:
            self.progress_bar.setValue(100)
            self.progress_bar.setFormat("Tests completed")
            self.stop_button.setEnabled(False)
            self.url_input.setEnabled(True)
    
    def on_test_error(self, error: str):
        """Handle test errors."""
        self.append_output(f"\nError: {error}")
        self.progress_bar.setFormat("Tests failed")
        self.stop_button.setEnabled(False)
        self.url_input.setEnabled(True)
        QMessageBox.critical(self, "Test Error", f"An error occurred during testing:\n{error}")
    
    def clear_results(self):
        """Clear all result fields."""
        self.results_table.setRowCount(0)
        self.details_text.clear()
        self.output_console.clear()
        self.test_results = {}
    
    def display_results(self, results: Dict):
        """Display the test results in the table."""
        try:
            self.results_table.setRowCount(0)
            
            for test_id, result in results.items():
                # Get test info
                test_info = next((t for t in self.AVAILABLE_TESTS if t[0] == test_id), None)
                test_name = test_info[1] if test_info else test_id.replace('_', ' ').title()
                
                # Determine status and severity
                is_vulnerable = result.get('vulnerable', False)
                status = "VULNERABLE" if is_vulnerable else "SECURE"
                severity = result.get('severity', 'info').upper()
                
                # Add row to table
                row = self.results_table.rowCount()
                self.results_table.insertRow(row)
                
                # Test name
                self.results_table.setItem(row, 0, QTableWidgetItem(test_name))
                
                # Status with color coding
                status_item = QTableWidgetItem(status)
                if is_vulnerable:
                    status_item.setBackground(Qt.red if severity in ['HIGH', 'CRITICAL'] else Qt.yellow)
                    status_item.setForeground(Qt.white if severity in ['HIGH', 'CRITICAL'] else Qt.black)
                else:
                    status_item.setBackground(Qt.green)
                self.results_table.setItem(row, 1, status_item)
                
                # Severity
                severity_item = QTableWidgetItem(severity)
                if severity in ['HIGH', 'CRITICAL']:
                    severity_item.setBackground(Qt.red)
                    severity_item.setForeground(Qt.white)
                elif severity == 'MEDIUM':
                    severity_item.setBackground(Qt.yellow)
                elif severity == 'LOW':
                    severity_item.setBackground(Qt.cyan)
                self.results_table.setItem(row, 2, severity_item)
                
                # Details (short summary)
                details = result.get('details', '')
                if isinstance(details, (list, dict)):
                    details = json.dumps(details, indent=2)
                details_summary = (details[:100] + '...') if len(str(details)) > 100 else details
                self.results_table.setItem(row, 3, QTableWidgetItem(str(details_summary)))
                
                # Store full details in the item's data role
                if 'details' in result:
                    self.results_table.item(row, 0).setData(Qt.UserRole, result['details'])
            
            # Resize columns to content
            self.results_table.resizeColumnsToContents()
            
        except Exception as e:
            logger.error(f"Error displaying test results: {e}", exc_info=True)
            self.append_output(f"\nError displaying results: {e}")
    
    def show_test_details(self, item):
        """Show detailed information about the selected test."""
        try:
            row = item.row()
            details = self.results_table.item(row, 0).data(Qt.UserRole)
            
            if details is not None:
                if isinstance(details, dict) or isinstance(details, list):
                    self.details_text.setPlainText(json.dumps(details, indent=2))
                else:
                    self.details_text.setPlainText(str(details))
            else:
                self.details_text.setPlainText("No additional details available.")
            
            # Switch to the details tab
            tab_widget = self.parent().parent()  # Get the QTabWidget
            tab_widget.setCurrentIndex(1)  # Switch to the Details tab
            
        except Exception as e:
            logger.error(f"Error showing test details: {e}", exc_info=True)
            self.append_output(f"\nError showing test details: {e}")
    
    def append_output(self, text: str):
        """Append text to the output console."""
        self.output_console.moveCursor(QTextCursor.End)
        self.output_console.insertPlainText(text + "\n")
        self.output_console.moveCursor(QTextCursor.End)
    
    def save_results(self):
        """Save the test results to a file."""
        if not self.test_results:
            QMessageBox.information(self, "No Results", "No test results to save.")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Test Results",
            "",
            "JSON Files (*.json);;Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(self.test_results, f, indent=2)
                
                self.append_output(f"\nResults saved to: {file_path}")
                QMessageBox.information(self, "Success", f"Results saved to:\n{file_path}")
                
            except Exception as e:
                logger.error(f"Error saving results: {e}", exc_info=True)
                QMessageBox.critical(self, "Error", f"Failed to save results:\n{e}")
