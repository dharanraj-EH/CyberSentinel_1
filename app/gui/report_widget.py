"""
Report widget for CyberSentinel GUI.
"""
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox,
    QPushButton, QFileDialog, QMessageBox, QTextEdit, QGroupBox,
    QFormLayout, QCheckBox, QProgressBar
)
from PyQt5.QtCore import Qt, pyqtSignal
import os
import json
from datetime import datetime
from pathlib import Path

class ReportWidget(QWidget):
    """Widget for generating and exporting scan reports."""
    
    generate_report_signal = pyqtSignal(str, str, dict)  # scan_id, format, options
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scan_id = None
        self.report_generating = False
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        main_layout = QVBoxLayout(self)
        
        # Report configuration group
        config_group = QGroupBox("Report Configuration")
        config_layout = QFormLayout()
        
        # Scan selection
        self.scan_combo = QComboBox()
        self.scan_combo.setPlaceholderText("Select a scan...")
        
        # Report format selection
        self.format_combo = QComboBox()
        self.format_combo.addItem("PDF", "pdf")
        self.format_combo.addItem("HTML", "html")
        self.format_combo.addItem("JSON", "json")
        self.format_combo.setCurrentIndex(0)
        
        # Report options
        self.include_exec_summary = QCheckBox("Include Executive Summary")
        self.include_exec_summary.setChecked(True)
        
        self.include_methodology = QCheckBox("Include Methodology")
        self.include_methodology.setChecked(True)
        
        self.include_findings = QCheckBox("Include Detailed Findings")
        self.include_findings.setChecked(True)
        
        self.include_recommendations = QCheckBox("Include Recommendations")
        self.include_recommendations.setChecked(True)
        
        # Add widgets to layout
        config_layout.addRow("Scan:", self.scan_combo)
        config_layout.addRow("Format:", self.format_combo)
        config_layout.addRow(QLabel("Options:"))
        config_layout.addRow("", self.include_exec_summary)
        config_layout.addRow("", self.include_methodology)
        config_layout.addRow("", self.include_findings)
        config_layout.addRow("", self.include_recommendations)
        
        config_group.setLayout(config_layout)
        
        # Generate button
        self.generate_btn = QPushButton("Generate Report")
        self.generate_btn.clicked.connect(self.generate_report)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        # Output preview
        self.preview_label = QLabel("Report Preview:")
        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)
        self.preview_text.setPlaceholderText("Report preview will appear here...")
        
        # Add widgets to main layout
        main_layout.addWidget(config_group)
        main_layout.addWidget(self.generate_btn)
        main_layout.addWidget(self.progress_bar)
        main_layout.addWidget(self.preview_label)
        main_layout.addWidget(self.preview_text)
        
        # Apply styles
        self.apply_styles()
    
    def set_scan_id(self, scan_id: str):
        """Set the current scan ID and update the UI."""
        self.scan_id = scan_id
        self.update_scan_list()
    
    def update_scan_list(self):
        """Update the list of available scans."""
        # In a real application, this would load the list of available scans
        # For now, we'll just add the current scan if it exists
        self.scan_combo.clear()
        
        if self.scan_id:
            self.scan_combo.addItem(f"Scan {self.scan_id}", self.scan_id)
    
    def generate_report(self):
        """Generate a report for the selected scan."""
        if not self.scan_combo.count() > 0:
            QMessageBox.warning(self, "No Scans", "No scans available to generate a report.")
            return
        
        # Get selected scan and format
        scan_id = self.scan_combo.currentData()
        report_format = self.format_combo.currentData()
        
        # Get report options
        options = {
            'include_exec_summary': self.include_exec_summary.isChecked(),
            'include_methodology': self.include_methodology.isChecked(),
            'include_findings': self.include_findings.isChecked(),
            'include_recommendations': self.include_recommendations.isChecked()
        }
        
        # Show progress
        self.report_generating = True
        self.generate_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        # Emit signal to generate the report
        self.generate_report_signal.emit(scan_id, report_format, options)
    
    def on_report_generated(self, success: bool, message: str = "", file_path: str = ""):
        """Handle report generation completion."""
        self.report_generating = False
        self.generate_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        if success:
            # Show success message
            QMessageBox.information(self, "Report Generated", message)
            
            # Update preview if it's a text-based format
            if file_path and file_path.endswith(('.html', '.json', '.txt')):
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                    
                    if file_path.endswith('.json'):
                        # Pretty-print JSON
                        data = json.loads(content)
                        self.preview_text.setPlainText(json.dumps(data, indent=2))
                    else:
                        # Display HTML or text as-is
                        if file_path.endswith('.html'):
                            self.preview_text.setHtml(content)
                        else:
                            self.preview_text.setPlainText(content)
                except Exception as e:
                    self.preview_text.setPlainText(f"Error loading preview: {str(e)}")
            else:
                self.preview_text.setPlainText("Preview not available for this format.")
        else:
            # Show error message
            QMessageBox.critical(self, "Report Generation Failed", message)
    
    def update_progress(self, value: int, message: str = ""):
        """Update the progress bar and status message."""
        self.progress_bar.setValue(value)
        if message:
            self.statusBar().showMessage(message)
    
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
            
            QTextEdit {
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 6px;
            }
        """)
