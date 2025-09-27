"""
Results widget for CyberSentinel GUI.
"""
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QTreeWidget, QTreeWidgetItem, QLabel, QTabWidget, QSplitter,
    QHeaderView, QMenu, QAction, QMessageBox, QFileDialog
)
from PyQt5.QtCore import Qt, pyqtSignal, QSize
from PyQt5.QtGui import QColor, QIcon, QFont

class ResultsWidget(QWidget):
    """Widget for displaying scan results."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.results = {}
        self.init_ui()
    
    def init_ui(self):
        """Initialize the user interface."""
        main_layout = QVBoxLayout(self)
        
        # Create a tab widget for different views
        self.tab_widget = QTabWidget()
        
        # Summary tab
        self.summary_tab = QWidget()
        self.setup_summary_tab()
        
        # Hosts tab
        self.hosts_tab = QWidget()
        self.setup_hosts_tab()
        
        # Vulnerabilities tab
        self.vulns_tab = QWidget()
        self.setup_vulns_tab()
        
        # Add tabs
        self.tab_widget.addTab(self.summary_tab, "Summary")
        self.tab_widget.addTab(self.hosts_tab, "Hosts")
        self.tab_widget.addTab(self.vulns_tab, "Vulnerabilities")
        
        # Add to main layout
        main_layout.addWidget(self.tab_widget)
        
        # Apply styles
        self.apply_styles()
    
    def setup_summary_tab(self):
        """Set up the summary tab."""
        layout = QVBoxLayout()
        
        # Summary cards
        cards_layout = QHBoxLayout()
        
        # Hosts card
        self.hosts_card = self.create_summary_card(
            "Hosts", "0", "#3a7cce"
        )
        
        # Services card
        self.services_card = self.create_summary_card(
            "Services", "0", "#28a745"
        )
        
        # Vulnerabilities card
        self.vulns_card = self.create_summary_card(
            "Vulnerabilities", "0", "#dc3545"
        )
        
        # Add cards to layout
        cards_layout.addWidget(self.hosts_card)
        cards_layout.addWidget(self.services_card)
        cards_layout.addWidget(self.vulns_card)
        
        # Add to main layout
        layout.addLayout(cards_layout)
        
        # Add scan details
        self.scan_details = QLabel("No scan results available.")
        self.scan_details.setWordWrap(True)
        layout.addWidget(self.scan_details)
        
        # Set layout
        self.summary_tab.setLayout(layout)
    
    def setup_hosts_tab(self):
        """Set up the hosts tab."""
        layout = QVBoxLayout()
        
        # Create hosts table
        self.hosts_table = QTableWidget()
        self.hosts_table.setColumnCount(5)
        self.hosts_table.setHorizontalHeaderLabels(["Host", "Status", "OS", "Open Ports", "Vulnerabilities"])
        self.hosts_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.hosts_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.hosts_table.setEditTriggers(QTableWidget.NoEditTriggers)
        
        # Set up context menu
        self.hosts_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.hosts_table.customContextMenuRequested.connect(self.show_host_context_menu)
        
        # Add to layout
        layout.addWidget(self.hosts_table)
        
        # Set layout
        self.hosts_tab.setLayout(layout)
    
    def setup_vulns_tab(self):
        """Set up the vulnerabilities tab."""
        layout = QVBoxLayout()
        
        # Create vulnerabilities tree
        self.vulns_tree = QTreeWidget()
        self.vulns_tree.setHeaderLabels(["Vulnerability", "Severity", "Host", "Port"])
        self.vulns_tree.setColumnWidth(0, 300)  # Wider column for vulnerability name
        self.vulns_tree.setSortingEnabled(True)
        self.vulns_tree.sortByColumn(1, Qt.AscendingOrder)  # Sort by severity by default
        
        # Set up context menu
        self.vulns_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.vulns_tree.customContextMenuRequested.connect(self.show_vuln_context_menu)
        
        # Add to layout
        layout.addWidget(self.vulns_tree)
        
        # Set layout
        self.vulns_tab.setLayout(layout)
    
    def create_summary_card(self, title: str, value: str, color: str) -> QWidget:
        """Create a summary card widget."""
        card = QWidget()
        card.setStyleSheet(f"""
            QWidget {{
                background-color: white;
                border-radius: 5px;
                border-left: 5px solid {color};
                padding: 10px;
            }}
            QLabel#title {{
                color: #6c757d;
                font-size: 14px;
            }}
            QLabel#value {{
                color: #212529;
                font-size: 24px;
                font-weight: bold;
            }}
        """)
        
        layout = QVBoxLayout(card)
        
        title_label = QLabel(title)
        title_label.setObjectName("title")
        
        value_label = QLabel(value)
        value_label.setObjectName("value")
        
        layout.addWidget(title_label)
        layout.addWidget(value_label)
        
        return card
    
    def display_results(self, results: dict):
        """Display scan results in the UI."""
        self.results = results
        
        # Update summary tab
        self.update_summary_tab()
        
        # Update hosts tab
        self.update_hosts_tab()
        
        # Update vulnerabilities tab
        self.update_vulns_tab()
    
    def update_summary_tab(self):
        """Update the summary tab with scan results."""
        # Update summary cards
        hosts_count = len(self.results.get('hosts', []))
        services_count = sum(len(host.get('services', [])) for host in self.results.get('hosts', []))
        vulns_count = sum(len(host.get('vulnerabilities', [])) for host in self.results.get('hosts', []))
        
        self.hosts_card.findChild(QLabel, "value").setText(str(hosts_count))
        self.services_card.findChild(QLabel, "value").setText(str(services_count))
        self.vulns_card.findChild(QLabel, "value").setText(str(vulns_count))
        
        # Update scan details
        target = self.results.get('target', 'Unknown')
        scan_type = self.results.get('scan_type', 'Unknown')
        status = self.results.get('status', 'Unknown')
        start_time = self.results.get('start_time', '')
        end_time = self.results.get('end_time', '')
        
        details = f"""
        <h3>Scan Details</h3>
        <p><b>Target:</b> {target}</p>
        <p><b>Type:</b> {scan_type}</p>
        <p><b>Status:</b> {status}</p>
        <p><b>Started:</b> {start_time}</p>
        <p><b>Completed:</b> {end_time if end_time else 'In progress'}</p>
        """
        
        self.scan_details.setText(details)
    
    def update_hosts_tab(self):
        """Update the hosts tab with scan results."""
        self.hosts_table.setRowCount(0)  # Clear existing rows
        
        hosts = self.results.get('hosts', [])
        for host in hosts:
            row = self.hosts_table.rowCount()
            self.hosts_table.insertRow(row)
            
            # Add host data to the table
            self.hosts_table.setItem(row, 0, QTableWidgetItem(host.get('ip', 'Unknown')))
            self.hosts_table.setItem(row, 1, QTableWidgetItem(host.get('status', 'Unknown')))
            self.hosts_table.setItem(row, 2, QTableWidgetItem(host.get('os', 'Unknown')))
            self.hosts_table.setItem(row, 3, QTableWidgetItem(str(len(host.get('services', [])))))
            self.hosts_table.setItem(row, 4, QTableWidgetItem(str(len(host.get('vulnerabilities', [])))))
    
    def update_vulns_tab(self):
        """Update the vulnerabilities tab with scan results."""
        self.vulns_tree.clear()
        
        hosts = self.results.get('hosts', [])
        for host in hosts:
            host_item = QTreeWidgetItem(self.vulns_tree)
            host_item.setText(0, host.get('ip', 'Unknown'))
            host_item.setExpanded(True)
            
            for vuln in host.get('vulnerabilities', []):
                vuln_item = QTreeWidgetItem(host_item)
                vuln_item.setText(0, vuln.get('name', 'Unknown'))
                vuln_item.setText(1, vuln.get('severity', 'Unknown'))
                vuln_item.setText(2, host.get('ip', 'Unknown'))
                vuln_item.setText(3, str(vuln.get('port', '')))
                
                # Set color based on severity
                severity = vuln.get('severity', '').lower()
                if 'critical' in severity:
                    color = QColor(220, 53, 69)  # Red
                elif 'high' in severity:
                    color = QColor(255, 193, 7)  # Yellow
                elif 'medium' in severity:
                    color = QColor(255, 152, 0)  # Orange
                elif 'low' in severity:
                    color = QColor(0, 123, 255)  # Blue
                else:
                    color = QColor(108, 117, 125)  # Gray
                
                for i in range(4):
                    vuln_item.setForeground(i, color)
    
    def show_host_context_menu(self, position):
        """Show context menu for host items."""
        menu = QMenu()
        
        view_details = QAction("View Details", self)
        view_details.triggered.connect(self.view_host_details)
        
        export_host = QAction("Export Host Info", self)
        export_host.triggered.connect(self.export_host_info)
        
        menu.addAction(view_details)
        menu.addAction(export_host)
        menu.exec_(self.hosts_table.viewport().mapToGlobal(position))
    
    def show_vuln_context_menu(self, position):
        """Show context menu for vulnerability items."""
        menu = QMenu()
        
        view_details = QAction("View Details", self)
        view_details.triggered.connect(self.view_vuln_details)
        
        export_vuln = QAction("Export Vulnerability", self)
        export_vuln.triggered.connect(self.export_vuln_info)
        
        menu.addAction(view_details)
        menu.addAction(export_vuln)
        menu.exec_(self.vulns_tree.viewport().mapToGlobal(position))
    
    def view_host_details(self):
        """View detailed information about the selected host."""
        selected = self.hosts_table.selectedItems()
        if not selected:
            return
        
        # Get the host IP from the first column of the selected row
        host_ip = selected[0].text()
        
        # Find the host in the results
        host = next((h for h in self.results.get('hosts', []) if h.get('ip') == host_ip), None)
        if not host:
            return
        
        # Show host details in a dialog
        self.show_host_dialog(host)
    
    def view_vuln_details(self):
        """View detailed information about the selected vulnerability."""
        selected = self.vulns_tree.selectedItems()
        if not selected:
            return
        
        # Get the selected item (skip if it's a host item)
        item = selected[0]
        if item.parent() is None:  # It's a host item
            return
        
        # Get vulnerability details
        vuln_name = item.text(0)
        host_ip = item.parent().text(0)
        
        # Find the host and vulnerability in the results
        host = next((h for h in self.results.get('hosts', []) if h.get('ip') == host_ip), None)
        if not host:
            return
        
        vuln = next((v for v in host.get('vulnerabilities', []) 
                    if v.get('name') == vuln_name), None)
        if not vuln:
            return
        
        # Show vulnerability details in a dialog
        self.show_vuln_dialog(vuln)
    
    def export_host_info(self):
        """Export host information to a file."""
        selected = self.hosts_table.selectedItems()
        if not selected:
            return
        
        # Get the host IP from the first column of the selected row
        host_ip = selected[0].text()
        
        # Find the host in the results
        host = next((h for h in self.results.get('hosts', []) if h.get('ip') == host_ip), None)
        if not host:
            return
        
        # Show save file dialog
        file_name, _ = QFileDialog.getSaveFileName(
            self, "Export Host Information", 
            f"host_{host_ip}.json", 
            "JSON Files (*.json);;All Files (*)"
        )
        
        if file_name:
            try:
                with open(file_name, 'w') as f:
                    import json
                    json.dump(host, f, indent=2)
                
                QMessageBox.information(
                    self, "Export Successful", 
                    f"Host information exported to {file_name}"
                )
            except Exception as e:
                QMessageBox.critical(
                    self, "Export Failed", 
                    f"Failed to export host information: {str(e)}"
                )
    
    def export_vuln_info(self):
        """Export vulnerability information to a file."""
        selected = self.vulns_tree.selectedItems()
        if not selected:
            return
        
        # Get the selected item (skip if it's a host item)
        item = selected[0]
        if item.parent() is None:  # It's a host item
            return
        
        # Get vulnerability details
        vuln_name = item.text(0)
        host_ip = item.parent().text(0)
        
        # Find the host and vulnerability in the results
        host = next((h for h in self.results.get('hosts', []) if h.get('ip') == host_ip), None)
        if not host:
            return
        
        vuln = next((v for v in host.get('vulnerabilities', []) 
                    if v.get('name') == vuln_name), None)
        if not vuln:
            return
        
        # Show save file dialog
        file_name, _ = QFileDialog.getSaveFileName(
            self, "Export Vulnerability Information", 
            f"vuln_{vuln_name.replace(' ', '_').lower()}.json", 
            "JSON Files (*.json);;All Files (*)"
        )
        
        if file_name:
            try:
                with open(file_name, 'w') as f:
                    import json
                    json.dump(vuln, f, indent=2)
                
                QMessageBox.information(
                    self, "Export Successful", 
                    f"Vulnerability information exported to {file_name}"
                )
            except Exception as e:
                QMessageBox.critical(
                    self, "Export Failed", 
                    f"Failed to export vulnerability information: {str(e)}"
                )
    
    def show_host_dialog(self, host):
        """Show a dialog with detailed host information."""
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QDialogButtonBox
        
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Host Details - {host.get('ip', 'Unknown')}")
        dialog.resize(600, 400)
        
        layout = QVBoxLayout()
        
        # Create text edit for displaying host details
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        
        # Format host details as HTML
        details = f"""
        <h2>Host Information</h2>
        <p><b>IP Address:</b> {ip}</p>
        <p><b>Status:</b> {status}</p>
        <p><b>Hostnames:</b> {hostnames}</p>
        <p><b>OS:</b> {os}</p>
        <p><b>Open Ports:</b> {port_count}</p>
        <p><b>Vulnerabilities:</b> {vuln_count}</p>
        
        <h3>Open Ports</h3>
        <ul>
        {ports}
        </ul>
        
        <h3>Vulnerabilities</h3>
        <ul>
        {vulns}
        </ul>
        """.format(
            ip=host.get('ip', 'Unknown'),
            status=host.get('status', 'Unknown'),
            hostnames=', '.join(host.get('hostnames', [])),
            os=host.get('os', 'Unknown'),
            port_count=len(host.get('services', [])),
            vuln_count=len(host.get('vulnerabilities', [])),
            ports=''.join(f"<li>{s.get('port', '?')}/{s.get('protocol', '?')} - {s.get('name', 'Unknown')} ({s.get('product', '')} {s.get('version', '')})</li>" 
                         for s in host.get('services', [])),
            vulns=''.join(f"<li>{v.get('name', 'Unknown')} - <span style='color:red'>{v.get('severity', 'Unknown')}</span></li>" 
                         for v in host.get('vulnerabilities', []))
        )
        
        text_edit.setHtml(details)
        
        # Add buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(dialog.accept)
        
        # Add widgets to layout
        layout.addWidget(text_edit)
        layout.addWidget(buttons)
        
        # Set layout
        dialog.setLayout(layout)
        
        # Show the dialog
        dialog.exec_()
    
    def show_vuln_dialog(self, vuln):
        """Show a dialog with detailed vulnerability information."""
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QDialogButtonBox
        
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Vulnerability - {vuln.get('name', 'Unknown')}")
        dialog.resize(700, 500)
        
        layout = QVBoxLayout()
        
        # Create text edit for displaying vulnerability details
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        
        # Format vulnerability details as HTML
        details = f"""
        <h2>{name}</h2>
        <p><b>Severity:</b> <span style='color:{severity_color}'>{severity}</span></p>
        <p><b>CVE:</b> {cve}</p>
        <p><b>CVSS Score:</b> {cvss}</p>
        <p><b>Affected Host:</b> {host}:{port}/{protocol}</p>
        
        <h3>Description</h3>
        <p>{description}</p>
        
        <h3>Solution</h3>
        <p>{solution}</p>
        
        <h3>References</h3>
        <ul>
        {references}
        </ul>
        """.format(
            name=vuln.get('name', 'Unknown'),
            severity=vuln.get('severity', 'Unknown'),
            severity_color='red' if 'high' in vuln.get('severity', '').lower() or 
                              'critical' in vuln.get('severity', '').lower() else 'black',
            cve=vuln.get('cve', 'N/A'),
            cvss=vuln.get('cvss', 'N/A'),
            host=vuln.get('host', 'Unknown'),
            port=vuln.get('port', '?'),
            protocol=vuln.get('protocol', 'tcp'),
            description=vuln.get('description', 'No description available.'),
            solution=vuln.get('solution', 'No solution available.'),
            references=''.join(f"<li><a href='{ref}'>{ref}</a></li>" 
                             for ref in vuln.get('references', []))
        )
        
        text_edit.setHtml(details)
        text_edit.setOpenExternalLinks(True)
        
        # Add buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok)
        buttons.accepted.connect(dialog.accept)
        
        # Add widgets to layout
        layout.addWidget(text_edit)
        layout.addWidget(buttons)
        
        # Set layout
        dialog.setLayout(layout)
        
        # Show the dialog
        dialog.exec_()
    
    def apply_styles(self):
        """Apply custom styles to the widget."""
        self.setStyleSheet("""
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
            
            QTableWidget {
                border: 1px solid #dee2e6;
                border-radius: 4px;
                gridline-color: #dee2e6;
            }
            
            QTableWidget::item {
                padding: 6px;
            }
            
            QTableWidget::item:selected {
                background-color: #e9ecef;
                color: #212529;
            }
            
            QHeaderView::section {
                background-color: #f8f9fa;
                padding: 8px;
                border: none;
                border-bottom: 1px solid #dee2e6;
            }
            
            QTreeWidget {
                border: 1px solid #dee2e6;
                border-radius: 4px;
            }
            
            QTreeWidget::item {
                padding: 4px 0;
            }
            
            QTreeWidget::item:selected {
                background-color: #e9ecef;
                color: #212529;
            }
        """)
