"""
Scanner tab for the CyberSentinel application.
"""
import logging
from threading import Event
import tempfile
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

from PyQt5.QtWidgets import (
    QWidget, QScrollArea, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QLineEdit,
    QComboBox, QTableWidget, QTableWidgetItem, QHeaderView, QProgressBar,
    QMessageBox, QGroupBox, QCheckBox, QFormLayout, QSpinBox, QSplitter,
    QTextEdit, QFileDialog, QTabWidget, QStyle, QApplication,
    QTreeWidget, QTreeWidgetItem
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize, QTimer
from PyQt5.QtGui import QTextCursor, QIcon, QColor

from ..scanner.nmap_engine import NmapScanner
from ..scanner.tcp_scanner import SocketScanner
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
    output_line = pyqtSignal(str)
    
    def __init__(self, target: str, scan_type: str, options: Dict[str, Any], parent=None):
        super().__init__(parent)
        self.target = target
        self.scan_type = scan_type
        self.options = options
        self._is_running = True
        self.cancel_event = Event()
        self.scanner = None
    
    def run(self):
        """Run the scan in a separate thread."""
        try:
            self.progress_updated.emit(0, "Initializing scan...")
            
            # Initialize the appropriate scanner
            if self.scan_type == "nmap":
                scanner = NmapScanner()
                self.scanner = scanner
                self.progress_updated.emit(10, "Starting Nmap scan...")

                # Build Nmap arguments from options to mirror detailed CLI output
                args: List[str] = ["-sT", "-v", "--host-timeout", "120s"]
                if self.options.get("service_scan"):
                    args.append("-sV")
                if self.options.get("os_detection"):
                    args.append("-O")
                if self.options.get("aggressive"):
                    args.append("-A")
                timing = self.options.get("timing")
                if isinstance(timing, int):
                    args.append(f"-T{timing}")
                if self.options.get("script_scan"):
                    script_arg = self.options.get("script_args") or "default"
                    args.append(f"--script={script_arg}")
                arguments = " ".join(args)

                # Create temporary XML output path for structured parsing
                with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as tmp:
                    xml_path = tmp.name

                # Stream output lines into the GUI
                def on_out(line: str):
                    self.output_line.emit(line)

                nmap_raw = scanner.scan(
                    self.target,
                    self.options.get("ports", "1-1024"),
                    arguments=arguments,
                    output_xml=xml_path,
                    stream=True,
                    on_output=on_out,
                    cancel_event=self.cancel_event,
                    timeout=180,
                )

                Path(xml_path).unlink(missing_ok=True)
                # If parsed XML available, flatten ports for the table view
                table_results: Dict[str, Any] = {"ports": []}
                hosts = nmap_raw.get("hosts", []) if isinstance(nmap_raw, dict) else []
                for host in hosts:
                    for p in host.get("ports", []):
                        state = p.get("state", {}).get("state", "")
                        service = p.get("service", {})
                        version = " ".join(filter(None, [service.get("product"), service.get("version")])).strip()
                        table_results["ports"].append(
                            {
                                "host": next((address.get("addr") for address in host.get("addresses", []) if address.get("addrtype") in ("ipv4", "ipv6")), self.target),
                                "port": p.get("port"),
                                "protocol": p.get("protocol", "tcp"),
                                "state": state,
                                "service": service.get("name") or service.get("product") or "",
                                "version": version,
                            }
                        )
                results = {"ports": table_results["ports"], "nmap": nmap_raw}
            else:
                scanner = SocketScanner(cancel_event=self.cancel_event)
                self.scanner = scanner
                self.progress_updated.emit(10, "Starting socket scan...")
                results = scanner.scan(
                    self.target,
                    self.options.get(
                        "ports",
                        [80, 443, 8080, 22, 21, 25, 110, 143, 443, 993, 995, 3306, 3389],
                    ),
                )
            
            if self.cancel_event.is_set():
                return
            if results.get('status') == 'error':
                raise RuntimeError(results.get('error', 'Scan failed'))
            self.progress_updated.emit(90, "Processing results...")
            self.scan_completed.emit(results)
            self.progress_updated.emit(100, "Scan completed successfully!")
            
        except Exception as e:
            logger.error(f"Scan failed: {e}", exc_info=True)
            if self.cancel_event.is_set():
                self.scan_completed.emit({'ports': [], 'status': 'cancelled', 'error': 'Assessment cancelled; results incomplete.'})
            else:
                self.error_occurred.emit(str(e))
        finally:
            self._is_running = False
    
    def stop(self):
        """Stop the scan."""
        self._is_running = False
        self.cancel_event.set()
        self.requestInterruption()
        if self.scanner and hasattr(self.scanner, "cancel"):
            self.scanner.cancel()
        self.progress_updated.emit(0, "Scan stopped by user.")


class ScannerTab(QWidget):
    """Tab for performing network scans."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scan_worker = None
        self.scan_results = {}
        self.transcript_lines: List[str] = []
        self._init_ui()
        self.script_scan.setChecked(False)
        self.script_scan.setEnabled(False)
        self.script_scan.setToolTip('Arbitrary NSE execution is disabled in the bounded desktop profile.')
        self.script_args.setEnabled(False)
        self.scan_type.currentIndexChanged.connect(self.apply_profile)
    
    def apply_profile(self):
        profile = self.scan_type.currentData()
        if profile == 'quick':
            self.port_range.setText('22,25,53,80,110,139,143,443,445,3389,8080')
            self.service_scan.setChecked(False)
            self.os_detection.setChecked(False)
        elif profile == 'full':
            self.port_range.setText('1-65535')
        elif profile == 'service':
            self.service_scan.setChecked(True)
        elif profile == 'os':
            self.os_detection.setChecked(True)

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
        self.scanner_type.addItem("Nmap Service Assessment", "nmap")
        self.scanner_type.addItem("TCP Connect Discovery", "socket")
        import shutil
        if not shutil.which("nmap"):
            self.scanner_type.setCurrentIndex(1)
        
        # Port range + presets
        self.port_range = QLineEdit("1-1024")
        self.port_range.setToolTip("Ports to scan (e.g., 80,443,8080 or 1-1000)")
        self.port_presets = QComboBox()
        self.port_presets.addItem("Custom", None)
        self.port_presets.addItem("Well-known (1-1023)", "1-1023")
        self.port_presets.addItem("Registered (1024-49151)", "1024-49151")
        self.port_presets.addItem("Dynamic/Ephemeral (49152-65535)", "49152-65535")
        self.port_presets.addItem("All (1-65535)", "1-65535")
        self.port_presets.setCurrentIndex(0)
        self.port_presets.setToolTip("Select a common port range preset or choose Custom to enter your own")
        self.port_presets.currentIndexChanged.connect(self._on_port_preset_changed)

        port_row = QWidget()
        port_row_layout = QHBoxLayout(port_row)
        port_row_layout.setContentsMargins(0, 0, 0, 0)
        port_row_layout.setSpacing(8)
        port_row_layout.addWidget(self.port_range, 1)
        port_row_layout.addWidget(self.port_presets)
        
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
        options_layout.addRow("Ports:", port_row)
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
        
        # Bottom panel: multi-tab (Nmap Output, Ports/Hosts, Topology, Host Details, Scans)
        bottom_panel = QTabWidget()

        # Nmap Output (live streaming)
        self.nmap_output_console = QTextEdit()
        self.nmap_output_console.setReadOnly(True)
        self.nmap_output_console.setFontFamily("Courier")
        self.nmap_output_console.setLineWrapMode(QTextEdit.NoWrap)

        # Ports / Hosts table
        self.ports_table = QTableWidget()
        self.ports_table.setColumnCount(5)
        self.ports_table.setHorizontalHeaderLabels(["Port", "Protocol", "State", "Service", "Version"])
        self.ports_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.ports_table.horizontalHeader().setStretchLastSection(True)
        self.ports_table.verticalHeader().setVisible(False)

        # Topology (traceroute hops)
        self.topology_tree = QTreeWidget()
        self.topology_tree.setHeaderLabels(["Hop", "RTT", "Address"])
        self.topology_tree.setColumnWidth(0, 80)
        self.topology_tree.setColumnWidth(1, 120)

        # Host Details (status, addresses, hostnames, uptime, sequences)
        self.host_details_tree = QTreeWidget()
        self.host_details_tree.setHeaderLabels(["Property", "Value"])
        self.host_details_tree.setColumnWidth(0, 220)

        # Scans (command, summary)
        self.scans_text = QTextEdit()
        self.scans_text.setReadOnly(True)
        self.scans_text.setFontFamily("Courier")

        # Add tabs
        bottom_panel.addTab(self.nmap_output_console, "Nmap Output")
        bottom_panel.addTab(self.ports_table, "Ports / Hosts")
        bottom_panel.addTab(self.topology_tree, "Topology")
        bottom_panel.addTab(self.host_details_tree, "Host Details")
        bottom_panel.addTab(self.scans_text, "Scans")
        
        # Add panels to splitter
        controls_scroll = QScrollArea()
        controls_scroll.setWidgetResizable(True)
        controls_scroll.setWidget(top_panel)
        controls_scroll.setMinimumHeight(230)
        splitter.addWidget(controls_scroll)
        splitter.addWidget(bottom_panel)
        
        # Set initial sizes
        splitter.setSizes([200, 400])
        
        # Add splitter to main layout
        main_layout.addWidget(splitter)
    
    def _on_port_preset_changed(self, index: int):
        """Update port range when a preset is selected."""
        preset = self.port_presets.itemData(index)
        if preset:
            self.port_range.setText(str(preset))
    
    def start_scan(self):
        """Start the scan with the current settings."""
        if self.scan_worker and self.scan_worker.isRunning():
            return
        if hasattr(self.window(), 'authorize_assessment') and not self.window().authorize_assessment(self.target_input.text().strip()):
            return
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
        self.ports_table.setRowCount(0)
        self.nmap_output_console.clear()
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
        self.scan_worker.output_line.connect(self.on_output_line)
        
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
            if hasattr(self.window(), 'record_assessment'):
                self.window().record_assessment('network', self.target_input.text().strip(), results)
            self.display_results(results)
            self.append_output("\nAssessment " + results.get("status", "completed"))

            # Ask Dashboard to reload recent scans
            try:
                mw = self.window()
                if mw and hasattr(mw, 'dashboard_tab') and hasattr(mw.dashboard_tab, 'reload_recent_scans'):
                    mw.dashboard_tab.reload_recent_scans()
            except Exception:
                pass
        except Exception as e:
            logger.error(f"Error processing scan results: {e}", exc_info=True)
            self.append_output(f"\nError processing results: {e}")
        finally:
            self.progress_bar.setValue(100)
            self.progress_bar.setFormat("Assessment " + results.get("status", "completed"))
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
            # When Nmap data present, use it to populate all tabs
            nmap_data = results.get("nmap") if isinstance(results, dict) else None

            # Populate Ports / Hosts table (from flattened list if available or from first host)
            ports_list = results.get("ports", []) if isinstance(results, dict) else []
            if not ports_list and nmap_data:
                # flatten from host 0
                hosts = nmap_data.get("hosts", [])
                if hosts:
                    for p in hosts[0].get("ports", []):
                        state = p.get("state", {}).get("state", "")
                        service = p.get("service", {})
                        version = " ".join(filter(None, [service.get("product"), service.get("version")])).strip()
                        ports_list.append({
                            "port": p.get("port"),
                            "protocol": p.get("protocol", "tcp"),
                            "state": state,
                            "service": service.get("name") or service.get("product") or "",
                            "version": version,
                        })

            # Clear and populate table
            self.ports_table.setRowCount(0)
            for port_info in ports_list:
                row = self.ports_table.rowCount()
                self.ports_table.insertRow(row)
                self.ports_table.setItem(row, 0, QTableWidgetItem(str(port_info.get("port", ""))))
                self.ports_table.setItem(row, 1, QTableWidgetItem(port_info.get("protocol", "tcp").lower()))
                state_str = str(port_info.get("state", ""))
                state_item = QTableWidgetItem(state_str)
                if state_str == "open":
                    state_item.setForeground(QColor("#2ecc71"))  # green
                elif state_str == "closed":
                    state_item.setForeground(QColor("#e74c3c"))  # red
                elif state_str == "filtered":
                    state_item.setForeground(QColor("#f1c40f"))  # yellow
                self.ports_table.setItem(row, 2, state_item)
                self.ports_table.setItem(row, 3, QTableWidgetItem(port_info.get("service", "")))
                self.ports_table.setItem(row, 4, QTableWidgetItem(port_info.get("version", "")))

            self.ports_table.resizeColumnsToContents()

            # Populate Host Details
            self.host_details_tree.clear()
            if nmap_data and nmap_data.get("hosts"):
                host = nmap_data["hosts"][0]
                root_item = QTreeWidgetItem([self.target_input.text().strip()])
                self.host_details_tree.addTopLevelItem(root_item)

                # Host Status
                status_item = QTreeWidgetItem(["Host Status"]) 
                state = host.get("status", {}).get("state", "unknown")
                status_item.addChild(QTreeWidgetItem(["State:", state]))
                # Port counts
                ports = host.get("ports", [])
                open_cnt = sum(1 for p in ports if p.get("state", {}).get("state") == "open")
                closed_cnt = sum(1 for p in ports if p.get("state", {}).get("state") == "closed")
                filtered_cnt = sum(1 for p in ports if p.get("state", {}).get("state") == "filtered")
                status_item.addChild(QTreeWidgetItem(["Open ports:", str(open_cnt)]))
                status_item.addChild(QTreeWidgetItem(["Filtered ports:", str(filtered_cnt)]))
                status_item.addChild(QTreeWidgetItem(["Closed ports:", str(closed_cnt)]))
                status_item.addChild(QTreeWidgetItem(["Scanned ports:", str(len(ports))]))
                # Uptime
                up = host.get("uptime", {})
                if up:
                    status_item.addChild(QTreeWidgetItem(["Up time:", str(up.get("seconds", ""))]))
                    status_item.addChild(QTreeWidgetItem(["Last boot:", up.get("lastboot", "")]))
                root_item.addChild(status_item)

                # Addresses
                addr_item = QTreeWidgetItem(["Addresses"]) 
                for a in host.get("addresses", []):
                    addr_item.addChild(QTreeWidgetItem([a.get("addrtype", "addr"), a.get("addr", "")]))
                root_item.addChild(addr_item)

                # Hostnames
                hn_item = QTreeWidgetItem(["Hostnames"]) 
                for hn in host.get("hostnames", []):
                    hn_item.addChild(QTreeWidgetItem([hn.get("type", "name"), hn.get("name", "")]))
                root_item.addChild(hn_item)

                # Sequences
                seq_item = QTreeWidgetItem(["TCP Sequence"]) 
                for k, v in host.get("tcpsequence", {}).items():
                    seq_item.addChild(QTreeWidgetItem([k, str(v)]))
                root_item.addChild(seq_item)
                ipid_item = QTreeWidgetItem(["IP ID Sequence"]) 
                for k, v in host.get("ipidsequence", {}).items():
                    ipid_item.addChild(QTreeWidgetItem([k, str(v)]))
                root_item.addChild(ipid_item)
                tcpts_item = QTreeWidgetItem(["TCP TS Sequence"]) 
                for k, v in host.get("tcptssequence", {}).items():
                    tcpts_item.addChild(QTreeWidgetItem([k, str(v)]))
                root_item.addChild(tcpts_item)

                # Times
                times = host.get("times", {})
                if times:
                    times_item = QTreeWidgetItem(["Times"]) 
                    for k, v in times.items():
                        times_item.addChild(QTreeWidgetItem([k, str(v)]))
                    root_item.addChild(times_item)

                self.host_details_tree.expandAll()

            # Populate Topology
            self.topology_tree.clear()
            if nmap_data and nmap_data.get("hosts"):
                host = nmap_data["hosts"][0]
                trace = host.get("trace", {})
                if trace and trace.get("hops"):
                    for hop in trace["hops"]:
                        hopnum = hop.get("ttl") or hop.get("hop") or ""
                        rtt = hop.get("rtt", "")
                        addr = hop.get("ipaddr") or hop.get("host") or hop.get("hostname") or ""
                        self.topology_tree.addTopLevelItem(QTreeWidgetItem([str(hopnum), str(rtt), str(addr)]))

            # Populate Scans info
            self.scans_text.clear()
            if nmap_data and nmap_data.get("command"):
                self.scans_text.append(f"Command: {nmap_data['command']}")
            elif isinstance(results, dict) and results.get("command"):
                self.scans_text.append(f"Command: {results['command']}")

            # Summary message
            open_ports = len([p for p in ports_list if str(p.get("state")) == "open"])
            self.append_output(f"\nScan complete. Found {open_ports} open ports.")
            
        except Exception as e:
            logger.error(f"Error displaying results: {e}", exc_info=True)
            self.append_output(f"\nError displaying results: {e}")
    
    def append_output(self, text: str):
        """Append text to the output console."""
        self.nmap_output_console.moveCursor(QTextCursor.End)
        self.nmap_output_console.insertPlainText(text + "\n")
        self.nmap_output_console.moveCursor(QTextCursor.End)
        # Keep transcript for saving
        self.transcript_lines.append(text)

    def on_output_line(self, text: str):
        """Receive a live output line from the scan worker and append it."""
        self.append_output(text)
    
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

