"""
Core application class for CyberSentinel.
"""
import logging
from typing import Dict, Any, Optional
from pathlib import Path
import json

from .scanner import PortScanner, WebScanner, SSLAnalyzer, VulnerabilityScanner
from ..models import ScanResult, ScanStatus

class CyberSentinelApp:
    """Main application class for CyberSentinel."""
    
    def __init__(self):
        """Initialize the CyberSentinel application."""
        self.logger = logging.getLogger(__name__)
        self.scan_results: Dict[str, ScanResult] = {}
        self.current_scan_id: Optional[str] = None
        
        # Initialize scanners
        self.port_scanner = PortScanner()
        self.web_scanner = WebScanner()
        self.ssl_analyzer = SSLAnalyzer()
        self.vuln_scanner = VulnerabilityScanner()
        
        # Create necessary directories
        self._setup_directories()
    
    def _setup_directories(self):
        """Create necessary directories for the application."""
        directories = [
            'scans',
            'reports',
            'logs'
        ]
        
        for directory in directories:
            Path(directory).mkdir(exist_ok=True)
    
    def start_scan(self, target: str, scan_type: str, options: Dict[str, Any]) -> str:
        """
        Start a new scan.
        
        Args:
            target: The target to scan (IP, hostname, or URL)
            scan_type: Type of scan to perform ('port', 'web', 'ssl', 'vulnerability')
            options: Additional scan options
            
        Returns:
            str: Scan ID
        """
        try:
            # Generate a unique scan ID
            import uuid
            import time
            scan_id = f"scan_{int(time.time())}_{uuid.uuid4().hex[:6]}"
            
            # Create a new scan result
            scan_result = ScanResult(
                scan_id=scan_id,
                target=target,
                scan_type=scan_type,
                status=ScanStatus.RUNNING,
                start_time=time.time(),
                options=options
            )
            
            # Store the scan result
            self.scan_results[scan_id] = scan_result
            self.current_scan_id = scan_id
            
            # Start the appropriate scan based on type
            if scan_type == 'port':
                self._run_port_scan(scan_id, target, options)
            elif scan_type == 'web':
                self._run_web_scan(scan_id, target, options)
            elif scan_type == 'ssl':
                self._run_ssl_scan(scan_id, target, options)
            elif scan_type == 'vulnerability':
                self._run_vulnerability_scan(scan_id, target, options)
            else:
                raise ValueError(f"Unknown scan type: {scan_type}")
            
            return scan_id
            
        except Exception as e:
            self.logger.error(f"Error starting scan: {str(e)}", exc_info=True)
            raise
    
    def _run_port_scan(self, scan_id: str, target: str, options: Dict[str, Any]):
        """Run a port scan."""
        try:
            # Update scan status
            self.scan_results[scan_id].status = ScanStatus.RUNNING
            
            # Run the port scan
            results = self.port_scanner.scan(target, **options)
            
            # Update scan results
            self.scan_results[scan_id].results = results
            self.scan_results[scan_id].status = ScanStatus.COMPLETED
            self.scan_results[scan_id].end_time = time.time()
            
        except Exception as e:
            self.logger.error(f"Port scan failed: {str(e)}", exc_info=True)
            self.scan_results[scan_id].status = ScanStatus.FAILED
            self.scan_results[scan_id].error = str(e)
    
    def _run_web_scan(self, scan_id: str, target: str, options: Dict[str, Any]):
        """Run a web application scan."""
        # Similar implementation to _run_port_scan
        pass
    
    def _run_ssl_scan(self, scan_id: str, target: str, options: Dict[str, Any]):
        """Run an SSL/TLS scan."""
        # Similar implementation to _run_port_scan
        pass
    
    def _run_vulnerability_scan(self, scan_id: str, target: str, options: Dict[str, Any]):
        """Run a vulnerability scan."""
        # Similar implementation to _run_port_scan
        pass
    
    def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """
        Get the status of a scan.
        
        Args:
            scan_id: The ID of the scan to check
            
        Returns:
            Dict containing scan status information
        """
        if scan_id not in self.scan_results:
            return {"error": "Scan ID not found"}
        
        return self.scan_results[scan_id].to_dict()
    
    def stop_scan(self, scan_id: str) -> bool:
        """
        Stop a running scan.
        
        Args:
            scan_id: The ID of the scan to stop
            
        Returns:
            bool: True if the scan was stopped, False otherwise
        """
        if scan_id not in self.scan_results:
            return False
            
        # Update scan status to cancelled
        self.scan_results[scan_id].status = ScanStatus.CANCELLED
        self.scan_results[scan_id].end_time = time.time()
        
        return True
    
    def export_report(self, scan_id: str, format: str = 'pdf') -> str:
        """
        Export a scan report.
        
        Args:
            scan_id: The ID of the scan to export
            format: The format to export to ('pdf', 'html', 'json')
            
        Returns:
            str: Path to the exported report
        """
        if scan_id not in self.scan_results:
            raise ValueError("Scan ID not found")
        
        # Get the scan result
        scan_result = self.scan_results[scan_id]
        
        # Generate the report
        if format == 'pdf':
            return self._generate_pdf_report(scan_result)
        elif format == 'html':
            return self._generate_html_report(scan_result)
        elif format == 'json':
            return self._generate_json_report(scan_result)
        else:
            raise ValueError(f"Unsupported report format: {format}")
    
    def _generate_pdf_report(self, scan_result: 'ScanResult') -> str:
        """Generate a PDF report."""
        # Implementation for PDF report generation
        pass
    
    def _generate_html_report(self, scan_result: 'ScanResult') -> str:
        """Generate an HTML report."""
        # Implementation for HTML report generation
        pass
    
    def _generate_json_report(self, scan_result: 'ScanResult') -> str:
        """Generate a JSON report."""
        report_path = f"reports/{scan_result.scan_id}.json"
        with open(report_path, 'w') as f:
            json.dump(scan_result.to_dict(), f, indent=2)
        return report_path
