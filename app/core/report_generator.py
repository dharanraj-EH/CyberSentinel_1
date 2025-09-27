"""
Report generation module for CyberSentinel.
"""
import os
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import logging
from jinja2 import Environment, FileSystemLoader, select_autoescape
from weasyprint import HTML

from ..utils import get_resource_path, ensure_directories, get_reports_dir

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Handles generation of reports in various formats."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the report generator.
        
        Args:
            config: Configuration dictionary for report generation
        """
        self.config = config or {}
        self.template_env = self._setup_template_environment()
        ensure_directories()
    
    def _setup_template_environment(self):
        """Set up the Jinja2 template environment."""
        # Get the templates directory from resources
        templates_dir = Path(get_resource_path('templates'))
        
        return Environment(
            loader=FileSystemLoader(str(templates_dir)),
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True
        )
    
    def generate_report(
        self,
        scan_data: Dict[str, Any],
        report_format: str = 'html',
        output_path: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate a report in the specified format.
        
        Args:
            scan_data: Dictionary containing scan results
            report_format: Output format ('html', 'pdf', 'json')
            output_path: Path to save the report (default: auto-generated)
            options: Additional options for report generation
            
        Returns:
            Path to the generated report file
        """
        if report_format not in ['html', 'pdf', 'json']:
            raise ValueError(f"Unsupported report format: {report_format}")
        
        options = options or {}
        
        # Prepare report data
        report_data = self._prepare_report_data(scan_data, options)
        
        # Generate the report in the requested format
        if report_format == 'json':
            return self._generate_json_report(report_data, output_path)
        else:
            # For HTML/PDF, render the template first
            html_content = self._render_template(report_data, options)
            
            if report_format == 'html':
                return self._generate_html_report(html_content, output_path, options)
            else:  # PDF
                return self._generate_pdf_report(html_content, output_path, options)
    
    def _prepare_report_data(
        self,
        scan_data: Dict[str, Any],
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Prepare data for the report template."""
        # Extract scan metadata
        scan_id = scan_data.get('scan_id', 'unknown')
        target = scan_data.get('target', 'Unknown')
        scan_type = scan_data.get('scan_type', 'Unknown')
        status = scan_data.get('status', 'completed')
        
        # Format timestamps
        start_time = scan_data.get('start_time', time.time())
        end_time = scan_data.get('end_time', time.time())
        duration = end_time - start_time if 'end_time' in scan_data else 0
        
        # Format dates for display
        report_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        scan_start_time = datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S') if start_time else 'N/A'
        scan_end_time = datetime.fromtimestamp(end_time).strftime('%Y-%m-%d %H:%M:%S') if 'end_time' in scan_data else 'In Progress'
        
        # Format duration
        hours, remainder = divmod(int(duration), 3600)
        minutes, seconds = divmod(remainder, 60)
        duration_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}" if duration > 0 else 'N/A'
        
        # Process findings
        findings = scan_data.get('findings', [])
        
        # Count findings by severity
        stats = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'total': len(findings)
        }
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in stats:
                stats[severity] += 1
        
        # Generate report title
        report_title = f"{scan_type.capitalize()} Scan Report - {target}"
        
        # Generate summary
        if stats['total'] == 0:
            report_summary = "No security issues were identified during the scan."
        else:
            issues = []
            for sev in ['critical', 'high', 'medium', 'low']:
                count = stats[sev]
                if count > 0:
                    issues.append(f"{count} {sev}")
            
            report_summary = (
                f"The scan identified {stats['total']} security issues ({', '.join(issues)}). "
                f"{stats['critical'] + stats['high']} of these are considered high or critical severity."
            )
        
        # Prepare the context for the template
        context = {
            # Report metadata
            'report_title': report_title,
            'report_date': report_date,
            'report_summary': report_summary,
            'generated_by': self.config.get('company_name', 'CyberSentinel'),
            
            # Scan information
            'scan_id': scan_id,
            'scan_target': target,
            'scan_type': scan_type,
            'scan_status': status.capitalize(),
            'scan_start_time': scan_start_time,
            'scan_end_time': scan_end_time,
            'scan_duration': duration_str,
            
            # Findings
            'findings': findings,
            'stats': stats,
            
            # Additional options
            'include_exec_summary': options.get('include_exec_summary', True),
            'include_methodology': options.get('include_methodology', True),
            'include_findings': options.get('include_findings', True),
            'include_recommendations': options.get('include_recommendations', True),
            
            # Company information
            'company': {
                'name': self.config.get('company_name', ''),
                'logo': self.config.get('company_logo', ''),
                'website': self.config.get('company_website', ''),
                'contact': self.config.get('company_contact', '')
            }
        }
        
        return context
    
    def _render_template(
        self,
        report_data: Dict[str, Any],
        options: Dict[str, Any]
    ) -> str:
        """Render the HTML template with the given data."""
        try:
            template = self.template_env.get_template('report.html')
            return template.render(**report_data)
        except Exception as e:
            logger.error(f"Failed to render report template: {e}")
            raise
    
    def _generate_html_report(
        self,
        html_content: str,
        output_path: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate an HTML report."""
        options = options or {}
        
        # Determine output path
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"cybersentinel_report_{timestamp}.html"
            output_path = str(get_reports_dir() / filename)
        
        # Ensure directory exists
        output_dir = os.path.dirname(output_path)
        os.makedirs(output_dir, exist_ok=True)
        
        # Write HTML content to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {output_path}")
        return output_path
    
    def _generate_pdf_report(
        self,
        html_content: str,
        output_path: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None
    ) -> str:
        """Generate a PDF report from HTML content."""
        options = options or {}
        
        # Determine output path
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"cybersentinel_report_{timestamp}.pdf"
            output_path = str(get_reports_dir() / filename)
        
        # Ensure directory exists
        output_dir = os.path.dirname(output_path)
        os.makedirs(output_dir, exist_ok=True)
        
        try:
            # Generate PDF from HTML
            HTML(string=html_content).write_pdf(
                output_path,
                stylesheets=[get_resource_path('templates/report.css')]
            )
            
            logger.info(f"PDF report generated: {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            raise
    
    def _generate_json_report(
        self,
        report_data: Dict[str, Any],
        output_path: Optional[str] = None
    ) -> str:
        """Generate a JSON report."""
        # Remove any template-specific data
        json_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'tool': 'CyberSentinel',
                'version': '1.0.0'
            },
            'scan': {
                'id': report_data.get('scan_id'),
                'target': report_data.get('scan_target'),
                'type': report_data.get('scan_type'),
                'status': report_data.get('scan_status'),
                'start_time': report_data.get('scan_start_time'),
                'end_time': report_data.get('scan_end_time'),
                'duration': report_data.get('scan_duration')
            },
            'findings': report_data.get('findings', []),
            'statistics': report_data.get('stats', {})
        }
        
        # Determine output path
        if not output_path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"cybersentinel_report_{timestamp}.json"
            output_path = str(get_reports_dir() / filename)
        
        # Ensure directory exists
        output_dir = os.path.dirname(output_path)
        os.makedirs(output_dir, exist_ok=True)
        
        # Write JSON to file
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"JSON report generated: {output_path}")
        return output_path
    
    def generate_executive_summary(
        self,
        scan_data: Dict[str, Any],
        output_format: str = 'text'
    ) -> str:
        """Generate an executive summary of the scan results.
        
        Args:
            scan_data: Dictionary containing scan results
            output_format: Output format ('text' or 'html')
            
        Returns:
            Formatted executive summary
        """
        # Prepare report data
        report_data = self._prepare_report_data(scan_data, {})
        
        if output_format == 'html':
            return f"""
            <h3>Executive Summary</h3>
            <p>{report_data['report_summary']}</p>
            <p>Scan of {report_data['scan_target']} completed on {report_data['scan_end_time']}.</p>
            """
        else:
            return f"""
            EXECUTIVE SUMMARY
            {'=' * 15}
            {report_data['report_summary']}
            
            Scan of {report_data['scan_target']} completed on {report_data['scan_end_time']}.
            """
