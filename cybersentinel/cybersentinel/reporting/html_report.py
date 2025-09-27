"""
HTML report generator for CyberSentinel.

This module provides functionality to generate interactive HTML reports from scan results.
"""

import json
import logging
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Union, List, Tuple
from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)

# Template directory relative to this file
TEMPLATE_DIR = Path(__file__).parent / 'templates'
STATIC_DIR = Path(__file__).parent / 'static'

class HTMLReportGenerator:
    """
    A class to generate HTML reports from scan results.
    
    This class provides methods to generate interactive HTML reports with various
    visualizations and to save them to files or directories.
    """
    
    def __init__(self, template_dir: Optional[Union[str, Path]] = None, 
                 static_dir: Optional[Union[str, Path]] = None):
        """
        Initialize the HTML report generator.
        
        Args:
            template_dir: Directory containing Jinja2 templates. If None, uses the default templates.
            static_dir: Directory containing static assets (CSS, JS, images). If None, uses the default assets.
        """
        self.template_dir = Path(template_dir) if template_dir else TEMPLATE_DIR
        self.static_dir = Path(static_dir) if static_dir else STATIC_DIR
        
        # Ensure template directory exists
        if not self.template_dir.exists():
            raise FileNotFoundError(f"Template directory not found: {self.template_dir}")
        
        # Set up Jinja2 environment
        self.env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Register custom filters
        self.env.filters['tojson_pretty'] = self._tojson_pretty
        self.env.filters['format_timestamp'] = self._format_timestamp
        self.env.filters['severity_class'] = self._severity_class
    
    def generate(self, scan_data: Dict[str, Any], 
                output_path: Union[str, Path],
                template_name: str = 'report.html',
                copy_assets: bool = True) -> str:
        """
        Generate an HTML report from scan data.
        
        Args:
            scan_data: A dictionary containing the scan results.
            output_path: Path to save the HTML report. If it's a directory, 
                       'index.html' will be used as the filename.
            template_name: Name of the Jinja2 template to use.
            copy_assets: Whether to copy static assets to the output directory.
                       
        Returns:
            The path to the generated HTML file.
            
        Raises:
            ValueError: If scan_data is empty or invalid.
            IOError: If there's an error writing the report or copying assets.
        """
        if not scan_data:
            raise ValueError("Scan data cannot be empty")
        
        output_path = Path(output_path)
        
        # If output_path is a directory, use index.html as the filename
        if output_path.is_dir() or not output_path.suffix.lower() == '.html':
            output_path = output_path / 'index.html'
        
        try:
            # Create output directory if it doesn't exist
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Add metadata if not already present
            report_data = self._enrich_with_metadata(scan_data)
            
            # Get the template
            template = self.env.get_template(template_name)
            
            # Render the template with the report data
            html_content = template.render(
                report=report_data,
                now=datetime.utcnow(),
                version="1.0.0"
            )
            
            # Write the HTML file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            # Copy static assets if requested
            if copy_assets:
                self._copy_static_assets(output_path.parent)
            
            logger.info(f"HTML report generated at: {output_path}")
            return str(output_path)
            
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}", exc_info=True)
            if isinstance(e, (ValueError, IOError)):
                raise
            raise IOError(f"Failed to generate HTML report: {e}")
    
    def _enrich_with_metadata(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add metadata to the scan data if not already present.
        
        Args:
            scan_data: The original scan data.
            
        Returns:
            The enriched scan data with metadata.
        """
        # Create a copy to avoid modifying the original
        report = scan_data.copy()
        
        # Add timestamp if not present
        if 'timestamp' not in report:
            report['timestamp'] = datetime.utcnow().isoformat() + 'Z'
        
        # Add report metadata
        if '_metadata' not in report:
            report['_metadata'] = {
                'report_format': 'cybersentinel-html-1.0',
                'generated_at': datetime.utcnow().isoformat() + 'Z',
                'generator': 'CyberSentinel HTML Report Generator',
                'version': '1.0.0'
            }
        
        # Ensure findings is a list if not present
        if 'findings' not in report:
            report['findings'] = []
        
        # Process findings to add computed fields
        for finding in report['findings']:
            # Add severity class for CSS styling
            if 'severity' in finding:
                finding['_severity_class'] = self._severity_class(finding['severity'])
            
            # Ensure all findings have required fields
            finding.setdefault('title', 'Untitled Finding')
            finding.setdefault('description', 'No description available.')
            finding.setdefault('severity', 'info')
            finding.setdefault('status', 'open')
        
        # Ensure summary exists
        if 'summary' not in report:
            report['summary'] = {
                'total_findings': len(report.get('findings', [])),
                'severity_counts': self._count_severities(report.get('findings', []))
            }
        
        # Add severity distribution for charts
        severity_dist = self._get_severity_distribution(report['findings'])
        report['_charts'] = {
            'severity_distribution': severity_dist,
            'severity_data': json.dumps(severity_dist, default=str)
        }
        
        return report
    
    def _copy_static_assets(self, output_dir: Path) -> None:
        """
        Copy static assets to the output directory.
        
        Args:
            output_dir: Directory to copy static assets to.
            
        Raises:
            IOError: If there's an error copying the assets.
        """
        if not self.static_dir.exists():
            logger.warning(f"Static assets directory not found: {self.static_dir}")
            return
        
        try:
            # Create static directory in output
            static_output_dir = output_dir / 'static'
            static_output_dir.mkdir(exist_ok=True)
            
            # Copy all files from static directory
            for item in self.static_dir.glob('*'):
                dest = static_output_dir / item.name
                if item.is_file():
                    shutil.copy2(item, dest)
                elif item.is_dir():
                    if dest.exists():
                        shutil.rmtree(dest)
                    shutil.copytree(item, dest)
            
            logger.debug(f"Copied static assets to: {static_output_dir}")
            
        except Exception as e:
            logger.error(f"Error copying static assets: {e}", exc_info=True)
            raise IOError(f"Failed to copy static assets: {e}")
    
    def _count_severities(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Count the number of findings by severity.
        
        Args:
            findings: List of finding dictionaries.
            
        Returns:
            A dictionary with severity levels as keys and counts as values.
        """
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'unknown': 0
        }
        
        for finding in findings:
            severity = str(finding.get('severity', 'unknown')).lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts['unknown'] += 1
        
        return severity_counts
    
    def _get_severity_distribution(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Get data for the severity distribution chart.
        
        Args:
            findings: List of finding dictionaries.
            
        Returns:
            A list of dictionaries with 'severity', 'count', and 'color' keys.
        """
        severity_colors = {
            'critical': '#FF3860',  # Red
            'high': '#FF7043',      # Deep Orange
            'medium': '#FFB74D',    # Orange
            'low': '#FFD54F',       # Yellow
            'info': '#4FC3F7',      # Light Blue
            'unknown': '#9E9E9E'    # Grey
        }
        
        counts = self._count_severities(findings)
        
        # Create distribution data for chart
        distribution = []
        for severity, count in counts.items():
            if count > 0:  # Only include severities with findings
                distribution.append({
                    'severity': severity.capitalize(),
                    'count': count,
                    'color': severity_colors.get(severity.lower(), '#9E9E9E'),
                    'class': self._severity_class(severity)
                })
        
        # Sort by severity (critical first, then high, medium, etc.)
        severity_order = {v: i for i, v in enumerate([
            'critical', 'high', 'medium', 'low', 'info', 'unknown'
        ])}
        
        distribution.sort(key=lambda x: severity_order.get(x['severity'].lower(), 999))
        
        return distribution
    
    # Custom Jinja2 filters
    @staticmethod
    def _tojson_pretty(obj: Any, **kwargs) -> str:
        """Convert object to pretty-printed JSON string."""
        return json.dumps(obj, indent=2, ensure_ascii=False, **kwargs)
    
    @staticmethod
    def _format_timestamp(timestamp: str, format_str: str = '%Y-%m-%d %H:%M:%S %Z') -> str:
        """Format a timestamp string."""
        if not timestamp:
            return 'N/A'
        
        try:
            # Try parsing ISO format
            if 'T' in timestamp and 'Z' in timestamp.upper():
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            else:
                dt = datetime.fromisoformat(timestamp)
            
            return dt.strftime(format_str)
        except (ValueError, TypeError):
            return str(timestamp)
    
    @staticmethod
    def _severity_class(severity: str) -> str:
        """Get the CSS class for a severity level."""
        severity = str(severity).lower()
        
        severity_classes = {
            'critical': 'is-danger',
            'high': 'is-warning',
            'medium': 'is-primary',
            'low': 'is-info',
            'info': 'is-link',
            'passed': 'is-success',
            'unknown': 'is-light'
        }
        
        return severity_classes.get(severity, 'is-light')
    
    @classmethod
    def from_scan_result(cls, scan_result: Any, **kwargs) -> 'HTMLReportGenerator':
        """
        Create an HTML report generator from a scan result object.
        
        This is a convenience method that extracts the relevant data from
        a scan result object and creates a new HTMLReportGenerator instance.
        
        Args:
            scan_result: A scan result object (e.g., from NmapScanner, SSLChecker, etc.).
            **kwargs: Additional arguments to pass to the HTMLReportGenerator constructor.
            
        Returns:
            A new HTMLReportGenerator instance.
        """
        # Extract data from scan result based on its type
        if hasattr(scan_result, 'to_dict'):
            scan_data = scan_result.to_dict()
        elif hasattr(scan_result, '__dict__'):
            scan_data = vars(scan_result)
        elif isinstance(scan_result, dict):
            scan_data = scan_result
        else:
            raise ValueError(f"Unsupported scan result type: {type(scan_result).__name__}")
        
        # Create a new instance with the extracted data
        generator = cls(**kwargs)
        generator.scan_data = scan_data
        return generator
