"""
JSON report generator for CyberSentinel.

This module provides functionality to generate JSON reports from scan results.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Union, List

logger = logging.getLogger(__name__)

class JSONReportGenerator:
    """
    A class to generate JSON reports from scan results.
    
    This class provides methods to generate JSON reports with various levels of detail
    and to save them to files or return them as strings.
    """
    
    def __init__(self, pretty_print: bool = True, indent: int = 2):
        """
        Initialize the JSON report generator.
        
        Args:
            pretty_print: Whether to format the JSON output with indentation and line breaks.
            indent: The number of spaces to use for indentation (if pretty_print is True).
        """
        self.pretty_print = pretty_print
        self.indent = indent if pretty_print else None
    
    def generate(self, scan_data: Dict[str, Any], output_path: Optional[Union[str, Path]] = None) -> Optional[str]:
        """
        Generate a JSON report from scan data.
        
        Args:
            scan_data: A dictionary containing the scan results.
            output_path: Optional path to save the JSON report. If not provided, 
                       the JSON string will be returned instead.
                       
        Returns:
            If output_path is None, returns the JSON string. Otherwise, returns None.
            
        Raises:
            ValueError: If scan_data is empty or invalid.
            IOError: If there's an error writing to the output file.
        """
        if not scan_data:
            raise ValueError("Scan data cannot be empty")
        
        try:
            # Add metadata if not already present
            report = self._enrich_with_metadata(scan_data)
            
            # Convert to JSON string
            json_str = json.dumps(
                report,
                indent=self.indent,
                ensure_ascii=False,
                default=self._json_serializer
            )
            
            # Save to file or return string
            if output_path:
                output_path = Path(output_path)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(json_str)
                
                logger.info(f"JSON report saved to: {output_path}")
                return None
            else:
                return json_str
                
        except (TypeError, ValueError) as e:
            logger.error(f"Error generating JSON report: {e}", exc_info=True)
            raise ValueError(f"Invalid scan data: {e}")
        except IOError as e:
            logger.error(f"Error writing JSON report to {output_path}: {e}", exc_info=True)
            raise IOError(f"Failed to write JSON report: {e}")
        except Exception as e:
            logger.error(f"Unexpected error generating JSON report: {e}", exc_info=True)
            raise
    
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
                'report_format': 'cybersentinel-json-1.0',
                'generated_at': datetime.utcnow().isoformat() + 'Z',
                'generator': 'CyberSentinel JSON Report Generator',
                'version': '1.0.0'
            }
        
        # Ensure findings is a list if not present
        if 'findings' not in report:
            report['findings'] = []
        
        # Ensure summary exists
        if 'summary' not in report:
            report['summary'] = {
                'total_findings': len(report.get('findings', [])),
                'severity_counts': self._count_severities(report.get('findings', []))
            }
        
        return report
    
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
    
    @staticmethod
    def _json_serializer(obj):
        """
        Custom JSON serializer for objects not serializable by default json code.
        
        Args:
            obj: The object to serialize.
            
        Returns:
            A JSON-serializable representation of the object.
            
        Raises:
            TypeError: If the object cannot be serialized.
        """
        if isinstance(obj, (datetime, )):
            return obj.isoformat()
        elif isinstance(obj, Path):
            return str(obj)
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        else:
            raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")
    
    @classmethod
    def from_scan_result(cls, scan_result: Any, **kwargs) -> 'JSONReportGenerator':
        """
        Create a JSON report generator from a scan result object.
        
        This is a convenience method that extracts the relevant data from
        a scan result object and creates a new JSONReportGenerator instance.
        
        Args:
            scan_result: A scan result object (e.g., from NmapScanner, SSLChecker, etc.).
            **kwargs: Additional arguments to pass to the JSONReportGenerator constructor.
            
        Returns:
            A new JSONReportGenerator instance.
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
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the report to a dictionary.
        
        Returns:
            A dictionary representation of the report.
        """
        return getattr(self, 'scan_data', {})
