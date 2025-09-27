"""
Tests for the reporting module.
"""

import unittest
import os
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

# Import the modules to test
from cybersentinel.reporting.pdf_report import PDFReportGenerator
from cybersentinel.reporting.html_report import HTMLReportGenerator


class TestPDFReportGenerator(unittest.TestCase):
    """Test cases for the PDFReportGenerator class."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_data = {
            'scan_id': 'test-scan-123',
            'target': 'example.com',
            'start_time': '2023-01-01T12:00:00Z',
            'end_time': '2023-01-01T12:05:00Z',
            'status': 'completed',
            'findings': [
                {
                    'id': 'CVE-2023-12345',
                    'severity': 'high',
                    'name': 'Test Vulnerability',
                    'description': 'A test vulnerability',
                    'solution': 'Apply patches',
                    'cvss_score': 8.1,
                    'affected_ports': [80, 443]
                }
            ]
        }
        
        # Create a temporary directory for test outputs
        self.temp_dir = tempfile.mkdtemp()
        self.output_file = os.path.join(self.temp_dir, 'test_report.pdf')
        
        # Initialize the report generator
        self.generator = PDFReportGenerator()
    
    def tearDown(self):
        """Clean up test files."""
        if os.path.exists(self.output_file):
            os.remove(self.output_file)
        os.rmdir(self.temp_dir)
    
    def test_generate_pdf_report(self):
        """Test generating a PDF report."""
        # Generate the report
        result = self.generator.generate(self.test_data, self.output_file)
        
        # Check that the file was created
        self.assertTrue(result)
        self.assertTrue(os.path.exists(self.output_file))
        
        # Check that the file is not empty
        self.assertGreater(os.path.getsize(self.output_file), 0)
    
    @patch('reportlab.platypus.SimpleDocTemplate.build')
    def test_generate_pdf_error_handling(self, mock_build):
        """Test error handling during PDF generation."""
        # Make the build method raise an exception
        mock_build.side_effect = Exception('Test error')
        
        # Generate the report (should handle the exception)
        with self.assertLogs(level='ERROR'):
            result = self.generator.generate(self.test_data, self.output_file)
        
        # Check that the method returned False on error
        self.assertFalse(result)


class TestHTMLReportGenerator(unittest.TestCase):
    """Test cases for the HTMLReportGenerator class."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_data = {
            'scan_id': 'test-scan-123',
            'target': 'example.com',
            'start_time': '2023-01-01T12:00:00Z',
            'end_time': '2023-01-01T12:05:00Z',
            'status': 'completed',
            'findings': [
                {
                    'id': 'CVE-2023-12345',
                    'severity': 'high',
                    'name': 'Test Vulnerability',
                    'description': 'A test vulnerability',
                    'solution': 'Apply patches',
                    'cvss_score': 8.1,
                    'affected_ports': [80, 443]
                }
            ]
        }
        
        # Create a temporary directory for test outputs
        self.temp_dir = tempfile.mkdtemp()
        self.output_file = os.path.join(self.temp_dir, 'test_report.html')
        
        # Initialize the report generator
        self.generator = HTMLReportGenerator()
    
    def tearDown(self):
        """Clean up test files."""
        if os.path.exists(self.output_file):
            os.remove(self.output_file)
        os.rmdir(self.temp_dir)
    
    def test_generate_html_report(self):
        """Test generating an HTML report."""
        # Generate the report
        result = self.generator.generate(self.test_data, self.output_file)
        
        # Check that the file was created
        self.assertTrue(result)
        self.assertTrue(os.path.exists(self.output_file))
        
        # Check that the file is not empty
        self.assertGreater(os.path.getsize(self.output_file), 0)
        
        # Check that the file contains expected content
        with open(self.output_file, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn('CyberSentinel Report', content)
            self.assertIn('example.com', content)
            self.assertIn('Test Vulnerability', content)
    
    @patch('jinja2.Template.render')
    def test_generate_html_error_handling(self, mock_render):
        """Test error handling during HTML generation."""
        # Make the render method raise an exception
        mock_render.side_effect = Exception('Test error')
        
        # Generate the report (should handle the exception)
        with self.assertLogs(level='ERROR'):
            result = self.generator.generate(self.test_data, self.output_file)
        
        # Check that the method returned False on error
        self.assertFalse(result)


class TestJSONReportGenerator(unittest.TestCase):
    """Test cases for the JSONReportGenerator class."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_data = {
            'scan_id': 'test-scan-123',
            'target': 'example.com',
            'start_time': '2023-01-01T12:00:00Z',
            'end_time': '2023-01-01T12:05:00Z',
            'status': 'completed',
            'findings': [
                {
                    'id': 'CVE-2023-12345',
                    'severity': 'high',
                    'name': 'Test Vulnerability',
                    'description': 'A test vulnerability',
                    'solution': 'Apply patches',
                    'cvss_score': 8.1,
                    'affected_ports': [80, 443]
                }
            ]
        }
        
        # Create a temporary directory for test outputs
        self.temp_dir = tempfile.mkdtemp()
        self.output_file = os.path.join(self.temp_dir, 'test_report.json')
        
        # Initialize the report generator
        self.generator = JSONReportGenerator()
    
    def tearDown(self):
        """Clean up test files."""
        if os.path.exists(self.output_file):
            os.remove(self.output_file)
        os.rmdir(self.temp_dir)
    
    def test_generate_json_report(self):
        """Test generating a JSON report."""
        # Generate the report
        result = self.generator.generate(self.test_data, self.output_file)
        
        # Check that the file was created
        self.assertTrue(result)
        self.assertTrue(os.path.exists(self.output_file))
        
        # Check that the file is not empty
        self.assertGreater(os.path.getsize(self.output_file), 0)
        
        # Check that the file contains valid JSON
        with open(self.output_file, 'r', encoding='utf-8') as f:
            content = json.load(f)
            self.assertEqual(content['scan_id'], 'test-scan-123')
            self.assertEqual(content['target'], 'example.com')
            self.assertEqual(len(content['findings']), 1)
            self.assertEqual(content['findings'][0]['id'], 'CVE-2023-12345')
    
    def test_generate_json_error_handling(self):
        """Test error handling during JSON generation."""
        # Create a non-serializable object to force a JSON encoding error
        invalid_data = self.test_data.copy()
        invalid_data['invalid'] = object()  # Objects are not JSON serializable
        
        # Generate the report (should handle the exception)
        with self.assertLogs(level='ERROR'):
            result = self.generator.generate(invalid_data, self.output_file)
        
        # Check that the method returned False on error
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()
