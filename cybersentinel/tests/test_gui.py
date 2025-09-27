"""
Tests for the GUI components.
"""

import unittest
from unittest.mock import patch, MagicMock
import sys
import os
from PyQt5.QtWidgets import QApplication
from PyQt5.QtTest import QTest
from PyQt5.QtCore import Qt

# Add the parent directory to the path so we can import the modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the modules to test
from cybersentinel.gui_main import CyberSentinelApp
from cybersentinel.gui.main_window import MainWindow


class TestCyberSentinelApp(unittest.TestCase):
    """Test cases for the CyberSentinelApp class."""
    
    @classmethod
    def setUpClass(cls):
        """Set up the QApplication for GUI testing."""
        cls.app = QApplication.instance()
        if cls.app is None:
            cls.app = QApplication(sys.argv)
    
    def setUp(self):
        """Set up test fixtures."""
        self.window = CyberSentinelApp()
        self.window.show()
    
    def tearDown(self):
        """Tear down test fixtures."""
        self.window.close()
    
    def test_window_title(self):
        """Test that the window title is set correctly."""
        self.assertEqual(self.window.windowTitle(), "CyberSentinel - Vulnerability Scanner")
    
    def test_tabs_exist(self):
        """Test that all expected tabs exist."""
        tab_widget = self.window.findChild(QTabWidget, "mainTabWidget")
        self.assertIsNotNone(tab_widget)
        
        # Check that all expected tabs are present
        tab_names = ["Dashboard", "Scan", "Results", "Reports", "Settings"]
        for i in range(tab_widget.count()):
            self.assertIn(tab_widget.tabText(i), tab_names)
    
    @patch('cybersentinel.scanner.nmap_wrapper.NmapScanner.scan')
    def test_start_scan(self, mock_scan):
        """Test starting a scan from the GUI."""
        # Mock the scan results
        mock_scan.return_value = {
            '127.0.0.1': {
                'status': {'state': 'up'},
                'tcp': {
                    80: {'state': 'open', 'name': 'http'},
                    443: {'state': 'open', 'name': 'https'}
                }
            }
        }
        
        # Find the scan button and click it
        scan_button = self.window.findChild(QPushButton, "startScanButton")
        self.assertIsNotNone(scan_button)
        
        # Simulate a button click
        QTest.mouseClick(scan_button, Qt.LeftButton)
        
        # Process events to allow the scan to start
        QApplication.processEvents()
        
        # Assert that the scan method was called
        mock_scan.assert_called_once()


class TestMainWindow(unittest.TestCase):
    """Test cases for the MainWindow class."""
    
    @classmethod
    def setUpClass(cls):
        """Set up the QApplication for GUI testing."""
        cls.app = QApplication.instance()
        if cls.app is None:
            cls.app = QApplication(sys.argv)
    
    def setUp(self):
        """Set up test fixtures."""
        self.window = MainWindow()
    
    def tearDown(self):
        """Tear down test fixtures."""
        self.window.close()
    
    def test_initial_state(self):
        """Test the initial state of the main window."""
        self.assertFalse(self.window.scan_in_progress)
        self.assertEqual(len(self.window.scan_results), 0)
    
    def test_update_scan_results(self):
        """Test updating scan results."""
        test_results = {
            'target': 'example.com',
            'ports': [
                {'port': 80, 'state': 'open', 'service': 'http'},
                {'port': 443, 'state': 'open', 'service': 'https'}
            ]
        }
        
        # Update the results
        self.window.update_scan_results(test_results)
        
        # Check that the results were updated
        self.assertEqual(len(self.window.scan_results), 1)
        self.assertEqual(self.window.scan_results[0]['target'], 'example.com')


if __name__ == '__main__':
    unittest.main()
