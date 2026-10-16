"""The desktop opens a dashboard without an authentication dialog."""
import subprocess
import sys


def test_application_starts_directly(tmp_path):
    source = '''
from unittest.mock import patch
from PyQt5.QtWidgets import QDialog
from cybersentinel.application import CyberSentinelApp
from cybersentinel.ui.main_window import MainWindow
with patch('cybersentinel.application.MainWindow', side_effect=lambda: MainWindow(workspace_root=ROOT)):
    app = CyberSentinelApp([])
    app.processEvents()
    assert app.main_window.isVisible()
    assert app.main_window.tab_widget.count() == 10
    assert not any(isinstance(widget, QDialog) for widget in app.topLevelWidgets())
    app.main_window.close()
print('Direct dashboard startup verified')
'''.replace('ROOT', repr(str(tmp_path)))
    result = subprocess.run([sys.executable, '-c', source], capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert 'Direct dashboard startup verified' in result.stdout
