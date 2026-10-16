"""Native desktop application lifecycle and command-line diagnostics."""
import sys
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication
from .ui.main_window import MainWindow
from .ui.theme import DESKTOP_STYLE
from .utils.resource_loader import load_icon
from . import version


class CyberSentinelApp(QApplication):
    """Open the local desktop workspace directly, without authentication."""
    def __init__(self, argv):
        super().__init__(argv)
        self.setApplicationName('CyberSentinel')
        self.setApplicationVersion(version)
        self.setOrganizationName('CyberSentinel')
        self.setStyle('Fusion')
        self.setStyleSheet(DESKTOP_STYLE)
        icon = load_icon('ssl.svg')
        if icon:
            self.setWindowIcon(icon)
        self.main_window = MainWindow()
        self.main_window.show()


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--self-check':
        from .services.diagnostics import self_check
        return self_check(sys.argv[2])
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = CyberSentinelApp(sys.argv)
    return app.exec_()
