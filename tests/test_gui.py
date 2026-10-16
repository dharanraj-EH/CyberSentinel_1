"""Desktop navigation and real action wiring without launching network jobs."""
from PyQt5.QtWidgets import QApplication
from cybersentinel.ui.main_window import MainWindow
from cybersentinel.services.assessment_store import AssessmentWorkspace


def test_desktop_modules_and_navigation(monkeypatch, tmp_path):
    monkeypatch.setattr('cybersentinel.ui.main_window.AssessmentWorkspace', lambda user: AssessmentWorkspace(user, tmp_path))
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    assert window.tab_widget.count() == 10
    assert window.navigation.count() == 10
    window.navigation.setCurrentRow(3)
    assert window.tab_widget.currentWidget() is window.web_tests_tab
    window._new_scan()
    assert window.tab_widget.currentWidget() is window.scanner_tab
    assert not window.scanner_tab.script_scan.isEnabled()
    assert not window.web_tests_tab.test_checkboxes['sql_injection'].isChecked()
    assert window.monitoring_tab.pages.count() == 7
    window.web_tests_tab.deselect_all_tests()
    window.web_tests_tab.select_all_tests()
    assert window.web_tests_tab.test_checkboxes['headers'].isChecked()
    assert not window.web_tests_tab.test_checkboxes['sql_injection'].isChecked()
    window.close()
