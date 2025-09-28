from PyQt5.QtWidgets import QWidget, QLabel, QVBoxLayout
from PyQt5.QtWidgets import (
    QHBoxLayout, QPushButton, QTreeWidget, QTreeWidgetItem, QFileDialog, QMessageBox
)
from PyQt5.QtCore import Qt, QUrl
from PyQt5.QtGui import QDesktopServices

import os
from pathlib import Path


class ReportsTab(QWidget):
    """List generated reports (JSON/HTML/PDF) and open them."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.reports_root = Path.home() / ".cybersentinel" / "reports"

        main_layout = QVBoxLayout(self)

        # Toolbar
        toolbar = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh")
        self.open_dir_btn = QPushButton("Open Reports Folder")
        self.delete_btn = QPushButton("Delete Selected")
        toolbar.addWidget(self.refresh_btn)
        toolbar.addWidget(self.open_dir_btn)
        toolbar.addWidget(self.delete_btn)
        toolbar.addStretch()

        # Tree listing
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Name", "Type", "Path"])
        self.tree.setColumnWidth(0, 260)
        self.tree.setColumnWidth(1, 120)
        self.tree.itemDoubleClicked.connect(self._open_item)

        # Assemble
        main_layout.addLayout(toolbar)
        main_layout.addWidget(self.tree)

        # Wire handlers
        self.refresh_btn.clicked.connect(self._load_reports)
        self.open_dir_btn.clicked.connect(self._open_reports_folder)
        self.delete_btn.clicked.connect(self._delete_selected)

        # Initial load
        self._load_reports()

    def _open_reports_folder(self):
        url = QUrl.fromLocalFile(str(self.reports_root))
        QDesktopServices.openUrl(url)

    def _load_reports(self):
        self.tree.clear()
        if not self.reports_root.exists():
            self.reports_root.mkdir(parents=True, exist_ok=True)
        # Expect structure: reports/web_audit/<target_timestamp>/report.{json,html,pdf}
        for category in sorted(self.reports_root.iterdir()):
            if not category.is_dir():
                continue
            category_item = QTreeWidgetItem([category.name, "Category", str(category)])
            self.tree.addTopLevelItem(category_item)

            for run_dir in sorted(category.iterdir()):
                if not run_dir.is_dir():
                    continue
                run_item = QTreeWidgetItem([run_dir.name, "Run", str(run_dir)])
                category_item.addChild(run_item)

                for fmt in ("json", "html", "pdf"):
                    fpath = run_dir / f"report.{fmt}"
                    if fpath.exists():
                        child = QTreeWidgetItem([fpath.name, fmt.upper(), str(fpath)])
                        run_item.addChild(child)

        self.tree.expandAll()

    def _open_item(self, item: QTreeWidgetItem):
        path = Path(item.text(2))
        if path.is_file():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    def _delete_selected(self):
        item = self.tree.currentItem()
        if not item:
            return
        path = Path(item.text(2))
        if not path.exists():
            return
        reply = QMessageBox.question(
            self,
            "Delete",
            f"Are you sure you want to delete:\n{path}",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            try:
                if path.is_file():
                    path.unlink()
                else:
                    # Delete directory recursively
                    import shutil
                    shutil.rmtree(path)
                self._load_reports()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete item:\n{e}")
