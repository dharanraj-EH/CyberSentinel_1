"""Shared native desktop theme."""
DESKTOP_STYLE = """
QMainWindow, QWidget { background: #101827; color: #dbe6f5; font-family: 'Segoe UI'; font-size: 10pt; }
QTabWidget::pane { border: 1px solid #2b3b52; background: #152136; border-radius: 8px; }
QTabBar::tab { background: #17243a; color: #9eafc7; padding: 15px 12px; border: 1px solid #25364e; }
QTabBar::tab:selected { background: #213a57; color: #69dfd0; border-left: 3px solid #4bd2bf; }
QGroupBox { border: 1px solid #30425b; border-radius: 8px; margin-top: 16px; padding: 16px 10px 10px; font-weight: 600; }
QGroupBox::title { subcontrol-origin: margin; left: 12px; color: #75ddd0; padding: 0 6px; }
QPushButton { background: #234b68; border: 1px solid #396b89; border-radius: 5px; padding: 8px 14px; color: #edf7ff; font-weight: 600; }
QPushButton:hover { background: #30617c; border-color: #62d6c8; }
QPushButton:disabled { background: #202c3e; color: #77869c; border-color: #2a3a50; }
QLineEdit, QComboBox, QSpinBox, QTextEdit, QPlainTextEdit { background: #0d1523; border: 1px solid #344963; border-radius: 5px; padding: 6px; selection-background-color: #285b74; }
QTableWidget, QTreeWidget, QListWidget { background: #121e30; alternate-background-color: #1a2a40; border: 1px solid #2d4059; gridline-color: #293d55; selection-background-color: #28516d; }
QHeaderView::section { background: #23364f; color: #d9e7f8; padding: 9px; border: 0; font-weight: 600; }
QTableWidget::item:selected, QTreeWidget::item:selected { color: #f0f8ff; background: #28516d; }
QTableCornerButton::section { background: #23364f; border: 0; }
QProgressBar { border: 1px solid #334b64; border-radius: 5px; background: #111d2d; text-align: center; min-height: 22px; }
QProgressBar::chunk { background: #277e83; border-radius: 4px; }
QToolBar { background: #19283d; border-bottom: 1px solid #304661; spacing: 8px; padding: 6px; }
QToolButton { padding: 7px; border-radius: 4px; }
QToolButton:hover { background: #2b425e; }
QMenuBar, QMenu, QStatusBar { background: #162238; color: #c2d1e5; }
QMenu::item:selected { background: #2b4d69; }
QLabel { background: transparent; }
QToolTip { color: #eef7ff; background: #29435e; border: 1px solid #5a819e; padding: 5px; }
"""
