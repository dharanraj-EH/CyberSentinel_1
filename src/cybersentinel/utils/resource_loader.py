"""
Utility for loading application resources such as icons, images, and UI files.
"""
import sys
import logging
from pathlib import Path
from typing import Optional, Union

logger = logging.getLogger(__name__)

def get_resource_path(relative_path: str) -> Path:
    """
    Get the absolute path to a resource file.
    
    This function works both in development and in PyInstaller bundles.
    
    Args:
        relative_path: Path to the resource relative to the package root.
        
    Returns:
        Path: Absolute path to the resource file.
    """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = Path(sys._MEIPASS)  # type: ignore
    except AttributeError:
        # Normal execution - get the directory of the current module
        base_path = Path(__file__).parent.parent.parent
    
    # Construct the full path
    full_path = base_path / relative_path
    
    # If the file doesn't exist, try to find it in the package
    if not full_path.exists():
        # Try to find the resource in the package
        package_path = Path(__file__).parent.parent / relative_path
        if package_path.exists():
            full_path = package_path
        else:
            logger.warning(f"Resource not found: {relative_path}")
    
    return full_path

def load_icon(icon_name: str) -> Optional['QIcon']:  # type: ignore
    """
    Load an icon from the resources.
    
    Args:
        icon_name: Name of the icon file (with extension).
        
    Returns:
        QIcon: The loaded icon, or None if loading failed.
    """
    try:
        from PyQt5.QtGui import QIcon
        icon_path = get_resource_path(f"icons/{icon_name}")
        if icon_path.exists():
            return QIcon(str(icon_path))
        logger.warning(f"Icon not found: {icon_name}")
    except ImportError:
        logger.warning("PyQt5 is not available for icon loading")
    except Exception as e:
        logger.error(f"Failed to load icon {icon_name}: {e}")
    
    return None

def load_stylesheet(style_name: str) -> str:
    """
    Load a stylesheet from the resources.
    
    Args:
        style_name: Name of the stylesheet file (with .qss extension).
        
    Returns:
        str: The loaded stylesheet content, or an empty string if loading failed.
    """
    try:
        style_path = get_resource_path(f"styles/{style_name}")
        if style_path.exists():
            return style_path.read_text(encoding='utf-8')
        logger.warning(f"Stylesheet not found: {style_name}")
    except Exception as e:
        logger.error(f"Failed to load stylesheet {style_name}: {e}")
    
    return ""

def load_ui(ui_name: str, parent=None):
    """
    Load a .ui file and return the generated widget.
    
    Args:
        ui_name: Name of the .ui file (with .ui extension).
        parent: Parent widget for the loaded UI.
        
    Returns:
        The loaded UI widget, or None if loading failed.
    """
    try:
        from PyQt5 import uic
        ui_path = get_resource_path(f"ui/{ui_name}")
        if ui_path.exists():
            return uic.loadUi(str(ui_path), parent)
        logger.warning(f"UI file not found: {ui_name}")
    except ImportError:
        logger.error("PyQt5.uic is not available for UI loading")
    except Exception as e:
        logger.error(f"Failed to load UI {ui_name}: {e}")
    
    return None
