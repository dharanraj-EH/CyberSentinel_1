"""
Resources for CyberSentinel application.
"""
from pathlib import Path

# Base resource directory
RESOURCE_DIR = Path(__file__).parent

# Subdirectories
ICON_DIR = RESOURCE_DIR / 'icons'
TEMPLATE_DIR = RESOURCE_DIR / 'templates'
ASSET_DIR = RESOURCE_DIR / 'assets'

# Ensure directories exist
ICON_DIR.mkdir(parents=True, exist_ok=True)
TEMPLATE_DIR.mkdir(parents=True, exist_ok=True)
ASSET_DIR.mkdir(parents=True, exist_ok=True)

def get_icon_path(icon_name: str) -> str:
    """Get the full path to an icon file."""
    return str(ICON_DIR / f"{icon_name}.png")

def get_template_path(template_name: str) -> str:
    """Get the full path to a template file."""
    return str(TEMPLATE_DIR / template_name)

def get_asset_path(asset_name: str) -> str:
    """Get the full path to an asset file."""
    return str(ASSET_DIR / asset_name)
