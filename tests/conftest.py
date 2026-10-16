import os
import sys
from pathlib import Path

# Canonical namespace from the repository root, independent of pytest entry point.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
