"""Package initialization for the VPN toolkit.

Ensures the package's ``src`` directory is on ``sys.path`` so legacy absolute
imports like ``import utils`` continue to resolve when executing
``python -m src.main``.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC_DIR = Path(__file__).resolve().parent
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

__all__ = []
