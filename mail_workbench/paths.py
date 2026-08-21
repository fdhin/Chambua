"""Resolve bundled static assets correctly both from source and when frozen.

PyInstaller's onefile bootloader unpacks bundled data into a temp directory
exposed as ``sys._MEIPASS``; running from source, assets live next to this
module. Getting this wrong means every asset 404s in the frozen binary.
"""

from __future__ import annotations

import sys
from pathlib import Path


def static_dir() -> Path:
    frozen = getattr(sys, "_MEIPASS", None)
    if frozen:
        return Path(frozen) / "static"
    return Path(__file__).resolve().parent / "static"
