"""Load the bundled static lists (abuse TLDs, URL shorteners).

Bundled per release, never fetched live (v2 spec §3, §12). Unknown or
missing files degrade to an empty set — detection silently stops, nothing
crashes.
"""

from __future__ import annotations

import threading

from .paths import data_dir

_cache: dict[str, frozenset[str]] = {}
_lock = threading.Lock()


def _load(filename: str) -> frozenset[str]:
    with _lock:
        if filename in _cache:
            return _cache[filename]
    entries: set[str] = set()
    try:
        path = data_dir() / filename
        for line in path.read_text(encoding="utf-8").splitlines():
            entry = line.strip().lower().lstrip(".")
            if entry and not entry.startswith("#"):
                entries.add(entry)
    except OSError:
        pass
    frozen = frozenset(entries)
    with _lock:
        _cache[filename] = frozen
    return frozen


def abuse_tlds() -> frozenset[str]:
    return _load("abuse_tlds.txt")


def url_shorteners() -> frozenset[str]:
    return _load("url_shorteners.txt")
