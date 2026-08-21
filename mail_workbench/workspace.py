"""Per-launch workspace under the OS cache dir.

Layout (one subdirectory per analysis record):

    <cache-dir>/session-<pid>/
      <record-uuid>/
        original.<ext>        exact bytes as dropped
        parsed.json           normalized parse output
        attachments/
          <sha256>.bin        each attachment, stored by hash
          manifest.json       filename ↔ sha256 map, plus MD5/SHA-1
        rendered.html         sanitized HTML body for the iframe
        plaintext.txt         text/plain part if present

The workspace is wiped on graceful shutdown (atexit; uvicorn also handles
SIGINT/SIGTERM which unwind through atexit). Orphaned session dirs older
than 24 hours — left behind by kill -9 or a crash — are removed on the
next startup.
"""

from __future__ import annotations

import atexit
import logging
import os
import shutil
import time
from pathlib import Path

from platformdirs import user_cache_dir

log = logging.getLogger("mail-workbench.workspace")

ORPHAN_MAX_AGE_SECONDS = 24 * 3600


class Workspace:
    def __init__(self, keep: bool = False, cache_root: Path | None = None):
        self.keep = keep
        self.cache_root = Path(cache_root) if cache_root else Path(user_cache_dir("mail-workbench"))
        self.cache_root.mkdir(parents=True, exist_ok=True)
        self._cleanup_orphans()
        # Distinct from PyInstaller's _MEIxxxxxx extraction dir and from
        # $TMPDIR conventions; pid alone per spec, orphan cleanup covers reuse.
        self.root = self.cache_root / f"session-{os.getpid()}"
        if self.root.exists():
            # Same pid as a crashed earlier run — remove its leftovers.
            shutil.rmtree(self.root, ignore_errors=True)
        self.root.mkdir(parents=True)
        atexit.register(self.wipe)

    def new_record_dir(self, record_id: str) -> Path:
        d = self.root / record_id
        d.mkdir(parents=True)
        return d

    def record_dir(self, record_id: str) -> Path | None:
        candidate = self.root / record_id
        if candidate.parent.resolve() == self.root.resolve() and candidate.is_dir():
            return candidate
        return None

    def _cleanup_orphans(self) -> None:
        cutoff = time.time() - ORPHAN_MAX_AGE_SECONDS
        for p in self.cache_root.glob("session-*"):
            try:
                if not p.is_dir():
                    continue
                if p.stat().st_mtime < cutoff:
                    log.info("removing orphaned workspace %s", p)
                    shutil.rmtree(p, ignore_errors=True)
            except OSError:
                pass

    def wipe(self) -> None:
        if self.keep:
            log.info("--keep-workspace set; leaving %s in place", self.root)
            return
        shutil.rmtree(self.root, ignore_errors=True)
