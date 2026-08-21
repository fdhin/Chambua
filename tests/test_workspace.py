"""Workspace lifecycle: orphan cleanup, record-dir containment."""

from __future__ import annotations

import os
import time
from pathlib import Path

from chambua.workspace import Workspace


def test_orphan_cleanup_on_startup(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    old = cache / "session-11111"
    old.mkdir()
    (old / "junk").write_text("stale")
    os.utime(old, (time.time() - 25 * 3600, time.time() - 25 * 3600))
    fresh = cache / "session-22222"
    fresh.mkdir()

    Workspace(keep=True, cache_root=cache)
    assert not old.exists()
    assert fresh.exists()  # recent sessions from other runs are left alone


def test_record_dir_rejects_traversal(tmp_path):
    ws = Workspace(keep=True, cache_root=tmp_path / "cache")
    assert ws.record_dir("../evil") is None
    assert ws.record_dir("does-not-exist") is None


def test_wipe_removes_session(tmp_path):
    ws = Workspace(keep=False, cache_root=tmp_path / "cache")
    assert ws.root.exists()
    ws.wipe()
    assert not ws.root.exists()


def test_wipe_respects_keep(tmp_path):
    ws = Workspace(keep=True, cache_root=tmp_path / "cache")
    ws.wipe()
    assert ws.root.exists()
