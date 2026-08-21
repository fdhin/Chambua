from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FIXTURES = ROOT / "tests" / "fixtures"

from mail_workbench.security import CsrfGuard  # noqa: E402
from mail_workbench.workspace import Workspace  # noqa: E402


@pytest.fixture()
def ws(tmp_path):
    return Workspace(keep=True, cache_root=tmp_path / "cache")


@pytest.fixture()
def fx():
    return FIXTURES


@pytest.fixture()
def client(tmp_path):
    from fastapi.testclient import TestClient

    from mail_workbench.server import create_app

    workspace = Workspace(keep=True, cache_root=tmp_path / "cache")
    guard = CsrfGuard()
    app = create_app(workspace, guard, {"127.0.0.1:9999", "localhost:9999"})
    with TestClient(app, base_url="http://127.0.0.1:9999") as c:
        c.csrf = guard.token
        c.workspace = workspace
        yield c


def upload(client, path: Path):
    return client.post(
        "/api/records",
        headers={"X-CSRF-Token": client.csrf},
        files={"files": (path.name, path.read_bytes(), "application/octet-stream")},
    )
