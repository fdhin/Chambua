"""Local-only hardening: Host header check (DNS-rebinding defense) and a
per-session CSRF synchronizer token on every state-changing endpoint."""

from __future__ import annotations

import secrets

from fastapi import HTTPException, Request


class HostCheckMiddleware:
    """Reject any request whose Host is not 127.0.0.1:<port> / localhost:<port>."""

    def __init__(self, app, allowed_hosts: set[str]):
        self.app = app
        self.allowed_hosts = {h.lower() for h in allowed_hosts}

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            host = b""
            for name, value in scope.get("headers") or []:
                if name == b"host":
                    host = value
                    break
            if host.decode("latin-1").lower() not in self.allowed_hosts:
                await send(
                    {
                        "type": "http.response.start",
                        "status": 403,
                        "headers": [
                            (b"content-type", b"text/plain"),
                            (b"content-length", b"18"),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": b"Host not permitted."})
                return
        await self.app(scope, receive, send)


class CsrfGuard:
    """Simple synchronizer token: /api/session hands it out, every
    state-changing endpoint must echo it in the X-CSRF-Token header."""

    def __init__(self):
        self.token = secrets.token_urlsafe(32)

    def issue(self) -> str:
        return self.token

    def require_header(self, request: Request) -> None:
        x_csrf_token = request.headers.get("x-csrf-token")
        if not x_csrf_token or not secrets.compare_digest(x_csrf_token, self.token):
            raise HTTPException(status_code=403, detail="missing or invalid CSRF token")
