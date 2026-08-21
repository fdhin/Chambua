"""Entry point: bind 127.0.0.1 on an OS-assigned free port, open the UI in
the default browser, serve until told to quit (via the UI's Quit button or
SIGINT/SIGTERM), then wipe the workspace via atexit."""

from __future__ import annotations

import argparse
import logging
import socket
import sys
import threading
import webbrowser

import uvicorn

from . import __version__
from .security import CsrfGuard
from .server import create_app
from .workspace import Workspace


def _pick_port() -> tuple[socket.socket, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(128)
    port = sock.getsockname()[1]
    return sock, port


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="chambua",
        description="Local inspector for suspicious email messages",
    )
    parser.add_argument("--keep-workspace", action="store_true",
                        help="do not delete the session workspace on exit (debugging)")
    parser.add_argument("--no-browser", action="store_true",
                        help="do not open the browser automatically")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )
    log = logging.getLogger("chambua")

    workspace = Workspace(keep=args.keep_workspace)
    guard = CsrfGuard()
    sock, port = _pick_port()
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
    app = create_app(workspace, guard, allowed_hosts)

    config = uvicorn.Config(
        app,
        log_level="warning",
        access_log=False,
        # The socket is passed explicitly; these are informational only.
        host="127.0.0.1",
        port=port,
    )
    server = uvicorn.Server(config)
    app.state.server = server

    url = f"http://127.0.0.1:{port}/"
    print(f"chambua {__version__} listening on {url}", file=sys.stderr)
    print(f"workspace: {workspace.root}", file=sys.stderr)

    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    def _stop(signum, frame):
        server.should_exit = True

    import signal

    signal.signal(signal.SIGTERM, _stop)
    try:
        server.run(sockets=[sock])
    except KeyboardInterrupt:
        pass
    finally:
        # atexit (registered by Workspace) wipes the session directory.
        log.info("shutting down")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
