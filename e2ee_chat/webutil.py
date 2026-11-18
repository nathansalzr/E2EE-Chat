"""Shared pieces for the local web pages (chat windows and the attacker dashboard).

Standard library only. Everything here serves 127.0.0.1 for the classroom demo.

- EventHub: fan-out of UI events to every open browser tab over Server-Sent
  Events, with a replay buffer so a refreshed tab catches up.
- same_origin(): the CSRF guard every POST endpoint uses.
- WebHandler: small BaseHTTPRequestHandler base with JSON/SSE helpers.
"""

import json
import os
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_REPLAY = 2000  # events kept for replay; bounds memory over a long demo


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    """Like ThreadingHTTPServer, but doesn't dump a traceback when a browser
    closes a connection.

    The chat windows and the dashboard hold long-lived Server-Sent Events
    streams. A tab refresh, navigation, or a window reconnect aborts one, which
    surfaces as a ConnectionError (WinError 10053/10054 on Windows) deep in the
    stdlib request handler — normal, not a bug. We swallow only connection
    errors; any other exception still reports as usual.
    """

    daemon_threads = True
    # HTTPServer turns on SO_REUSEADDR. On Windows that lets a second program
    # share a port that's already in use instead of failing, so a stale window
    # or dashboard could silently keep the traffic. Fail loudly there instead.
    allow_reuse_address = os.name != "nt"

    def handle_error(self, request, client_address):
        import sys

        if isinstance(sys.exc_info()[1], ConnectionError):
            return  # a client hung up on a stream; nothing to see
        super().handle_error(request, client_address)


LOOPBACK = ("127.0.0.1", "localhost", "::1")


class EventHub:
    """Publish events to every subscriber; new subscribers get the backlog first."""

    def __init__(self, max_replay: int = MAX_REPLAY):
        self._subscribers: list[queue.Queue] = []
        self._history: list[dict] = []
        self._max = max_replay
        self._lock = threading.Lock()

    def publish(self, event: dict) -> None:
        with self._lock:
            self._history.append(event)
            if len(self._history) > self._max:
                del self._history[: len(self._history) - self._max]
            subscribers = list(self._subscribers)
        for q in subscribers:
            q.put(event)

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue()
        with self._lock:
            backlog = list(self._history)
            self._subscribers.append(q)
        for event in backlog:  # replay so a freshly opened tab is caught up
            q.put(event)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def clear(self) -> None:
        """Forget the replay backlog (e.g. the dashboard's Clear button)."""
        with self._lock:
            self._history.clear()

    def backlog(self) -> list[dict]:
        with self._lock:
            return list(self._history)


def allowed_origins(host: str, port: int) -> set[str]:
    """Our own web origin(s). On loopback, 127.0.0.1 and localhost are the same
    server but different browser origins, so accept both; otherwise buttons
    silently fail depending on which name the user typed."""
    hosts = {host}
    if host in LOOPBACK:
        hosts |= {"127.0.0.1", "localhost"}
    return {f"http://{h}:{port}" for h in hosts}


def same_origin(headers, host: str, port: int) -> bool:
    """Reject cross-site POSTs (CSRF).

    Browsers send Origin on POSTs, and a page on another site would carry its
    own origin, not ours. We also require application/json, which a plain
    HTML form can't send without a CORS preflight we never answer. A missing
    Origin means a non-browser client (tests, curl), which has no ambient
    browser session to abuse.
    """
    if not headers.get("Content-Type", "").startswith("application/json"):
        return False
    origin = headers.get("Origin")
    if origin is None:
        return True
    return origin in allowed_origins(host, port)


class WebHandler(BaseHTTPRequestHandler):
    """Base handler: quiet logging plus JSON, body and SSE helpers.

    Subclasses read their app object from ``self.server.app``.
    """

    def log_message(self, *args):  # no per-request lines in the terminal
        pass

    @property
    def app(self):
        return self.server.app  # type: ignore[attr-defined]

    def send_bytes(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, obj: dict, status: int = 200) -> None:
        self.send_bytes(status, "application/json", json.dumps(obj).encode("utf-8"))

    def read_json(self) -> dict:
        """The request body as a dict ({} if empty or not a JSON object)."""
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            return {}
        if length <= 0 or length > 65_536:
            return {}
        try:
            body = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            return {}
        return body if isinstance(body, dict) else {}

    def check_origin(self) -> bool:
        """CSRF guard for POSTs; sends 403 and returns False when it fails."""
        # The page's own address: a chat window's web_host (its .host is the
        # relay it dials), or the dashboard's host.
        host = getattr(self.app, "web_host", None) or self.app.host
        if same_origin(self.headers, host, self.app.web_port):
            return True
        self.send_bytes(403, "text/plain", b"forbidden")
        return False

    def stream(self, hub: EventHub) -> None:
        """Serve one Server-Sent Events stream until the tab closes."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        q = hub.subscribe()
        try:
            while True:
                event = q.get()
                self.wfile.write(f"data: {json.dumps(event)}\n\n".encode("utf-8"))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            hub.unsubscribe(q)
