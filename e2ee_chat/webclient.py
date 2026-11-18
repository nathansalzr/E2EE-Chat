"""Web UI for one chat participant (demo only).

Serves a small local web page and bridges it to a ChatClient over the existing
protocol and crypto. The browser is just a display; all the real work (the
X25519 handshake and AES-256-GCM encryption) happens in Python; the browser
only ever sees decrypted text from its own ChatClient. No new dependencies —
only the standard library. --mode plain gives the unencrypted UC-1 chat for the
demo's "before" step.

Run one per participant, each on its own web port:

    python -m e2ee_chat.webclient --user alice --peer bob --web-port 8001
    python -m e2ee_chat.webclient --user bob --peer alice --web-port 8002

Add --port 6060 to route a participant through the MITM (same attack as the
terminal demo). The relay server still runs with `python -m e2ee_chat.server`.
"""

import argparse
import json
import queue
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from e2ee_chat.client import MODES, ChatClient, RegistrationError, SessionNotReady
from e2ee_chat.protocol import DEFAULT_PORT, MessageTooLarge, port_number


class ChatApp:
    """Holds the participant's ChatClient and fans every event out to the open
    browser tabs (there is usually one, but a refresh opens another)."""

    def __init__(self, user: str, peer: str, mode: str = "e2ee"):
        self.user = user
        self.peer = peer
        self.mode = mode
        # True once we can chat: after the handshake in e2ee mode, at once in plain mode.
        self.ready = mode == "plain"
        self._subscribers: list[queue.Queue] = []
        self._history: list[dict] = []
        self._lock = threading.Lock()

    # --- pub/sub between the receive thread and the SSE handlers ---
    def publish(self, event: dict) -> None:
        with self._lock:
            self._history.append(event)
            subscribers = list(self._subscribers)
        for q in subscribers:
            q.put(event)

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue()
        with self._lock:
            history = list(self._history)
            self._subscribers.append(q)
        for event in history:  # replay so a freshly opened tab is caught up
            q.put(event)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    # --- translate ChatClient messages into UI events ---
    def on_message(self, msg: dict) -> None:
        kind = msg.get("type")
        if kind == "chat":
            event = {"kind": "chat", "from": msg.get("from"), "text": msg.get("text")}
            if msg.get("encrypted") and self.mode == "e2ee":
                event["encrypted"] = True  # arrived as ciphertext and passed the GCM check
            self.publish(event)
        elif kind == "integrity_error":
            self.publish(
                {
                    "kind": "error",
                    "text": f"message failed integrity check (from {msg.get('from')}), dropped",
                }
            )
        elif kind == "downgrade_rejected":
            self.publish(
                {
                    "kind": "error",
                    "text": "plaintext message rejected (possible downgrade attack)",
                }
            )
        elif kind == "secure_session":
            self.ready = True
            self.publish({"kind": "secure", "key_hash": msg.get("key_hash")})
        elif kind == "error":
            # While the handshake is still in flight, a user_offline just means we
            # announced our key before the peer joined — not worth showing.
            if msg.get("code") == "user_offline" and not self.ready:
                return
            self.publish({"kind": "error", "text": f"{msg.get('code')}: {msg.get('message')}"})
        elif kind == "disconnected":
            self.publish({"kind": "system", "text": "connection to the server was lost"})


_PAGE = Path(__file__).with_name("webclient_page.html").read_text(encoding="utf-8")


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # quiet: no per-request logging to the terminal
        pass

    @property
    def app(self) -> ChatApp:
        return self.server.app  # type: ignore[attr-defined]

    def _send_bytes(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj: dict) -> None:
        self._send_bytes(200, "application/json", json.dumps(obj).encode("utf-8"))

    def do_GET(self) -> None:
        if self.path == "/" or self.path.startswith("/index"):
            page = (
                _PAGE.replace("__USER__", self.app.user)
                .replace("__PEER__", self.app.peer)
                .replace("__MODE__", self.app.mode)
            )
            self._send_bytes(200, "text/html; charset=utf-8", page.encode("utf-8"))
        elif self.path == "/events":
            self._stream_events()
        else:
            self._send_bytes(204, "text/plain", b"")

    def do_POST(self) -> None:
        if self.path != "/send":
            self._send_bytes(404, "text/plain", b"not found")
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            text = json.loads(self.rfile.read(length)).get("text", "")
        except (ValueError, TypeError):
            text = ""
        if not text.strip():
            self._json({"ok": False, "reason": "empty"})
            return
        try:
            self.app.client.send_chat(self.app.peer, text)
        except SessionNotReady:
            self._json({"ok": False, "reason": "not_ready"})
            return
        except (OSError, MessageTooLarge):
            self._json({"ok": False, "reason": "offline"})
            return
        # Echo our own message locally so it shows in our window (the server
        # relays it to the peer, not back to us).
        event = {"kind": "chat", "from": self.app.user, "text": text, "mine": True}
        if self.app.mode == "e2ee":
            event["encrypted"] = True
        self.app.publish(event)
        self._json({"ok": True})

    def _stream_events(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        q = self.app.subscribe()
        try:
            while True:
                event = q.get()
                self.wfile.write(f"data: {json.dumps(event)}\n\n".encode("utf-8"))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass  # the browser tab closed
        finally:
            self.app.unsubscribe(q)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="E2EE Chat web UI (one participant)")
    parser.add_argument("--user", required=True, help="your username")
    parser.add_argument("--peer", required=True, help="who your messages go to")
    parser.add_argument("--host", default="127.0.0.1", help="relay server (or MITM) address")
    parser.add_argument(
        "--port",
        type=port_number,
        default=DEFAULT_PORT,
        help="relay server port (use 6060 to go through the MITM)",
    )
    parser.add_argument(
        "--web-port",
        type=port_number,
        default=8000,
        help="local port to serve this participant's window on",
    )
    parser.add_argument(
        "--mode",
        choices=MODES,
        default="e2ee",
        help="e2ee: encrypt every message (default); plain: UC-1 plaintext, for the demo",
    )
    parser.add_argument("--no-open", action="store_true", help="don't open a browser automatically")
    args = parser.parse_args(argv)

    app = ChatApp(args.user, args.peer, args.mode)
    client = ChatClient(
        args.host,
        args.port,
        args.user,
        on_message=app.on_message,
        peer=args.peer,
        mode=args.mode,
    )
    app.client = client
    try:
        client.connect()
    except (ConnectionError, RegistrationError) as exc:
        raise SystemExit(f"! {exc}") from exc

    httpd = ThreadingHTTPServer((args.host, args.web_port), _Handler)
    httpd.daemon_threads = True
    httpd.app = app  # type: ignore[attr-defined]
    url = f"http://{args.host}:{args.web_port}/"
    print(
        f"[web] {args.user}'s window at {url}  (peer: {args.peer}, relay: {args.host}:{args.port})"
    )
    if not args.no_open:
        threading.Thread(target=lambda: webbrowser.open(url), daemon=True).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[web] stopping")
    finally:
        client.close()
        httpd.server_close()


if __name__ == "__main__":
    main()
