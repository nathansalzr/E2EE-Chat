"""Web UI for one chat participant (demo only).

Serves a small local web page and bridges it to a ChatClient over the existing
protocol and crypto. The browser is just a display; all the real work (the
X25519 handshake and AES-256-GCM encryption) happens in Python; the browser
only ever sees decrypted text from its own ChatClient. Standard library only.

The window **auto-reconnects**, so the attacker can change mode (or the server
blip) without the presenter restarting anything, and it can switch between
plain and e2ee live. Keys on disk persist across reconnects, so a reconnect
whose key changed raises the trust-on-first-use alarm (UC-5).

Run one per participant, each on its own web port:

    python -m e2ee_chat.webclient --user alice --peer bob --web-port 8001
    python -m e2ee_chat.webclient --user bob --peer alice --web-port 8002

Add --port 6060 to route a participant through the MITM.
"""

import argparse
import threading
import time
import webbrowser
from http.server import ThreadingHTTPServer  # return type
from pathlib import Path

from e2ee_chat.client import MODES, ChatClient, KeyNotTrusted, RegistrationError, SessionNotReady
from e2ee_chat.protocol import DEFAULT_PORT, MessageTooLarge, is_valid_username, port_number
from e2ee_chat.webutil import EventHub, QuietThreadingHTTPServer, WebHandler

RECONNECT_BACKOFF = (0.3, 0.6, 1.0, 2.0)  # seconds between reconnect attempts; steady at the last


class ChatApp:
    """Owns the participant's ChatClient, its reconnection, and the event feed.

    on_message() (called from a client's receive thread) translates protocol
    messages into UI events and pushes them to the browser through an EventHub.
    """

    def __init__(
        self, user, peer, mode="e2ee", host="127.0.0.1", port=DEFAULT_PORT, keys_dir="keys"
    ):
        self.user = user
        self.peer = peer
        self.mode = mode
        self.host = host  # relay/MITM address the ChatClient dials
        self.port = port
        self.keys_dir = keys_dir
        self.web_host = "127.0.0.1"  # for the CSRF origin check (set in main)
        self.web_port = 8000
        self.ready = mode == "plain"
        self.hub = EventHub()
        self.store = None  # optional history store (set in main); None = don't persist
        self.client = None
        self._stop = False  # True after /abort: stop auto-reconnecting
        self._gen = 0  # bumped on every (re)connect request; supersedes a stale attempt
        self._connecting = False  # at most one connect worker runs at a time
        self._lock = threading.Lock()

    # --- connection lifecycle -------------------------------------------
    def start(self) -> None:
        """Ensure a single connect worker is (re)establishing the session.

        Bumps the generation so any worker in backoff rebuilds with the current
        mode, and spawns a worker only if none is already running. This keeps
        exactly one ChatClient per window, so a mode toggle and a drop-triggered
        reconnect can't race into two overlapping connections.
        """
        with self._lock:
            if self._stop:
                return
            self._gen += 1
            if self._connecting:
                return  # a live worker will pick up the new generation
            self._connecting = True
        threading.Thread(target=self._connect_loop, name="connect", daemon=True).start()

    def _connect_loop(self) -> None:
        try:
            self._connect_until_done()
        finally:
            # Whatever happened (connected, stopped, or a crash), this worker is
            # gone, so never leave the flag latched: a latched flag would make
            # every later start() trust a dead worker and the window would freeze.
            with self._lock:
                self._connecting = False

    def _connect_until_done(self) -> None:
        attempt = 0
        while not self._stop:
            with self._lock:
                gen = self._gen
                mode = self.mode
            try:
                # Built inside the try: in e2ee mode the constructor loads the
                # key file, and a corrupt one raises ValueError right here.
                client = ChatClient(
                    self.host,
                    self.port,
                    self.user,
                    on_message=self.on_message,
                    peer=self.peer,
                    mode=mode,
                    keys_dir=self.keys_dir,
                )
            except ValueError:
                # Retrying can't fix a bad key file. Say so and stop; switching
                # to plain (which needs no key) still works.
                self.hub.publish(
                    {
                        "kind": "event",
                        "level": "error",
                        "text": f"cannot read the key file for {self.user}; delete "
                        f"keys/{self.user}.key to make a new one, or switch to Plain",
                    }
                )
                self.hub.publish({"kind": "status", "state": "aborted", "mode": mode})
                return
            try:
                client.connect()
            except (ConnectionError, RegistrationError):
                # Server briefly gone, or our old name still draining after a drop
                # (username_taken). Wait and try again with the current mode.
                attempt += 1
                if self._wait(RECONNECT_BACKOFF[min(attempt, len(RECONNECT_BACKOFF) - 1)]):
                    continue
                return
            with self._lock:
                superseded = self._stop or self._gen != gen
                if not superseded:
                    self.client = client
            if superseded:
                client.close()  # a newer request arrived while we were connecting
                attempt = 0
                continue
            self.hub.publish({"kind": "status", "state": "connected", "mode": mode})
            return

    def _wait(self, seconds: float) -> bool:
        """Sleep in small steps; return False if a stop was requested meanwhile."""
        end = time.time() + seconds
        while time.time() < end:
            if self._stop:
                return False
            time.sleep(0.05)
        return not self._stop

    def set_mode(self, mode: str) -> bool:
        """Switch between plain and e2ee by reconnecting in the new mode."""
        if mode not in MODES:
            return False
        with self._lock:
            if mode == self.mode:
                return True
            self.mode = mode
            self.ready = mode == "plain"
            old = self.client
            self.client = None
            self._stop = False
        if old is not None:
            old.close()  # intentional: close() suppresses the disconnected event
        self.hub.publish({"kind": "status", "state": "switching", "mode": mode})
        self.start()
        return True

    def abort(self) -> None:
        """Stop the session and stop auto-reconnecting (the key wasn't trusted)."""
        with self._lock:
            self._stop = True
            client = self.client
            self.client = None
        if client is not None:
            client.abort()  # emits session_aborted -> bubble + aborted status
        else:
            # Aborted mid-reconnect: no client to emit it, so publish the status
            # ourselves, or the page never shows its Reconnect button.
            self.hub.publish({"kind": "status", "state": "aborted", "mode": self.mode})

    def shutdown(self) -> None:
        """Process teardown (Ctrl+C / demo stop): close quietly.

        Unlike abort(), nothing is written to the saved history, so a normal
        stop doesn't leave a 'session aborted' line in the next run.
        """
        with self._lock:
            self._stop = True
            client = self.client
            self.client = None
        if client is not None:
            client.close()  # close() emits no events

    def reconnect(self) -> None:
        """Manual reconnect after an abort."""
        with self._lock:
            self._stop = False
        self.start()

    # --- outgoing actions from the browser ------------------------------
    def send(self, text: str) -> str:
        with self._lock:
            client = self.client
        if client is None:
            return "offline"
        try:
            client.send_chat(self.peer, text)
        except KeyNotTrusted:
            return "key_changed"
        except SessionNotReady:
            return "not_ready"
        except (OSError, MessageTooLarge):
            return "offline"
        event = {"kind": "chat", "from": self.user, "text": text, "mine": True}
        # Label by the client that actually sent it, not self.mode: a mode switch
        # landing mid-send must not put a 🔒 on a message that went out in plain.
        if client.secure:
            event["encrypted"] = True
        self._emit(event, save=True)
        return "ok"

    def trust(self) -> bool:
        with self._lock:
            client = self.client
        return bool(client and client.trust_peer())

    def load_history(self) -> None:
        """Replay the saved conversation into the feed as greyed 'earlier' items,
        so a reopened window shows past messages like a real messaging app."""
        if self.store is None:
            return
        try:
            saved = self.store.load()
        except Exception:  # noqa: BLE001 - a bad history file must never stop the window
            return
        for event in saved:
            self.hub.publish({**event, "earlier": True})

    # --- incoming protocol messages -> UI events ------------------------
    def _emit(self, event: dict, save: bool = False) -> None:
        self.hub.publish(event)
        if save and self.store is not None:
            self.store.append(event)

    def on_message(self, msg: dict) -> None:
        kind = msg.get("type")
        if kind == "chat":
            event = {"kind": "chat", "from": msg.get("from"), "text": msg.get("text")}
            if msg.get("encrypted") and self.mode == "e2ee":
                event["encrypted"] = True
            self._emit(event, save=True)
        elif kind == "integrity_error":
            self._emit(
                {
                    "kind": "event",
                    "level": "error",
                    "text": f"message failed integrity check (from {msg.get('from')}), dropped",
                },
                save=True,
            )
        elif kind == "downgrade_rejected":
            self._emit(
                {
                    "kind": "event",
                    "level": "error",
                    "text": "plaintext message rejected (possible downgrade attack)",
                },
                save=True,
            )
        elif kind == "secure_session":
            trust = msg.get("trust")
            self.ready = trust != "changed"
            self.hub.publish(
                {
                    "kind": "secure",
                    "key_hash": msg.get("key_hash"),
                    "trust": trust,
                    "peer": msg.get("peer"),
                    "my_fingerprint": msg.get("my_fingerprint"),
                    "peer_fingerprint": msg.get("peer_fingerprint"),
                }
            )
            if trust == "new":
                self._emit(
                    {
                        "kind": "event",
                        "level": "info",
                        "text": f"{msg.get('peer')}: new contact, key pinned",
                    },
                    save=True,
                )
            elif trust == "changed":
                self._emit(
                    {
                        "kind": "event",
                        "level": "alarm",
                        "text": f"⚠ {msg.get('peer')}'s key CHANGED — possible "
                        "man-in-the-middle. Verify fingerprints, then Trust or Abort.",
                    },
                    save=True,
                )
        elif kind == "held_untrusted":
            self._emit(
                {
                    "kind": "event",
                    "level": "error",
                    "text": f"message from {msg.get('from')} dropped (not shown): key changed",
                },
                save=True,
            )
        elif kind == "key_trusted":
            self.ready = True
            self._emit(
                {
                    "kind": "trusted",
                    "peer": msg.get("peer"),
                    "fingerprint": msg.get("peer_fingerprint"),
                    "text": f"{msg.get('peer')}'s new key trusted and pinned",
                },
                save=True,
            )
        elif kind == "session_aborted":
            self._emit({"kind": "event", "level": "info", "text": "session aborted"}, save=True)
            self.hub.publish({"kind": "status", "state": "aborted", "mode": self.mode})
        elif kind == "error":
            if msg.get("code") == "user_offline" and not self.ready:
                return
            self.hub.publish(
                {
                    "kind": "event",
                    "level": "error",
                    "text": f"{msg.get('code')}: {msg.get('message')}",
                }
            )
        elif kind == "disconnected":
            with self._lock:
                self.client = None  # the dropped client; send() reports offline until reconnect
                # Not ready again until the new handshake finishes (so the
                # reconnect's user_offline race stays hidden, like on first connect).
                self.ready = self.mode == "plain"
            self.hub.publish({"kind": "status", "state": "reconnecting", "mode": self.mode})
            if not self._stop:
                self.start()  # auto-reconnect; keys persist so pins/alarms still apply


_PAGE = Path(__file__).with_name("webclient_page.html").read_text(encoding="utf-8")


class _Handler(WebHandler):
    def do_GET(self) -> None:
        if self.path == "/" or self.path.startswith("/index"):
            page = (
                _PAGE.replace("__USER__", self.app.user)
                .replace("__PEER__", self.app.peer)
                .replace("__MODE__", self.app.mode)
            )
            self.send_bytes(200, "text/html; charset=utf-8", page.encode("utf-8"))
        elif self.path == "/events":
            self.stream(self.app.hub)
        else:
            self.send_bytes(204, "text/plain", b"")

    def do_POST(self) -> None:
        if self.path not in ("/send", "/trust", "/abort", "/mode", "/reconnect"):
            self.send_bytes(404, "text/plain", b"not found")
            return
        if not self.check_origin():
            return
        body = self.read_json()
        if self.path == "/trust":
            self.send_json({"ok": self.app.trust()})
        elif self.path == "/abort":
            self.app.abort()
            self.send_json({"ok": True})
        elif self.path == "/reconnect":
            self.app.reconnect()
            self.send_json({"ok": True})
        elif self.path == "/mode":
            mode = body.get("mode")
            ok = self.app.set_mode(mode) if isinstance(mode, str) else False
            self.send_json({"ok": ok, "mode": self.app.mode}, status=200 if ok else 400)
        else:  # /send
            text = body.get("text", "")
            if not isinstance(text, str) or not text.strip():
                self.send_json({"ok": False, "reason": "empty"})
                return
            reason = self.app.send(text)
            self.send_json({"ok": reason == "ok", "reason": reason})


def start_window(app: ChatApp) -> ThreadingHTTPServer:
    """Start one participant's web server on a background thread; return it."""
    httpd = QuietThreadingHTTPServer((app.web_host, app.web_port), _Handler)
    httpd.daemon_threads = True
    httpd.app = app  # type: ignore[attr-defined]
    app.load_history()  # replay saved conversation before the live events
    app.start()
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


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
        help="e2ee: encrypt every message (default); plain: UC-1 plaintext",
    )
    parser.add_argument("--no-open", action="store_true", help="don't open a browser automatically")
    args = parser.parse_args(argv)

    for label, name in (("--user", args.user), ("--peer", args.peer)):
        if not is_valid_username(name):
            raise SystemExit(f"! {label} must be 1-20 of letters, digits, _ or -")

    app = ChatApp(args.user, args.peer, args.mode, host=args.host, port=args.port)
    app.web_host = args.host
    app.web_port = args.web_port
    try:
        from e2ee_chat.history import HistoryStore

        app.store = HistoryStore(args.user, args.peer, keys_dir=app.keys_dir)
    except Exception:  # noqa: BLE001 - history is a nice-to-have, never block the demo
        app.store = None

    httpd = start_window(app)
    url = f"http://{args.host}:{args.web_port}/"
    print(
        f"[web] {args.user}'s window at {url}  (peer: {args.peer}, relay: {args.host}:{args.port})"
    )
    if not args.no_open:
        threading.Thread(target=lambda: webbrowser.open(url), daemon=True).start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n[web] stopping")
    finally:
        app.shutdown()  # quiet: don't write 'session aborted' to history
        httpd.shutdown()
        httpd.server_close()


if __name__ == "__main__":
    main()
