"""Tests for the web-UI bridge (ChatApp): translating ChatClient messages into
browser events, mode/ready state, history replay, and the CSRF guard. The
HTTP/SSE plumbing is exercised against a real local server where needed."""

import json
import queue
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from e2ee_chat import webclient
from e2ee_chat.webclient import ChatApp


def drain(q: queue.Queue) -> list[dict]:
    out = []
    try:
        while True:
            out.append(q.get_nowait())
    except queue.Empty:
        return out


def events(app, msg) -> list[dict]:
    """Subscribe, deliver one ChatClient message, return what reached the UI.

    Clears the hub first so repeated calls on one app don't replay earlier events.
    """
    app.hub.clear()
    q = app.hub.subscribe()
    app.on_message(msg)
    return drain(q)


# --- message translation ---------------------------------------------------


def test_chat_becomes_a_chat_event_with_lock_in_e2ee():
    app = ChatApp("alice", "bob")  # e2ee
    (ev,) = events(app, {"type": "chat", "from": "bob", "text": "hi", "encrypted": True})
    assert ev == {"kind": "chat", "from": "bob", "text": "hi", "encrypted": True}


def test_plain_mode_chat_has_no_lock():
    app = ChatApp("alice", "bob", mode="plain")
    (ev,) = events(app, {"type": "chat", "from": "bob", "text": "hi", "encrypted": True})
    assert ev["kind"] == "chat" and "encrypted" not in ev  # flag ignored in plain mode


def test_integrity_and_downgrade_become_error_events():
    app = ChatApp("alice", "bob")
    (a,) = events(app, {"type": "integrity_error", "from": "bob"})
    (b,) = events(app, {"type": "downgrade_rejected", "from": "bob"})
    assert a["kind"] == "event" and a["level"] == "error" and "integrity" in a["text"]
    assert b["kind"] == "event" and b["level"] == "error" and "downgrade" in b["text"]


def test_secure_event_carries_trust_and_fingerprints():
    app = ChatApp("alice", "bob")
    evs = events(
        app,
        {
            "type": "secure_session",
            "key_hash": "ab12",
            "trust": "new",
            "peer": "bob",
            "my_fingerprint": "AAAA BBBB",
            "peer_fingerprint": "CCCC DDDD",
        },
    )
    secure = next(e for e in evs if e["kind"] == "secure")
    assert secure["trust"] == "new"
    assert secure["my_fingerprint"] == "AAAA BBBB" and secure["peer_fingerprint"] == "CCCC DDDD"
    assert app.ready is True  # a new/pinned key is ready to chat
    assert any(e["kind"] == "event" and "new contact" in e["text"] for e in evs)


def test_changed_key_blocks_and_alarms():
    app = ChatApp("alice", "bob")
    evs = events(
        app, {"type": "secure_session", "key_hash": "x", "trust": "changed", "peer": "bob"}
    )
    assert app.ready is False  # sending stays blocked until trusted
    assert any(
        e["kind"] == "event" and e["level"] == "alarm" and "CHANGED" in e["text"] for e in evs
    )
    assert any(e["kind"] == "secure" and e["trust"] == "changed" for e in evs)


def test_held_trusted_and_aborted():
    app = ChatApp("alice", "bob")
    (held,) = events(app, {"type": "held_untrusted", "from": "bob"})
    assert held["kind"] == "event" and held["level"] == "error" and "dropped" in held["text"]

    trusted = events(app, {"type": "key_trusted", "peer": "bob", "peer_fingerprint": "AAAA"})
    t = next(e for e in trusted if e["kind"] == "trusted")
    assert t["fingerprint"] == "AAAA" and app.ready is True

    aborted = events(app, {"type": "session_aborted"})
    assert any(e["kind"] == "event" and "aborted" in e["text"] for e in aborted)
    assert any(e["kind"] == "status" and e["state"] == "aborted" for e in aborted)


def test_user_offline_suppressed_until_ready():
    app = ChatApp("alice", "bob")  # not ready yet (e2ee, no handshake)
    assert events(app, {"type": "error", "code": "user_offline", "message": "bob offline"}) == []


def test_disconnected_sets_reconnecting_status():
    app = ChatApp("alice", "bob")
    app._stop = True  # don't actually spawn a reconnect thread in the test
    evs = events(app, {"type": "disconnected"})
    assert any(e["kind"] == "status" and e["state"] == "reconnecting" for e in evs)


def test_ready_defaults_by_mode():
    assert ChatApp("alice", "bob", mode="plain").ready is True
    assert ChatApp("alice", "bob").ready is False


# --- history replay --------------------------------------------------------


class _FakeStore:
    def __init__(self, saved):
        self.saved = saved
        self.appended = []

    def load(self):
        return list(self.saved)

    def append(self, event):
        self.appended.append(event)


def test_load_history_replays_as_earlier():
    app = ChatApp("alice", "bob")
    app.store = _FakeStore(
        [
            {"kind": "chat", "from": "bob", "text": "yesterday"},
            {"kind": "event", "level": "alarm", "text": "bob's key CHANGED"},
        ]
    )
    q = app.hub.subscribe()
    app.load_history()
    out = drain(q)
    assert all(e.get("earlier") for e in out)
    assert out[0]["text"] == "yesterday" and "CHANGED" in out[1]["text"]


def test_messages_are_saved_to_history():
    app = ChatApp("alice", "bob")
    app.store = _FakeStore([])
    app.on_message({"type": "chat", "from": "bob", "text": "save me", "encrypted": True})
    assert app.store.appended[0]["text"] == "save me"


# --- CSRF guard against a real local server --------------------------------


def _free_port():
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _serve(app):
    app.web_host = "127.0.0.1"
    app.web_port = _free_port()
    httpd = ThreadingHTTPServer(("127.0.0.1", app.web_port), webclient._Handler)
    httpd.app = app
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{app.web_port}"


def _post(url, headers, body=b'{"text": "hi"}'):
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=2) as r:  # noqa: S310
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, None


def test_csrf_guard_on_send():
    app = ChatApp("alice", "bob", mode="plain")
    sent = []
    app.send = lambda text: sent.append(text) or "ok"  # type: ignore[assignment]
    httpd, base = _serve(app)
    try:
        assert (
            _post(
                base + "/send",
                {"Content-Type": "application/json", "Origin": "http://evil.example"},
            )[0]
            == 403
        )
        form = {"Content-Type": "application/x-www-form-urlencoded"}
        assert _post(base + "/send", form)[0] == 403
        assert _post(base + "/send", {"Content-Type": "application/json", "Origin": base})[1]["ok"]
        local = base.replace("127.0.0.1", "localhost")
        assert _post(base + "/send", {"Content-Type": "application/json", "Origin": local})[1]["ok"]
        assert sent == ["hi", "hi"]
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_main_rejects_bad_username():
    import pytest

    with pytest.raises(SystemExit):
        webclient.main(["--user", "alice", "--peer", "../evil", "--web-port", "0"])


def test_quiet_server_hides_client_disconnect_tracebacks(capsys):
    from http.server import BaseHTTPRequestHandler

    from e2ee_chat.webutil import QuietThreadingHTTPServer

    srv = QuietThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    try:
        try:
            raise ConnectionAbortedError("browser closed the SSE stream")
        except ConnectionError:
            srv.handle_error(None, ("127.0.0.1", 0))
    finally:
        srv.server_close()
    assert "Traceback" not in capsys.readouterr().err


# --- review fixes ----------------------------------------------------------


def _wait_until(pred, timeout=5.0):
    import time

    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.05)
    return False


def test_corrupt_key_file_does_not_freeze_the_window(tmp_path):
    from e2ee_chat.server import ChatServer

    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "alice.key").write_bytes(b"too short to be a key")
    server = ChatServer(port=0)
    server.start()
    app = ChatApp("alice", "bob", mode="e2ee", port=server.port, keys_dir=str(keys))
    q = app.hub.subscribe()
    try:
        app.start()
        # the worker gives up cleanly instead of latching _connecting
        assert _wait_until(lambda: not app._connecting)
        assert any("key file" in e.get("text", "") for e in drain(q))
        # and the window can still be used in plain mode
        assert app.set_mode("plain")
        assert _wait_until(lambda: app.client is not None)
    finally:
        app.shutdown()
        server.stop()


def test_shutdown_writes_nothing_to_history():
    app = ChatApp("alice", "bob")
    app.store = _FakeStore([])

    class _Client:
        def close(self):
            pass

    app.client = _Client()
    app.shutdown()
    assert app.store.appended == []  # a normal stop isn't a "session aborted"


def test_abort_mid_reconnect_still_shows_reconnect_button():
    app = ChatApp("alice", "bob")  # no client yet
    q = app.hub.subscribe()
    app.abort()
    assert any(e["kind"] == "status" and e["state"] == "aborted" for e in drain(q))


def test_drop_resets_ready():
    app = ChatApp("alice", "bob")
    app.ready = True  # session was up
    app._stop = True  # don't spawn a reconnect worker in the test
    app.on_message({"type": "disconnected"})
    assert app.ready is False


def test_send_label_follows_the_client_that_sent():
    app = ChatApp("alice", "bob")  # window says e2ee...
    app.store = _FakeStore([])

    class _PlainClient:  # ...but the live client is a plain one
        secure = False

        def send_chat(self, to, text):
            pass

    app.client = _PlainClient()
    assert app.send("hi") == "ok"
    assert "encrypted" not in app.store.appended[0]  # no false 🔒


def test_web_server_will_not_share_a_busy_port():
    import socket

    import pytest

    from e2ee_chat.webutil import QuietThreadingHTTPServer

    squatter = socket.socket()
    squatter.bind(("127.0.0.1", 0))
    squatter.listen()
    port = squatter.getsockname()[1]
    try:
        with pytest.raises(OSError):
            QuietThreadingHTTPServer(("127.0.0.1", port), webclient._Handler)
    finally:
        squatter.close()
