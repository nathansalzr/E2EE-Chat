"""Tests for the web-UI bridge logic (ChatApp). The HTTP/SSE plumbing is
exercised by hand; this pins the message translation and event fan-out."""

from e2ee_chat.webclient import ChatApp


def test_chat_message_becomes_a_chat_event():
    app = ChatApp("alice", "bob")
    q = app.subscribe()
    app.on_message({"type": "chat", "from": "bob", "text": "hi"})
    assert q.get(timeout=1) == {"kind": "chat", "from": "bob", "text": "hi"}


def test_secure_session_marks_ready_and_emits_key_hash():
    app = ChatApp("alice", "bob")
    q = app.subscribe()
    assert app.ready is False
    app.on_message({"type": "secure_session", "key_hash": "ab12cd34"})
    assert app.ready is True
    ev = q.get(timeout=1)
    assert ev["kind"] == "secure" and ev["key_hash"] == "ab12cd34"


def test_user_offline_is_suppressed_before_ready_but_shown_after():
    app = ChatApp("alice", "bob")
    q = app.subscribe()
    # Before the handshake completes, a user_offline is just the connect race.
    app.on_message({"type": "error", "code": "user_offline", "message": "bob is not connected"})
    assert q.empty()
    # Once the session is established, a real user_offline is worth showing.
    app.on_message({"type": "secure_session", "key_hash": "ab12"})
    q.get(timeout=1)  # the secure event
    app.on_message({"type": "error", "code": "user_offline", "message": "bob left"})
    event = q.get(timeout=1)
    assert event["kind"] == "error" and "user_offline" in event["text"]


def test_new_subscriber_replays_history():
    app = ChatApp("alice", "bob")
    app.on_message({"type": "chat", "from": "bob", "text": "earlier"})
    q = app.subscribe()  # opened a tab after the message arrived
    assert q.get(timeout=1) == {"kind": "chat", "from": "bob", "text": "earlier"}


# --- UC-4 events -----------------------------------------------------------


def test_encrypted_chat_keeps_the_lock_marker():
    app = ChatApp("alice", "bob")
    q = app.subscribe()
    app.on_message({"type": "chat", "from": "bob", "text": "hi", "encrypted": True})
    assert q.get(timeout=1) == {"kind": "chat", "from": "bob", "text": "hi", "encrypted": True}


def test_integrity_and_downgrade_become_warnings():
    app = ChatApp("alice", "bob")
    q = app.subscribe()
    app.on_message({"type": "integrity_error", "from": "bob"})
    app.on_message({"type": "downgrade_rejected", "from": "bob"})
    first, second = q.get(timeout=1), q.get(timeout=1)
    assert first["kind"] == "error" and "integrity check" in first["text"]
    assert second["kind"] == "error" and "downgrade" in second["text"]


def test_plain_mode_is_ready_immediately():
    assert ChatApp("alice", "bob", mode="plain").ready is True
    assert ChatApp("alice", "bob").ready is False


def test_plain_mode_never_shows_the_lock():
    app = ChatApp("alice", "bob", mode="plain")
    q = app.subscribe()
    app.on_message({"type": "chat", "from": "bob", "text": "hi", "encrypted": True})
    assert "encrypted" not in q.get(timeout=1)


# --- UC-5: fingerprints, key-change alarm, CSRF guard ---------------------


def test_secure_event_carries_trust_and_fingerprints():
    app = ChatApp("alice", "bob")
    q = app.subscribe()
    app.on_message(
        {
            "type": "secure_session",
            "key_hash": "ab12",
            "trust": "new",
            "peer": "bob",
            "my_fingerprint": "AAAA BBBB",
            "peer_fingerprint": "CCCC DDDD",
        }
    )
    ev = q.get(timeout=1)
    assert ev["kind"] == "secure" and ev["trust"] == "new"
    assert ev["my_fingerprint"] == "AAAA BBBB" and ev["peer_fingerprint"] == "CCCC DDDD"
    assert app.ready is True


def test_changed_key_does_not_mark_ready():
    app = ChatApp("alice", "bob")
    app.on_message({"type": "secure_session", "key_hash": "x", "trust": "changed", "peer": "bob"})
    assert app.ready is False  # sending stays blocked until the user trusts


def test_held_and_trusted_and_aborted_events():
    app = ChatApp("alice", "bob")
    q = app.subscribe()
    app.on_message({"type": "held_untrusted", "from": "bob"})
    app.on_message({"type": "key_trusted", "peer": "bob", "fingerprint": "AAAA"})
    app.on_message({"type": "session_aborted"})
    first, second, third = q.get(timeout=1), q.get(timeout=1), q.get(timeout=1)
    assert first["kind"] == "error" and "dropped" in first["text"]
    assert second["kind"] == "trusted" and app.ready is True
    assert third["kind"] == "system" and "aborted" in third["text"]


def _free_web_port():
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_csrf_and_content_type_guard_on_post(monkeypatch):
    import json
    import threading
    import urllib.error
    import urllib.request
    from http.server import ThreadingHTTPServer

    from e2ee_chat import webclient

    app = ChatApp("alice", "bob", mode="plain")
    app.host = "127.0.0.1"
    port = _free_web_port()
    app.web_port = port

    sent = []

    class FakeClient:
        def send_chat(self, to, text):
            sent.append(text)

    app.client = FakeClient()

    httpd = ThreadingHTTPServer(("127.0.0.1", port), webclient._Handler)
    httpd.app = app
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"

    def post(headers, body=b'{"text": "hi"}'):
        req = urllib.request.Request(  # noqa: S310
            base + "/send", data=body, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=2) as r:  # noqa: S310
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, None

    try:
        # a cross-site Origin is rejected
        code, _ = post({"Content-Type": "application/json", "Origin": "http://evil.example"})
        assert code == 403
        # wrong content-type (what a plain HTML form sends) is rejected
        code, _ = post({"Content-Type": "application/x-www-form-urlencoded"})
        assert code == 403
        # same-origin json is accepted
        code, res = post({"Content-Type": "application/json", "Origin": base})
        assert code == 200 and res["ok"] is True
        assert sent == ["hi"]
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_trusted_event_carries_peer_fingerprint():
    app = ChatApp("alice", "bob")
    q = app.subscribe()
    app.on_message({"type": "key_trusted", "peer": "bob", "peer_fingerprint": "AAAA BBBB"})
    ev = q.get(timeout=1)
    assert ev["kind"] == "trusted" and ev["fingerprint"] == "AAAA BBBB"  # was always None before


def test_csrf_accepts_localhost_and_127_as_same_loopback_origin(monkeypatch):
    import json
    import threading
    import urllib.request
    from http.server import ThreadingHTTPServer

    from e2ee_chat import webclient

    app = ChatApp("alice", "bob", mode="plain")
    app.host = "127.0.0.1"
    port = _free_web_port()
    app.web_port = port

    class FakeClient:
        def send_chat(self, to, text):
            pass

    app.client = FakeClient()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), webclient._Handler)
    httpd.app = app
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    def post(origin):
        req = urllib.request.Request(  # noqa: S310
            f"http://127.0.0.1:{port}/send",
            data=b'{"text": "hi"}',
            headers={"Content-Type": "application/json", "Origin": origin},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=2) as r:  # noqa: S310
            return json.loads(r.read())["ok"]

    try:
        # the server binds 127.0.0.1 but the user may type either loopback name
        assert post(f"http://localhost:{port}") is True
        assert post(f"http://127.0.0.1:{port}") is True
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_webclient_main_rejects_bad_username():
    import pytest

    from e2ee_chat import webclient

    with pytest.raises(SystemExit):
        webclient.main(["--user", "alice", "--peer", "../evil", "--web-port", "0"])
