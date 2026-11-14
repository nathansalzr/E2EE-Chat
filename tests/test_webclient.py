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
    assert q.get(timeout=1) == {"kind": "secure", "key_hash": "ab12cd34"}


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
