"""Tests for the plaintext CLI client (T5, T7).

These run a real ChatServer on a free port. Each client puts whatever it
receives into a queue, so a test can wait for a message with a timeout.
"""

import queue
import socket
import struct
import threading
import time

import pytest

from e2ee_chat.client import ChatClient, RegistrationError, format_message, main
from e2ee_chat.protocol import recv_msg, send_msg
from e2ee_chat.server import ChatServer


@pytest.fixture
def server():
    srv = ChatServer(port=0)
    srv.start()
    yield srv
    srv.stop()


@pytest.fixture
def make_client(server):
    """Factory: make_client("alice") returns (client, inbox) and cleans up after the test."""
    made = []

    def _make(name: str):
        inbox: queue.Queue = queue.Queue()
        client = ChatClient("127.0.0.1", server.port, name, on_message=inbox.put)
        client.connect()
        made.append(client)
        return client, inbox

    yield _make
    for client in made:
        client.close()


def free_port() -> int:
    """A port with nothing listening on it."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_two_clients_exchange_messages(make_client):
    alice, _ = make_client("alice")
    _, bob_inbox = make_client("bob")
    alice.send_chat("bob", "hi")
    msg = bob_inbox.get(timeout=1)  # US-1 AC2: arrives within 1 second
    assert (msg["type"], msg["from"], msg["text"]) == ("chat", "alice", "hi")


def test_connect_when_server_down_raises_connection_error():
    client = ChatClient("127.0.0.1", free_port(), "alice", on_message=lambda m: None)
    with pytest.raises(ConnectionError, match="cannot reach server"):
        client.connect()


def test_duplicate_username_raises_registration_error(server, make_client):
    make_client("alice")
    twin = ChatClient("127.0.0.1", server.port, "alice", on_message=lambda m: None)
    with pytest.raises(RegistrationError) as err:
        twin.connect()
    assert err.value.code == "username_taken"


def test_server_stop_triggers_disconnected_callback(server, make_client):
    _, inbox = make_client("alice")
    server.stop()
    assert inbox.get(timeout=2) == {"type": "disconnected"}


def test_offline_peer_error_is_delivered(make_client):
    alice, inbox = make_client("alice")
    alice.send_chat("carol", "anyone there?")
    msg = inbox.get(timeout=1)
    assert (msg["type"], msg["code"]) == ("error", "user_offline")


def test_close_is_idempotent(make_client):
    alice, _ = make_client("alice")
    alice.close()
    alice.close()


def test_format_message_chat_error_disconnected():
    assert format_message({"type": "chat", "from": "alice", "to": "bob", "text": "hi"}) == (
        "[alice] hi"
    )
    assert format_message(
        {"type": "error", "code": "user_offline", "message": "bob is not connected"}
    ) == ("! user_offline: bob is not connected")
    assert format_message({"type": "disconnected"}) == "! connection to server lost"


def test_main_exits_cleanly_when_server_down(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--port", str(free_port()), "--user", "alice", "--peer", "bob"])
    assert exit_info.value.code == 1
    output = capsys.readouterr()
    assert "cannot reach server" in output.out + output.err


def test_main_sends_typed_lines_to_peer(server, monkeypatch, tmp_path):
    # UC-3: both ends run the handshake, so bob is a secure client too.
    bob_inbox: queue.Queue = queue.Queue()
    bob = ChatClient(
        "127.0.0.1",
        server.port,
        "bob",
        on_message=bob_inbox.put,
        peer="alice",
        keys_dir=str(tmp_path),
    )
    bob.connect()
    lines = iter(["hello bob", "/quit"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(lines))
    monkeypatch.chdir(tmp_path)  # keep alice's keys/ out of the repo
    main(["--port", str(server.port), "--user", "alice", "--peer", "bob"])
    got = None
    deadline = time.time() + 2
    while time.time() < deadline:
        msg = bob_inbox.get(timeout=2)
        if msg.get("type") == "chat":  # skip the secure_session handshake event
            got = msg
            break
    assert got is not None and (got["from"], got["text"]) == ("alice", "hello bob")
    bob.close()


def test_format_message_strips_terminal_control_codes():
    # A peer could send ANSI escape codes to recolor or rewrite our terminal.
    msg = {"type": "chat", "from": "alice", "to": "bob", "text": "\x1b[2Jgotcha\x07"}
    assert format_message(msg) == "[alice] ?[2Jgotcha?"


def fake_server(script):
    """Start a one-connection fake server that runs script(sock) after accepting.

    Lets a test play a hostile server (or a MITM) without touching ChatServer.
    """
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()

    def run():
        conn, _ = listener.accept()
        with conn:
            script(conn)
        listener.close()

    threading.Thread(target=run, daemon=True).start()
    return listener.getsockname()[1]


def test_bad_frame_from_server_is_skipped_not_fatal():
    def script(conn):
        recv_msg(conn)  # the register message
        send_msg(conn, {"type": "registered", "username": "alice"})
        nested = b'{"type": "chat", "x": ' + b"[" * 32_000 + b"]" * 32_000 + b"}"
        conn.sendall(struct.pack("!I", len(nested)) + nested)
        send_msg(conn, {"type": "chat", "from": "bob", "to": "alice", "text": "after"})
        time.sleep(1)

    inbox: queue.Queue = queue.Queue()
    client = ChatClient("127.0.0.1", fake_server(script), "alice", on_message=inbox.put)
    client.connect()
    msg = inbox.get(timeout=2)
    assert (msg["type"], msg["text"]) == ("chat", "after")  # not "disconnected"
    client.close()


def test_registration_error_text_is_sanitized():
    def script(conn):
        recv_msg(conn)
        send_msg(conn, {"type": "error", "code": "username_taken", "message": "\x1b[2Jtaken"})

    client = ChatClient("127.0.0.1", fake_server(script), "alice", on_message=lambda m: None)
    with pytest.raises(RegistrationError) as err:
        client.connect()
    assert "\x1b" not in str(err.value)
    assert err.value.message == "?[2Jtaken"


def test_main_ctrl_c_during_connect_exits_without_traceback(monkeypatch, capsys):
    def interrupted(self):
        raise KeyboardInterrupt

    monkeypatch.setattr(ChatClient, "connect", interrupted)
    with pytest.raises(SystemExit) as exit_info:
        main(["--user", "alice", "--peer", "bob"])
    assert exit_info.value.code == 1
    assert "Traceback" not in capsys.readouterr().err


# --- UC-3 handshake (Task 4) ---------------------------------------------

from e2ee_chat.client import HANDSHAKE_TIMEOUT_SECONDS, SessionNotReady  # noqa: E402
from e2ee_chat.crypto_utils import load_or_create_keypair, public_key_b64  # noqa: E402


def make_secure(server, tmp_path, name, peer, keep):
    inbox: queue.Queue = queue.Queue()
    c = ChatClient(
        "127.0.0.1", server.port, name, on_message=inbox.put, peer=peer, keys_dir=str(tmp_path)
    )
    c.connect()
    keep.append(c)
    return c, inbox


@pytest.fixture
def secure(server, tmp_path):
    made = []
    yield lambda name, peer: make_secure(server, tmp_path, name, peer, made)
    for c in made:
        c.close()


def test_handshake_same_key_alice_first(secure):
    alice, _ = secure("alice", "bob")
    bob, _ = secure("bob", "alice")
    assert alice.session_ready.wait(2) and bob.session_ready.wait(2)
    assert alice.session_key is not None
    assert alice.session_key == bob.session_key


def test_handshake_same_key_bob_first(secure):
    bob, _ = secure("bob", "alice")
    alice, _ = secure("alice", "bob")
    assert alice.session_ready.wait(2) and bob.session_ready.wait(2)
    assert alice.session_key == bob.session_key is not None


def test_chat_blocked_until_session_ready(secure):
    alice, _ = secure("alice", "bob")  # bob never connects -> never ready
    assert not alice.session_ready.is_set()
    with pytest.raises(SessionNotReady):
        alice.send_chat("bob", "too early")


def test_duplicate_pubkey_is_ignored(secure):
    alice, _ = secure("alice", "bob")
    bob, _ = secure("bob", "alice")
    assert alice.session_ready.wait(2)
    established = alice.session_key
    alice._handle_pubkey({"type": "pubkey", "from": "bob", "key": alice.peer_public})  # same key
    assert alice.session_key is established  # not re-derived


def test_reconnect_with_new_key_rederives(secure, tmp_path):
    alice, _ = secure("alice", "bob")
    bob, _ = secure("bob", "alice")
    assert alice.session_ready.wait(2)
    first = alice.session_key
    new_peer_key = public_key_b64(load_or_create_keypair("bob_v2", keys_dir=str(tmp_path)))
    alice._handle_pubkey({"type": "pubkey", "from": "bob", "key": new_peer_key})
    assert alice.session_ready.is_set()
    assert alice.session_key != first  # re-derived on the changed key


def test_malformed_pubkey_does_not_crash_client(secure, tmp_path):
    alice, _ = secure("alice", "bob")  # not ready (bob offline)
    alice._handle_pubkey({"type": "pubkey", "from": "bob", "key": "!!!not-valid-base64!!!"})
    assert not alice.session_ready.is_set()  # survived, still not ready
    good = public_key_b64(load_or_create_keypair("bob", keys_dir=str(tmp_path)))
    alice._handle_pubkey({"type": "pubkey", "from": "bob", "key": good})
    assert alice.session_ready.is_set()  # a good key afterwards still works


def test_reconnect_with_same_key_both_converge(secure, server, tmp_path):
    # Finding 1: a client reconnecting with its SAME persisted key must converge.
    alice, _ = secure("alice", "bob")
    bob, _ = secure("bob", "alice")
    assert alice.session_ready.wait(2) and bob.session_ready.wait(2)

    bob.close()
    deadline = time.time() + 2
    while "bob" in server.online_users() and time.time() < deadline:
        time.sleep(0.02)

    bob2_inbox: queue.Queue = queue.Queue()
    bob2 = ChatClient(
        "127.0.0.1",
        server.port,
        "bob",
        on_message=bob2_inbox.put,
        peer="alice",
        keys_dir=str(tmp_path),
    )
    bob2.connect()
    try:
        assert bob2.session_ready.wait(2)  # reconnecting side must establish
        assert bob2.session_key == alice.session_key
    finally:
        bob2.close()


def test_pubkey_from_a_stranger_is_ignored(secure):
    # Finding 2: a third client must not be able to overwrite an established session.
    alice, _ = secure("alice", "bob")
    bob, _ = secure("bob", "alice")
    assert alice.session_ready.wait(2) and bob.session_ready.wait(2)
    established = alice.session_key

    secure("carol", "alice")  # carol tries to hand alice a key
    time.sleep(0.3)
    assert alice.session_key == established  # unchanged: alice only trusts bob


def test_main_exits_cleanly_on_corrupt_key_file(server, monkeypatch, tmp_path, capsys):
    # Finding 4: a truncated keys/<user>.key must not crash with a traceback.
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "alice.key").write_bytes(b"too short to be a key")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as exit_info:
        main(["--port", str(server.port), "--user", "alice", "--peer", "bob"])
    assert exit_info.value.code == 1
    err = capsys.readouterr().err
    assert "key file" in err.lower()
    assert "Traceback" not in err


def test_main_ctrl_c_during_handshake_exits_cleanly(server, monkeypatch, tmp_path, capsys):
    # Finding 5: Ctrl+C while waiting for the handshake exits cleanly (no traceback).
    bob = ChatClient(
        "127.0.0.1",
        server.port,
        "bob",
        on_message=lambda m: None,
        peer="alice",
        keys_dir=str(tmp_path),
    )
    bob.connect()
    monkeypatch.chdir(tmp_path)

    # Raise only on the handshake wait (keyed by its timeout), not on the
    # internal Event.wait that Thread.start() uses.
    real_wait = threading.Event.wait

    def boom(self, timeout=None):
        if timeout == HANDSHAKE_TIMEOUT_SECONDS:
            raise KeyboardInterrupt
        return real_wait(self, timeout)

    monkeypatch.setattr(threading.Event, "wait", boom)
    main(["--port", str(server.port), "--user", "alice", "--peer", "bob"])  # must not raise
    assert "Traceback" not in capsys.readouterr().err
    bob.close()
