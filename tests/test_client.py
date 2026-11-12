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


def test_main_sends_typed_lines_to_peer(server, make_client, monkeypatch):
    _, bob_inbox = make_client("bob")
    lines = iter(["hello bob", "/quit"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(lines))
    main(["--port", str(server.port), "--user", "alice", "--peer", "bob"])
    msg = bob_inbox.get(timeout=1)
    assert (msg["from"], msg["text"]) == ("alice", "hello bob")


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
