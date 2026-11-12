"""Tests for the relay server (T4, T7).

Every test starts a real ChatServer on a free port (port=0) and talks to it
over real sockets, the same way client.py will.
"""

import socket
import struct
import time

import pytest

from e2ee_chat.protocol import MAX_FRAME, recv_msg, send_msg
from e2ee_chat.server import ChatServer


@pytest.fixture
def server():
    srv = ChatServer(port=0)
    srv.start()
    yield srv
    srv.stop()


def open_socket(server: ChatServer) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", server.port), timeout=2)
    sock.settimeout(2)
    return sock


def connect(server: ChatServer, name: str) -> socket.socket:
    """Open a connection and register name, checking the server said yes."""
    sock = open_socket(server)
    send_msg(sock, {"type": "register", "username": name})
    assert recv_msg(sock) == {"type": "registered", "username": name}
    return sock


def wait_until(condition, timeout: float = 1.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.02)
    return False


def test_register_and_relay_chat(server):
    alice, bob = connect(server, "alice"), connect(server, "bob")
    send_msg(alice, {"type": "chat", "to": "bob", "text": "hi"})
    assert recv_msg(bob) == {"type": "chat", "from": "alice", "to": "bob", "text": "hi"}


def test_relay_works_both_ways(server):
    alice, bob = connect(server, "alice"), connect(server, "bob")
    send_msg(alice, {"type": "chat", "to": "bob", "text": "ping"})
    assert recv_msg(bob)["text"] == "ping"
    send_msg(bob, {"type": "chat", "to": "alice", "text": "pong"})
    reply = recv_msg(alice)
    assert reply["from"] == "bob"
    assert reply["text"] == "pong"


def test_server_overwrites_from_field(server):
    alice, bob = connect(server, "alice"), connect(server, "bob")
    send_msg(alice, {"type": "chat", "from": "bob", "to": "bob", "text": "it's me, bob"})
    assert recv_msg(bob)["from"] == "alice"


def test_duplicate_username_rejected(server):
    first = connect(server, "alice")  # keep a reference so the socket stays open
    second = open_socket(server)
    send_msg(second, {"type": "register", "username": "alice"})
    reply = recv_msg(second)
    assert reply["type"] == "error"
    assert reply["code"] == "username_taken"
    # same connection can try again with another name
    send_msg(second, {"type": "register", "username": "alice2"})
    assert recv_msg(second) == {"type": "registered", "username": "alice2"}
    first.close()


def test_invalid_username_rejected(server):
    sock = open_socket(server)
    send_msg(sock, {"type": "register", "username": "al ice"})
    reply = recv_msg(sock)
    assert (reply["type"], reply["code"]) == ("error", "invalid_username")


def test_chat_before_register(server):
    sock = open_socket(server)
    send_msg(sock, {"type": "chat", "to": "bob", "text": "hi"})
    assert recv_msg(sock)["code"] == "not_registered"


def test_recipient_offline(server):
    alice = connect(server, "alice")
    send_msg(alice, {"type": "chat", "to": "carol", "text": "hi"})
    reply = recv_msg(alice)
    assert (reply["type"], reply["code"]) == ("error", "user_offline")


def test_malformed_json_gets_error_and_connection_survives(server):
    alice, bob = connect(server, "alice"), connect(server, "bob")
    body = b"{not json"
    alice.sendall(struct.pack("!I", len(body)) + body)
    assert recv_msg(alice)["code"] == "bad_message"
    send_msg(alice, {"type": "chat", "to": "bob", "text": "still here"})
    assert recv_msg(bob)["text"] == "still here"


def test_unknown_type_gets_bad_message(server):
    alice = connect(server, "alice")
    send_msg(alice, {"type": "dance"})
    assert recv_msg(alice)["code"] == "bad_message"


def test_relay_without_to_gets_bad_message(server):
    alice = connect(server, "alice")
    send_msg(alice, {"type": "chat", "text": "to nobody"})
    assert recv_msg(alice)["code"] == "bad_message"


def test_oversized_frame_drops_only_that_client(server):
    alice, bob = connect(server, "alice"), connect(server, "bob")
    attacker = open_socket(server)
    attacker.sendall(struct.pack("!I", MAX_FRAME + 1))
    assert attacker.recv(1) == b""  # server hung up on it
    send_msg(alice, {"type": "chat", "to": "bob", "text": "unaffected"})
    assert recv_msg(bob)["text"] == "unaffected"


def test_disconnect_frees_username(server):
    bob = connect(server, "bob")
    bob.close()
    assert wait_until(lambda: "bob" not in server.online_users())
    connect(server, "bob")  # the name can be used again


@pytest.mark.parametrize(
    "msg",
    [
        {"type": "pubkey", "to": "bob", "key": "AAAA"},
        {"type": "encrypted", "to": "bob", "nonce": "BBBB", "ciphertext": "CCCC"},
    ],
)
def test_pubkey_and_encrypted_are_relayed(server, msg):
    alice, bob = connect(server, "alice"), connect(server, "bob")
    send_msg(alice, msg)
    assert recv_msg(bob) == {**msg, "from": "alice"}


def test_stop_is_idempotent(server):
    server.stop()
    server.stop()


def test_main_rejects_out_of_range_port(capsys):
    from e2ee_chat.server import main

    with pytest.raises(SystemExit) as exit_info:
        main(["--port", "99999"])
    assert exit_info.value.code == 2
    assert "port must be 0-65535" in capsys.readouterr().err


def test_lone_surrogate_gets_bad_message_and_connection_survives(server):
    alice, bob = connect(server, "alice"), connect(server, "bob")
    body = rb'{"type": "chat", "to": "bob", "text": "\ud800"}'  # JSON escape for a lone surrogate
    alice.sendall(struct.pack("!I", len(body)) + body)
    assert recv_msg(alice)["code"] == "bad_message"
    send_msg(alice, {"type": "chat", "to": "bob", "text": "still here"})
    assert recv_msg(bob)["text"] == "still here"
