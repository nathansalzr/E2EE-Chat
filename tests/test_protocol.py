"""Tests for the shared framing helpers (T3).

Each test uses socket.socketpair(): two connected sockets in one process,
so we can test real socket behavior without a server.
"""

import socket
import struct
import threading

import pytest

from e2ee_chat.protocol import (
    MAX_FRAME,
    BadMessage,
    ProtocolError,
    encode_frame,
    is_valid_username,
    recv_frame,
    recv_msg,
    send_msg,
)

CHAT = {"type": "chat", "to": "bob", "text": "hi"}


@pytest.fixture
def pair():
    a, b = socket.socketpair()
    a.settimeout(2)
    b.settimeout(2)
    yield a, b
    a.close()
    b.close()


def raw_frame(body: bytes) -> bytes:
    return struct.pack("!I", len(body)) + body


def test_round_trip_simple_message(pair):
    a, b = pair
    send_msg(a, CHAT)
    assert recv_msg(b) == CHAT


def test_round_trip_unicode_text(pair):
    a, b = pair
    msg = {"type": "chat", "to": "bob", "text": "héllo 👋"}
    send_msg(a, msg)
    assert recv_msg(b) == msg


def test_recv_handles_split_frame(pair):
    a, b = pair
    data = encode_frame(CHAT)

    def drip():
        for i in range(len(data)):
            a.sendall(data[i : i + 1])

    writer = threading.Thread(target=drip)
    writer.start()
    assert recv_msg(b) == CHAT
    writer.join()


def test_two_frames_back_to_back(pair):
    a, b = pair
    second = {"type": "chat", "to": "bob", "text": "second"}
    a.sendall(encode_frame(CHAT) + encode_frame(second))
    assert recv_msg(b) == CHAT
    assert recv_msg(b) == second


def test_clean_close_returns_none(pair):
    a, b = pair
    a.close()
    assert recv_msg(b) is None


def test_truncated_frame_raises(pair):
    a, b = pair
    a.sendall(struct.pack("!I", 10) + b"abc")
    a.close()
    with pytest.raises(ProtocolError):
        recv_msg(b)


def test_truncated_length_prefix_raises(pair):
    a, b = pair
    a.sendall(b"\x00\x00")
    a.close()
    with pytest.raises(ProtocolError):
        recv_msg(b)


def test_oversized_length_raises(pair):
    a, b = pair
    a.sendall(struct.pack("!I", MAX_FRAME + 1))
    with pytest.raises(ProtocolError) as err:
        recv_frame(b)
    assert not isinstance(err.value, BadMessage)


def test_recv_frame_returns_raw_body(pair):
    a, b = pair
    a.sendall(raw_frame(b'{"type": "chat"}'))
    assert recv_frame(b) == b'{"type": "chat"}'


@pytest.mark.parametrize(
    "body",
    [b"{not json", b"[1, 2]", b"{}", b'{"type": 5}', b"\xff\xfe"],
    ids=["invalid_json", "non_object", "missing_type", "type_not_string", "bad_utf8"],
)
def test_bad_content_raises_bad_message(pair, body):
    a, b = pair
    a.sendall(raw_frame(body))
    with pytest.raises(BadMessage):
        recv_msg(b)


def test_encode_rejects_oversized_message():
    with pytest.raises(ProtocolError):
        encode_frame({"type": "chat", "to": "bob", "text": "x" * 70_000})


@pytest.mark.parametrize("name", ["alice", "Bob_2", "a-b", "x" * 20])
def test_valid_usernames(name):
    assert is_valid_username(name)


@pytest.mark.parametrize("name", ["", "x" * 21, "al ice", "bob!", None, 5])
def test_invalid_usernames(name):
    assert not is_valid_username(name)


# Inputs a hostile sender (like the UC-2 MITM) can put inside a perfectly valid frame.
HOSTILE_BODIES = {
    "deep_nesting": b'{"type": "chat", "x": ' + b"[" * 32_000 + b"]" * 32_000 + b"}",
    "huge_integer": b'{"type": "chat", "n": ' + b"9" * 5000 + b"}",
    "lone_surrogate": rb'{"type": "chat", "to": "bob", "text": "\ud800"}',
}


def send_in_background(sock: socket.socket, data: bytes) -> threading.Thread:
    """Send from another thread so the reader can drain the socket at the same time.

    Needed for big frames: on macOS, socketpair() buffers only about 8 KB, so a
    64 KB sendall() blocks until someone reads, and in a single thread nobody can.
    """
    writer = threading.Thread(target=sock.sendall, args=(data,), daemon=True)
    writer.start()
    return writer


def test_big_frame_is_received_whole(pair):
    """A frame larger than the OS socket buffer still arrives intact."""
    a, b = pair
    msg = {"type": "chat", "to": "bob", "text": "x" * 60_000}
    writer = send_in_background(a, encode_frame(msg))
    assert recv_msg(b) == msg
    writer.join(timeout=2)


@pytest.mark.parametrize("body", HOSTILE_BODIES.values(), ids=HOSTILE_BODIES.keys())
def test_hostile_content_raises_bad_message(pair, body):
    a, b = pair
    writer = send_in_background(a, raw_frame(body))  # deep_nesting is ~64 KB
    with pytest.raises(BadMessage):
        recv_msg(b)
    writer.join(timeout=2)
