"""Shared message framing for the server, the client and the MITM (T3).

TCP delivers a stream of bytes, not separate messages: one send can arrive
in pieces, and two sends can arrive glued together. So every message goes
over the wire as a frame: a 4-byte length, then that many bytes of JSON.
See docs/protocol.md for the full message catalog.
"""

import argparse
import json
import re
import socket
import struct
import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM 

DEFAULT_PORT = 5050  # not 5000: macOS uses that port for AirPlay
MAX_FRAME = 65_536  # biggest body we accept, so a bad length can't eat all memory

# Message types the server forwards by "to" without looking inside them.
# pubkey and encrypted are reserved for UC-3 and UC-4.
RELAY_TYPES = frozenset({"chat", "pubkey", "encrypted"})

USERNAME_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,20}")

_LENGTH = struct.Struct("!I")  # 4-byte unsigned int, network (big-endian) byte order


class ProtocolError(Exception):
    """The byte stream is broken (truncated or oversized frame). Close the connection."""


class BadMessage(ProtocolError):
    """The frame arrived fine but its content isn't a valid message.

    The connection can stay open; the server answers with a bad_message error.
    Because this is a subclass of ProtocolError, always catch BadMessage *first*.
    """


class MessageTooLarge(ProtocolError):
    """We tried to send a message bigger than MAX_FRAME. Nothing was sent."""


def is_valid_username(name: object) -> bool:
    """Return True if name follows the username rule in docs/protocol.md."""
    return isinstance(name, str) and USERNAME_PATTERN.fullmatch(name) is not None


def port_number(text: str) -> int:
    """argparse type for --port: a whole number from 0 to 65535 (0 = any free port)."""
    try:
        port = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number") from None
    if not 0 <= port <= 65_535:
        raise argparse.ArgumentTypeError("port must be 0-65535")
    return port


def encode_frame(msg: dict) -> bytes:
    """Turn a message dict into the bytes we put on the wire."""
    body = json.dumps(msg, ensure_ascii=False).encode("utf-8")
    if len(body) > MAX_FRAME:
        raise MessageTooLarge(f"message is {len(body)} bytes; the limit is {MAX_FRAME}")
    return _LENGTH.pack(len(body)) + body


def send_msg(sock: socket.socket, msg: dict) -> None:
    """Send one message. sendall keeps going until every byte is out."""
    sock.sendall(encode_frame(msg))

def encrypt_text(plain: str, key: bytes) -> str:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plain.encode("utf-8"), associated_data = None)
    payload = nonce + ciphertext
    return base64.b64encode(payload).decode("utf-8")


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    """Read exactly count bytes, looping because recv may return fewer.

    Returns fewer bytes only if the other side closed the connection.
    """
    chunks = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:  # the other side closed the connection
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_frame(sock: socket.socket) -> bytes | None:
    """Read one frame and return its raw body.

    Returns None if the connection closed cleanly between frames.
    Raises ProtocolError if it closed mid-frame or the length is too big.
    """
    header = _recv_exact(sock, _LENGTH.size)
    if not header:
        return None
    if len(header) < _LENGTH.size:
        raise ProtocolError("connection closed in the middle of a length prefix")

    (length,) = _LENGTH.unpack(header)
    if length > MAX_FRAME:  # check before reading, so we never buffer a huge body
        raise ProtocolError(f"frame of {length} bytes is over the {MAX_FRAME}-byte limit")

    body = _recv_exact(sock, length)
    if len(body) < length:
        raise ProtocolError("connection closed in the middle of a message")
    return body


def decode_body(body: bytes) -> dict:
    """Parse a frame body into a message dict, or raise BadMessage.

    A hostile sender can put things inside a valid frame that make json.loads
    blow up in surprising ways, so every one of them becomes BadMessage:
      - invalid UTF-8 or invalid JSON
      - numbers with thousands of digits (ValueError)
      - thousands of nested brackets (RecursionError)
      - a lone "\\ud800" escape, which parses fine but can't be sent on again.
        Re-encoding here catches it now instead of crashing when we forward it.
    """
    try:
        msg = json.loads(body.decode("utf-8"))
        json.dumps(msg, ensure_ascii=False).encode("utf-8")
    except (ValueError, RecursionError) as exc:  # ValueError covers the decode errors too
        raise BadMessage("message is not valid UTF-8 JSON") from exc
    if not isinstance(msg, dict) or not isinstance(msg.get("type"), str):
        raise BadMessage('message must be a JSON object with a string "type"')
    return msg


def recv_msg(sock: socket.socket) -> dict | None:
    """Read and decode one message. Returns None when the connection closes cleanly."""
    body = recv_frame(sock)
    if body is None:
        return None
    return decode_body(body)

def decrypt(payload: str, key: bytes) -> str:
    raw_payload = base64.b64decode(payload)
    nonce = raw_payload[:12]
    ciphertext_with_tag = raw_payload[12:]
    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(
        nonce, ciphertext_with_tag, associated_data=None
    )
    return plaintext_bytes.decode("utf-8")