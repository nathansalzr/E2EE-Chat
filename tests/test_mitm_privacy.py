"""Security check (T21, US-3 AC2): the private key never reaches the wire.

Runs a real session through the MITM and asserts the intercepted log captured
the public-key handshake but contains no private-key material.
"""

import base64
import socket
import threading
import time

from cryptography.hazmat.primitives import serialization

from e2ee_chat import mitm
from e2ee_chat.client import ChatClient
from e2ee_chat.server import ChatServer


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_port(port: int, timeout: float = 3.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return
        except OSError:
            time.sleep(0.02)
    raise AssertionError(f"nothing listening on {port}")


def _start_mitm(listen_port: int, server_port: int, log_file: str) -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", listen_port))
    listener.listen()

    def accept_loop():
        while True:
            try:
                client_sock, _ = listener.accept()
            except OSError:
                return
            threading.Thread(
                target=mitm.handle_client,
                args=(client_sock, "127.0.0.1", server_port, log_file),
                daemon=True,
            ).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    return listener


def _private_key_b64(client: ChatClient) -> str:
    raw = client._my_private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    return base64.b64encode(raw).decode("ascii")


def test_private_key_never_appears_in_mitm_log(tmp_path):
    server_port = _free_port()
    mitm_port = _free_port()
    log_file = str(tmp_path / "intercepted.log")

    server = ChatServer(port=server_port)
    server.start()
    _wait_port(server_port)
    listener = _start_mitm(mitm_port, server_port, log_file)
    _wait_port(mitm_port)

    kd = str(tmp_path)
    alice = ChatClient("127.0.0.1", mitm_port, "alice", lambda m: None, peer="bob", keys_dir=kd)
    bob = ChatClient("127.0.0.1", mitm_port, "bob", lambda m: None, peer="alice", keys_dir=kd)
    alice.connect()
    bob.connect()
    assert alice.session_ready.wait(3) and bob.session_ready.wait(3)

    alice.close()
    bob.close()
    listener.close()
    server.stop()

    log = open(log_file, encoding="utf-8").read()
    assert "pubkey" in log  # the public-key handshake WAS captured
    assert _private_key_b64(alice) not in log  # but no private key leaked
    assert _private_key_b64(bob) not in log
