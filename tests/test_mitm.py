"""Smoke tests for the UC-2 man-in-the-middle.

These lock in US-2 AC1 (clients routed through the MITM still chat normally) and
AC2/AC3 (every message is written to the log in readable plaintext), and guard
the UTF-8 logging fix so a non-ASCII message can't silently break the relay.
"""

import socket
import threading
import time

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
    """Start the MITM accept loop on a background thread; return the listener."""
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


def test_chat_flows_through_mitm_and_is_logged(tmp_path):
    server_port = _free_port()
    mitm_port = _free_port()
    log_file = str(tmp_path / "intercepted.log")

    server = ChatServer(port=server_port)
    server.start()
    _wait_port(server_port)
    listener = _start_mitm(mitm_port, server_port, log_file)
    _wait_port(mitm_port)

    received: list[dict] = []
    bob = ChatClient("127.0.0.1", mitm_port, "bob", received.append)
    bob.connect()
    alice = ChatClient("127.0.0.1", mitm_port, "alice", lambda m: None)
    alice.connect()
    time.sleep(0.2)

    plaintext = "meet at library 3pm 你好 \U0001f600"  # non-ASCII guards the utf-8 fix
    alice.send_chat("bob", plaintext)
    time.sleep(0.4)

    # AC1: the message reached Bob normally, through the MITM.
    assert any(m.get("from") == "alice" and m.get("text") == plaintext for m in received)

    alice.close()
    bob.close()
    listener.close()
    server.stop()

    # AC2/AC3: the log exists and shows the conversation in readable plaintext.
    with open(log_file, encoding="utf-8") as f:
        log = f.read()
    assert plaintext in log
    assert "client->server" in log
