"""mitm.py — a man-in-the-middle that sits between a client and the server (UC-2).

It listens where clients expect the server, forwards every message to the real
server so the chat still works, and logs a copy of each one to intercepted.log.
In the plaintext build the log is readable; after E2EE it will be ciphertext.

Run it with:  python -m e2ee_chat.mitm [--mode log] [--port 6060]
              [--server-host 127.0.0.1] [--server-port 5050]

Attack code, for our own app on our own machines only.
"""

import argparse
import socket
import threading
from datetime import datetime

from e2ee_chat.protocol import (
    BadMessage,
    ProtocolError,
    port_number,
    recv_msg,
    send_msg,
)

LISTEN_HOST = "127.0.0.1"  # this machine
LISTEN_PORT = 6060  # where clients connect, thinking it's the server
SERVER_HOST = "127.0.0.1"  # the real server
SERVER_PORT = 5050  # the real server's port
LOG_FILE = "intercepted.log"

# One lock shared by every thread so two directions never interleave a log line.
_log_lock = threading.Lock()


def log_message(log_file, direction, msg):
    """Write one intercepted message to the log file and print it on screen."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    line = f"[{timestamp}] {direction} {msg}"
    with _log_lock:
        print("[mitm]", line)  # show it in the attacker's terminal
        # utf-8 + errors="replace": chat text is free-form (emoji, non-Latin), and
        # without this the default Windows cp1252 codec raises on the first such
        # character and we'd lose that message and every one after it.
        with open(log_file, "a", encoding="utf-8", errors="replace") as f:
            f.write(line + "\n")


def pump(source, destination, direction, log_file):
    """Read messages from source, log them, and pass them to destination.

    Runs until one side hangs up or the stream breaks. One pump handles one
    direction; we run two so both directions flow at once. Any socket or
    protocol error just ends this direction cleanly instead of crashing the
    thread, and handle_client() closes both sockets afterwards.
    """
    try:
        while True:
            msg = recv_msg(source)
            if msg is None:  # the other side closed cleanly
                break
            log_message(log_file, direction, msg)
            send_msg(destination, msg)
    except (OSError, ProtocolError, BadMessage):
        # A reset connection, a half-closed socket, or a malformed frame.
        # Nothing to recover: let this direction end and fall through to cleanup.
        pass


def handle_client(client_sock, server_host, server_port, log_file):
    """One client connected to us. Connect to the real server and relay both ways."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_sock.connect((server_host, server_port))
    except OSError as exc:
        print(f"[mitm] cannot reach the real server at {server_host}:{server_port}: {exc}")
        client_sock.close()
        server_sock.close()
        return

    # Forward client->server in the background; server->client in this thread.
    up = threading.Thread(
        target=pump,
        args=(client_sock, server_sock, "client->server", log_file),
        daemon=True,
    )
    up.start()
    pump(server_sock, client_sock, "server->client", log_file)

    # When either direction ends, close both sockets. Closing them makes the
    # other pump's blocked recv return, so no thread or socket is left dangling
    # and the real server sees the client leave (freeing the username).
    for sock in (client_sock, server_sock):
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description="E2EE Chat man-in-the-middle (UC-2)")
    parser.add_argument("--host", default=LISTEN_HOST, help="address to listen on")
    parser.add_argument(
        "--port",
        type=port_number,
        default=LISTEN_PORT,
        help="port clients connect to (defaults to 6060)",
    )
    parser.add_argument("--server-host", default=SERVER_HOST, help="the real server's address")
    parser.add_argument(
        "--server-port", type=port_number, default=SERVER_PORT, help="the real server's port"
    )
    parser.add_argument(
        "--mode",
        choices=["log"],
        default="log",
        help="log: forward and record every message (tamper/swap-keys come later)",
    )
    parser.add_argument("--log-file", default=LOG_FILE, help="where to write intercepted traffic")
    args = parser.parse_args(argv)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.host, args.port))
    listener.listen()
    print(
        f"[mitm] mode={args.mode} listening on {args.host}:{args.port}, "
        f"forwarding to {args.server_host}:{args.server_port}"
    )

    try:
        while True:
            client_sock, addr = listener.accept()
            print(f"[mitm] client connected from {addr}")
            threading.Thread(
                target=handle_client,
                args=(client_sock, args.server_host, args.server_port, args.log_file),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        print("\n[mitm] stopping")
    finally:
        listener.close()


if __name__ == "__main__":
    main()
