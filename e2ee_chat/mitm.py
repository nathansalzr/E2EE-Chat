"""mitm.py — a man-in-the-middle that sits between a client and the server (UC-2, UC-4).

It listens where clients expect the server, forwards every message to the real
server so the chat still works, and logs a copy of each one to intercepted.log.
In plain mode the log is readable; in e2ee mode it is only base64 ciphertext.

Modes:
  log     forward and record every message (UC-2; re-run against e2ee in UC-4)
  tamper  also flip one byte of every encrypted message's ciphertext (US-6)

Run it with:  python -m e2ee_chat.mitm [--mode log|tamper] [--port 6060]
              [--server-host 127.0.0.1] [--server-port 5050]

Attack code, for our own app on our own machines only.
"""

import argparse
import base64
import binascii
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
MODES = ("log", "tamper")

# Tampering happens on the way IN to the server only. When both clients sit
# behind this MITM, every message passes through it twice (sender->server and
# server->recipient); flipping the same bit both times would undo the change.
TAMPER_DIRECTION = "client->server"

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


def tamper(msg):
    """Return a copy of an encrypted message with one ciphertext byte flipped.

    The attacker can't read the ciphertext, but it can still change it. AES-GCM's
    authentication tag is what lets the recipient notice (US-6). Anything that
    isn't a well-formed encrypted message is returned unchanged.
    """
    if msg.get("type") != "encrypted" or not isinstance(msg.get("ciphertext"), str):
        return msg
    try:
        raw = bytearray(base64.b64decode(msg["ciphertext"], validate=True))
    except (binascii.Error, ValueError):
        return msg
    if not raw:
        return msg
    raw[0] ^= 0x01  # flip a single bit of the first ciphertext byte
    return {**msg, "ciphertext": base64.b64encode(bytes(raw)).decode("ascii")}


def pump(source, destination, direction, log_file, mode="log"):
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
            if mode == "tamper" and direction == TAMPER_DIRECTION:
                altered = tamper(msg)
                if altered is not msg:
                    log_message(log_file, f"{direction} TAMPERED", altered)
                    msg = altered
            send_msg(destination, msg)
    except (OSError, ProtocolError, BadMessage):
        # A reset connection, a half-closed socket, or a malformed frame.
        # Nothing to recover: let this direction end and fall through to cleanup.
        pass


def handle_client(client_sock, server_host, server_port, log_file, mode="log"):
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
        args=(client_sock, server_sock, "client->server", log_file, mode),
        daemon=True,
    )
    up.start()
    pump(server_sock, client_sock, "server->client", log_file, mode)

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
    parser = argparse.ArgumentParser(description="E2EE Chat man-in-the-middle (UC-2, UC-4)")
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
        choices=MODES,
        default="log",
        help="log: forward and record every message; "
        "tamper: also flip one byte of each encrypted message (swap-keys comes in UC-5)",
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
                args=(client_sock, args.server_host, args.server_port, args.log_file, args.mode),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        print("\n[mitm] stopping")
    finally:
        listener.close()


if __name__ == "__main__":
    main()
