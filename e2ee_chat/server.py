"""Relay server: forwards messages between registered users (T4, T7).

Run it with:  python -m e2ee_chat.server [--host 127.0.0.1] [--port 5050]

The server is a middleman by design, like the servers behind real chat apps.
It reads only the "type" and "to" fields to decide where a message goes, and
it never prints message text. That's the point UC-2 makes: anyone sitting in
the middle *could* read everything unless the clients encrypt end to end.
"""

import argparse
import os
import socket
import sys
import threading
import time

from e2ee_chat.protocol import (
    DEFAULT_PORT,
    RELAY_TYPES,
    BadMessage,
    MessageTooLarge,
    ProtocolError,
    decode_body,
    is_valid_username,
    port_number,
    recv_frame,
    send_msg,
)

ACCEPT_POLL_SECONDS = 0.5  # how often the accept loop checks whether we're stopping


def log(text: str) -> None:
    """Print one server status line (never message text)."""
    print(f"[server] {text}", flush=True)


class _Connection:
    """One connected client: its socket, its username once registered, and a send lock."""

    def __init__(self, sock: socket.socket, address: tuple):
        self.sock = sock
        self.address = address
        self.username: str | None = None
        # Two clients can message the same person at the same moment. The lock
        # stops their frames from getting interleaved on this socket.
        self._send_lock = threading.Lock()

    def send(self, msg: dict) -> None:
        """Send a message. A dead connection is ignored; its own thread cleans it up."""
        with self._send_lock:
            try:
                send_msg(self.sock, msg)
            except OSError:
                pass

    def send_error(self, code: str, message: str) -> None:
        """Send {"type": "error", ...} with one of the codes in docs/protocol.md."""
        self.send({"type": "error", "code": code, "message": message})

    def close(self) -> None:
        """Hang up on this client."""
        try:
            # shutdown wakes up a thread blocked in recv; close alone may not
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


class ChatServer:
    """A thread-per-client relay. Use start() and stop(); main() wraps them for the CLI."""

    def __init__(self, host: str = "127.0.0.1", port: int = DEFAULT_PORT):
        self.host = host
        self.port = port  # pass 0 to let the OS pick a free port (used by the tests)
        self._listener: socket.socket | None = None
        self._users: dict[str, _Connection] = {}  # username -> connection
        self._connections: set[_Connection] = set()  # every open connection, registered or not
        self._lock = threading.Lock()  # guards _users and _connections
        self._stopping = threading.Event()

    # ---- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        """Bind, listen, and start accepting clients in a background thread."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.name != "nt":
            # Lets us restart right away on macOS/Linux. Skipped on Windows, where
            # SO_REUSEADDR would let another program steal a port that's in use.
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind((self.host, self.port))
            listener.listen()
        except OSError:
            listener.close()
            raise
        # A timeout makes accept() return regularly so the loop can notice stop().
        listener.settimeout(ACCEPT_POLL_SECONDS)
        self._listener = listener
        self.port = listener.getsockname()[1]
        threading.Thread(target=self._accept_loop, name="accept", daemon=True).start()

    def stop(self) -> None:
        """Close the listener and every client connection. Safe to call twice."""
        if self._stopping.is_set():
            return
        self._stopping.set()
        if self._listener is not None:
            self._listener.close()
        with self._lock:
            connections = list(self._connections)
        for conn in connections:
            conn.close()

    def online_users(self) -> set[str]:
        """Names of everyone registered right now (a copy, safe to read)."""
        with self._lock:
            return set(self._users)

    # ---- per-connection work ------------------------------------------------

    def _accept_loop(self) -> None:
        """Background thread: accept new clients and give each its own thread."""
        while not self._stopping.is_set():
            try:
                sock, address = self._listener.accept()
            except TimeoutError:
                continue  # nobody connected in the last half second; check _stopping again
            except OSError:
                break  # the listener was closed by stop()
            sock.settimeout(None)  # client sockets block; only the listener polls
            conn = _Connection(sock, address)
            with self._lock:
                self._connections.add(conn)
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: _Connection) -> None:
        """Read messages from one client until it disconnects or breaks the framing."""
        try:
            while True:
                body = recv_frame(conn.sock)
                if body is None:
                    break  # client closed the connection
                try:
                    msg = decode_body(body)
                except BadMessage as exc:  # must come before ProtocolError (it's a subclass)
                    conn.send_error("bad_message", str(exc))
                    continue  # the frame was fine, so the connection can keep going
                self._handle(conn, msg)
        except (ProtocolError, OSError):
            pass  # broken framing or a dropped connection: hang up on this client only
        except Exception as exc:  # last resort: one bad client must never take down the server
            log(f"dropping {conn.username or conn.address[0]}: unexpected {type(exc).__name__}")
        finally:
            self._drop(conn)

    def _handle(self, conn: _Connection, msg: dict) -> None:
        """Route one decoded message by its type."""
        kind = msg["type"]
        if kind == "register":
            self._register(conn, msg)
        elif kind in RELAY_TYPES:
            self._relay(conn, msg)
        else:
            conn.send_error("bad_message", f"unknown message type {kind!r}")

    def _register(self, conn: _Connection, msg: dict) -> None:
        """Claim a username for this connection, or explain why not."""
        if conn.username is not None:
            conn.send_error("bad_message", f"already registered as {conn.username}")
            return
        name = msg.get("username")
        if not is_valid_username(name):
            conn.send_error("invalid_username", "use 1-20 letters, digits, underscores or hyphens")
            return
        with self._lock:
            taken = name in self._users
            if not taken:
                self._users[name] = conn
                conn.username = name
        if taken:
            conn.send_error("username_taken", f"{name} is already connected")
            return
        conn.send({"type": "registered", "username": name})
        log(f"{name} joined from {conn.address[0]}")

    def _relay(self, conn: _Connection, msg: dict) -> None:
        """Forward a chat/pubkey/encrypted message to the user named in "to"."""
        if conn.username is None:
            conn.send_error("not_registered", "register a username first")
            return
        recipient = msg.get("to")
        if not isinstance(recipient, str):
            conn.send_error("bad_message", 'relay messages need a string "to" field')
            return
        with self._lock:
            target = self._users.get(recipient)
        if target is None:
            conn.send_error("user_offline", f"{recipient} is not connected")
            return
        # Set "from" ourselves so nobody can pretend to be someone else.
        forwarded = {**msg, "from": conn.username}
        try:
            target.send(forwarded)
        except MessageTooLarge:  # adding "from" pushed it over the size limit
            conn.send_error("bad_message", "message is too large")
            return
        log(f"{conn.username} -> {recipient} ({msg['type']})")  # never the text itself

    def _drop(self, conn: _Connection) -> None:
        """Forget a client that left: free its username and close its socket."""
        with self._lock:
            self._connections.discard(conn)
            # Only remove the name if it still points at this connection.
            if conn.username and self._users.get(conn.username) is conn:
                del self._users[conn.username]
        conn.close()
        if conn.username:
            log(f"{conn.username} left")


def main(argv: list[str] | None = None) -> None:
    """Command-line entry point: parse options, start the server, wait for Ctrl+C."""
    parser = argparse.ArgumentParser(description="E2EE Chat relay server")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="address to listen on (default 127.0.0.1, this computer only; "
        "use 0.0.0.0 for the two-machine test)",
    )
    parser.add_argument("--port", type=port_number, default=DEFAULT_PORT)
    args = parser.parse_args(argv)

    server = ChatServer(args.host, args.port)
    try:
        server.start()
    except OSError as exc:
        print(
            f"cannot start server on {args.host}:{args.port}: {exc.strerror or exc}",
            file=sys.stderr,
        )
        sys.exit(1)
    log(f"listening on {args.host}:{server.port} (Ctrl+C to stop)")

    try:
        # The real work happens on background threads. The main thread just
        # sleeps in short steps so Ctrl+C is noticed quickly, on Windows too.
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
        log("stopped")


if __name__ == "__main__":
    main()
