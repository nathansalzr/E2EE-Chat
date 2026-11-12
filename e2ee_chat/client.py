"""Plaintext command-line chat client (T5, T7).

Run it with:  python -m e2ee_chat.client --user alice --peer bob

Every line you type goes to --peer. Messages from others print as they arrive.
--mode plain is the only mode for now; UC-4 adds --mode e2ee.
"""

import argparse
import socket
import sys
import threading
from collections.abc import Callable

from e2ee_chat.protocol import (
    DEFAULT_PORT,
    BadMessage,
    MessageTooLarge,
    ProtocolError,
    port_number,
    recv_msg,
    send_msg,
)

CONNECT_TIMEOUT_SECONDS = 5


class RegistrationError(Exception):
    """The server said no to our username (taken or invalid)."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class ChatClient:
    """Connects to the server, registers a username, and receives in the background.

    on_message is called (from the receive thread) with every message the
    server sends, plus {"type": "disconnected"} once if the server goes away.
    """

    def __init__(self, host: str, port: int, username: str, on_message: Callable[[dict], None]):
        self.host = host
        self.port = port
        self.username = username
        self.on_message = on_message
        self._sock: socket.socket | None = None
        self._closing = False  # set by close(), so we don't report our own hang-up

    def connect(self) -> None:
        """Connect and register. Raises ConnectionError or RegistrationError."""
        address = f"{self.host}:{self.port}"
        try:
            sock = socket.create_connection((self.host, self.port), timeout=CONNECT_TIMEOUT_SECONDS)
        except OSError as exc:
            raise ConnectionError(f"cannot reach server at {address}") from exc

        try:
            send_msg(sock, {"type": "register", "username": self.username})
            reply = recv_msg(sock)  # still has the 5 s timeout
        except (OSError, ProtocolError) as exc:
            sock.close()
            raise ConnectionError(f"server at {address} did not answer") from exc

        if reply is None or reply.get("type") not in ("registered", "error"):
            sock.close()
            raise ConnectionError(f"unexpected reply from server at {address}")
        if reply["type"] == "error":
            sock.close()
            # Clean the text now: it gets printed, and it came from the network.
            raise RegistrationError(
                sanitize_for_terminal(reply.get("code", "error")),
                sanitize_for_terminal(reply.get("message", "")),
            )

        sock.settimeout(None)  # from here on, the receive thread waits as long as it needs
        self._sock = sock
        threading.Thread(target=self._receive_loop, name="receive", daemon=True).start()

    def send_chat(self, to: str, text: str) -> None:
        """Send one chat message. Raises OSError if the connection is gone."""
        send_msg(self._sock, {"type": "chat", "to": to, "text": text})

    def close(self) -> None:
        """Hang up. Safe to call more than once."""
        self._closing = True
        if self._sock is None:
            return
        try:
            self._sock.shutdown(socket.SHUT_RDWR)  # wakes the receive thread
        except OSError:
            pass
        self._sock.close()

    def _receive_loop(self) -> None:
        """Runs on its own thread: hand every incoming message to on_message."""
        try:
            while True:
                try:
                    msg = recv_msg(self._sock)
                except BadMessage:
                    # One garbled message (e.g. injected by a MITM) isn't a reason
                    # to hang up. Skip it and keep listening. BadMessage is a kind
                    # of ProtocolError, so it has to be caught here, first.
                    continue
                if msg is None:
                    break  # server closed the connection
                self.on_message(msg)
        except Exception:  # noqa: S110 - any failure here means the same thing to the user
            # Usually broken framing (ProtocolError) or a dropped connection
            # (OSError). Either way we stop listening and tell the user below,
            # instead of the thread dying silently and leaving them waiting.
            pass
        if not self._closing:
            self.on_message({"type": "disconnected"})


def sanitize_for_terminal(text: object) -> str:
    """Replace control characters so nobody can send us terminal escape codes.

    Escape codes can clear the screen, recolor text, or fake other lines.
    """
    return "".join(ch if ch.isprintable() else "?" for ch in str(text))


def format_message(msg: dict) -> str:
    """Turn a message from the server into the line we show the user."""
    kind = msg.get("type")
    clean = sanitize_for_terminal
    if kind == "chat":
        return f"[{clean(msg.get('from'))}] {clean(msg.get('text'))}"
    if kind == "error":
        return f"! {clean(msg.get('code'))}: {clean(msg.get('message'))}"
    if kind == "disconnected":
        return "! connection to server lost"
    return f"? unexpected {clean(kind)} message"


def main(argv: list[str] | None = None) -> None:
    """Command-line entry point: connect, then send each typed line to --peer."""
    parser = argparse.ArgumentParser(description="E2EE Chat client")
    parser.add_argument("--host", default="127.0.0.1", help="server address")
    parser.add_argument("--port", type=port_number, default=DEFAULT_PORT)
    parser.add_argument("--user", required=True, help="your username")
    parser.add_argument("--peer", required=True, help="who your messages go to")
    parser.add_argument("--mode", choices=["plain"], default="plain")
    args = parser.parse_args(argv)

    lost = threading.Event()

    def show(msg: dict) -> None:
        """Print an incoming message, and remember if the server went away."""
        if msg.get("type") == "disconnected":
            lost.set()
        print(format_message(msg), flush=True)

    client = ChatClient(args.host, args.port, args.user, on_message=show)
    try:
        client.connect()
    except (ConnectionError, RegistrationError) as exc:
        print(f"! {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:  # Ctrl+C while still connecting
        print("! cancelled", file=sys.stderr)
        sys.exit(1)

    print(f"Connected as {args.user}. Messages go to {args.peer}. Type /quit to leave.")
    try:
        while not lost.is_set():
            try:
                line = input()
            except (EOFError, KeyboardInterrupt):
                break
            if line.strip() == "/quit" or lost.is_set():
                break
            if not line.strip():
                continue
            try:
                client.send_chat(args.peer, line)
            except MessageTooLarge:
                print("! message too long", flush=True)
            except OSError:
                print("! connection to server lost", flush=True)
                break
    finally:
        client.close()


if __name__ == "__main__":
    main()
