"""Saved chat history for the web demo, encrypted at rest (UC web demo).

Like a real messaging app, a conversation is kept so a reopened window shows
earlier messages and so a later "key changed" event reads against them. The
file is encrypted with a key derived from the user's own private key, so a
copied history file is unreadable without that user's ``keys/<user>.key``.
This is "data at rest" protection, distinct from the "data in transit" E2EE.

Format: one base64 line per entry, each `nonce||AES-256-GCM(json)`. A corrupt
or tampered line is skipped, never shown.
"""

import base64
import json
import os
import threading

from e2ee_chat.crypto_utils import (
    IntegrityError,
    chat_aad,  # reused shape: b"e2ee-chat v1|<a>|<b>"; here as the history AAD
    decrypt_message,
    derive_storage_key,
    encrypt_message,
    load_or_create_keypair,
)
from e2ee_chat.protocol import is_valid_username


def _history_path(me: str, peer: str, keys_dir: str) -> str:
    for name in (me, peer):
        if not is_valid_username(name):
            raise ValueError(f"not a valid username: {name!r}")
    return os.path.join(keys_dir, "history", me, f"{peer}.log")


class HistoryStore:
    """Append-only, encrypted-at-rest log of one conversation for one user."""

    def __init__(self, me: str, peer: str, keys_dir: str = "keys"):
        self.me = me
        self.peer = peer
        self.path = _history_path(me, peer, keys_dir)
        # The same private key the client uses; derive a separate storage key.
        private_key = load_or_create_keypair(me, keys_dir)
        self._key = derive_storage_key(private_key)
        self._aad = chat_aad(f"history:{me}", peer)
        self._lock = threading.Lock()

    def append(self, event: dict) -> None:
        """Encrypt one UI event and append it. Failures never break the chat."""
        try:
            payload = json.dumps(event, ensure_ascii=False)
            nonce, ciphertext = encrypt_message(self._key, payload, self._aad)
            line = base64.b64encode(f"{nonce}:{ciphertext}".encode("ascii")).decode("ascii")
            with self._lock:
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
                with open(self.path, "a", encoding="ascii") as f:
                    f.write(line + "\n")
        except (OSError, ValueError, TypeError):
            pass  # a save failure must not crash the window

    def load(self) -> list[dict]:
        """Return the saved events in order. Corrupt/tampered lines are skipped."""
        with self._lock:
            try:
                # Read bytes and decode per line, so one bad byte only costs
                # its own line instead of failing the whole file.
                with open(self.path, "rb") as f:
                    raw_lines = f.read().splitlines()
            except OSError:
                return []
        events = []
        for raw in raw_lines:
            if not raw.strip():
                continue
            try:
                decoded = base64.b64decode(raw.decode("ascii"), validate=True).decode("ascii")
                nonce, ciphertext = decoded.split(":", 1)
                text = decrypt_message(self._key, nonce, ciphertext, self._aad)
                event = json.loads(text)
            except (IntegrityError, ValueError, UnicodeDecodeError):
                continue  # skip anything we can't verify and read
            if isinstance(event, dict):
                events.append(event)
        return events
