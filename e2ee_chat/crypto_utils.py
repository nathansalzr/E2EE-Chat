"""Key operations for end-to-end encryption (UC-3).

All asymmetric crypto lives here so it can be unit-tested without sockets.
Primitives come only from the `cryptography` library — no homemade crypto.
"""

import base64
import hashlib
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_RAW = serialization.Encoding.Raw
_RAW_PRIV = serialization.PrivateFormat.Raw
_RAW_PUB = serialization.PublicFormat.Raw
_NO_ENC = serialization.NoEncryption()


def load_or_create_keypair(username: str, keys_dir: str = "keys") -> X25519PrivateKey:
    """Load this user's X25519 private key from disk, or create and save one.

    The private key is stored as its raw 32 bytes at ``<keys_dir>/<username>.key``.
    The folder is gitignored; the private key never leaves the machine.
    """
    path = os.path.join(keys_dir, f"{username}.key")
    if os.path.exists(path):
        with open(path, "rb") as f:
            return X25519PrivateKey.from_private_bytes(f.read())

    private_key = X25519PrivateKey.generate()
    os.makedirs(keys_dir, exist_ok=True)
    with open(path, "wb") as f:
        f.write(private_key.private_bytes(_RAW, _RAW_PRIV, _NO_ENC))
    return private_key


def public_key_b64(private_key: X25519PrivateKey) -> str:
    """Return the public key as base64 of its raw 32 bytes (printable, for the wire)."""
    raw = private_key.public_key().public_bytes(_RAW, _RAW_PUB)
    return base64.b64encode(raw).decode("ascii")


def fingerprint(public_key_b64_str: str) -> str:
    """SHA-256 of a base64 public key, as grouped uppercase hex.

    Shown to users so they can compare keys out-of-band (used in UC-5).
    Grouping (a space every 4 hex chars) makes it easy to read aloud.
    """
    digest = hashlib.sha256(base64.b64decode(public_key_b64_str)).hexdigest().upper()
    return " ".join(digest[i : i + 4] for i in range(0, len(digest), 4))


# Both clients MUST use these identical parameters, or they derive different
# keys and every encrypted message in UC-4 fails to decrypt.
_HKDF_SALT = None
_HKDF_INFO = b"e2ee-chat v1 session key"


def derive_session_key(my_private_key: X25519PrivateKey, peer_public_b64: str) -> bytes:
    """Agree a shared 32-byte AES-256 key with the peer.

    X25519 ECDH produces a shared secret from our private key and the peer's
    public key (the same secret on both sides); HKDF-SHA256 turns it into a
    uniform 256-bit key. The private key never leaves this function.
    """
    peer_public = X25519PublicKey.from_public_bytes(base64.b64decode(peer_public_b64))
    shared_secret = my_private_key.exchange(peer_public)
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=_HKDF_INFO,
    ).derive(shared_secret)
