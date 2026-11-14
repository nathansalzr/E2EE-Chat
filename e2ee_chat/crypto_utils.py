"""Key operations for end-to-end encryption (UC-3).

All asymmetric crypto lives here so it can be unit-tested without sockets.
Primitives come only from the `cryptography` library — no homemade crypto.
"""

import base64
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

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
