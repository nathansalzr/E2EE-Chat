"""Crypto for end-to-end encryption: key exchange (UC-3) and message encryption (UC-4).

All crypto lives here so it can be unit-tested without sockets.
Primitives come only from the `cryptography` library — no homemade crypto.
"""

import base64
import binascii
import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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


# --- UC-4: message encryption (AES-256-GCM) -------------------------------

NONCE_BYTES = 12  # 96-bit nonce, the size AES-GCM is designed for
_AAD_PREFIX = b"e2ee-chat v1"


class IntegrityError(Exception):
    """A message failed decryption: tampered, wrong key, wrong sender, or malformed.

    One exception for every failure on purpose: the receiver's reaction is the
    same ("message failed integrity check"), and we don't tell an attacker
    which check tripped.
    """


def chat_aad(sender: str, recipient: str) -> bytes:
    """Associated data that binds a ciphertext to who sent it and who it's for.

    AES-GCM authenticates the AAD without encrypting it. The sender uses its own
    name and the recipient's; the receiver rebuilds it from the server-stamped
    ``from`` and its own name. If a MITM relabels or redirects a message, the
    AAD no longer matches and the tag check fails.
    """
    return b"|".join([_AAD_PREFIX, sender.encode("utf-8"), recipient.encode("utf-8")])


def encrypt_message(key: bytes, plaintext: str, aad: bytes) -> tuple[str, str]:
    """Encrypt one chat message. Returns (nonce_b64, ciphertext_b64).

    A fresh random nonce every call: reusing a nonce with the same key breaks
    AES-GCM completely, so it is never derived from a counter we could reset.
    The ciphertext includes GCM's 16-byte authentication tag at the end.
    """
    nonce = os.urandom(NONCE_BYTES)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad)
    return (
        base64.b64encode(nonce).decode("ascii"),
        base64.b64encode(ciphertext).decode("ascii"),
    )


def decrypt_message(key: bytes, nonce_b64: object, ciphertext_b64: object, aad: bytes) -> str:
    """Decrypt and verify one chat message, or raise IntegrityError.

    Fields come straight off the network, so anything is checked: types,
    strict base64, nonce length, the GCM tag (tampering / wrong key / wrong
    AAD), and that the plaintext is valid UTF-8.
    """
    if not isinstance(nonce_b64, str) or not isinstance(ciphertext_b64, str):
        raise IntegrityError("nonce and ciphertext must be strings")
    try:
        nonce = base64.b64decode(nonce_b64, validate=True)
        ciphertext = base64.b64decode(ciphertext_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise IntegrityError("not valid base64") from exc
    if len(nonce) != NONCE_BYTES:
        raise IntegrityError("wrong nonce length")
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
        return plaintext.decode("utf-8")
    except (InvalidTag, UnicodeDecodeError) as exc:
        raise IntegrityError("authentication failed") from exc
