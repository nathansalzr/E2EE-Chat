"""Checks that the cryptography library does what our design relies on, on every OS in CI.

This is not our app code. It only proves the building blocks work:
X25519 key agreement -> HKDF-SHA256 -> AES-256-GCM, including tamper detection.
"""

import os

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"e2ee-chat test")
    return hkdf.derive(shared_secret)


def test_x25519_both_sides_derive_the_same_key():
    alice, bob = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    alice_key = derive_key(alice.exchange(bob.public_key()))
    bob_key = derive_key(bob.exchange(alice.public_key()))
    assert alice_key == bob_key
    assert len(alice_key) == 32  # AES-256


def test_aes_gcm_round_trip_and_tamper_detection():
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)  # fresh 96-bit nonce per message
    ciphertext = AESGCM(key).encrypt(nonce, b"hi bob", None)

    assert b"hi bob" not in ciphertext
    assert AESGCM(key).decrypt(nonce, ciphertext, None) == b"hi bob"

    tampered = bytes([ciphertext[0] ^ 0x01]) + ciphertext[1:]
    with pytest.raises(InvalidTag):
        AESGCM(key).decrypt(nonce, tampered, None)
