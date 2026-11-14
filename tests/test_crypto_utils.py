"""Unit tests for e2ee_chat.crypto_utils (UC-3)."""

import base64

from e2ee_chat.crypto_utils import (
    load_or_create_keypair,
    public_key_b64,
)


def test_keypair_created_then_reused(tmp_path):
    k1 = load_or_create_keypair("alice", keys_dir=str(tmp_path))
    assert (tmp_path / "alice.key").exists()
    k2 = load_or_create_keypair("alice", keys_dir=str(tmp_path))
    assert public_key_b64(k1) == public_key_b64(k2)  # same key loaded, not regenerated


def test_public_key_b64_is_decodable_32_bytes(tmp_path):
    k = load_or_create_keypair("bob", keys_dir=str(tmp_path))
    raw = base64.b64decode(public_key_b64(k))
    assert len(raw) == 32
