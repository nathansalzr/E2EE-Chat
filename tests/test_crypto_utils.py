"""Unit tests for e2ee_chat.crypto_utils (UC-3)."""

import base64

import pytest

from e2ee_chat.crypto_utils import (
    derive_session_key,
    fingerprint,
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


def test_fingerprint_is_stable_and_grouped(tmp_path):
    pub = public_key_b64(load_or_create_keypair("alice", keys_dir=str(tmp_path)))
    fp = fingerprint(pub)
    assert fp == fingerprint(pub)  # deterministic
    assert set(fp.replace(" ", "")) <= set("0123456789ABCDEF")  # hex only
    assert " " in fp  # grouped for readability


def test_different_keys_give_different_fingerprints(tmp_path):
    a = public_key_b64(load_or_create_keypair("a", keys_dir=str(tmp_path)))
    b = public_key_b64(load_or_create_keypair("b", keys_dir=str(tmp_path)))
    assert fingerprint(a) != fingerprint(b)


def test_both_sides_derive_the_same_key(tmp_path):
    alice = load_or_create_keypair("alice", keys_dir=str(tmp_path))
    bob = load_or_create_keypair("bob", keys_dir=str(tmp_path))
    ka = derive_session_key(alice, public_key_b64(bob))
    kb = derive_session_key(bob, public_key_b64(alice))
    assert ka == kb and len(ka) == 32  # same 256-bit key on both sides


def test_different_peers_give_different_keys(tmp_path):
    alice = load_or_create_keypair("alice", keys_dir=str(tmp_path))
    bob = load_or_create_keypair("bob", keys_dir=str(tmp_path))
    eve = load_or_create_keypair("eve", keys_dir=str(tmp_path))
    assert derive_session_key(alice, public_key_b64(bob)) != derive_session_key(
        alice, public_key_b64(eve)
    )


def test_bad_peer_key_raises(tmp_path):
    alice = load_or_create_keypair("alice", keys_dir=str(tmp_path))
    with pytest.raises(Exception):
        derive_session_key(alice, "not-valid-base64-or-key")
