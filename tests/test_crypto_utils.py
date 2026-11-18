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
    with pytest.raises(ValueError):  # bad base64 / wrong key length both subclass ValueError
        derive_session_key(alice, "not-valid-base64-or-key")


# --- UC-4: AES-256-GCM message encryption (T27) ---------------------------

from e2ee_chat.crypto_utils import (  # noqa: E402
    IntegrityError,
    chat_aad,
    decrypt_message,
    encrypt_message,
)

KEY = bytes(range(32))
AAD = chat_aad("alice", "bob")


def test_encrypt_decrypt_round_trip():
    nonce, ct = encrypt_message(KEY, "hello bob 👋", AAD)
    assert decrypt_message(KEY, nonce, ct, AAD) == "hello bob 👋"  # US-5 AC2


def test_nonce_is_96_bits_and_never_repeats():
    nonces = {encrypt_message(KEY, "same text", AAD)[0] for _ in range(1000)}
    assert len(nonces) == 1000  # US-5 AC1: fresh nonce every message
    assert all(len(base64.b64decode(n)) == 12 for n in nonces)


def test_same_text_gives_different_ciphertext():
    assert encrypt_message(KEY, "hi", AAD)[1] != encrypt_message(KEY, "hi", AAD)[1]


def test_ciphertext_does_not_contain_the_plaintext():
    _, ct = encrypt_message(KEY, "attack at dawn", AAD)
    assert b"attack" not in base64.b64decode(ct)


def _flip_one_byte(b64: str) -> str:
    raw = bytearray(base64.b64decode(b64))
    raw[0] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")


def test_flipped_ciphertext_byte_is_rejected():
    nonce, ct = encrypt_message(KEY, "pay alice $10", AAD)
    with pytest.raises(IntegrityError):  # US-6: GCM tag catches a 1-bit change
        decrypt_message(KEY, nonce, _flip_one_byte(ct), AAD)


def test_flipped_nonce_is_rejected():
    nonce, ct = encrypt_message(KEY, "hi", AAD)
    with pytest.raises(IntegrityError):
        decrypt_message(KEY, _flip_one_byte(nonce), ct, AAD)


def test_wrong_key_is_rejected():
    nonce, ct = encrypt_message(KEY, "hi", AAD)
    with pytest.raises(IntegrityError):
        decrypt_message(bytes(32), nonce, ct, AAD)


def test_relabelled_sender_is_rejected():
    # A MITM changes "from": the receiver rebuilds a different AAD and the tag fails.
    nonce, ct = encrypt_message(KEY, "hi", chat_aad("alice", "bob"))
    with pytest.raises(IntegrityError):
        decrypt_message(KEY, nonce, ct, chat_aad("eve", "bob"))


@pytest.mark.parametrize(
    "nonce, ct",
    [
        ("!!!", "AAAA"),  # not base64
        ("AAAA", "AAAA"),  # 3-byte nonce
        (None, "AAAA"),  # wrong type
        ("AAAAAAAAAAAAAAAA", 123),  # wrong type
        ("AAAAAAAAAAAAAAAA", ""),  # empty ciphertext (no tag)
    ],
)
def test_malformed_fields_raise_integrity_error(nonce, ct):
    with pytest.raises(IntegrityError):
        decrypt_message(KEY, nonce, ct, AAD)
