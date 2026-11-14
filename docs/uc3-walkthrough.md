# UC-3 walkthrough: set up a secure session (X25519 key exchange)

What we built for UC-3 (US-3 + US-4), which files belong to which task, what each piece does, and why.
This is the **foundation of the defense**: it gives Alice and Bob a shared secret key the server and MITM can't compute. UC-4 then uses that key to encrypt.
Design: [`plans/2026-11-13-uc3-secure-session-design.md`](plans/2026-11-13-uc3-secure-session-design.md). Plan: [`plans/2026-11-13-uc3-secure-session-plan.md`](plans/2026-11-13-uc3-secure-session-plan.md).

## What it does

- Each client generates an **X25519 keypair** on first run and reuses it after (saved in `keys/<username>.key`, gitignored — the private key never leaves the machine).
- Before any chat, the two clients **swap public keys** over the existing `pubkey` message, relayed by the server.
- Each side combines **its private key with the peer's public key** (ECDH) and runs HKDF-SHA256 to get the **same AES-256 session key**. The server and MITM only ever see public keys, so they can't compute it.
- Chat is **blocked until the session key exists**, and each client prints a short hash of the key so you can confirm both sides match.

```
Alice                          server (relays pubkey)                    Bob
  │  announce pubkey(A) ───────────────►  ──────────────────► receive, derive
  │  ◄────────── receive, derive  ◄─────────────── reply pubkey(B)  │
  │                                                                 │
  A.priv + B.pub ──ECDH──► shared secret ──HKDF──► same AES-256 key ◄── B.priv + A.pub
```

**Key point:** the shared secret is never transmitted. It's computed independently on each side from one private key that stays home and one public key that's safe to send. That's the whole magic of asymmetric key exchange — and why a wiretap (the MITM) can't reconstruct it.

## Files by task

| Task | Files | What's in them |
|---|---|---|
| **T19** Keypair gen/load | `e2ee_chat/crypto_utils.py`, `tests/test_crypto_utils.py` | Generate/save/load an X25519 keypair; `keys/` gitignored |
| **T20** Export + fingerprint | `crypto_utils.py` | Public key as base64; SHA-256 fingerprint (grouped hex) — used in UC-5 |
| **T24** Session key | `crypto_utils.py` | X25519 ECDH + HKDF-SHA256 → AES-256 key |
| **T25** Client handshake | `e2ee_chat/client.py`, `tests/test_client.py` | Swap keys on connect, derive, block chat until ready |
| **T26** Debug hash | `client.py` | Print a short hash of the session key so both sides can confirm they match |
| **T21** No key on the wire | `tests/test_mitm_privacy.py` | Run a session through the MITM; assert the private key never appears in `intercepted.log` |

No server or protocol changes: `protocol.md` already defined the `pubkey` message, and the server already relays it blindly.

## What each piece does

### `e2ee_chat/crypto_utils.py` — all the crypto (T19, T20, T24)

| Function | Job |
|---|---|
| `load_or_create_keypair(username)` | Load `keys/<username>.key`, or generate an X25519 keypair and save it (raw 32 bytes) |
| `public_key_b64(private_key)` | The public key as base64 — what goes on the wire |
| `fingerprint(public_key_b64)` | SHA-256 of the public key as grouped hex, for the out-of-band check in UC-5 |
| `derive_session_key(my_private, peer_public_b64)` | ECDH → shared secret → HKDF-SHA256 → 32-byte AES-256 key. **Fixed, identical HKDF salt/info on both sides** — that's what makes both clients land on the *same* key |

### `e2ee_chat/client.py` — the handshake (T25, T26)

- On connect, the client **announces** its public key to its peer.
- When it receives the peer's key, it **derives the session key** and (for an announcement) **replies** once with its own key.
- `send_chat` raises until the session is ready, so **no plaintext is sent before the handshake finishes**; `main()` waits for the session before it accepts typed input.
- On success it prints `* secure session ready (key 9f3a…)`. Matching hashes on both windows = proof the key agreement worked (US-4 AC3).

## Design decisions (and why)

- **X25519, not RSA:** modern elliptic-curve Diffie-Hellman (what Signal and WireGuard use). Each side mixes its private key with the other's public key and both get the same secret, which never crosses the wire. A few lines with the `cryptography` library; no homemade crypto.
- **ECDH + HKDF-SHA256:** ECDH gives a shared secret; HKDF turns it into a clean, uniform 256-bit AES key. Both sides must use the **same salt and info string**, or they'd derive different keys and every UC-4 message would fail to decrypt.
- **Announce-vs-reply handshake:** an *announcement* always draws one *reply*; a reply draws none. This converges no matter who connects first, survives a client reconnecting with its same saved key, and can't loop. (Our first version deduped on the key value and got this wrong — a code review caught that a same-key reconnect would hang; see the dev log.)
- **Trust only the configured peer:** the client ignores a `pubkey` whose server-stamped `from` isn't its peer, so a third user can't slip in a key and desync the session.
- **Block chat until the key exists:** no message is ever sent in the clear before the secure session is set up (US-4 AC1).
- **The private key never leaves the machine:** it's only loaded locally and used in ECDH, never put in a message. `keys/` is gitignored, and a test (T21) proves the private key never shows up in the MITM's log.
- **No server change:** the server still just relays `pubkey` like any other message — it can't read the keys it forwards, which is exactly the point.

## Where this lands on the CIA triad

UC-3 **sets up** the shared key; it doesn't encrypt yet. But it's the enabler for:
- **Confidentiality** (UC-4): messages encrypted with this key — the MITM sees only ciphertext.
- **Integrity** (UC-4): AES-GCM's auth tag rejects tampered messages.
- **Authenticity** (UC-5): fingerprint verification catches a MITM that swaps keys.

**Honest limitation (important for the report):** UC-3's exchange is **unauthenticated**. An active MITM could substitute its own keys here and neither side would notice yet — that's the exact gap UC-5 (fingerprint verification) closes. The `fingerprint()` helper is built now so UC-5 can use it.

## Tests

- **Crypto (`test_crypto_utils.py`):** keypair is created then reused from disk; the public key round-trips; **two keypairs derive the *same* session key from each other's public key** (the core property); different peers give different keys; a bad peer key raises.
- **Handshake (`test_client.py`):** two clients converge on the same key in **either** connect order; chat is blocked until ready; a duplicate key is ignored; a reconnect with a new key re-derives; a malformed key doesn't crash the client; a key from a stranger is ignored; a same-key reconnect still converges.
- **Security (`test_mitm_privacy.py`):** run a real session through the MITM and assert the log captured the `pubkey` handshake but **no private-key bytes** (T21, US-3 AC2).

Full suite: all green on Ubuntu, Windows and macOS (CI). Lint and format checks pass.

## What's next

UC-4 uses this `session_key` to encrypt each message with **AES-256-GCM** (`--mode e2ee`). Then we re-run the UC-2 attack: the MITM log and Wireshark show only ciphertext. UC-5 adds the fingerprint check that defeats a key-swapping MITM.
