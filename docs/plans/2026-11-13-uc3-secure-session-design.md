# UC-3 design: set up a secure session (X25519 key exchange)

Design doc for UC-3 (US-3 keypair generation + US-4 public-key exchange). A builder could plan from this without re-reading the backlog. **Nothing gets built until this is approved.**

## Intent and why
Give Alice and Bob a **shared secret key that the server and the MITM cannot compute**, so UC-4 can encrypt messages with it. This is the asymmetric-crypto core of the project: each side keeps a private key on its own machine, they swap only public keys, and both derive the same AES-256 key by combining their private key with the other's public key. Without this, there's nothing to encrypt with.

## Goals
- Each client generates an X25519 keypair on first run and reuses it after (US-3 AC1).
- The private key never leaves the machine and never appears on the wire (US-3 AC2).
- The public key can be exported as base64 (US-3 AC3).
- Before any chat, the two clients exchange public keys using the existing `pubkey` message type (US-4 AC1).
- Both sides derive the **same** AES-256 session key via X25519 ECDH + HKDF-SHA256, shown by a matching debug hash (US-4 AC3).
- The MITM log shows public keys only — no private-key material (US-4 AC2).

## Non-goals (explicitly later)
- **Encrypting chat messages** — that's UC-4. After UC-3, chat is still sent as plaintext `chat` messages; only the shared key and a debug hash are new.
- **Detecting a key-swap MITM** — UC-3's exchange is *unauthenticated*, so an active MITM could substitute its own keys here. Defending that is UC-5 (fingerprints). The `fingerprint` helper (T20) is built now but *used* for verification in UC-5.

## Anti-goals (would be a failure even if it "works")
- Any homemade crypto. Use only the `cryptography` library's primitives.
- A private key written anywhere it could be committed, logged, or sent.
- A handshake that only works when one specific client connects first.

## Constraints
- `cryptography==50.0.2` only (already a dependency).
- Touches **`client.py` + new `crypto_utils.py`** only. No server or protocol changes — `protocol.md` already defines `pubkey`, and the server already relays it blindly.
- Must run on Windows and macOS (CI on both).

## Approaches considered (the handshake)
Either client may connect first, so "who sends their public key when" is the real design fork.

1. **Symmetric clients — CHOSEN.** Each client *announces* its public key on connect and *replies* once to a peer's announcement (an added `reply` flag on the `pubkey` message tells the two apart; the server relays it blindly). Converges no matter who connects first, tolerates the peer being offline at first, and survives a peer reconnecting with its same persisted key — all with **zero server changes**. Trade-off: one or two extra `pubkey` messages; a reply is terminal so it can't ping-pong, and only the configured peer's key is accepted.
2. **Server announces presence.** Server notifies a client when its peer is online, then they exchange. Cleaner ordering but requires a new server message and breaks the "UC-3 only touches the clients" boundary. Rejected.
3. **Lowest-username initiates.** Deterministic initiator, but still needs presence to know when to start, so it collapses into approach 2's problem. Rejected.

Key generation (X25519), key agreement (ECDH + HKDF-SHA256 → AES-256), and the `pubkey` message shape were already decided in the backlog / protocol spec v1; they are not re-opened here.

## The design

### New file: `e2ee_chat/crypto_utils.py`
A small, well-tested module. No sockets, no I/O beyond the key file — easy to unit-test.

| Function | Behavior |
|---|---|
| `load_or_create_keypair(username) -> X25519PrivateKey` | If `keys/<username>.key` exists, load it; else generate an X25519 keypair, save the private key (raw 32 bytes) to `keys/<username>.key`, and return it. Creates `keys/` if missing. |
| `public_key_b64(private_key) -> str` | Raw 32-byte X25519 public key, base64-encoded (US-3 AC3). |
| `fingerprint(public_key_b64) -> str` | SHA-256 of the public key, shown as grouped hex (e.g. `AB12 CD34 …`). Built now, used in UC-5. |
| `derive_session_key(my_private_key, peer_public_b64) -> bytes` | X25519 ECDH to a shared secret, then HKDF-SHA256 to a 32-byte (AES-256) key. **Fixed, identical HKDF `salt` and `info` on both sides** (e.g. `salt=None`, `info=b"e2ee-chat v1 session key"`) — this is what makes both clients land on the same key. Returns the 32-byte key. |

### Key persistence
- Private keys saved at `keys/<username>.key`, raw bytes. **Add `keys/` to `.gitignore`** (confirm it's already there; the UC-1 gitignore lists `keys/` — reuse it).
- The private key is only ever loaded locally and used in ECDH. It is never put in a message. (T21 verifies this against `intercepted.log`.)

### Handshake in `client.py` (approach 1)
State per client, guarded by locks — the announce runs on the main thread while replies and derivation run on the receive thread: `my_private`, `peer_public` (None until received), `session_key` (None until derived). A **send lock** serializes every socket write (both threads write the one socket); an **hs lock** guards the handshake state.

The `pubkey` message carries a boolean **`reply`** so a client can tell an *announcement* apart from a *reply*. The server relays the field blindly (no server change).

1. On connect + register: load/create keypair, send an **announcement** `{"type":"pubkey","to":<peer>,"key":<my pub b64>,"reply":false}`. If the peer is offline the server returns `user_offline` and drops it — fine: we're online when the later-joining peer announces, so their send reaches us.
2. On receiving a `pubkey`:
   - **Ignore it unless its server-stamped `from` is our configured peer.** (Stops a third client from overwriting our session and making the two honest clients hold different keys.)
   - If the key **changed** (first contact, or the peer reconnected with a different key) → derive `session_key`, store it, mark ready, emit the debug hash. An unchanged key is not re-derived.
   - **If it was an announcement (`reply` falsey) → reply once with our key (`reply:true`); if it was a reply → send nothing.** Answering every announcement (even for an unchanged key) is what lets a peer reconnecting with its *same persisted key* still receive ours; replies being terminal is what stops the ping-pong.
3. **Block chat until `session_key` is set.** `send_chat` raises `SessionNotReady` until then; `main()` waits for the session before accepting input. (US-4 AC1: no chat before the handshake finishes.)

**Why this converges (the invariant):** an announcement always draws exactly one reply, and a reply draws none. So every honest exchange — either connect order, first contact or a same-key reconnect — settles in a bounded number of messages with no loop, and only our configured peer can set up our key.

### Debug visibility (T26)
When `--debug` (or always in UC-3), each client prints a short hash of its session key, e.g. `session key: 9f3a…` (first bytes of SHA-256 of the key — **never the key itself**). Matching hashes on both clients = US-4 AC3 evidence for a screenshot.

## Tests
- **Unit (`tests/test_crypto_utils.py`):** keypair is created then reused from disk; `public_key_b64` round-trips; two keypairs derive the *same* session key from each other's public key (the core property); `derive_session_key` is symmetric; `fingerprint` format is stable; same public key → same fingerprint.
- **Integration (extend `tests/test_client.py`):** two in-process clients through the real server complete the handshake and end with equal session keys, in *either* connect order.
- **Security (T21, manual + a test):** run a session through the MITM and assert `intercepted.log` contains the `pubkey` messages but **no** private-key bytes.

## Task + acceptance-criteria mapping
| Task | This doc covers | AC |
|---|---|---|
| T19 keypair gen/save/load | `load_or_create_keypair`, `keys/` gitignored | US-3 AC1 |
| T20 base64 + fingerprint | `public_key_b64`, `fingerprint` | US-3 AC3 |
| T21 no private key on wire | security test + MITM check (Nathan) | US-3 AC2 |
| T24 session key (ECDH+HKDF) | `derive_session_key` | US-4 AC3 |
| T25 client handshake | the `client.py` handshake, block-until-ready | US-4 AC1 |
| T26 debug hash | session-key hash print | US-4 AC2/AC3 |

## What's left to the builder
- Exact CLI surface for the debug hash (`--debug` flag vs always-on in UC-3): builder's call; recommend always-on in UC-3, move behind `--debug` in UC-4.
- Whether an early typed line is dropped with a notice or queued and sent once ready: builder's call; a notice is simpler.
- HKDF `info` string wording — any fixed value works as long as both sides match.
- `keys/<username>.key` is relative to the working directory, so running a client from a different folder would generate a *new* keypair instead of reusing the saved one (US-3 "reuse after first run"). My call: document "run clients from the project root" (which is how the README already runs everything); a builder may instead anchor `keys/` to a fixed base path.

## Security notes
- Both sides **must** use identical HKDF `salt`/`info`, or they derive different keys and every message fails to decrypt in UC-4.
- This exchange is unauthenticated — an active MITM can swap keys (UC-5 problem). UC-3 does not claim to stop that.
- Private-key files should not be world-readable; for a class demo, `keys/` gitignored is the key control (NFR-4).
