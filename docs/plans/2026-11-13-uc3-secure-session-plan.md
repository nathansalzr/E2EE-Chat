# UC-3 Secure Session Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the two chat clients a shared AES-256 session key, derived from an X25519 key exchange, that the server and MITM cannot compute.

**Architecture:** A new `crypto_utils.py` holds all key operations (generate/load, base64 export, fingerprint, ECDH+HKDF derivation). `client.py` runs a symmetric handshake over the existing `pubkey` message type: each client sends its public key on connect and replies whenever it sees a *new* peer key, deduping repeats; chat is blocked until the session key exists. No server or protocol changes.

**Tech Stack:** Python 3.12, `cryptography==50.0.2` (X25519, HKDF-SHA256), stdlib `socket`/`threading`, pytest.

**Spec:** [`docs/plans/2026-11-13-uc3-secure-session-design.md`](2026-11-13-uc3-secure-session-design.md)

## Global Constraints
- Crypto primitives come **only** from the `cryptography` library — no homemade crypto.
- The private key is never put in a message and never logged; only the public key goes on the wire.
- Both sides use **identical** HKDF parameters: `salt=None`, `info=b"e2ee-chat v1 session key"`, length 32.
- Keys stored at `keys/<username>.key` as raw 32 bytes; `keys/` and `*.key` are already gitignored (no task needed — verified).
- Runs on Windows and macOS (CI on both).
- UC-3 does **not** encrypt chat messages (that is UC-4) and does **not** authenticate the exchange (that is UC-5).

## Review Focus
Inputs the design implies but a happy-path test would miss, most likely to bite first:
1. **Malformed `pubkey` from the MITM** (bad base64, wrong length) — the attacker sits exactly here; the client must not crash. → tested in Task 4.
2. **Peer reconnects with a *new* key mid-session** — both sides must re-derive the *same* new key, or UC-4 silently fails to decrypt. → tested in Task 4.
3. **A chat line typed before the session is ready** — must be blocked/queued, never sent as early plaintext (US-4 AC1). → tested in Task 4.
4. **Duplicate `pubkey` (same key) arrives** — must be ignored so the handshake can't ping-pong. → tested in Task 4.
5. **First run with no `keys/` directory** — it is created and a keypair is generated and reused next run. → tested in Task 1.

---

## File Structure
- **Create** `e2ee_chat/crypto_utils.py` — all key operations; no sockets.
- **Create** `tests/test_crypto_utils.py` — unit tests for the above.
- **Modify** `e2ee_chat/client.py` — add the handshake, block-until-ready, debug hash.
- **Modify** `tests/test_client.py` — handshake integration tests (both connect orders, the Review-Focus cases).
- **Create** `tests/test_mitm_privacy.py` — no private key on the wire (T21).

---

### Task 1: Keypair generation, persistence, and public-key export

**Files:**
- Create: `e2ee_chat/crypto_utils.py`
- Test: `tests/test_crypto_utils.py`

**Interfaces:**
- Produces:
  - `load_or_create_keypair(username: str, keys_dir: str = "keys") -> X25519PrivateKey`
  - `public_key_b64(private_key: X25519PrivateKey) -> str`

- [ ] **Step 1: Write failing tests**

```python
def test_keypair_created_then_reused(tmp_path):
    k1 = load_or_create_keypair("alice", keys_dir=str(tmp_path))
    assert (tmp_path / "alice.key").exists()
    k2 = load_or_create_keypair("alice", keys_dir=str(tmp_path))
    assert public_key_b64(k1) == public_key_b64(k2)   # same key loaded, not regenerated

def test_public_key_b64_is_decodable_32_bytes(tmp_path):
    k = load_or_create_keypair("bob", keys_dir=str(tmp_path))
    raw = base64.b64decode(public_key_b64(k))
    assert len(raw) == 32
```

- [ ] **Step 2: Run tests, verify they fail** — `pytest tests/test_crypto_utils.py -v` → FAIL (module/functions not defined).

- [ ] **Step 3: Implement both functions in `crypto_utils.py`.** `load_or_create_keypair`: if `<keys_dir>/<username>.key` exists, read 32 raw bytes and `X25519PrivateKey.from_private_bytes`; else create `keys_dir`, `X25519PrivateKey.generate()`, write its raw private bytes (`Encoding.Raw`, `PrivateFormat.Raw`, `NoEncryption`), return it. `public_key_b64`: raw public bytes → `base64.b64encode` → str.

- [ ] **Step 4: Run tests, verify they pass.**

- [ ] **Step 5: Commit** — `git commit -m "feat(crypto): X25519 keypair generate/load and base64 public key (T19)"`

---

### Task 2: Public-key fingerprint

**Files:**
- Modify: `e2ee_chat/crypto_utils.py`
- Test: `tests/test_crypto_utils.py`

**Interfaces:**
- Produces: `fingerprint(public_key_b64_str: str) -> str` (SHA-256 of the raw public key, grouped uppercase hex)

- [ ] **Step 1: Write failing tests**

```python
def test_fingerprint_is_stable_and_grouped(tmp_path):
    pub = public_key_b64(load_or_create_keypair("alice", keys_dir=str(tmp_path)))
    fp = fingerprint(pub)
    assert fp == fingerprint(pub)                 # deterministic
    assert set(fp.replace(" ", "")) <= set("0123456789ABCDEF")  # hex
    assert " " in fp                               # grouped for readability

def test_different_keys_differ(tmp_path):
    a = public_key_b64(load_or_create_keypair("a", keys_dir=str(tmp_path)))
    b = public_key_b64(load_or_create_keypair("b", keys_dir=str(tmp_path)))
    assert fingerprint(a) != fingerprint(b)
```

- [ ] **Step 2: Run tests, verify they fail.**

- [ ] **Step 3: Implement `fingerprint`** — `sha256(base64.b64decode(public_key_b64_str)).hexdigest().upper()`, inserting a space every 4 chars.

- [ ] **Step 4: Run tests, verify they pass.**

- [ ] **Step 5: Commit** — `git commit -m "feat(crypto): SHA-256 public-key fingerprint (T20)"`

---

### Task 3: Session-key derivation (ECDH + HKDF)

**Files:**
- Modify: `e2ee_chat/crypto_utils.py`
- Test: `tests/test_crypto_utils.py`

**Interfaces:**
- Consumes: `load_or_create_keypair`, `public_key_b64` (Task 1)
- Produces: `derive_session_key(my_private_key: X25519PrivateKey, peer_public_b64: str) -> bytes` (32-byte AES-256 key)

- [ ] **Step 1: Write the failing tests** (the core correctness property)

```python
def test_both_sides_derive_the_same_key(tmp_path):
    alice = load_or_create_keypair("alice", keys_dir=str(tmp_path))
    bob = load_or_create_keypair("bob", keys_dir=str(tmp_path))
    ka = derive_session_key(alice, public_key_b64(bob))
    kb = derive_session_key(bob, public_key_b64(alice))
    assert ka == kb and len(ka) == 32            # same 256-bit key on both sides

def test_different_peers_give_different_keys(tmp_path):
    alice = load_or_create_keypair("alice", keys_dir=str(tmp_path))
    bob = load_or_create_keypair("bob", keys_dir=str(tmp_path))
    eve = load_or_create_keypair("eve", keys_dir=str(tmp_path))
    assert derive_session_key(alice, public_key_b64(bob)) != derive_session_key(alice, public_key_b64(eve))

def test_bad_peer_key_raises(tmp_path):
    alice = load_or_create_keypair("alice", keys_dir=str(tmp_path))
    with pytest.raises(Exception):
        derive_session_key(alice, "not-valid-base64-or-key")
```

- [ ] **Step 2: Run tests, verify they fail.**

- [ ] **Step 3: Implement `derive_session_key`** — `my_private_key.exchange(X25519PublicKey.from_public_bytes(base64.b64decode(peer_public_b64)))` → shared secret; `HKDF(algorithm=SHA256(), length=32, salt=None, info=b"e2ee-chat v1 session key").derive(shared_secret)`. Use the exact `salt`/`info`/length from Global Constraints.

- [ ] **Step 4: Run tests, verify they pass.**

- [ ] **Step 5: Commit** — `git commit -m "feat(crypto): X25519 ECDH + HKDF session key (T24)"`

---

### Task 4: Client handshake (send, dedup, derive, block chat)

**Files:**
- Modify: `e2ee_chat/client.py`
- Test: `tests/test_client.py`

**Interfaces:**
- Consumes: `load_or_create_keypair`, `public_key_b64`, `derive_session_key` (Tasks 1, 3)
- Produces (on `ChatClient`): the constructor takes the peer name; `session_key: bytes | None` is set once derived; a `session_ready` threading.Event is set when it is; `send_chat` raises or no-ops until `session_ready` is set.

- [ ] **Step 1: Write failing tests** (cover Review-Focus 1–4). Use the existing in-process server+client test helpers.

```python
def test_handshake_same_key_alice_first(server):
    # alice connects, then bob; both end with equal, non-None session keys
def test_handshake_same_key_bob_first(server):
    # reverse connect order; same result (convergence in either order)
def test_chat_blocked_until_session_ready(server):
    # calling send_chat before the handshake completes does not send a plaintext chat frame
def test_duplicate_pubkey_is_ignored(server):
    # a second identical pubkey does not trigger another reply (no ping-pong)
def test_reconnect_with_new_key_rederives(server):
    # peer sends a different key; both sides converge on the new shared key
def test_malformed_pubkey_does_not_crash_client(server):
    # a pubkey with invalid base64 is handled, client stays alive, session stays not-ready
```

- [ ] **Step 2: Run tests, verify they fail.**

- [ ] **Step 3: Implement the handshake in `client.py` per the design's "Handshake" section** — on connect send our `pubkey` to the peer; intercept incoming `pubkey` messages in the receive path before display; **guard `peer_public`/`session_key` with one lock**; dedup on the peer key value (ignore an exact repeat, else store + reply + `derive_session_key` + set `session_ready` + print the debug hash); block `send_chat` until `session_ready`. A malformed peer key is caught and leaves the session not-ready rather than raising out of the receive thread.

- [ ] **Step 4: Run tests, verify they pass** (plus the full suite stays green).

- [ ] **Step 5: Commit** — `git commit -m "feat(client): X25519 handshake, block chat until session ready (T25, T26)"`

---

### Task 5: Verify no private key reaches the wire (T21)

**Files:**
- Create: `tests/test_mitm_privacy.py`

**Interfaces:**
- Consumes: the handshake (Task 4), `mitm.py`, `load_or_create_keypair` (Task 1)

- [ ] **Step 1: Write the failing test**

```python
def test_private_key_never_appears_in_mitm_log(tmp_path):
    # run server + mitm + two clients through port 6060 (as in test_mitm.py),
    # complete the handshake, then read the intercepted log and assert:
    #   - at least one {"type": "pubkey", ...} was captured
    #   - each client's raw private-key bytes (base64) do NOT appear in the log
```

- [ ] **Step 2: Run test, verify it fails** (handshake/log wiring not complete until Task 4).

- [ ] **Step 3: Implement the test harness** reusing the `_start_mitm` pattern from `tests/test_mitm.py`; derive each client's private-key base64 from its `keys/<username>.key` and assert absence in the log.

- [ ] **Step 4: Run test, verify it passes.**

- [ ] **Step 5: Commit** — `git commit -m "test(security): no private key on the wire through the MITM (T21)"`

---

## Self-review

**1. Spec coverage:** US-3 AC1 → Task 1; AC2 → Task 5; AC3 → Task 1 (`public_key_b64`). US-4 AC1 → Task 4 (block-until-ready); AC2 → Task 5 + Task 4; AC3 → Task 3 (same key) + Task 4 (debug hash). T19→T1, T20→T2, T24→T3, T25/T26→T4, T21→T5. No gaps.

**2. Step scan:** Each code step gives a signature and leaves the body to the implementer; test steps carry named assertions with the spec's exact values (32 bytes, the HKDF `salt`/`info`). No "handle edge cases" placeholders.

**3. Type consistency:** `load_or_create_keypair`, `public_key_b64`, `fingerprint`, `derive_session_key` are named identically everywhere they appear; `session_key`/`session_ready` names match between Task 4's interface and tests.

**4. Review Focus:** all five items have an owning test (1–4 in Task 4, 5 in Task 1).

**5. Proportion:** Plan is close to the design's length; code blocks are test assertions and signatures, not function bodies. OK.
