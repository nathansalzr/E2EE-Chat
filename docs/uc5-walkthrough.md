# UC-5 walkthrough: verify a contact's key and catch key changes

What we built for UC-5 (US-7), which files belong to which task, what each piece does, and why.
This is the **authenticity** layer, and our strongest Q&A material. UC-4 made messages unreadable, but the key exchange itself was never verified. UC-5 shows the attack that still works against that, then the two defenses that stop it.
Plan: [`plans/2026-11-18-uc5-fingerprint-verification-plan.md`](plans/2026-11-18-uc5-fingerprint-verification-plan.md).

## The gap UC-5 closes

In UC-3/UC-4, Alice and Bob swap public keys over the untrusted network and nobody checks whose keys they really are. An active man-in-the-middle can give each side **its own** public key:

```
Alice ──pub(A)──►  [ MITM: swaps in pub(M) ]  ──pub(M)──► Bob
Alice ◄─pub(M)──  [ MITM: swaps in pub(M) ]  ◄──pub(B)─── Bob

Alice shares a key with M (thinks it's Bob).   Bob shares a key with M (thinks it's Alice).
Every message: Alice→M (decrypt, read, re-encrypt)→Bob.  Both see "secure session ready".
```

Encryption alone didn't help: both sides are encrypting, just to the attacker. This is the classic weakness behind Signal's safety numbers, WhatsApp's security code, and SSH's host-key prompt.

## What it does

- **`mitm --mode swap-keys`** carries out that attack against our own app (demo only).
- **`/fingerprint`** shows each user a short SHA-256 fingerprint of their own key and their peer's. Comparing them over a **separate channel** (in person or phone) reveals the swap: under the attack, Alice's "bob" fingerprint is really the attacker's and won't match Bob's own.
- **`/abort`** ends the session when the fingerprints don't match.
- **Trust-on-first-use (TOFU):** each client **pins** a peer's public key the first time it sees it (`keys/known_peers/<me>/<peer>.pub`). On every later session it compares. If the key changed, it raises a loud alarm, **blocks sending**, and **drops incoming messages without showing them** until the user runs `/trust` (after verifying) or `/abort`. Messages that arrive during the untrusted window are discarded, not queued — `/trust` only affects messages from then on.

## Files by task

| Task | Files | What's in them |
|---|---|---|
| **T35** Key-swap attack | `e2ee_chat/mitm.py`, `tests/test_mitm.py` | `KeySwapper`, `--mode swap-keys`: hand each side the attacker's key, decrypt/re-encrypt in the middle |
| **T34** Fingerprints | `e2ee_chat/client.py`, `tests/test_client.py` | `fingerprints()`, `/fingerprint`; the event carries both fingerprints (reuses `fingerprint()` from UC-3) |
| **T69** Trust-on-first-use | `crypto_utils.py`, `client.py` | `check_pin` / `pin_key`; pin on first contact, alarm + block on change |
| **T36** Abort / trust | `client.py` | `/abort` ends the session; `/trust` re-pins a verified key |
| Web UI | `webclient.py`, `webclient_page.html`, `tests/test_webclient.py` | fingerprint panel, red key-change alarm, Trust/Abort buttons, CSRF guard |
| **T37** Evidence | `docs/05_Evidence/` | key-swap log, mismatched-fingerprint screenshot, TOFU alarm screenshot (recorded by hand) |

No server or protocol change: the server still blindly relays `pubkey` and `encrypted`.

## What each piece does

### `crypto_utils.py`: key pinning (T69)

| Function | Job |
|---|---|
| `check_pin(me, peer, key, keys_dir)` | Compare `key` with the pinned one. `new` (and pins it), `pinned` (match), or `changed` (differs). A corrupt pin returns `changed` — fail closed |
| `pin_key(me, peer, key, keys_dir)` | Write/replace the pin (used by `/trust`) |
| `generate_keypair()` | A throwaway in-memory X25519 keypair, for the attacker's own key |

Pin files live under `keys/` (already gitignored) and are scoped per local user: `keys/known_peers/<me>/<peer>.pub`. Usernames are validated against the server's own rule before they're used as path parts, so nothing can escape the folder.

### `client.py`: fingerprints, trust, the alarm (T34, T36, T69)

- `_handle_pubkey` runs `check_pin` whenever the peer key is new or changed (which also covers a mid-session re-key). The `secure_session` event now carries `trust`, `my_fingerprint` and `peer_fingerprint`.
- A `changed` key clears `self.trusted`. While untrusted:
  - `send_chat` raises `KeyNotTrusted` (a `SessionNotReady` subclass), so nothing is sent.
  - incoming `encrypted` messages become `held_untrusted`: dropped, never shown (not buffered for later).
- `trust_peer()` re-pins the current key and unblocks; `abort()` closes the session.
- The new `secure_session`, `held_untrusted`, `key_trusted` and `session_aborted` types are in `LOCAL_EVENTS`, so a network frame can't fake them.

### `mitm.py`: the key-swap attack (T35)

- `KeySwapper` holds one in-memory attacker keypair and, behind a lock, the AES key it shares with each username.
- On the **client→server leg only** (same reason as tamper mode: a message crossing the MITM twice must not be processed twice):
  - a `pubkey` from a user is recorded and replaced with the attacker's public key;
  - an `encrypted` message is decrypted with the sender's shared key, **logged in the clear**, and re-encrypted for the recipient.
- It uses the same `cryptography` primitives as the client. The attacker isn't breaking AES; it just holds a key it was handed because nobody checked.

### Web UI

- A fingerprint panel ("you: … / bob: …") for the out-of-band comparison.
- On a changed key: a red alarm banner with **Trust new key** and **Abort** buttons, and the send box disabled until the user decides.
- **CSRF guard on every POST:** requests must be `application/json` and, if a browser sets `Origin`, same-origin (both `127.0.0.1` and `localhost` count as our loopback origin, so the buttons work whichever name the user typed). Without this, any website the presenter had open could POST to `localhost:8001/trust` and silently accept a swapped key.

## Design decisions (and why)

- **Fingerprints anchor the first contact; TOFU guards every session after.** The one-time out-of-band check is the only thing that can catch a swap on the *very first* exchange. Pinning then turns that into a continuous "is this still the same key?" monitor, so a MITM that arrives later (a user roams onto a hostile network) is flagged automatically. This is exactly the SSH model.
- **Fail closed.** A corrupt or unreadable pin counts as `changed`. When in doubt, alarm rather than trust.
- **Block, don't just warn.** On a changed key, sending is refused and incoming messages are hidden, so a user who ignores the banner still can't leak a message to an attacker's key.
- **`/trust` re-pins only the current key, and only on explicit action.** It never auto-accepts. The user is meant to compare fingerprints first; the command just records the decision.
- **Attacker keypair is in memory only.** Never written to `keys/`, nothing to clean up, and it can't be mistaken for a real user's key.
- **No new protocol.** Fingerprints are computed locally; pinning is local; the swap attack works within the existing message types. The server still can't tell any of this is happening, which is the point.

## Where this lands on the CIA triad

- **Authenticity ✅:** fingerprints prove *who* holds the key, and TOFU proves it's still the same key over time. This is the piece that makes UC-4's encryption trustworthy.
- Confidentiality and integrity (UC-4) only hold once you know you're encrypting to the right person, which is what UC-5 establishes.

## Honest limitations (for the report)

- **TOFU trusts the first key it sees.** If an attacker is already in the middle at first contact and the users never compare fingerprints, the attacker's key gets pinned as "trusted". Only the out-of-band check closes that, which is why we keep both.
- **Users can skip verification.** The security depends on someone actually comparing fingerprints. Real apps have the same problem (most people never check safety numbers).
- **No forward secrecy / no replay protection**, carried over from UC-4. Static keys mean a stolen key file decrypts past traffic.
- **A real PKI would use certificates.** TLS solves authenticity with certificate authorities instead of manual fingerprint checks; messaging apps use the fingerprint model we built.

## Tests

- **Pinning (`test_crypto_utils.py`):** new → pinned → changed; a changed key is not auto-pinned; pins are per-user; a corrupt pin fails closed; unsafe usernames are rejected.
- **Client (`test_client.py`):** first contact reports `new` with both fingerprints matching the real keys; same keys next session are `pinned` and chat works; a changed key alarms, blocks `send_chat`, holds incoming messages, then `trust_peer()` re-pins and unblocks; `abort()` ends the session; spoofed UC-5 events from the network are dropped; the CLI commands behave.
- **Attack (`test_mitm.py`):** swap-keys lets the attacker read the chat (AC2) and makes the fingerprints disagree (AC3); after a clean session pins the real keys, the swap trips the TOFU alarm on both sides, sending is blocked, and nothing leaks.
- **Web UI (`test_webclient.py`):** the new events translate; a changed key doesn't mark the session ready; the CSRF guard rejects a cross-site or wrong-content-type POST.

Full suite: 155 tests green; `ruff check` and `ruff format --check` clean.

## What's next

This completes the attack-and-defense arc (UC-1 → UC-5). Remaining work is the report, the slides and the demo (UC-7), plus the evidence screenshots. Forward secrecy and replay protection are documented as future work.
