# UC-4 Encrypted Messaging: design and plan

**Goal:** encrypt every chat message end to end with AES-256-GCM using the UC-3 session key. The UC-2 attack then captures only ciphertext, a tampered message is rejected, and a plaintext message can't be slipped in (no downgrade).

**Stories:** US-5 (encrypted messaging), US-6 (tamper detection). **Tasks:** T27, T28, T29, T31, T32, T33, T66.

## Starting point
- A first version (PR 7, `feat/encrypted-messaging`) proved AES-GCM round-trips with a random 12-byte nonce. It was branched before UC-2/UC-3 merged, so it used a hardcoded test key, put the crypto in `protocol.py`, reused the `chat` type, and dropped the connection on a bad tag.
- We rebuilt UC-4 on a fresh branch from `main` (`feat/us5-encrypted-messaging`), keeping its nonce and base64 approach.

## Design
- **Wire format:** the reserved `encrypted` type, `{"type","to","nonce","ciphertext"}`, with base64 fields. No server change.
- **Crypto (`crypto_utils.py`):** `encrypt_message` / `decrypt_message` / `chat_aad` / `IntegrityError`. Every decryption failure maps to `IntegrityError`.
- **AAD:** `b"e2ee-chat v1|<sender>|<recipient>"`. The receiver rebuilds it from the server-stamped `from` and its own name. Usernames can't contain `|` (server rule), so the encoding is unambiguous.
- **Client modes:** `e2ee` (default: handshake, then encrypted frames) and `plain` (UC-1, no handshake). A client given a peer but no mode is e2ee.
- **Receive path:** `encrypted` → decrypt → `chat` with `encrypted: True`, or `integrity_error`. Plaintext `chat` in e2ee mode → `downgrade_rejected`. Formatting never decrypts.
- **MITM tamper mode:** flip one bit of the ciphertext on the client→server leg only, so a message that passes the MITM twice isn't flipped back.
- **Web UI:** a `--mode` flag, a 🔒 marker, and red warnings for integrity/downgrade events.

## Review focus (inputs a happy-path test would miss)
1. Tampered or malformed `encrypted` frames must not kill the receive thread. → client + MITM tests
2. A plaintext `chat` reaching an e2ee client must never be displayed. → T66 test
3. Nonce reuse. → 1,000-nonce uniqueness test
4. A relabelled `from` must fail the tag. → AAD test
5. The double-pass through the MITM must not undo the tamper. → end-to-end tamper test
6. Network frames must not impersonate local events (fake "secure session ready", fake 🔒). → spoofing tests (found in code review)

## Steps
- [x] T27 crypto helpers + tests
- [x] T28 / T32 / T66 client e2ee mode, tamper rejection, downgrade rejection + tests
- [x] T31 `mitm --mode tamper` + tests
- [x] Web UI mode + warnings + tests
- [x] Docs: walkthrough, dev log, README, protocol, security story, demo script, roadmap
- [ ] T29 / T33 evidence recorded by hand (before/after log, Wireshark, tamper screenshot)
- [ ] PR reviewed by a teammate, merged, tag `v0.3-e2ee`
