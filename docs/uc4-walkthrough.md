# UC-4 walkthrough: send and receive an encrypted message (AES-256-GCM)

This covers what we built for UC-4 (US-5 + US-6), which files belong to which task, what each piece does, and why.
This is the **"stop an attack" half** of the project. The exact UC-2 attack now captures only ciphertext. If the attacker changes even one bit, the receiver catches it and drops the message.
Plan: [`plans/2026-11-17-uc4-encrypted-messaging-plan.md`](plans/2026-11-17-uc4-encrypted-messaging-plan.md).

## What it does

- In `--mode e2ee` (now the **default**), every chat line is encrypted with **AES-256-GCM**. The key is the UC-3 session key, which only Alice and Bob have.
- Each message gets a **fresh random 96-bit nonce**. Sending the same text twice produces different ciphertext.
- On the wire a message is `{"type": "encrypted", "to": "bob", "nonce": "<base64>", "ciphertext": "<base64>"}`. The server and the MITM relay it, but there's nothing readable in it.
- The receiver decrypts and **checks GCM's authentication tag**. If the message was altered, encrypted under another key, relabelled with a different sender, or malformed, it fails. Bob then sees `! message failed integrity check (from alice), dropped` and stays connected.
- In e2ee mode, the client **refuses plaintext `chat` messages** and warns `plaintext message rejected (possible downgrade attack)`.
- `--mode plain` keeps the UC-1 behaviour, so the demo can still show the "before" picture.

```
Alice                         MITM / server (relay only)                    Bob
"meet at 5"                                                                  
  │ AES-256-GCM(key, nonce, "meet at 5", AAD=alice|bob)                        
  │ ── {"type":"encrypted","nonce":"q3V…","ciphertext":"8fJ2…"} ──►  ──────────►│
  │                    sees only base64 noise                    decrypt + verify tag
  │                                                                  "meet at 5" ✔
  │                                                                              │
  │        mitm --mode tamper flips 1 bit of the ciphertext ──────────►  tag fails ✘
  │                                                      "message failed integrity check"
```

**Key point:** GCM gives us **two guarantees in one primitive**. Encryption keeps the text secret (confidentiality), and the authentication tag proves nobody changed it (integrity). The attacker can still *alter* bytes, but it can't do so without getting caught.

## Files by task

| Task | Files | What's in them |
|---|---|---|
| **T27** Encrypt/decrypt helpers | `e2ee_chat/crypto_utils.py`, `tests/test_crypto_utils.py` | `encrypt_message`, `decrypt_message`, `chat_aad`, `IntegrityError` |
| **T28** `--mode e2ee` | `e2ee_chat/client.py`, `tests/test_client.py` | Send `encrypted` instead of `chat`; decrypt on receive; `--mode plain` still works |
| **T32** Reject tampered messages | `client.py` | Any failed decryption becomes `integrity_error`: never displayed, connection stays up |
| **T66** No downgrade | `client.py` | An e2ee client turns any plaintext `chat` into `downgrade_rejected` |
| **T31** `mitm --mode tamper` | `e2ee_chat/mitm.py`, `tests/test_mitm.py` | Flip one bit of each encrypted message's ciphertext before forwarding |
| Web UI | `e2ee_chat/webclient.py`, `webclient_page.html`, `tests/test_webclient.py` | `--mode` flag, 🔒 on encrypted messages, red warnings for integrity/downgrade |
| **T29 / T33** Evidence | `docs/05_Evidence/` | Before/after attack log, Wireshark, tamper screenshot (recorded by hand) |

No server change. `protocol.md` already reserved the `encrypted` type, and the server relays it blindly like any other message.

## What each piece does

### `e2ee_chat/crypto_utils.py`: message crypto (T27)

| Function | Job |
|---|---|
| `encrypt_message(key, text, aad)` | AES-256-GCM with a fresh `os.urandom(12)` nonce; returns `(nonce_b64, ciphertext_b64)`. The ciphertext ends with the 16-byte auth tag |
| `decrypt_message(key, nonce_b64, ciphertext_b64, aad)` | Strict base64, nonce must be exactly 12 bytes, verify the tag, decode UTF-8. **Any** failure raises one `IntegrityError` |
| `chat_aad(sender, recipient)` | Associated data `e2ee-chat v1\|alice\|bob`. It's authenticated but not encrypted, and it ties the ciphertext to who sent it and who it's for |

### `e2ee_chat/client.py`: the e2ee mode (T28, T32, T66)

- `send_chat` in e2ee mode won't send until the session key exists (from UC-3). It then encrypts with AAD `sender|recipient` and sends an `encrypted` frame. It only sends to the session peer, because nobody else shares the key.
- The receive thread decrypts `encrypted` frames **before** anything reaches the screen. The CLI and the web UI only ever get plain `chat` events (marked `encrypted: True`) or a warning.
- `format_message` just formats. It never decrypts. (This fixed a bug from the first version; see the dev log.)

### `e2ee_chat/mitm.py`: tamper mode (T31)

- `tamper(msg)` base64-decodes the ciphertext, flips one bit, re-encodes, and returns a new message. Anything that isn't a well-formed `encrypted` message passes through untouched (US-6 AC3).
- It logs both the original and the `TAMPERED` copy, so the attacker's terminal shows exactly what was changed.
- It tampers only on the **client → server** leg. When both clients go through the MITM, a message passes it twice. Flipping the same bit twice would undo the attack.

## Design decisions (and why)

- **AES-256-GCM:** an AEAD cipher, so encryption and tamper detection come in one standard primitive (used in TLS 1.3, Signal, WireGuard-style designs). It comes from the `cryptography` library, not homemade crypto (NFR-1).
- **Random 96-bit nonce per message:** reusing a nonce with the same key breaks GCM completely. It leaks the XOR of the two plaintexts and lets an attacker forge tags. 12 random bytes is the size GCM is designed for, and we test that 1,000 encryptions never repeat a nonce.
- **AAD = sender + recipient:** the server stamps `from`, and the receiver rebuilds the AAD from it. If a MITM relabels a message ("this came from bob") or redirects it, the tag check fails. It's cheap, and it closes a gap that confidentiality alone leaves open.
- **A separate `encrypted` message type, not ciphertext inside `chat.text`:** the spec reserved it, the server needs no change, and the receiver can tell "encrypted" from "plaintext" by type. That's what makes downgrade rejection possible.
- **No downgrade (T66):** without it, a MITM could drop the encrypted frames and inject a plaintext `chat` that looks genuine. An e2ee client never displays plaintext.
- **One `IntegrityError` for every failure:** bad tag, wrong key, wrong AAD, bad base64 and bad UTF-8 all look the same to the user and to the attacker. We don't reveal which check failed.
- **Drop, don't disconnect:** a tampered message is rejected and the chat continues. Otherwise the attacker could end anyone's session just by flipping a bit.
- **Secure by default:** `--mode e2ee` is the default, so you have to opt in to plaintext, and the client warns `plain mode: messages are NOT encrypted`.
- **Network messages can't impersonate local events:** the client creates `secure_session`, `integrity_error` and `downgrade_rejected` itself and drops any frame from the network using those names. Only a successful decryption can mark a message 🔒. A code review showed a MITM could otherwise print a fake `secure session ready (key …)`, the very line UC-5's verification relies on.
- **Crypto stays in `crypto_utils.py`** (NFR-5), so it's unit-tested without sockets and readable in one place.

## Where this lands on the CIA triad

- **Confidentiality ✅:** the MITM log and Wireshark show only base64 ciphertext and nonces.
- **Integrity ✅:** a single flipped bit is caught by the GCM tag, and the message is never displayed.
- **Authenticity ⏳ (UC-5):** GCM proves the message came from *someone holding the session key*. Because UC-3's key exchange is unauthenticated, an active MITM that swaps public keys would hold that key. UC-5's fingerprint check closes that gap.
- **Availability:** a tampered message is dropped, not fatal. An attacker that drops everything can still block the chat, which no encryption prevents.

## Honest limitations (for the report)

- **No replay protection:** an attacker can re-send an old valid `encrypted` frame and it will decrypt again. A fix would be a per-message counter in the AAD. This is future work, together with forward secrecy.
- **Unauthenticated key exchange until UC-5**, as above.
- **Same key every session, no forward secrecy:** the session key comes from each user's long-lived X25519 key, so Alice and Bob get the same AES key every time they talk. A stolen `keys/` file would decrypt recorded past traffic, and the replay gap spans sessions. Ephemeral keys per session are future work.
- **Server `error` frames are still shown in e2ee mode** (e.g. `user_offline`). A malicious server could put misleading text in one. They're marked with `!`, not shown as chat.
- **Tamper demo needs the sender behind the MITM:** tampering acts on the client→server leg, so the *sending* client must connect through port 6060. Tamper mode flips every encrypted message. AC3 ("untouched messages still arrive") is shown by switching back to `--mode log` and by the tests.
- **Metadata is still visible:** the server and MITM see who talks to whom, when, and roughly how long each message is. E2EE hides content, not traffic patterns.

## Tests

- **Crypto (`test_crypto_utils.py`):**
  - Round trip with emoji.
  - 1,000 nonces are all unique and 12 bytes.
  - The same text gives different ciphertext.
  - Plaintext isn't present in the ciphertext.
  - A flipped ciphertext or nonce byte, the wrong key, a relabelled sender (AAD) and malformed fields all raise `IntegrityError`.
- **Client (`test_client.py`):**
  - Exact text arrives encrypted.
  - Only ciphertext is on the wire.
  - A tampered message gives `integrity_error`, the connection survives, and the next message still arrives.
  - Plaintext is rejected as a downgrade.
  - An encrypted message before the session exists is rejected.
  - Plain mode skips the handshake.
  - It won't encrypt to a non-peer.
- **Attack (`test_mitm.py`):**
  - The real UC-2 attack against e2ee: the log contains `encrypted`/`ciphertext` but **none of the words** of the message (US-5 AC3).
  - `--mode tamper` end to end: Bob gets `integrity_error`.
  - `tamper()` changes exactly one byte and leaves other messages alone.
- **Spoofing (`test_client.py`):** in both modes, a server or MITM sending our own local event types (`secure_session`, `integrity_error`, …) is ignored. A plaintext `chat` carrying `"encrypted": true` can't fake the 🔒.
- **Web UI (`test_webclient.py`):** the 🔒 flag and both warnings are translated; plain mode is ready at once and never shows a 🔒.

Full suite: 125 tests green; `ruff check` and `ruff format --check` clean.

## What's next

UC-5 adds `/fingerprint` and `mitm --mode swap-keys`. It shows that a key-swapping MITM beats naive E2EE, and that comparing fingerprints out-of-band catches it (plus the TOFU key-change alarm).
