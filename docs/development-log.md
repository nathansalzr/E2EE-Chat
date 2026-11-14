# Development log

What we actually did for each use case, what we saw, and what didn't work.
This feeds the report's "what worked / what didn't" section and the slides.
Write it in plain language as you go, the same day you do the work, while the details are fresh.

**How to add an entry:** fill in each heading for your use case, replace _TBD_, tick the boxes, and put your name on **Done by**.
Screenshots go in OneDrive `05_Evidence` as `YYYY-MM-DD_UC#_what.png`.

---

## UC-1: Send and receive a chat message (plaintext)

**Date:** 2026-11-11 · **Done by:** _TBD (names)_ · **Tag:** `v0.1-plaintext` _(not yet)_

### Goal
Two users chat through our relay server in plaintext. This is the "before" picture: everything later attacks it or fixes it.

### What we built
- `e2ee_chat/protocol.py`: every message is a 4-byte length followed by JSON, so a message split across TCP reads still arrives whole.
- `e2ee_chat/server.py`: a relay server that registers usernames and forwards each message to the user named in `to`.
- `e2ee_chat/client.py`: a command-line chat client. Every line you type goes to your `--peer`.
- 69 automated tests, run by CI on Ubuntu, Windows and macOS.

### How we ran it
Using **three PowerShell windows**, one per program:

| Window | Command | What it showed |
|---|---|---|
| 1. Server | `.venv\Scripts\python -m e2ee_chat.server` | `[server] listening on 127.0.0.1:5050` |
| 2. Alice | `.venv\Scripts\python -m e2ee_chat.client --user alice --peer bob` | `Connected as alice. Messages go to bob.` |
| 3. Bob | `.venv\Scripts\python -m e2ee_chat.client --user bob --peer alice` | `Connected as bob. Messages go to alice.` |

### What we saw
- Running each script in its own window, we used the server to connect Bob and Alice, and they could send messages to each other.
- A message typed in Alice's window appeared in Bob's as `[alice] <message>` right away, and replies worked the other way too.
- The server window showed who joined and left, plus one line per message, such as `alice -> bob (chat)`. **It never showed the message text, but it received every message in plaintext and could have read it.** That's the weakness UC-2 exploits.

### Error handling we checked
| What we tried | What happened |
|---|---|
| Messaging Bob after he typed `/quit` | Alice saw `! user_offline: bob is not connected` |
| A second client also called `alice` | `! username_taken: alice is already connected`, and it exited |
| Stopping the server with Ctrl+C | Both clients printed `! connection to server lost` |
| Starting a client with no server | `! cannot reach server at 127.0.0.1:5050`, with no crash or traceback |

_Tick or correct these once you've tried each one yourself._

### What didn't work (and how we fixed it)
- **A test failed only on macOS in CI.** A 64 KB test message was sent into a socket pair before anything read from it. macOS's socket buffer is only about 8 KB, so the send waited for a reader that never started. Windows and Linux buffer more, so they passed. We fixed the test to send from a second thread. This is why CI runs on all three operating systems.
- **Our own code review found that hostile JSON could crash a connection.** Thousands of nested brackets, numbers thousands of digits long, or a broken Unicode character would kill that connection's thread, and the client would silently stop receiving. We now treat all of these as a `bad_message`. This matters for UC-2, because the attacker sits exactly where it can send them.
- **Terminal escape codes:** a peer could send characters that clear or rewrite your terminal. The client now replaces anything unprintable with `?` before showing it.

### Still to do
- [ ] Two-machine test over a phone hotspot (`docs/two-machine-setup.md`)
- [ ] A teammate who didn't write the code runs it from the README alone (US-1 AC5)
- [ ] Screenshot → `05_Evidence/2026-11-1X_UC1_plaintext-chat.png`, plus a 20-second clip
- [ ] Tag `v0.1-plaintext`

---

## UC-2: Intercept chat traffic as a man-in-the-middle

**Date:** 2026-11-13 · **Done by:** Vishank (MITM + first intercept run and evidence), Nathan (code review, hardening, tests, merge) · **Tag:** `v0.2-attack` _(not yet — waiting on the Wireshark shot)_

### Goal
Prove that plaintext chat is readable in transit, which covers the "perform an attack" half of the assignment.

### How we ran it
Four windows: server, attacker, Alice, Bob. The clients connect to the attacker's port (6060) instead of the server's (5050).

| Window | Command |
|---|---|
| 1. Server | `.venv\Scripts\python -m e2ee_chat.server` |
| 2. Attacker | `.venv\Scripts\python -m e2ee_chat.mitm --mode log` _(port 6060, forwards to 5050)_ |
| 3. Alice | `.venv\Scripts\python -m e2ee_chat.client --port 6060 --user alice --peer bob` |
| 4. Bob | `.venv\Scripts\python -m e2ee_chat.client --port 6060 --user bob --peer alice` |

Plus Wireshark capturing on the loopback adapter, filtered to `tcp.port == 6060`. _(Wireshark step still to do.)_

### What we saw
- Alice and Bob chatted normally through the MITM and couldn't tell it was there (US-2 AC1).
- The attacker window printed every message live, and `intercepted.log` captured the whole conversation — registrations and chat, both directions — in **readable plaintext**, including a planted "secret code" (AC2, AC3).
- The real server still only logged `alice -> bob (chat)` with no text, which is the point: the server looks innocent, but anyone *in the path* reads everything.

### What didn't work (and how we fixed it)
A code review plus an independent "fresh-eyes" review of `mitm.py` found five issues; all are fixed on the merged branch (PR #2). The useful ones for the report:
- **A single emoji or non-Latin character crashed the attacker's logging on Windows** and silently dropped that message and every message after it. The log file was opened without `encoding="utf-8"`, so Windows' default cp1252 codec raised on the first such character. Lesson: always set the encoding when writing text files; the default is platform-dependent. Fixed with `encoding="utf-8", errors="replace"`.
- **The MITM never closed its sockets when a client left,** so a blocked relay thread leaked and the real server never saw the client disconnect — the username stayed "taken" on reconnect. Fixed by closing both sockets when either direction ends.
- **The documented `--mode log` flag didn't actually exist** (the file had no argument parsing), so the attacker was really being run as plain `python -m e2ee_chat.mitm`. Added proper `--host`/`--port`/`--mode` arguments matching the server and client.
- Smaller: protocol/connection errors now end a relay direction cleanly instead of throwing a traceback, and a lock stops the two directions interleaving lines in the log.
- Added `tests/test_mitm.py` (a smoke test for the relay + plaintext logging) so these can't silently regress. Full suite: 70 tests pass.

### Evidence
- [x] Attacker terminal + `intercepted.log` screenshot (`docs/05_Evidence/uc2-plaintext-intercept.png1.jpeg`, `png2.jpeg`)
- [x] Wireshark screenshot showing the message text (`docs/05_Evidence/UC2_wireshark-plaintext.png`)
- [ ] 20-second clip

---

## UC-3: Set up a secure session (key exchange)

**Date:** 2026-11-13 · **Done by:** Nathan (design, implementation, review fixes, tests) · **Tag:** `v0.3-e2ee` _(not yet — UC-4 encryption still to come)_

### Goal
Both clients end up with the same AES-256 key, and the server and attacker can't compute it.

### What we built
- `crypto_utils.py`: X25519 keypair generate/load (`keys/<user>.key`, gitignored), base64 public key, SHA-256 fingerprint, and the session-key derivation (X25519 ECDH → HKDF-SHA256 → 32-byte AES-256 key).
- A handshake in `client.py`: each client **announces** its public key and **replies** once to the peer's announcement; chat is blocked until the shared key exists; both print a short hash of the key.
- New tests (crypto, handshake in both connect orders, no-private-key-on-wire). Full suite 92, lint + format clean.

### How we ran it
Through the new **web UI** (and the terminal): `python -m e2ee_chat.server`, then `python -m e2ee_chat.webclient --user alice --peer bob --web-port 8001` and the same for bob on 8002.

### What we saw
- Both windows showed the **same session-key hash** (e.g. `6ec58545`) — proof the two sides agreed on one key without it ever crossing the wire.
- The handshake converges no matter who connects first, and survives a client reconnecting with its saved key.
- A session run through the MITM shows the `pubkey` exchange in `intercepted.log` but **no private key** (`test_mitm_privacy.py`, US-3 AC2).

### What didn't work (and how we fixed it)
- A code review caught **two convergence bugs**: our first dedup rule (on the key value) silently dropped a same-key reconnect, and the handshake trusted a `pubkey` from *any* client, letting a third user desync the session. Both fixed (announce-vs-reply handshake, and trusting only the configured peer), each with a failing test first.
- **CI was red** at the `ruff format --check` step (stricter than `ruff check`, never satisfied since UC-2). Fixed by running `ruff format`.

### Evidence
- [x] Matching session-key hashes — visible side-by-side in the two web windows (screenshot for the report)

---

## Demo: web UI for the presentation

To make the live demo readable, each participant runs a small **localhost web window** instead of a raw terminal (`e2ee_chat/webclient.py`, stdlib only — no new dependencies). The browser is just a display; the real client, protocol and crypto stay in Python, so the terminal MITM attack is unchanged (point a window through the attacker with `--port 6060`). The window shows the secure-session key hash (UC-3) and the chat; it will show encrypted messages once UC-4 lands.

---

## UC-4: Send and receive an encrypted message

**Date:** _TBD_ · **Done by:** _TBD_ · **Tag:** `v0.3-e2ee` _(not yet)_

### Goal
The UC-2 attack now captures only gibberish, and a tampered message is rejected. This covers the "stop an attack" half.

### How we ran it _(planned)_
UC-2's four windows again, but both clients use `--mode e2ee`. Then restart the attacker with `--mode tamper`.

### What we saw
_TBD: the attacker log before vs. after encryption; what Bob saw when a message was tampered with._

### What didn't work
_TBD_

### Evidence
- [ ] Before/after side-by-side (plaintext log vs. ciphertext log)
- [ ] Wireshark capture showing only ciphertext
- [ ] "message failed integrity check" screenshot
- [ ] Clips

---

## UC-5: Verify a contact's key and catch key changes

**Date:** _TBD_ · **Done by:** _TBD_ · **Tag:** `v1.0` _(code freeze, Nov 16)_

### Goal
Show that encryption alone isn't enough when the attacker swaps public keys, then show the defense: a one-time fingerprint check that anchors first contact, **plus trust-on-first-use (TOFU)** that pins the peer's key and alarms if it ever changes. Together: encrypted messages **and** a continuous "same trusted key?" alarm.

### How we ran it _(planned)_
UC-2's four windows, with the attacker on `--mode swap-keys`. First nobody checks (attacker reads the "encrypted" chat); then both users `/fingerprint` and compare out-of-band (mismatch → `/abort`). Finally, pin a key, reconnect with a changed key, and show the TOFU "key changed — re-verify" alarm firing on its own.

### What we saw
_TBD: did the attacker read the "encrypted" chat? Did the fingerprints differ? Did the TOFU alarm fire on a changed key and stay silent on an unchanged one?_

### What didn't work
_TBD_

### Evidence
- [ ] Attacker reading the chat during the key swap
- [ ] Mismatched fingerprints screenshot
- [ ] TOFU "key changed" alarm screenshot
- [ ] Clips

---

## UC-7: Present the attack and the defense

**Date:** _TBD_ · **Done by:** _whole team_

### What we did
_TBD: rehearsal time, who presented which part, demo appointment date._

### What didn't work
_TBD: anything that broke in rehearsal or the live demo, and how the backup video was used._
