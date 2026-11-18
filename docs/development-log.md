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

To make the live demo readable, each participant runs a small **localhost web window** instead of a raw terminal (`e2ee_chat/webclient.py`, stdlib only — no new dependencies). The browser is just a display; the real client, protocol and crypto stay in Python, so the terminal MITM attack is unchanged (point a window through the attacker with `--port 6060`). The window shows the secure-session key hash (UC-3) and the chat; since UC-4 it marks encrypted messages with 🔒 and shows integrity/downgrade warnings in red.

---

## Demo: one-command web console (no restarts)

**Date:** 2026-11-19 · **Done by:** Nathan

To run the whole project in the browser like a real messaging app, we added a browser-driven console: `python -m e2ee_chat.demo` starts the server, the attacker and both chat windows, and you drive everything by clicking.

### What we built
- **Attacker dashboard** (`dashboard.py`) with an `off` mode and **live mode switching** — the MITM mode lives in a shared `AttackState` the relay reads per frame, so Off/Listen/Tamper/Swap-keys change with a button, no restart.
- **Auto-reconnecting chat windows** (`webclient.py`) with a live Plain/E2EE toggle and a single-flight connect guard, so switching the attack never needs a client restart. Keys persist across reconnects, so the UC-5 key-change alarm fires live.
- **Saved conversation, encrypted at rest** (`history.py`): `keys/history/<me>/<peer>.log`, AES-256-GCM with a key derived from the user's own private key. A reopened window replays earlier messages and shows a "key changed" bubble inline.
- Shared web helpers (`webutil.py`) and a one-command launcher (`demo.py`).
- 44 new tests (174 total), lint and format clean. Full write-up: [`web-demo-walkthrough.md`](web-demo-walkthrough.md).

### What we saw
- The full flow runs with no restarts: plain → listen → encrypt → tamper → downgrade → swap-keys, then a clean-session-then-swap that fires the key-change alarm and blocks sending while nothing leaks.
- History survives a refresh and the on-disk file shows no plaintext.

### What didn't work (and how we fixed it)
- **Auto-reconnect exposed a latent MITM bug.** When a client disconnected, only one of the relay's two pumps noticed; the other stayed blocked, the relay→server socket never closed, and the server kept the username registered — so an instant reconnect hit `username_taken` over and over. Fixed by shutting down both sockets when either pump ends. The terminal demo never reconnected instantly, so it never surfaced.
- **A mode toggle plus a drop could spawn two clients for one window.** Added a single-flight guard (generation counter + connecting flag under one lock) so there's exactly one client per window.
- **Code review found six more**, all fixed with a regression test each:
  - the refactored standalone `mitm.py` ran a second accept loop that silently dropped about half the clients;
  - a corrupt key file killed a window's connect worker and froze it for good (now it reports the problem and Plain still works);
  - one non-ASCII byte in a history file broke loading the whole file;
  - a normal Ctrl+C wrote "session aborted" into the saved history;
  - after a reconnect the window could show a spurious `user_offline` error;
  - a mode switch landing mid-send could put a 🔒 on a message that went out in plain.
- Terminal noise: a browser closing an event stream printed a `ConnectionAbortedError` traceback. Harmless, now silenced.
- **A leftover terminal MITM silently stole the demo's traffic.** During testing, an old `mitm --mode swap-keys` from a terminal run was still listening on 6060. Because the MITM set `SO_REUSEADDR`, Windows let the demo bind 6060 too and kept sending connections to the old process. The windows talked to an attacker with no dashboard, and its pre-fix code never released connections, so the E2EE toggle hung. Fixed by not setting `SO_REUSEADDR` on Windows for the MITM and the web servers (the relay server already did this). The launcher now stops with "port 6060 for the attacker (MITM) is already in use" and how to find the process. Security+ angle: `SO_REUSEADDR` on Windows enables port hijacking, which is why `SO_EXCLUSIVEADDRUSE` exists.

---

## UC-4: Send and receive an encrypted message

**Date:** 2026-11-17 · **Done by:** Alex (first AES-GCM version, PR 7), Nathan (rebuild on the UC-3 session key, tamper/downgrade handling, MITM tamper mode, web UI, tests, docs) · **Tag:** `v0.3-e2ee` _(after merge + evidence)_

### Goal
The UC-2 attack now captures only gibberish, and a tampered message is rejected. This covers the "stop an attack" half.

### What we built
- `crypto_utils.py`: AES-256-GCM `encrypt_message` / `decrypt_message` with a fresh 12-byte nonce per message, AAD binding sender and recipient, and one `IntegrityError` for every failure.
- `client.py --mode e2ee` (now the default): sends the reserved `encrypted` message type, decrypts before display, drops tampered messages without disconnecting, and rejects plaintext as a possible downgrade. `--mode plain` keeps the UC-1 chat for the demo.
- `mitm.py --mode tamper`: flips one bit of each encrypted message's ciphertext.
- Web UI: `--mode`, a 🔒 on encrypted messages, red warnings for integrity/downgrade.
- 33 new tests (125 total), lint and format clean. Full write-up: [`uc4-walkthrough.md`](uc4-walkthrough.md).

### How we ran it
UC-2's four windows again (server, `mitm --mode log`, alice and bob on `--port 6060`), with both clients in the default e2ee mode. Then we restarted the attacker with `--mode tamper`.

### What we saw
- With `--mode plain` the attacker log shows the chat in clear text. In e2ee mode the same attack logs only `{'type': 'encrypted', 'nonce': '…', 'ciphertext': '…'}`, with no readable words. The automated version of this check is `test_e2ee_through_mitm_log_shows_only_ciphertext`.
- With `--mode tamper`, Bob sees `! message failed integrity check (from alice), dropped`, stays connected, and the next untampered message still arrives.
- _TBD when recorded: Wireshark observations on `tcp.port == 6060`._

### What didn't work (and how we fixed it)
- **The first version (PR 7) was branched before UC-2/UC-3 merged.** It used a hardcoded test key instead of the session key and conflicted with `main` in `client.py`. We rebuilt UC-4 on a fresh branch from `main` and kept its nonce and base64 approach.
- **A bad tag disconnected the chat.** After catching `InvalidTag`, the first version still returned an unset variable. The receive thread crashed and the user saw "connection lost". Now every decryption failure becomes an `integrity_error` event and the chat continues.
- **Decrypting inside `format_message`** meant any non-encrypted message (an error, a plaintext chat) also crashed the display. Now decryption happens once in the receive thread, and formatting never touches ciphertext.
- **Tampering twice cancels out.** With both clients behind the MITM, every message passes it twice, and flipping the same bit on both legs restores the original. Tamper mode now only acts on the client→server leg.
- **Code review: spoofed local events.** A MITM could send a frame typed `secure_session` and the client printed a fake `* secure session ready (key deadbeef)`. A plaintext chat with `"encrypted": true` showed a 🔒 in the web UI. Now network frames using our local event names are dropped, and only a real decryption sets the 🔒. Both are covered by tests.

### Evidence
- [ ] Before/after side-by-side (plaintext log vs. ciphertext log)
- [ ] Wireshark capture showing only ciphertext
- [ ] "message failed integrity check" screenshot
- [ ] Clips

---

## UC-5: Verify a contact's key and catch key changes

**Date:** 2026-11-18 · **Done by:** Nathan (swap-keys attack, fingerprints, TOFU, web UI, tests, docs) · **Tag:** `v1.0` _(after merge + evidence)_

### Goal
Show that encryption alone isn't enough when the attacker swaps public keys, then show the defense: a one-time fingerprint check that anchors first contact, **plus trust-on-first-use (TOFU)** that pins the peer's key and alarms if it ever changes. Together: encrypted messages **and** a continuous "same trusted key?" alarm.

### What we built
- `mitm.py --mode swap-keys`: a `KeySwapper` hands each client the attacker's public key and decrypts/re-encrypts in the middle.
- `/fingerprint`, `/trust`, `/abort` in `client.py`; the `secure_session` event now carries both fingerprints and a `trust` value.
- TOFU pinning in `crypto_utils.py` (`check_pin`/`pin_key`): a changed key alarms, blocks sending, and hides incoming messages until `/trust` or `/abort`.
- Web UI: fingerprint panel, red key-change alarm with Trust/Abort buttons, plus a CSRF guard on all POSTs.
- 36 new tests (155 total), lint and format clean. Full write-up: [`uc5-walkthrough.md`](uc5-walkthrough.md).

### How we ran it
UC-2's four windows with the attacker on `--mode swap-keys`. First with fresh keys (nobody has pinned anything); then a clean `--mode log` session to pin the real keys, followed by reconnecting under `--mode swap-keys`.

### What we saw
- **The swap worked:** Alice and Bob showed *different* session-key hashes (each shares a key with the attacker), and the attacker log printed `DECRYPTED alice->bob: transfer 5000 to account 8891`. `/fingerprint` showed Alice's "bob" fingerprint differing from Bob's own — the out-of-band mismatch that reveals the attack.
- **TOFU caught it:** after a clean session pinned the real keys, reconnecting under the swap fired `!!! WARNING: bob's key has CHANGED`, sending was blocked, and the test message never appeared in the attacker's log.
- An unchanged key stays silent (just `* secure session ready`), and a brand-new contact shows the "verify once" hint.

### What didn't work (and how we fixed it)
- **A shared test helper didn't pass the attacker's keypair.** `_start_mitm_mode` was written for UC-4 (log/tamper) and never built a `KeySwapper`, so the first swap-keys tests saw no swap. Fixed by constructing one for that mode.
- **CSRF on the web UI.** Adding `/trust` meant a web page the presenter had open could POST to `localhost:8001/trust` and silently accept a swapped key. Added an Origin + `application/json` check on every POST, with a test.

### Evidence
- [ ] Attacker reading the chat during the key swap (`DECRYPTED` log line)
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
