# Demo video script: performing the attack, then stopping it

A shot-by-shot script for the recorded demo (and the live office-hours demo). It follows the use cases and shows end-to-end encryption defeating a man-in-the-middle through **encryption** (confidentiality + integrity) and **fingerprint verification** (authenticity).

- **Target length:** 10–12 minutes of demo + ~5 minutes Q&A (US-10 AC1).
- **Every member speaks** (US-10 AC1/AC4). Speaker tags below are placeholders — assign real names.
- **Record a backup video** (US-10 AC2) even if you also demo live.
- **Companion:** the storyline and threat model are in [`security-story.md`](security-story.md); the stage/command table is in [`ROADMAP.md`](ROADMAP.md).

## What you can record *today* vs. later

| Scene | Needs | Recordable now? |
|---|---|---|
| 1 Intro | slide/title | ✅ |
| 2 Plaintext chat (UC-1) | server + 2 clients | ✅ |
| 3 The attack (UC-2) | `mitm --mode log` + Wireshark | ✅ (`v0.2-attack`) |
| 4 Encryption defeats it (UC-4) | `client --mode e2ee` | ⏳ after UC-4 |
| 5 Tamper is caught (US-6) | `mitm --mode tamper` | ⏳ after UC-4 |
| 6 Key-swap beats naive E2EE (US-7) | `mitm --mode swap-keys` | ⏳ after UC-5 |
| 7 Fingerprints catch it (US-7) | `/fingerprint`, `/abort` | ⏳ after UC-5 |
| 8 CIA wrap + conclusion | slide | ✅ |

> Record scenes 1–3 and 8 now to lock in the UC-2 milestone; add 4–7 as each use case lands. Shooting in this order also lets each stage reuse the same window layout.

## Standard setup (use the same layout in every scene)

Arrange terminals so the camera tells the story left-to-right:

```
┌─────────────┬─────────────┐
│  ALICE      │   BOB       │   top row = the two honest users
├─────────────┴─────────────┤
│  ATTACKER (mitm.py)       │   middle = the man-in-the-middle, highlighted
├───────────────────────────┤
│  SERVER                   │   bottom = the relay
└───────────────────────────┘
+ Wireshark window for scene 3 (and scenes 4/6 to show ciphertext)
```

**Pre-record checklist:**
- [ ] `git checkout main && git pull` so you're on the tagged build.
- [ ] venv active in all four terminals.
- [ ] Font size large enough to read on screen (≥16pt); dark theme is fine.
- [ ] Delete any old `intercepted.log` so the capture starts clean.
- [ ] Wireshark on the loopback adapter, filter `tcp.port == 6060`, not yet recording.
- [ ] Have a short, memorable line ready to type (e.g. `Transfer $5000 to account 8891`) so the stakes are obvious.

---

## Scene 1 — Intro & threat model  *(~1 min)*  — Speaker: PM

- **Screen-record:** title slide → one simple diagram (Alice → server → Bob, with the attacker on the wire).
- **Narration:**
  > "We built a terminal chat app and then attacked it. Our attacker is a *man-in-the-middle*: someone sitting in the network path — think a rogue Wi-Fi hotspot or ARP spoofing on a shared network. The question this project answers: what can that attacker see, and how do we stop them? We'll show it in three acts — read the chat, encrypt the chat, and then beat the one attack that still works against naive encryption."

## Scene 2 — Plaintext chat works (UC-1)  *(~1 min)*  — Speaker: Crypto lead

- **Screen-record:** server starting, then Alice and Bob connecting and chatting.
- **On-screen action:**
  ```
  python -m e2ee_chat.server
  python -m e2ee_chat.client --user alice --peer bob
  python -m e2ee_chat.client --user bob --peer alice
  ```
  Alice types `Hi Bob`, Bob replies. Point out the **server window**: it logs `alice -> bob (chat)` but never the text.
- **Narration:**
  > "Normal chat through our relay server. Notice the server only logs *that* a message passed, not its content — it looks innocent. But it *could* read everything, and so can anyone else in the path. That's what we prove next."

## Scene 3 — The attack: reading plaintext (UC-2)  *(~2.5 min)*  — Speaker: Attack lead

- **Screen-record:** start the MITM, reconnect the clients through port 6060, chat, then show `intercepted.log` **and** the Wireshark Follow-TCP-Stream.
- **On-screen action:**
  ```
  python -m e2ee_chat.mitm --mode log
  python -m e2ee_chat.client --port 6060 --user alice --peer bob
  python -m e2ee_chat.client --port 6060 --user bob --peer alice
  ```
  Alice types the memorable line (`Transfer $5000 to account 8891`). Show the attacker terminal printing it live; open `intercepted.log`; switch to Wireshark → right-click a packet → **Follow → TCP Stream** → the message is in the clear.
- **Narration:**
  > "Now the clients connect through our attacker on port 6060 — exactly the position ARP or DNS spoofing would give a real attacker, without the victims noticing. The chat still works, so nobody suspects a thing. But watch: every message lands in `intercepted.log` in plain text, and Wireshark shows the same words sitting right in the packet. No confidentiality at all."
- **CIA callout (on screen):** ✗ Confidentiality broken.

## Scene 4 — Encryption defeats the same attack (UC-4)  *(~2 min)*  — Speaker: Crypto lead  ⏳
- **Screen-record:** the **same** MITM still running, clients restarted in `--mode e2ee`, chat, then back to `intercepted.log` / Wireshark showing gibberish.
- **On-screen action (planned):**
  ```
  python -m e2ee_chat.client --port 6060 --user alice --peer bob --mode e2ee
  python -m e2ee_chat.client --port 6060 --user bob --peer alice --mode e2ee
  ```
  Alice sends the same line. Show `intercepted.log` now contains only base64 ciphertext + nonce.
- **Narration:**
  > "Same attacker, same wiretap — we changed nothing on the attacker's side. The clients now do an X25519 key exchange and encrypt with AES-256-GCM. The attacker's log is now meaningless base64, and Wireshark shows no readable words. The private keys never left either machine. That's **confidentiality**."
- **CIA callout:** ✓ Confidentiality restored.

## Scene 5 — Tampering is caught (US-6)  *(~1.5 min)*  — Speaker: Attack lead  ⏳
- **Screen-record:** attacker in tamper mode; Bob's client rejecting the altered message.
- **On-screen action (planned):**
  ```
  python -m e2ee_chat.mitm --mode tamper
  ```
  Alice sends a message; the MITM flips one byte; Bob's window shows `message failed integrity check` and does **not** display it.
- **Narration:**
  > "Encryption hides the message — but could the attacker still *change* it? AES-GCM adds an authentication tag. We flip a single byte in transit, and Bob's client rejects it outright instead of showing altered text. That's **integrity**."
- **CIA callout:** ✓ Integrity.

## Scene 6 — Key-swap beats *naive* E2EE (US-7)  *(~1.5 min)*  — Speaker: Crypto lead  ⏳
- **Screen-record:** attacker in swap-keys mode, nobody verifying; attacker reading the "encrypted" chat again.
- **On-screen action (planned):**
  ```
  python -m e2ee_chat.mitm --mode swap-keys
  ```
  Clients connect in `--mode e2ee` but nobody checks fingerprints; show the attacker reading plaintext again.
- **Narration:**
  > "Here's the attack most people miss. If the attacker intercepts the *key exchange* and hands each side its own public key, it can decrypt and re-encrypt in the middle. Both sides think they're secure — but the attacker reads everything. Encryption alone didn't save us. This is the real-world gap behind Signal's safety numbers and SSH's fingerprint prompt."
- **CIA callout:** ✗ Authenticity broken — encryption isn't enough on its own.

## Scene 7 — Fingerprints catch the swap (US-7)  *(~1.5 min)*  — Speaker: Nathan
- **Screen-record:** same swap-keys attack, but Alice and Bob run `/fingerprint` and compare out-of-band.  ⏳
- **On-screen action (planned):** each client prints its own and the peer's fingerprint; Alice reads hers aloud (the "second channel"); they **don't match**; the user runs `/abort`.
- **Narration:**
  > "The fix is to verify *who holds the key*. Each client shows a short fingerprint of the keys in use. Alice and Bob compare them over a channel the attacker doesn't control — in person or by phone. With the attacker swapping keys, the fingerprints don't match, so they know they're being intercepted and abort. That's **authenticity** — and it's the piece that makes the encryption actually trustworthy."
- **CIA callout:** ✓ Authenticity.

## Scene 7b — The ongoing alarm: trust-on-first-use (US-7)  *(~1 min)*  — Speaker: Nathan  ⏳
- **Screen-record:** Alice and Bob chat once cleanly (key pinned), then reconnect with the peer's key changed — the client fires a "key changed — re-verify" warning on its own.
- **On-screen action (planned):** show a clean session (no warning), then a reconnect where the peer's pinned key no longer matches → the app alarms and asks to re-verify before continuing.
- **Narration:**
  > "Verifying once is good, but you shouldn't have to do it every time. The app **pins** your contact's key the first time and watches it. If that key ever changes — a man-in-the-middle sliding in later, or just a new phone — you get an alarm and re-check. Same idea as SSH's 'host key changed' warning. Encryption plus a continuous 'is this still the same trusted key?' check."
- **CIA callout:** ✓ Authenticity (continuous).

## Scene 8 — Wrap: the CIA story  *(~1 min)*  — Speaker: PM

- **Screen-record:** a summary slide — the attack→defense table from `security-story.md`.
- **Narration:**
  > "Same attacker the whole way through. Plaintext: they read everything. Encryption gave us **confidentiality** and **integrity** — unreadable, and tamper-proof. And fingerprint verification gave us **authenticity**, beating the key-swap attack that defeats naive encryption. The one thing we don't claim is availability — a man-in-the-middle can still cut the line, and defending that wasn't our goal. Everything we built mirrors how Signal, SSH and TLS solve the same problem in the real world."

---

## Editing / submission checklist
- [ ] Total runtime 10–15 min incl. intro and wrap (US-10 AC1).
- [ ] Every team member is heard (US-10 AC1/AC4).
- [ ] Each attack scene shows the attacker's view *and* the victim's view side by side.
- [ ] On-screen CIA callouts (✗/✓) at each stage.
- [ ] Captions or a lower-third naming the current use case, for the grader.
- [ ] Export a backup copy; store it with the evidence, not only on one laptop (US-10 AC2).

*Status: scenes 1–3 and 8 are recordable against the current `v0.2-attack` build. Scenes 4–7 become recordable as UC-4 and UC-5 are implemented.*
