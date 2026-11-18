# Demo guide: run every feature, and why it matters

This is the hands-on runbook for the live class demo and the office-hours demo. Each step gives you:
- the **commands** to run,
- **what the class should see**,
- the **real-world case** it maps to, so the audience knows why it matters outside our project.

The narrated video version is [`demo-script.md`](demo-script.md); the threat model is in [`security-story.md`](security-story.md).

> **Ethics:** every attack here runs only against our own app on our own machines (localhost). Never point `mitm.py` at anyone else's traffic.

## The one-sentence pitch

> A plaintext chat can be read and changed by anyone in the network path. We prove it, then add end-to-end encryption so the same attacker sees only noise and gets caught if they tamper. Signal, WhatsApp, iMessage and SSH solve the same problem the same way.

## Why this project is relevant

- **Encryption in transit alone isn't enough.** HTTPS/TLS protects you from the coffee-shop Wi-Fi, but the *server* still sees your messages. If that server is breached, misconfigured or subpoenaed, everything is exposed. **End-to-end** encryption means only the two endpoints hold the key, which is the point of our relay server that "can't read what it forwards".
- **On-path (man-in-the-middle) attacks are real and cheap:** rogue "Free Wi-Fi" hotspots (evil twin), ARP poisoning on a shared LAN, DNS spoofing, a compromised router. Our `mitm.py` plays that attacker.
- **The same building blocks run the apps everyone uses:**
  - X25519 key exchange and AES-GCM authenticated encryption are used in TLS 1.3, Signal and WireGuard.
  - Fingerprint checks are Signal's "safety numbers", WhatsApp's "security code", and SSH's "host key" prompt.

## Setup (do this before class)

Open **four terminals** (PowerShell) and run this in each:

```powershell
cd C:\Users\owner\Projects\school\E2EE-Chat
```
```powershell
.\.venv\Scripts\Activate.ps1
```

Arrange them: **Alice | Bob** on top, **Attacker** in the middle, **Server** at the bottom. Make the font large (≥16 pt).

Checklist:
- [ ] On `main` with the latest pull (`git switch main`, `git pull`).
- [ ] `python -m pytest -q` passes. This is a 10-second confidence check before going live.
- [ ] Old logs removed: `Remove-Item intercepted*.log -ErrorAction SilentlyContinue`
- [ ] No leftover clients from a rehearsal. If you get `username_taken`, close the old one or restart the server.
- [ ] Have a high-stakes line ready to type: **`Transfer $5000 to account 8891`**

---

## Step 1: Normal chat (UC-1, the baseline)

**Server terminal** (leave it running for the whole demo):
```powershell
python -m e2ee_chat.server
```
**Alice:**
```powershell
python -m e2ee_chat.client --mode plain --user alice --peer bob
```
**Bob:**
```powershell
python -m e2ee_chat.client --mode plain --user bob --peer alice
```

Alice types `Hi Bob`.

**The class sees:**
- Bob gets `[alice] Hi Bob`.
- The server logs only `alice -> bob (chat)`, never the text.
- Both clients warn `! plain mode: messages are NOT encrypted`.

**Real-world case:** this is any app that sends messages without encryption, like old SMS-style systems, internal tools on "trusted" networks, or IoT devices that talk in the clear. It works fine, and that's the problem: nothing looks wrong.

**Talking point:** "The server is polite and doesn't log our text. But it *could*, and so can anyone else in the path."

Close Alice and Bob (`/quit`) before the next step.

---

## Step 2: The attack: reading everything (UC-2)

**Attacker terminal:**
```powershell
python -m e2ee_chat.mitm --mode log
```
**Alice and Bob**, now pointed at the attacker's port 6060:
```powershell
python -m e2ee_chat.client --port 6060 --mode plain --user alice --peer bob
```
```powershell
python -m e2ee_chat.client --port 6060 --mode plain --user bob --peer alice
```

Alice types `Transfer $5000 to account 8891`.

**The class sees:**
- The chat still works, so Bob suspects nothing.
- The attacker terminal prints the message live, and `intercepted.log` holds the whole conversation.
- *Optional:* in Wireshark (loopback adapter, filter `tcp.port == 6060`), Follow → TCP Stream shows the same words in the packet.

**Real-world cases:**
- **Evil-twin Wi-Fi:** an attacker names a hotspot "Airport_Free_WiFi". Every device that joins routes through them, exactly like our clients routing through port 6060.
- **ARP poisoning on a shared LAN** (dorm, office, hotel): the attacker tells the network "I'm the router" and becomes the man in the middle.
- **A compromised or malicious server:** even with no attacker on the wire, the relay operator sees all plaintext. Many data breaches are exactly this: stored or relayed messages that were readable.

**Security+ tie-in:** on-path attack, evil twin, ARP poisoning. CIA: ✗ **confidentiality**.

Save the evidence, then close Alice, Bob and the attacker:
```powershell
Rename-Item intercepted.log intercepted-plain.log
```

---

## Step 3: Encryption defeats the same attack (UC-3 + UC-4)

**Attacker** (unchanged, same attack):
```powershell
python -m e2ee_chat.mitm --mode log
```
**Alice and Bob**, with no `--mode` flag because encryption is the default:
```powershell
python -m e2ee_chat.client --port 6060 --user alice --peer bob
```
```powershell
python -m e2ee_chat.client --port 6060 --user bob --peer alice
```

Alice sends the same `Transfer $5000 to account 8891`.

**The class sees:**
- Both clients print `* secure session ready (key xxxxxxxx)` with the **same hash**. They agreed on one key without ever sending it.
- Bob reads the message normally.
- The attacker only gets `{'type': 'encrypted', 'nonce': '…', 'ciphertext': '…'}`.
- Proof there's no readable text in the log (prints nothing):
  ```powershell
  Select-String -Path intercepted.log -Pattern "Transfer","8891"
  ```
- The attacker's log *does* contain the `pubkey` messages. Public keys are safe to show; the private keys never leave `keys/`.

**What's happening (one breath):** each client has an X25519 keypair. They swap **public** keys, and each combines its own private key with the other's public key (Diffie-Hellman) to compute the same secret. HKDF turns that secret into an AES-256 key. Every message is encrypted with AES-256-GCM and a fresh random nonce.

**Real-world cases:**
- **Signal / WhatsApp / iMessage:** the provider relays your messages but can't read them. That's our server.
- **TLS 1.3 (HTTPS):** the same idea, a Diffie-Hellman key exchange then AES-GCM, protects every website login.
- **Healthcare and legal messaging:** regulations like HIPAA push providers toward encryption so a server breach doesn't expose patient data.

**Security+ tie-in:** asymmetric vs. symmetric crypto, key exchange, hybrid encryption. CIA: ✓ **confidentiality**.

Put `intercepted-plain.log` and the new `intercepted.log` side by side. **This is the best slide in the deck.**

Save it, then close everything except the server:
```powershell
Rename-Item intercepted.log intercepted-e2ee.log
```

---

## Step 4: Tampering is caught (US-6)

**Attacker**, now altering traffic:
```powershell
python -m e2ee_chat.mitm --mode tamper
```
**Alice and Bob**, the same e2ee commands as Step 3. The **sender must connect through 6060**, because tampering happens on the way in.

Alice sends `Transfer $5000 to account 8891`.

**The class sees:**
- The attacker log shows each frame followed by a `TAMPERED` copy with one changed character in the ciphertext.
- Bob gets `! message failed integrity check (from alice), dropped`. **The altered message is never shown**, and Bob is still connected.

**Real-world cases:**
- **Payment and invoice fraud:** an attacker who can't read a message might still try to change a bank account number or amount in transit. AES-GCM's authentication tag makes any change, even a single bit, detectable.
- **Software updates and firmware:** the same principle (verify integrity before trusting data) is why updates are signed and why HTTPS uses authenticated encryption.
- **Encryption without integrity is a known trap.** Older modes like AES-CBC without a MAC allowed "bit-flipping" and padding-oracle attacks. AEAD modes such as GCM were adopted to close that gap.

**Talking point:** "The attacker can't read it, but they *can* still poke at it. GCM gives us a tamper seal: break it and the message is thrown away."

**Security+ tie-in:** integrity, hashing/MACs, AEAD. CIA: ✓ **integrity**.

To show that untouched messages still arrive, restart the attacker with `--mode log` and messages flow again.

---

## Step 5: No downgrade (T66)

Stop the attacker. Connect **straight to the server** (no `--port`), with Alice encrypted and Bob in plain mode:
```powershell
python -m e2ee_chat.client --user alice --peer bob
```
```powershell
python -m e2ee_chat.client --mode plain --user bob --peer alice
```

Bob types `this is really bob, trust me`.

**The class sees:**
- Alice first prints `! secure session not established yet (is your peer online?)`. That's expected, because a plain client never sends a key.
- When Bob types, Alice shows `! plaintext message rejected (possible downgrade attack) (from bob)`. The text is never displayed.

**Real-world cases:**
- **SSL stripping:** a classic on-path attack that quietly rewrote HTTPS links to HTTP so victims fell back to plaintext. HSTS was created to stop browsers from downgrading.
- **Protocol downgrade attacks** (POODLE, FREAK, Logjam): attackers forced connections onto old, weak crypto. The fix in each case was "refuse to fall back".
- Our rule is the same: **once you're in encrypted mode, plaintext is an alarm, not a fallback.**

**Security+ tie-in:** downgrade attacks, secure configuration and baselines.

---

## Step 6: The web UI (optional, for a cleaner audience view)

With the server running (add `--port 6060` to either to route it through the attacker):
```powershell
python -m e2ee_chat.webclient --user alice --peer bob --web-port 8001
```
```powershell
python -m e2ee_chat.webclient --user bob --peer alice --web-port 8002
```

**The class sees:**
- Chat-app windows with a green 🔒 status and matching key hashes.
- A 🔒 on every encrypted message.
- Red warnings for tamper and downgrade events.

`--mode plain` shows an amber "NOT encrypted" banner instead. It's a good side-by-side for non-technical viewers.

---

## Step 7: The attack that beats naive encryption (UC-5)

This is the strongest part of the demo. Encryption alone isn't enough if nobody checks *whose* key they're using.

Start fresh so nothing is pre-trusted:
```powershell
Remove-Item keys\known_peers -Recurse -ErrorAction SilentlyContinue
```
**Attacker**, now swapping keys:
```powershell
python -m e2ee_chat.mitm --mode swap-keys
```
**Alice and Bob** in e2ee mode through port 6060:
```powershell
python -m e2ee_chat.client --port 6060 --user alice --peer bob
```
```powershell
python -m e2ee_chat.client --port 6060 --user bob --peer alice
```

Alice sends `Transfer $5000 to account 8891`.

**The class sees:**
- Both still say `* secure session ready`, so nothing looks wrong, but their key hashes **differ**.
- The attacker terminal prints `DECRYPTED alice->bob: Transfer $5000 to account 8891`. Encryption didn't help, because each side is encrypting *to the attacker*.

**Now the fix.** Both run `/fingerprint` and read the lines aloud to each other (the "out-of-band" channel):
- Alice's "bob" fingerprint will **not** match Bob's own "your fingerprint" line.
- A mismatch means someone swapped the keys. Either user runs `/abort`.

**Real-world cases:**
- **Signal "safety numbers", WhatsApp "security code":** the exact same fingerprint comparison, so two people can confirm no one is in the middle.
- **SSH host keys:** the first time you connect, SSH pins the server's key; this is the fingerprint you're asked to accept.
- **TLS / HTTPS:** solves the same problem with certificate authorities instead of a manual check — a trusted third party vouches for the key.

**Security+ tie-in:** authenticity, PKI, certificate validation, out-of-band verification.

## Step 8: The ongoing alarm — trust-on-first-use (UC-5)

Verifying once is good; you shouldn't have to do it every time. The client **pins** a contact's key the first time and watches it.

1. First, a clean session so the real keys get pinned. Run the attacker in plain log mode:
   ```powershell
   python -m e2ee_chat.mitm --mode log
   ```
   Connect Alice and Bob (e2ee, port 6060), chat once. Each shows `* new contact …: key pinned`.
2. Stop the attacker, restart it swapping keys, and reconnect:
   ```powershell
   python -m e2ee_chat.mitm --mode swap-keys
   ```

**The class sees:** both clients fire `!!! WARNING: bob's key has CHANGED since your last session`, sending is blocked, and incoming messages are hidden until the user runs `/trust` (after re-verifying) or `/abort`. The attacker never sees the next message.

**Real-world case:** this is SSH's `REMOTE HOST IDENTIFICATION HAS CHANGED!` warning, and WhatsApp's "your security code with X changed". It catches a man-in-the-middle who shows up *after* first contact, or flags a legitimate reinstall so you re-verify.

In the **web UI**, the same change shows a red alarm banner with **Trust new key** and **Abort** buttons, and the message box is disabled until you choose.

## Honest limitations (expect these questions)

| Question | Answer |
|---|---|
| Can the attacker replay an old message? | Yes, for now. There's no message counter. Real protocols number messages. Future work. |
| If someone steals `keys/alice.key`? | They could decrypt recorded past traffic. We use long-lived keys, so there's no **forward secrecy**. Signal's Double Ratchet fixes this with new keys constantly. Future work. |
| Does encryption hide *who* is talking? | No. The server and attacker still see who messages whom, when, and roughly how long. That's metadata, and E2EE protects content only. |
| Can the attacker block the chat? | Yes. They can drop everything. Encryption protects confidentiality and integrity, not **availability**. |
| Did you write your own crypto? | No. Only standard primitives from the `cryptography` library (X25519, HKDF-SHA256, AES-256-GCM). Rolling your own crypto is a classic mistake. |

## CIA scorecard (end slide)

| Stage | Attacker can… | C | I | A(uth) |
|---|---|:-:|:-:|:-:|
| Plaintext (UC-1/2) | read and change everything | ✗ | ✗ | ✗ |
| E2EE (UC-3/4) | see only ciphertext; tampering is caught | ✓ | ✓ | ✗ |
| + Fingerprints (UC-5) | can't swap keys unnoticed | ✓ | ✓ | ✓ |

## Reset between rehearsals

```powershell
Remove-Item intercepted*.log -ErrorAction SilentlyContinue
```

Ctrl+C every terminal, then restart the server. Keep `keys/` between runs so the session-key hash stays the same. Delete `keys/` only to show a fresh key being generated.
