# Security story: attack it, then stop it

The one-page backbone for the report and the presentation. It ties every use case to a threat and to the security property it protects, so the project reads as a single argument instead of five separate features.

**The thesis in one sentence:** a man-in-the-middle can read and alter a plaintext chat in transit; end-to-end encryption makes the same attacker see only ciphertext and get caught if they tamper; and fingerprint verification defeats the one attack that still beats naive encryption — the attacker swapping in its own keys.

---

## The system we built

| Piece | Role |
|---|---|
| `server.py` | A relay. Registers usernames and forwards each message to its recipient. It can see everything that passes through. |
| `client.py` (Alice, Bob) | The two chat users. Encrypts by default (`--mode e2ee`, UC-4); `--mode plain` keeps the unencrypted chat for the demo. Later gains a `/fingerprint` command. |
| `mitm.py` | Our own red-team man-in-the-middle. Sits in the path, forwards traffic so the chat still works, and logs everything. `--mode tamper` flips a ciphertext bit (UC-4); later gains `--mode swap-keys`. |
| Encryption (coming) | X25519 key exchange → shared AES-256-GCM session key. |
| Fingerprints (coming) | A short SHA-256 hash of each public key, compared out-of-band to detect key substitution. |

## Threat model (who the attacker is)

- **The attacker is in the network path** between the clients and the server — an active man-in-the-middle, not just a passive sniffer.
- **What they can do:** read every byte in transit, forward it, change it, drop it, or inject their own. In our demo the attacker also runs the relay position directly.
- **What they cannot do:** break AES-256-GCM or X25519, read a private key off a victim's machine, or touch the endpoints. Private keys never leave the device.
- **Assumptions:** the two users can compare a short fingerprint through a second channel they trust (in person, phone call) — the same assumption Signal and SSH make.
- **Out of scope:** endpoint compromise (malware on Alice's laptop), denial of service / availability, and traffic-analysis metadata (who talks to whom, and when).

**Honest note for the report:** in the demo the clients connect straight to the MITM's port (`--port 6060`). A real attacker instead gets into the path *below* the application — ARP spoofing on a LAN, a rogue Wi-Fi access point, or DNS spoofing — so the app's configured address silently routes through them. We simulate the *position*, not the lure; the interception logic is identical.

## Security properties (CIA — and where this project actually lands)

| Property | How we provide it | Shown by |
|---|---|---|
| **Confidentiality** | AES-256-GCM encrypts each message; only the holders of the session key can read it. | MITM log + Wireshark show only ciphertext after UC-4. |
| **Integrity** | AES-GCM's authentication tag changes if a single bit is altered; the recipient rejects it. | The tamper test: Bob sees `message failed integrity check`. |
| **Authenticity** of the key / endpoint | A one-time fingerprint comparison proves each side is talking to the *real* peer's key, not the attacker's substitute; **trust-on-first-use (TOFU)** then pins that key and alarms if it ever changes. | Fingerprints mismatch when the MITM swaps keys; a changed pinned key raises a "key changed — re-verify" alarm. |
| **Availability** | *Out of scope.* A MITM can drop or delay messages (denial of service); defending availability is not a goal of this project. | — |

> **Say this precisely in Q&A:** end-to-end encryption here directly delivers **Confidentiality** and **Integrity** (the two CIA properties cryptography protects in transit). The fingerprint check plus TOFU adds **Authenticity** — not the one-time kind, but *continuous*: verify the key once out-of-band, then the app watches it every session and alarms on any change. That is technically a fourth property, not part of the classic CIA triad. **Availability** we explicitly do not address. Being exact here reads as maturity, not a gap.

**The product promise, in one line:** every message is encrypted end-to-end, *and* the app continuously confirms you're still talking to the same verified key — the moment that key changes (a man-in-the-middle, a new device, a reinstall), you're alarmed and asked to re-verify. Fingerprint = verify once; TOFU = watch forever.

## The arc (attack → defense), stage by stage

Each stage is the *same attacker in the same position*; only the clients' defenses change.

| # | Use case | What the attacker does | What they get | Property proven | Built? |
|---|---|---|---|---|---|
| 1 | **UC-2** | Reads plaintext in transit (`mitm --mode log` + Wireshark) | The whole conversation in cleartext | *Motivation:* no confidentiality without encryption | ✅ Done (`v0.2-attack`) |
| 2 | **UC-4** | Reruns the exact same attack against encrypted chat | Only base64 ciphertext + nonce — no readable words | **Confidentiality** | ✅ Done (UC-4) |
| 3 | **UC-4 / US-6** | Flips one byte of ciphertext (`mitm --mode tamper`) | Bob's client rejects the message | **Integrity** | ✅ Done (UC-4) |
| 4 | **UC-5 / US-7** | Swaps its own public keys during the exchange (`mitm --mode swap-keys`), nobody checks | Reads the "encrypted" chat again — naive E2EE defeated | *Shows the real remaining threat* | ⏳ Pending |
| 5 | **UC-5 / US-7** | Same key-swap, but Alice and Bob compare fingerprints | Fingerprints don't match → they abort → attacker fails | **Authenticity** | ⏳ Pending |
| 6 | **UC-5 / US-7** | Appears *after* a trusted first contact and swaps keys | The peer's pinned key no longer matches → the app alarms automatically → user re-verifies | **Authenticity (continuous / TOFU)** | ⏳ Pending |

**Why stage 4 strengthens the project instead of weakening it:** the key-swap attack is a *known, fundamental* limitation of exchanging public keys over an untrusted channel — it exists whether or not we demo it. A project that stops at stage 3 looks secure but has an unaddressed hole a sharp grader would find. By showing the attack *and* the fingerprint defense, we prove the encryption is complete: it stands up to the strongest attacker, not just a passive one.

## Real-world anchors (for the report and Q&A)

Every defense here mirrors something in production security:

- **AES-256-GCM** — the same authenticated encryption used in TLS 1.3 and disk encryption.
- **X25519 key exchange** — the elliptic-curve Diffie-Hellman used by Signal, WireGuard and modern TLS.
- **Fingerprint verification** — Signal's "safety numbers," WhatsApp's "security code," SSH's host-key fingerprint prompt, and HTTPS certificate validation all exist to defeat exactly this key-swap MITM.

## One-line conclusion for the report

> We performed a man-in-the-middle attack that read our chat in plaintext, then defended against the *same attacker* with authenticated encryption and out-of-band key verification — demonstrating confidentiality, integrity and authenticity against an active adversary, and showing why encryption alone is not enough without verifying who holds the keys.

---

*Status: UC-1 to UC-4 are implemented (plaintext chat, the attack, the key exchange, encryption + tamper detection). UC-5 (fingerprints, key-change alarm) is planned per [`ROADMAP.md`](ROADMAP.md); the stages above marked ⏳ become recordable as those land.*
