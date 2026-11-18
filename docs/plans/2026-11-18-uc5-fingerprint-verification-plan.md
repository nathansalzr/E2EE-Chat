# UC-5 Fingerprint verification + TOFU: design and plan

**Goal:** show that encryption alone doesn't stop an active MITM who swaps public keys, then add the two defenses: a one-time out-of-band fingerprint check, and trust-on-first-use key pinning.

**Stories/tasks:** US-7; T34 (fingerprints), T35 (swap-keys attack), T36 (abort/trust), T37 (evidence), T69 (TOFU pinning).

## Design
- **Attack (`mitm.py --mode swap-keys`):** a `KeySwapper` with one in-memory attacker keypair and a lock-guarded `username → shared key` map. On the client→server leg it replaces each `pubkey` with the attacker's key and decrypts/re-encrypts each `encrypted` message, logging the plaintext. Client→server only, so a message crossing the MITM twice isn't double-processed.
- **Fingerprints (`/fingerprint`):** reuse `crypto_utils.fingerprint()`. The `secure_session` event carries `my_fingerprint` and `peer_fingerprint`.
- **TOFU (`check_pin`/`pin_key`):** pin the peer's key at `keys/known_peers/<me>/<peer>.pub`. `new` / `pinned` / `changed`; corrupt pin → `changed` (fail closed). Usernames validated before use as path parts.
- **Trust state:** a `changed` key clears `self.trusted`; `send_chat` raises `KeyNotTrusted` and incoming messages become `held_untrusted` until `/trust` (re-pin) or `/abort`.
- **Web UI:** fingerprint panel, red alarm + Trust/Abort buttons, send disabled until trusted. CSRF guard (Origin + Content-Type) on all POSTs.

## Review focus
1. Swap: a username unknown when its first encrypted frame arrives → forward unchanged, don't crash.
2. Path traversal via usernames in the pin filename.
3. Fail-closed on corrupt/unreadable pins.
4. A mid-session re-key keeps `trusted`/`session_ready` consistent under `_hs_lock`.
5. A changed key can never display a message or allow a send before `/trust`.
6. Network frames can't spoof the new local events.
7. CSRF guard actually blocks a cross-site POST to `/trust`.

## Steps
- [x] T69 pinning helpers + tests
- [x] T34/T36 client fingerprints, trust, abort, TOFU alarm + tests
- [x] T35 `mitm --mode swap-keys` + tests
- [x] Web UI panel, alarm, buttons, CSRF guard + tests
- [x] Docs: walkthrough, dev log, README, demo guide/script, security story, roadmap, protocol
- [ ] T37 evidence recorded by hand
- [ ] PR reviewed by a teammate, merged, tag `v1.0`
