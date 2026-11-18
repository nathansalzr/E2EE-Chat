# Web demo console walkthrough: the whole project in the browser

What we built so the entire attack-and-defense story runs in a browser like a real
messaging app, with **no restarts** mid-demo and a **saved conversation** that shows
when a key changed. This sits on top of UC-1 to UC-5; the crypto is unchanged.

## What it does

- **One command** starts everything: `python -m e2ee_chat.demo`.
- An **attacker dashboard** in the browser switches the attack live — Off, Listen, Tamper, Swap keys — with buttons, and shows intercepted traffic colour-coded. No restart between attacks.
- Each **chat window auto-reconnects**, so switching the attacker's mode (or a blip) never makes the presenter restart a client. It can also switch **plain ↔ e2ee** live.
- A **saved conversation** persists per contact, encrypted at rest. Reopening a window shows earlier messages, and a **"key CHANGED" bubble appears inline** against them — the way Signal/WhatsApp show "security code changed".

## Files

| File | What's in it |
|---|---|
| `webutil.py` | Shared `EventHub` (Server-Sent Events + replay), the CSRF guard, and a small HTTP handler base — used by both the windows and the dashboard |
| `mitm.py` | `AttackState` (mode read per frame), an `off` mode, live `set_mode()`, `start_listener()`; a teardown fix (below) |
| `dashboard.py`, `dashboard_page.html` | The attacker console: mode buttons and the live intercept feed |
| `webclient.py`, `webclient_page.html` | Auto-reconnecting chat window, live mode toggle, Trust/Abort, history replay |
| `history.py` | Encrypted-at-rest conversation log |
| `demo.py` | One-command launcher: server + attacker + two windows |
| `crypto_utils.py` | `derive_storage_key()` for the history-at-rest key |

## How each piece works

### Attacker: one state, read per frame (`mitm.py`)
- An `AttackState` holds the current mode, the key swapper, and the live connections, all behind a lock.
- The relay pumps read `state.mode` **per frame**, so the dashboard changes the attack mid-stream.
- `off` forwards without logging — the clients can point at the attacker the whole demo and it's invisible until you turn Listen on.
- Switching **to or from swap-keys** drops the live connections on purpose: the clients auto-reconnect and redo the handshake through the new mode, which is the moment the key-change alarm fires.

### Chat window: never needs a restart (`webclient.py`)
- `ChatApp` owns the `ChatClient` and reconnects on a drop, with backoff. A **single-flight** guard (a generation counter plus a "connecting" flag under one lock) guarantees exactly one client per window, so a mode switch and a drop-triggered reconnect can't race into two connections.
- The plain/e2ee toggle reconnects in the new mode. Keys on disk persist across reconnects, so a clean reconnect is silent (`pinned`) and a reconnect whose key changed raises the alarm (`changed`) — the same UC-5 logic, now reachable live.
- Abort stops auto-reconnect and offers a Reconnect button.

### Saved history, encrypted at rest (`history.py`)
- Stored at `keys/history/<me>/<peer>.log` (under the gitignored `keys/`).
- Each line is `AES-256-GCM(json)` with a key from `derive_storage_key(private_key)` — HKDF over the user's own private key. A copied history file is unreadable without that user's `keys/<user>.key`.
- Corrupt or tampered lines are skipped, never shown.
- On page load the window replays the saved conversation as greyed "earlier" messages, so a later key-change bubble reads in context.

## Design decisions (and why)

- **Live mode switching instead of restarts.** A restart loses the audience. Holding the mode in shared state and reading it per frame lets the dashboard change the attack between two messages.
- **Dropping connections on a swap-keys switch.** The key-change alarm can only fire on a fresh handshake. Rather than ask the presenter to reconnect, the attacker resets the connections and the windows reconnect themselves.
- **Single-flight reconnect.** Reconnecting with the same username races the server's cleanup of the old one. One client per window plus the MITM teardown fix (below) makes reconnects clean, with no `username_taken` churn.
- **History encrypted at rest.** This is "data at rest" protection, separate from the "data in transit" E2EE. It makes the point that a stored conversation needs its own key, and that a stolen file is useless without it. (Security+: data states — at rest vs in transit; the two need separate controls.)
- **CSRF guard on every POST.** The windows and dashboard take actions (send, trust, switch mode) over local HTTP. Requiring same-origin and `application/json` stops any other page the presenter has open from driving them.
- **127.0.0.1 only.** Everything binds to loopback. This is a classroom demo on our own machine, not a service.

## A bug this surfaced (good report material)

Auto-reconnect exposed a latent flaw in the MITM. When a client disconnected, only one of the two relay pumps noticed; the other stayed blocked reading from the server, so the relay→server socket never closed and the **server kept the username registered**. A quick reconnect with the same name then hit `username_taken` repeatedly. The fix: when either pump ends, shut down both sockets so the other pump wakes and the connection tears down fully. It didn't show up until a client started reconnecting instantly, which the terminal demo never did.

## Demo flow (all in the browser, no restarts)

1. **Off** — Alice and Bob chat in plain.
2. **Listen** — the dashboard shows the text in red (readable).
3. Toggle both windows to **E2EE** — the dashboard now shows only grey ciphertext.
4. **Tamper** — Bob gets a "failed integrity check" bubble.
5. Bob toggles to **Plain** — Alice shows the downgrade warning.
6. **Swap keys** on a fresh contact (`--reset`) — the dashboard shows `DECRYPTED` lines; `/fingerprint` differs.
7. **Listen → chat (pins keys) → Swap keys** — both windows auto-reconnect and a **"key CHANGED" bubble** appears in the saved conversation; sending is blocked; Trust or Abort.

## Honest limitations (for the report)

- **History is your own plaintext, stored encrypted-at-rest.** It's the decrypted conversation (that's the point of a chat history), protected by your local key. If someone has both your history file and your key file, they can read it. Forward secrecy and history expiry are future work.
- **History protects each line, not the order of lines.** Every line has its own GCM tag, so a changed line is caught, but someone with write access to the file could delete, repeat or reorder whole lines unnoticed. A per-line counter in the AAD would fix it; noted as future work.
- **The demo trusts the local machine.** Loopback only, CSRF-guarded, but anyone at your keyboard can click the buttons. That's fine for a class demo.
- Carried over from UC-4/5: no forward secrecy, no replay protection, TOFU trusts the first key it sees.

## Tests

- `test_webutil`-style coverage lives in `test_webclient.py`, `test_mitm.py`, `test_history.py`, `test_demo.py`:
  - live mode switch takes effect; `off` writes no log; switching to swap-keys drops connections;
  - history round-trips, holds no plaintext, is unreadable under another user's key, skips corrupt lines, rejects unsafe names;
  - the window translates every event, replays history as "earlier", saves messages;
  - the CSRF guard rejects cross-origin and non-JSON POSTs and accepts both loopback spellings;
  - the launcher starts all three pages and stops cleanly.
- Full suite: 174 tests; `ruff check` and `ruff format --check` clean.
