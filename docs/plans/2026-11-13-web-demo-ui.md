# Web demo UI — short design

A localhost web window per chat participant, so the demo looks like a real chat app instead of raw terminals. **Presentation only — it does not change the protocol or the crypto.**

## Intent
Make the live demo (and the recorded video) readable: Alice and Bob each get a browser window that behaves like a chat app, while the relay server and the MITM stay in the terminal so the attack mechanics are still visible.

## Approach (chosen): stdlib web wrapper, no new dependencies
- A new `e2ee_chat/webclient.py` serves a small HTML/JS chat page from Python's built-in `http.server` and bridges it to a `ChatClient` — the **same tested client, protocol and X25519/AES-GCM crypto**. The browser is only a display.
- One process = one participant = one browser window: `python -m e2ee_chat.webclient --user alice --peer bob --web-port 8001`.
- Browser ← server: **Server-Sent Events** (`GET /events`). Browser → server: `fetch` **POST** (`/send`). No WebSocket, no framework.
- It connects to the relay like any client, so `--port 6060` routes it **through the MITM** — the terminal attack demo is unchanged.

## Non-goals
- No crypto in the browser (stays in Python). The browser↔backend hop is local and trusted; the real endpoint is the Python process — we say so in the demo.
- Not a production app, no auth, localhost only.

## What it shows
- The **secure-session fingerprint** when the UC-3 handshake completes (a lock + short key hash that matches on both windows).
- Messages as a normal chat. Today they're still plaintext on the wire (UC-4 adds encryption); the same UI will show encrypted messages once UC-4 lands.

## Pieces
- `webclient.py`: `ChatApp` (holds the client + a pub/sub fan-out to browser tabs) + an `http.server` handler (`GET /`, `GET /events` SSE, `POST /send`). Opens the browser on start.
- Inline HTML/CSS/JS page (no build step).
