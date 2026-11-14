# UC-2 walkthrough: intercept chat traffic as a man-in-the-middle

What we built for UC-2 (US-2), which files belong to which task, what each piece does, and why.
This is the **"perform an attack"** half of the project: it proves that plaintext chat is readable in transit.
Companion to [`uc1-walkthrough.md`](uc1-walkthrough.md). Message format: [`protocol.md`](protocol.md).

## What it does

- The attacker runs `mitm.py`, which listens on port **6060** — where the clients *think* the server is.
- Each client is started with `--port 6060`, so it connects to the MITM instead of the real server (port 5050).
- For every client that connects, the MITM opens its own connection to the real server and **relays every message both ways**, so Alice and Bob chat normally and can't tell (US-2 AC1).
- As each message passes through, the MITM **logs a copy** — timestamp, direction, and content — to `intercepted.log` and prints it live in the attacker's terminal (AC2, AC3).
- Because UC-1 is plaintext, the log is fully readable. UC-4 (encryption) is what turns that log into useless ciphertext, and UC-5 (fingerprints) is what catches the MITM swapping keys.

```
Alice --TCP--> mitm.py (6060) --TCP--> server.py (5050) --TCP--> mitm.py --TCP--> Bob
                  |  logs + prints every message both ways
                  v
            intercepted.log   (plaintext, gitignored)
```

**Why point the clients at the MITM directly?** In a real attack the attacker would use ARP or DNS spoofing to trick the clients onto its port. We skip that and point them there on purpose, on our own machines, and say so in the report. The interception logic is identical; only *how the victim is lured* is simplified.

## Files by task

| Task | Files | What's in them |
|---|---|---|
| **T14** MITM forwarding | `e2ee_chat/mitm.py` | Listen on 6060, open a server connection per client, relay both ways (one thread per direction) |
| **T15** MITM logging | `e2ee_chat/mitm.py` (`log_message`) | Write timestamp, direction and content to `intercepted.log`; live print to the terminal |
| **T17** Attack evidence | `docs/05_Evidence/uc2-plaintext-intercept.png*.jpeg` | Screenshots of the attacker terminal and the plaintext log |
| T12 MITM sketch | (design, by hand) | One-page sketch reviewed before coding |
| T13 Threat model | (design, by hand) | Who the attacker is, what they can see/change, out of scope |
| T16 README "Running the attack" | `README.md` | Start order, ports, where the log goes, ethics rule — *still to add* |

`intercepted.log` is **gitignored** (`.gitignore`: `intercepted.log` and `*.log`) and never committed — the captured traffic stays on the attacker's machine. Confirmed with `git ls-files`.

## What each piece does

### `e2ee_chat/mitm.py`: the man-in-the-middle (T14, T15)

| Name | Job |
|---|---|
| `LISTEN_HOST`/`LISTEN_PORT` | `127.0.0.1:6060` — where clients connect, thinking it's the server |
| `SERVER_HOST`/`SERVER_PORT` | `127.0.0.1:5050` — the real server the MITM forwards to |
| `log_message(direction, msg)` | Timestamp the message, print it, and append it to `intercepted.log` |
| `pump(source, destination, direction)` | Loop: read one message from `source`, log it, send it to `destination`, until the stream ends |
| `handle_client(client_sock)` | One connected client: open a socket to the real server, then run two pumps — one per direction — so both ways flow at once |
| `main()` | Bind and listen on 6060; accept clients, one thread each |

**How it reuses UC-1.** The MITM imports `recv_msg` / `send_msg` from `protocol.py`, the exact framing the server and client use. It doesn't need to understand the protocol — it just decodes each length-prefixed JSON frame far enough to log and re-send it. That's *why* the relay is transparent: the clients see byte-for-byte what they'd get from the real server.

**Threading model.** One `handle_client` thread per client. Inside it, the client→server direction runs in a daemon thread and the server→client direction runs inline. Two pumps = both directions move independently, so neither side blocks the other.

## Design decisions (and why)

- **A transparent relay, not a parser:** the MITM forwards every frame unchanged, so the chat keeps working and the attack is invisible (AC1). Later modes (`--mode tamper`, `--mode swap-keys`) will be the *only* places it changes what passes through.
- **Reusing `protocol.py`:** the attacker speaks the same wire format as the real server for free. If the protocol changes, the MITM follows automatically.
- **Log to a file *and* the terminal:** the file is the evidence artifact; the live print is what you screenshot for the demo.
- **`intercepted.log` is gitignored:** captured traffic is attack output, not source. It must never land in the repo (NFR-4).
- **Thread per direction:** simple to read and explain, and enough for a localhost demo.

## Tests

`tests/test_mitm.py` adds a smoke test: it starts the server + MITM + two in-process clients on free ports, sends a message containing non-ASCII text, and asserts it (a) reaches the peer unchanged (AC1) and (b) lands in the log as readable plaintext (AC2/AC3). This locks the behavior in — including the UTF-8 fix below — before the tamper/swap-keys modes build on this file. Full suite: **70 tests pass**, ruff clean.

## Issues found in review and fixed

A code review + independent "fresh-eyes" pass turned up five issues. All are fixed on this branch; the review itself is kept here as a record of the reasoning (good report material).

1. **(High) Non-ASCII message crashed logging on Windows.** `log_message` opened the log with `open(LOG_FILE, "a")` and no `encoding=`, so on Windows it used cp1252. The protocol serializes with `ensure_ascii=False`, so any emoji or non-Latin character (`你好`, `😀`) raised `UnicodeEncodeError`. Because logging happens *before* forwarding and the pump had no error handling, that message was dropped **and so was every later message in that direction** — breaking AC1/AC2/AC3. **Fixed:** open with `encoding="utf-8", errors="replace"`.
2. **(Medium) Sockets and threads were never closed.** `handle_client` closed nothing, so after a client hung up one pump stayed blocked on its socket forever, the real server never saw the client leave (username stuck as "taken" on reconnect), and sockets/threads leaked per connection. **Fixed:** `handle_client` now shuts down and closes both sockets when either pump ends, which also unblocks the other pump.
3. **(Medium) The documented `--mode log` flag didn't exist.** The docs said `python -m e2ee_chat.mitm --mode log`, but `mitm.py` had no argparse — ports were hardcoded and flags silently ignored (the original evidence screenshots run it as plain `python -m e2ee_chat.mitm`). **Fixed:** added argparse with `--host`/`--port`/`--server-host`/`--server-port` (reusing `protocol.port_number`) and `--mode {log}`, matching `server.py`/`client.py`. `tamper`/`swap-keys` get added to the `--mode` choices in their phases.
4. **(Low) Protocol/connection errors weren't caught.** A malformed frame or abrupt TCP reset raised out of a pump with a traceback. **Fixed:** the pump loop catches `OSError`/`ProtocolError`/`BadMessage` and ends that direction cleanly, falling through to the socket cleanup.
5. **(Low) Concurrent, unlocked log writes.** Both pump threads opened and wrote the log with no lock, so lines could interleave. **Fixed:** a module-level `threading.Lock` guards the print + write (mirroring the send lock in `server.py`).

Minor/left as-is: the log line is a Python dict repr (readable, so AC3 is met; pulling out `from`/`to`/`text` would read even cleaner — a nice-to-have). `--log-file` now lets you point the log somewhere fixed instead of the current directory.

## Still to do (for US-2 to be fully done)

- [ ] **AC5 — Wireshark capture** of the same chat showing the message text in the packets (filter `tcp.port == 6060`), screenshot saved in `05_Evidence`. The committed evidence covers AC2–AC4 (terminal + log) but **not** the Wireshark packet view. *(Manual, needs a person at the keyboard.)*
- [ ] **T16 — README "Running the attack"** section: start order, ports, where the log goes, the ethics rule.
- [ ] Tag `v0.2-attack` once AC5 + T16 are done.
- [ ] Fill in the UC-2 entry in `development-log.md` (date, who ran it) once the run is finalized.
