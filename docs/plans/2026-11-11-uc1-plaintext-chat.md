# UC-1 Plaintext Chat Implementation Plan

**Goal:** Two users chat in plaintext through our relay server. This is the "before" picture that UC-2 attacks and UC-3/UC-4 defend.

**Architecture:** One shared framing module (`protocol.py`) that every program uses: server, client, and later the MITM. The server is a thread-per-client relay that forwards messages by recipient name and never needs to read the text. The client is a CLI with a send loop on the main thread and a receive thread.

**Tech Stack:** Python 3.12+ standard library (`socket`, `threading`, `json`, `struct`, `argparse`), pytest, ruff.

**Spec:** `docs/ROADMAP.md` (sections 2 and 5, UC-1) and US-1 in the backlog workbook (AC1-AC5). Covers tasks T1, T3, T4, T5, T6, T7, T8, T9 and the `v0.1-plaintext` tag (T67). T2 (repo + CI) is done.

## Global Constraints

- Python `>=3.12`, standard library only for UC-1. `cryptography` is not used until UC-3.
- Every message is a **4-byte big-endian unsigned length prefix + UTF-8 JSON object** with a `"type"` field.
- Max frame body: **65536 bytes**. Anything larger is a protocol error and the connection is closed.
- Default port **5050** (macOS reserves 5000 for AirPlay). The server binds **127.0.0.1** by default; `--host 0.0.0.0` only for the two-machine test.
- Usernames: **1-20 characters, letters, digits, `_` or `-`** (regex `^[A-Za-z0-9_-]{1,20}$`).
- The server **sets `from`** on every relayed message from the sender's registered name. Clients can't spoof it.
- The server never prints or logs message text, only `sender -> recipient (type)`.
- Every feature ships with tests; `ruff check .`, `ruff format --check .` and `pytest` pass before each commit.
- Client `--mode` exists now with one choice, `plain`; `e2ee` is added in UC-4 (T28).

## Review Focus

1. **A message split across several TCP reads**: it must still arrive whole (Task 2 `test_recv_handles_split_frame`).
2. **A bad length prefix (huge or truncated)**: the server drops that client and keeps serving everyone else (Task 3 `test_oversized_frame_drops_only_that_client`).
3. **Valid frame, bad JSON or a missing `type`**: the server answers `bad_message` and keeps the connection open (Task 3 `test_malformed_json_gets_error_and_connection_survives`).
4. **A client sets `from` to someone else's name**: the recipient sees the real sender (Task 3 `test_server_overwrites_from_field`).
5. **A client vanishes mid-chat (laptop lid closed)**: its username is freed and the server doesn't crash (Task 3 `test_disconnect_frees_username`).

---

### Task 1: Protocol spec v1 (T1), team sign-off gate

**Files:**
- Create: `docs/protocol.md` (copy to OneDrive `02_Design` for the team to review)

**Interfaces:**
- Produces: the message catalog every later task codes against.

- [ ] **Step 1: Write `docs/protocol.md`** with exactly these sections:
  - **Framing:** `struct.pack("!I", len(body)) + body`, body = `json.dumps(msg, ensure_ascii=False).encode("utf-8")`, max body 65536 bytes.
  - **Messages (UC-1):**
    | Direction | Message |
    |---|---|
    | client → server | `{"type": "register", "username": "alice"}` |
    | server → client | `{"type": "registered", "username": "alice"}` |
    | client → server | `{"type": "chat", "to": "bob", "text": "hi"}` |
    | server → recipient | `{"type": "chat", "from": "alice", "to": "bob", "text": "hi"}` |
    | server → client | `{"type": "error", "code": "<code>", "message": "<human text>"}` |
  - **Error codes:** `invalid_username`, `username_taken`, `not_registered`, `user_offline`, `bad_message`.
  - **Reserved for UC-3/UC-4 (relayed exactly like `chat`):** `{"type": "pubkey", "to", "key"}` and `{"type": "encrypted", "to", "nonce", "ciphertext"}`. Relay types = `chat`, `pubkey`, `encrypted`.
  - **Order:** connect → `register` → wait for `registered` or `error` → relay messages.
  - **Ports:** server 5050, MITM 6060 (UC-2).
- [ ] **Step 2: Team sign-off.** Post `docs/protocol.md` in the group chat and get a thumbs-up from all four members. The roadmap rule is no coding against the protocol before this.
- [ ] **Step 3: Commit** `docs/protocol.md`: `git commit -m "Add protocol spec v1 (T1)"`

---

### Task 2: Shared framing helpers (T3)

**Files:**
- Create: `e2ee_chat/protocol.py`
- Test: `tests/test_protocol.py`

**Interfaces:**
- Produces:
  - `DEFAULT_PORT = 5050`, `MAX_FRAME = 65536`, `RELAY_TYPES = frozenset({"chat", "pubkey", "encrypted"})`
  - `USERNAME_PATTERN` (compiled regex from Global Constraints), `is_valid_username(name: str) -> bool`
  - `class ProtocolError(Exception)`: framing is broken; the caller should close the connection.
  - `encode_frame(msg: dict) -> bytes`
  - `send_msg(sock: socket.socket, msg: dict) -> None` (uses `sock.sendall`)
  - `recv_frame(sock: socket.socket) -> bytes | None`: framing only. Returns the raw body, `None` on a clean close before a new frame starts, and raises `ProtocolError` on a truncated frame or an oversized length.
  - `class BadMessage(ProtocolError)`: the frame was fine but the content wasn't. The server answers `bad_message` and keeps the connection.
  - `decode_body(body: bytes) -> dict`: raises `BadMessage` on bad UTF-8, invalid JSON, or a JSON value that isn't an object with a string `type`.
  - `recv_msg(sock: socket.socket) -> dict | None`: `recv_frame` followed by `decode_body`. Clients use this; the server calls the two halves separately.

- [ ] **Step 1: Write the failing tests** using `socket.socketpair()`:
  - `test_round_trip_simple_message`: send `{"type": "chat", "to": "bob", "text": "hi"}`, receive the identical dict.
  - `test_round_trip_unicode_text`: `"text": "héllo 👋"` survives.
  - `test_recv_handles_split_frame`: write `encode_frame(msg)` one byte at a time from a thread; `recv_msg` returns `msg`.
  - `test_two_frames_back_to_back`: two frames in one `sendall`; two `recv_msg` calls return them in order.
  - `test_clean_close_returns_none`: close the writer, and `recv_msg` returns `None`.
  - `test_truncated_frame_raises`: send the prefix for 10 bytes plus 3 bytes, close; `ProtocolError`.
  - `test_oversized_length_raises`: prefix `MAX_FRAME + 1`; `ProtocolError` without reading the body.
  - `test_invalid_json_raises_bad_message` / `test_non_object_json_raises_bad_message` (body `b"[1,2]"`) / `test_missing_type_raises_bad_message` (body `b"{}"`): each raises `BadMessage`.
  - `test_recv_frame_returns_raw_body`: `recv_frame` returns the exact body bytes without decoding.
  - `test_encode_rejects_oversized_message`: `encode_frame` on a 70,000-char text raises `ProtocolError`.
  - `test_username_rules`: `alice`, `Bob_2`, `a-b` valid; `""`, `"a" * 21`, `"al ice"`, `"bob!"` invalid.
- [ ] **Step 2: Run** `pytest tests/test_protocol.py -v`. Expected: FAIL (module not found).
- [ ] **Step 3: Implement `e2ee_chat/protocol.py`.** `recv_frame` reads with a private `_recv_exact(sock, n) -> bytes` that loops on `sock.recv` until it has `n` bytes (that's what handles split reads); EOF at zero bytes into the prefix → `None`, EOF anywhere else → `ProtocolError`. Check the length against `MAX_FRAME` before reading the body.
- [ ] **Step 4: Run** `pytest tests/test_protocol.py -v`. Expected: all PASS.
- [ ] **Step 5: Run** `ruff check . && ruff format --check . && pytest`, then commit: `git commit -m "Add length-prefixed JSON framing helpers (T3)"`

---

### Task 3: Relay server with error handling (T4, T7 server side)

**Files:**
- Create: `e2ee_chat/server.py`
- Test: `tests/test_server.py`

**Interfaces:**
- Consumes: everything from Task 2.
- Produces:
  - `class ChatServer(host: str = "127.0.0.1", port: int = DEFAULT_PORT)`
    - `start() -> None`: binds, listens and starts the accept thread; after it returns, `self.port` is the real port (tests pass `port=0`).
    - `stop() -> None`: closes the listening socket and every client connection; idempotent.
    - `online_users() -> set[str]`
  - `main(argv: list[str] | None = None) -> None`: `--host` (default `127.0.0.1`), `--port` (default 5050); prints `[server] listening on HOST:PORT`, Ctrl+C stops cleanly. Run with `python -m e2ee_chat.server`.
- Behavior:
  - First message must be `register`. Invalid name → `invalid_username`, taken → `username_taken` (the connection stays open so the client can retry); success → `registered`.
  - A relay type before registering → `not_registered`.
  - A relay type with a valid `to`: forward a copy with `"from"` set to the sender's registered name; recipient missing → `user_offline` to the sender.
  - Unknown `type`, or a relay message without a string `to` → `bad_message`.
  - `BadMessage` (from `decode_body`): reply `bad_message`, keep the connection.
  - Any other `ProtocolError` (from `recv_frame`): send nothing, close **only** that connection.
  - Disconnect (clean or not): remove the username and close the socket. One lock guards the user table; each connection has its own send lock so two senders can't interleave bytes.
  - Console logs only `alice -> bob (chat)`, never the text.

- [ ] **Step 1: Write the failing tests.** A pytest fixture starts `ChatServer(port=0)` and stops it after; a helper `connect(name)` opens a socket with a 2 s timeout, registers, and asserts the `registered` reply.
  - `test_register_and_relay_chat`: alice sends `{"type":"chat","to":"bob","text":"hi"}`; bob receives `{"type":"chat","from":"alice","to":"bob","text":"hi"}`.
  - `test_relay_works_both_ways`
  - `test_server_overwrites_from_field`: alice sends `"from": "bob"`; bob receives `"from": "alice"`.
  - `test_duplicate_username_rejected` → `error`/`username_taken`, then registering `alice2` on the same socket succeeds.
  - `test_invalid_username_rejected` → `invalid_username` for `"al ice"`.
  - `test_chat_before_register` → `not_registered`.
  - `test_recipient_offline` → `user_offline`.
  - `test_malformed_json_gets_error_and_connection_survives`: send a valid prefix + `b"{not json"`; get `bad_message`; a following valid chat still relays.
  - `test_unknown_type_gets_bad_message`
  - `test_oversized_frame_drops_only_that_client`: a third socket sends prefix `MAX_FRAME + 1`; its next `recv` returns `b""`; alice → bob still works.
  - `test_disconnect_frees_username`: bob closes; within 1 s `"bob" not in server.online_users()`; a new `bob` can register.
  - `test_pubkey_and_encrypted_are_relayed`: both reserved types arrive at the recipient with `from` set.
- [ ] **Step 2: Run** `pytest tests/test_server.py -v`. Expected: FAIL (module not found).
- [ ] **Step 3: Implement `e2ee_chat/server.py`.** One thread per client runs a loop: `recv_frame` → `decode_body` → handle. `ChatServer.stop()` closes the listening socket and every client socket, which unblocks their threads.
- [ ] **Step 4: Run** `pytest -v`. Expected: all PASS.
- [ ] **Step 5: Manual check:** `python -m e2ee_chat.server` prints `[server] listening on 127.0.0.1:5050`, and Ctrl+C exits without a traceback.
- [ ] **Step 6: Run the checks and commit:** `git commit -m "Add relay server with registration and error handling (T4, T7)"`

---

### Task 4: Plaintext CLI client (T5, T7 client side)

**Files:**
- Create: `e2ee_chat/client.py`
- Test: `tests/test_client.py`

**Interfaces:**
- Consumes: Task 2 helpers; Task 3 `ChatServer` (tests only).
- Produces:
  - `class RegistrationError(Exception)`: carries the server's error `code` and `message`.
  - `class ChatClient(host: str, port: int, username: str, on_message: Callable[[dict], None])`
    - `connect() -> None`: opens the socket, registers, and waits up to 5 s for the reply. Raises `ConnectionError("cannot reach server at HOST:PORT")` if it can't connect, or `RegistrationError` on an `error` reply. Starts the receive thread on success.
    - `send_chat(to: str, text: str) -> None`
    - `close() -> None`: idempotent.
    - The receive thread calls `on_message(msg)` for every message, and calls `on_message({"type": "disconnected"})` once if the server goes away.
  - `format_message(msg: dict) -> str`: `chat` → `"[alice] hi"`; `error` → `"! user_offline: bob is not connected"`; `disconnected` → `"! connection to server lost"`.
  - `main(argv=None)`: `--host` (127.0.0.1), `--port` (5050), `--user` (required), `--peer` (required), `--mode` (choices `["plain"]`, default `plain`). Every typed line goes to `--peer`; `/quit` exits. Errors print one line and exit with code 1, never a traceback. Run with `python -m e2ee_chat.client --user alice --peer bob`.

- [ ] **Step 1: Write the failing tests** (real `ChatServer(port=0)` fixture; messages collected into a `queue.Queue` by `on_message`):
  - `test_two_clients_exchange_messages`: alice `send_chat("bob","hi")`; bob's queue yields a chat from alice with text `hi` within 1 s (US-1 AC2).
  - `test_connect_when_server_down_raises_connection_error`: port of a closed socket → `ConnectionError` containing `"cannot reach server"`.
  - `test_duplicate_username_raises_registration_error` → `.code == "username_taken"`.
  - `test_server_stop_triggers_disconnected_callback`: `server.stop()`; the queue gets `{"type": "disconnected"}` within 2 s.
  - `test_offline_peer_error_is_delivered`: send to `carol`; the queue gets `error`/`user_offline`.
  - `test_format_message_chat_error_disconnected`: exact strings from Interfaces.
  - `test_main_exits_cleanly_when_server_down`: `main(["--port", str(closed_port), "--user", "a", "--peer", "b"])` raises `SystemExit(1)`, and stdout/stderr contain `cannot reach server`.
- [ ] **Step 2: Run** `pytest tests/test_client.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement `e2ee_chat/client.py`.** Read input with `input()` in `main`, catching `EOFError`/`KeyboardInterrupt` as `/quit`. Incoming messages print on their own line.
- [ ] **Step 4: Run** `pytest -v`. Expected: all PASS.
- [ ] **Step 5: Manual check (US-1 AC2), three terminals:** run the server, then `--user alice --peer bob` and `--user bob --peer alice`. A message appears on the other side in under 1 s.
- [ ] **Step 6: Run the checks and commit:** `git commit -m "Add plaintext CLI client (T5, T7)"`

---

### Task 5: Run docs, two-machine test, evidence and tag (T8, T6, T9, T67)

**Files:**
- Modify: `README.md` (new "Running the chat" section)
- Create: `docs/two-machine-setup.md`

- [ ] **Step 1: README "Running the chat" (T8):** the three commands from Task 4 Step 5 for Windows and macOS, the `/quit` command, and the note that the server only accepts connections from this computer unless started with `--host 0.0.0.0`.
- [ ] **Step 2: `docs/two-machine-setup.md` (T6):**
  - find your IP (`ipconfig` / `ipconfig getifaddr en0`)
  - start the server with `--host 0.0.0.0`
  - allow Python through Windows Defender Firewall on **Private networks only**
  - on macOS, click "Allow" on the incoming-connections prompt
  - use a phone hotspot (campus Wi-Fi blocks device-to-device traffic)
  - fallback: three terminals on one laptop
  - close the firewall rule afterwards
- [ ] **Step 3: Two-machine test (T6, US-1 AC1-AC2):** follow the doc on two laptops; record pass/fail in the workbook.
- [ ] **Step 4: AC5 check (T8):** a teammate who didn't write the code follows the README alone and gets a chat working.
- [ ] **Step 5: Evidence (T9, T68):** a screenshot to `05_Evidence/2026-11-1X_UC1_plaintext-chat.png` and a 20-second clip.
- [ ] **Step 6: Commit the docs, then tag (T67):** run from a fresh clone first, then `git tag v0.1-plaintext && git push origin v0.1-plaintext`.

---

## US-1 acceptance criteria → where they're proven

| AC | Proven by |
|---|---|
| AC1 connect + distinct usernames | `test_register_and_relay_chat`, `test_duplicate_username_rejected`, Task 5 Step 3 |
| AC2 message in < 1 s, labeled | `test_two_clients_exchange_messages`, Task 4 Step 5 |
| AC3 spec format, server doesn't read text | `test_pubkey_and_encrypted_are_relayed`; server logs never include text |
| AC4 offline / server down → clear error, no crash | `test_recipient_offline`, `test_connect_when_server_down_raises_connection_error`, `test_server_stop_triggers_disconnected_callback`, `test_main_exits_cleanly_when_server_down` |
| AC5 README alone is enough | Task 5 Step 4 |
