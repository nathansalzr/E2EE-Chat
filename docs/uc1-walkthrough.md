# UC-1 walkthrough: plaintext chat

What we built for UC-1 (US-1), which files belong to which task, what each piece does, and why we built it this way.
Plan: [`plans/2026-11-11-uc1-plaintext-chat.md`](plans/2026-11-11-uc1-plaintext-chat.md). Message format: [`protocol.md`](protocol.md).

## What it does

- Alice and Bob each run `client.py`, which connects to `server.py`.
- Each client registers a username. The server keeps a table of username → connection.
- When Alice types a line, her client sends `{"type": "chat", "to": "bob", "text": ...}`. The server looks up Bob, stamps `"from": "alice"` on it and forwards it.
- Everything is **plaintext**. The server *could* read every message, and so could anyone in between. UC-2 proves that, and UC-3/UC-4 fix it.

```
Alice's client ──TCP──► server.py ──TCP──► Bob's client
   (client.py)      looks up "to",       (client.py)
                    sets "from"
```

## Files by task

| Task | Files | What's in them |
|---|---|---|
| **T1** Protocol spec | `docs/protocol.md` | Framing, every message type, error codes, ports |
| **T3** Framing helpers | `e2ee_chat/protocol.py`, `tests/test_protocol.py` | Length-prefixed JSON send/receive, size limit, username rule |
| **T4** Relay server | `e2ee_chat/server.py`, `tests/test_server.py` | Registration, relaying, spoof-proof `from` |
| **T5** Plaintext client | `e2ee_chat/client.py`, `tests/test_client.py` | `ChatClient` class + command-line chat |
| **T7** Error handling | in `server.py`, `client.py` and their tests | Offline users, duplicate names, bad JSON, server down, Ctrl+C |
| **T6** Two-machine test | `docs/two-machine-setup.md` | IP, firewall and hotspot steps for Windows and macOS |
| **T8** Run instructions | `README.md` ("Running the chat") | Three-terminal quick start |
| T2 Repo + CI | (done earlier) | `.github/workflows/ci.yml`, tests run on Ubuntu, Windows, macOS |
| T9 Evidence, T67 tag | (team, by hand) | Screenshot + clip in `05_Evidence`, tag `v0.1-plaintext` |

## What each piece does

### `e2ee_chat/protocol.py`: shared by every program (T3)

| Name | Job |
|---|---|
| `DEFAULT_PORT`, `MAX_FRAME`, `RELAY_TYPES` | Port 5050, the 64 KiB size cap, and the three types the server forwards |
| `ProtocolError` | The byte stream is broken. Close the connection. |
| `BadMessage` | The frame arrived fine, but its content isn't a valid message. Reply `bad_message` and keep going. |
| `MessageTooLarge` | We tried to send something over the cap. Nothing was sent. |
| `is_valid_username()` | 1-20 letters, digits, `_` or `-` |
| `port_number()` | Checks `--port` is 0-65535 so a typo gives a clear error |
| `encode_frame()` / `send_msg()` | Message dict → 4-byte length + JSON bytes → socket |
| `_recv_exact()` | Keeps calling `recv` until it has exactly N bytes (TCP may hand them over in pieces) |
| `recv_frame()` | Reads one frame's raw bytes, enforcing the size cap *before* reading the body |
| `decode_body()` | Bytes → dict, turning every kind of bad input into `BadMessage` |
| `recv_msg()` | `recv_frame` + `decode_body`, for clients |

### `e2ee_chat/server.py`: the relay (T4, T7)

| Name | Job |
|---|---|
| `_Connection` | One client: socket, username, and a send lock so two senders can't interleave bytes |
| `ChatServer.start()` / `stop()` | Bind and listen in the background; close everything on stop |
| `_accept_loop()` | Accepts new clients, one thread each |
| `_serve()` | One client's loop: read frame → decode → handle; drops only that client on broken framing |
| `_handle()` | Routes by `type`: `register`, a relay type, or `bad_message` |
| `_register()` | Claims a username (or `invalid_username` / `username_taken`) |
| `_relay()` | Looks up `to`, sets `from`, forwards; `user_offline` if they aren't connected |
| `_drop()` | Frees the username and closes the socket when a client leaves |
| `main()` | `python -m e2ee_chat.server`: options, start, wait for Ctrl+C |

### `e2ee_chat/client.py`: the chat program (T5, T7)

| Name | Job |
|---|---|
| `ChatClient.connect()` | Connects, registers, then starts the receive thread; clear errors if the server is down or the name is taken |
| `ChatClient.send_chat()` | Sends one chat message |
| `_receive_loop()` | Background thread: passes each message to the screen, skips garbled ones, reports a lost connection once |
| `sanitize_for_terminal()` | Replaces control characters so nobody can send terminal escape codes |
| `format_message()` | Message → the line you see: `[alice] hi`, `! user_offline: ...` |
| `main()` | `python -m e2ee_chat.client --user alice --peer bob`: every typed line goes to the peer |

## Design decisions (and why)

- **Length-prefixed frames:** TCP is a byte stream, so one send can arrive split up or glued to the next. A 4-byte length in front of each message tells the receiver exactly where it ends.
- **A 64 KiB cap, checked before reading:** a hostile sender can't claim a 4 GB message and make the server allocate it.
- **The server sets `from`:** clients can't pretend to be someone else to the server. (This doesn't stop a MITM, which is the point of UC-3 and UC-5.)
- **Bad content ≠ broken stream:** bad JSON gets an error reply and the connection stays up. Broken framing drops only that one client, so everyone else keeps chatting.
- **Hostile-JSON handling:** thousands of nested brackets, giant numbers and lone Unicode surrogates can crash Python's JSON handling. We turn them all into `bad_message`, because in UC-2 the MITM can send exactly these.
- **Escape-code sanitizing:** a peer, a server or a MITM could send text that clears or rewrites your terminal. The client prints only printable characters.
- **Only `127.0.0.1` by default:** the server isn't reachable from the network unless you deliberately pass `--host 0.0.0.0`.
- **Port 5050:** macOS uses 5000 for AirPlay.
- **The server never prints message text:** it logs `alice -> bob (chat)` only. It *could* read the text, and UC-2 shows that anyone in the middle can too.
- **`pubkey` and `encrypted` are relayed already:** UC-3 and UC-4 only change the clients, not the server.
- **`--mode plain` exists now:** UC-4 adds `--mode e2ee` next to it, so the demo can show both.
- **Thread per client:** simple to read and explain, and plenty for a class demo.

## Tests (68, all in CI on Ubuntu, Windows and macOS)

| US-1 acceptance criterion | Tests |
|---|---|
| AC1 connect with different usernames | `test_register_and_relay_chat`, `test_duplicate_username_rejected`, `test_invalid_username_rejected` |
| AC2 message arrives in < 1 s, labeled | `test_two_clients_exchange_messages`, `test_relay_works_both_ways`, `test_main_sends_typed_lines_to_peer` |
| AC3 spec format, server doesn't read text | `test_round_trip_*`, `test_recv_handles_split_frame`, `test_pubkey_and_encrypted_are_relayed` |
| AC4 clear errors, no crash | `test_recipient_offline`, `test_connect_when_server_down_raises_connection_error`, `test_server_stop_triggers_disconnected_callback`, `test_main_exits_cleanly_when_server_down`, `test_main_ctrl_c_during_connect_exits_without_traceback` |
| AC5 README alone is enough | Manual: a teammate who didn't write the code follows the README |

Security tests: `test_server_overwrites_from_field`, `test_oversized_frame_drops_only_that_client`, `test_hostile_content_raises_bad_message`, `test_lone_surrogate_gets_bad_message_and_connection_survives`, `test_bad_frame_from_server_is_skipped_not_fatal`, `test_format_message_strips_terminal_control_codes`, `test_registration_error_text_is_sanitized`.

## Known limitations (fine for a class demo, worth naming in the report)

- **A slow receiver can stall senders.** If someone stops reading, people messaging them wait too. A real server would give each connection its own outgoing queue.
- **No connection limit or idle timeout.** Lots of idle connections could use up threads (a "slowloris"-style denial of service).
- **Error replies echo what the client sent,** so a deliberately huge `to` name gets the sender dropped instead of an error reply.
- **The server log prints a relay line even if delivery just failed.**
- **After "connection to server lost", the client waits for Enter** before exiting.
