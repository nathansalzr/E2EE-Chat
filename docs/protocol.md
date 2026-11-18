# Protocol spec v1 (T1)

This document defines how every program in the project talks over the network: the server, the client, and later the MITM.
If you change it, everyone's code has to change too, so propose changes in the group chat first.

**Status:** draft. Review at kickoff, then copy it to OneDrive `02_Design`.

## Framing

TCP is a stream of bytes, not a stream of messages. One `send` can arrive as several `recv` calls, and two sends can arrive in one. So every message is sent as a **frame**:

```
+----------------------+------------------------------+
| length (4 bytes)     | body (length bytes)          |
| big-endian unsigned  | UTF-8 JSON object            |
+----------------------+------------------------------+
```

- In Python: `struct.pack("!I", len(body)) + body`, where `body = json.dumps(msg, ensure_ascii=False).encode("utf-8")`.
- **Max body: 65,536 bytes.** A bigger length means a broken or hostile sender, and the connection is closed. The cap stops one client from making the server allocate gigabytes.
- Every body is a JSON **object** with a string `"type"` field.

## Connection order

1. The client connects to the server (default port **5050**).
2. The client sends `register`.
3. The server answers `registered` or `error`. After an error the client may try another name on the same connection.
4. After that, the client sends and receives relay messages until it disconnects.

## Messages (UC-1)

| Direction | Message |
|---|---|
| client → server | `{"type": "register", "username": "alice"}` |
| server → client | `{"type": "registered", "username": "alice"}` |
| client → server | `{"type": "chat", "to": "bob", "text": "hi"}` |
| server → recipient | `{"type": "chat", "from": "alice", "to": "bob", "text": "hi"}` |
| server → client | `{"type": "error", "code": "user_offline", "message": "bob is not connected"}` |

**Usernames:** 1-20 characters, letters, digits, `_` or `-`.

**The server sets `from`.** Whatever a client puts in `from` is replaced with its registered name, so nobody can pretend to be someone else to the server.

## Error codes

| Code | When |
|---|---|
| `invalid_username` | The name breaks the username rule |
| `username_taken` | Someone online already has that name |
| `not_registered` | A relay message arrived before `register` succeeded |
| `bad_message` (already registered) | `register` was sent again on a connection that already has a name |
| `user_offline` | The `to` user isn't connected |
| `bad_message` | The frame was fine but its content wasn't a valid message: invalid UTF-8 or JSON, not an object, no `type`, an unknown `type`, a relay message with no `to`, or JSON built to break the parser (thousands of nested brackets, numbers thousands of digits long, a lone `\ud800` escape) |

## Relay messages

The server forwards these three types the same way, by `to`. It doesn't interpret any other field: it copies the whole message, including any extra fields, and only sets `from`.

| Type | Used in | Shape (client → server) |
|---|---|---|
| `chat` | UC-1 | `{"type": "chat", "to": "bob", "text": "hi"}` |
| `pubkey` | UC-3 | `{"type": "pubkey", "to": "bob", "key": "<base64 X25519 public key>"}` |
| `encrypted` | UC-4 | `{"type": "encrypted", "to": "bob", "nonce": "<base64>", "ciphertext": "<base64>"}` |

Because the server never needs to understand `pubkey` or `encrypted`, UC-3 and UC-4 only change the clients.

## Encrypted messages (UC-4)

- `nonce`: base64 of a fresh random 12-byte (96-bit) nonce, new for every message.
- `ciphertext`: base64 of AES-256-GCM output (the encrypted UTF-8 text followed by the 16-byte authentication tag), using the UC-3 session key.
- **Associated data (AAD):** `e2ee-chat v1|<sender>|<recipient>` in UTF-8, authenticated but not sent. The receiver rebuilds it from the server-stamped `from` and its own username, so a relabelled or redirected message fails the tag check. Usernames can't contain `|`, so this is unambiguous.
- A client in `e2ee` mode (the default) sends only `encrypted` chat messages and **never displays a plaintext `chat`**. It reports it as a possible downgrade attack instead.
- If decryption fails for any reason (bad tag, wrong key, wrong AAD, bad base64, wrong nonce length), the message is dropped with "message failed integrity check" and the connection stays open.

## Ports

| Program | Default port |
|---|---|
| Server | 5050 (not 5000, which macOS uses for AirPlay) |
| MITM (UC-2, UC-4) | 6060 |

The server listens only on `127.0.0.1` unless it's started with `--host 0.0.0.0` for the two-machine test.
