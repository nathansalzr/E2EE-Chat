# E2EE Chat

A terminal chat app built three ways to show one security story:

1. **Plaintext chat**: two clients talk through a relay server.
2. **The attack**: a man-in-the-middle (`mitm.py`) sits between the clients and the server and reads every message. A Wireshark capture shows the same text in the packets.
3. **The defense**: end-to-end encryption (X25519 key exchange + AES-256-GCM). The same attack now captures only ciphertext, tampered messages are rejected, and fingerprint checks catch a MITM that swaps public keys.

CECS 378 semester project, CSULB, Fall 2026. Due Nov 20, 2026.

**Build plan:** [`docs/ROADMAP.md`](docs/ROADMAP.md)

## Stack

| Layer | Tech |
|---|---|
| Language | Python 3.12 |
| Networking | TCP sockets (standard library) |
| Crypto | [`cryptography`](https://cryptography.io): X25519, HKDF-SHA256, AES-256-GCM |
| Tests / lint | pytest, ruff |
| CI | GitHub Actions: Ubuntu + Windows on every PR, plus macOS on main (lint → format check → tests) |

## Project structure

```
E2EE-Chat/
├── e2ee_chat/               the app (server, client, mitm, protocol, crypto_utils as they land)
├── tests/                   pytest tests; every feature ships with tests
├── docs/                    roadmap and design notes
├── .github/workflows/ci.yml CI: runs on every PR and every push to main
├── requirements.txt         runtime dependencies
└── requirements-dev.txt     + test and lint tools
```

## Getting started

You need Python 3.12 or newer (CI tests on 3.12). Create a virtual environment so the project's packages stay separate from your system Python.

**Windows (PowerShell):**

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
```

**macOS:**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
```

If PowerShell refuses to run `Activate.ps1` (script execution is disabled), skip activating and put `.venv\Scripts\` in front of each command instead, e.g. `.venv\Scripts\python -m pytest`.

## Running the chat

Open **three terminals** in the project folder, with the virtual environment active in each.

**1. Start the server:**

```bash
python -m e2ee_chat.server
```

You should see `[server] listening on 127.0.0.1:5050`.

**2. Start Alice:**

```bash
python -m e2ee_chat.client --user alice --peer bob
```

**3. Start Bob:**

```bash
python -m e2ee_chat.client --user bob --peer alice
```

Type a line in Alice's terminal and press Enter; it shows up in Bob's as `[alice] ...`. Type `/quit` (or press Ctrl+C) to leave, and press Ctrl+C in the server terminal to stop it.

| Option | Meaning | Default |
|---|---|---|
| `--host` | Server: address to listen on. Client: server address to connect to. | `127.0.0.1` |
| `--port` | Port number | `5050` |
| `--user` | Your username (1-20 letters, digits, `_` or `-`) | required |
| `--peer` | Who your messages go to | required |
| `--mode` | `plain` for now; `e2ee` arrives in UC-4 | `plain` |

By default the server only accepts connections from the same computer. To chat between two laptops, see [`docs/two-machine-setup.md`](docs/two-machine-setup.md).

**What the server prints:** who joined and left, and `alice -> bob (chat)` for each message. It never prints message text, but it *could* read it, and so could anyone in the middle. That's what UC-2 shows.

The message format is in [`docs/protocol.md`](docs/protocol.md).

## Running the checks (same as CI)

```bash
ruff check .
ruff format --check .
pytest
```

Run `ruff format .` to fix formatting automatically.

## How we work

- **Branch per task:** `feat/<story>-<short-desc>` (e.g. `feat/us2-mitm-logger`), `chore/<desc>` for setup and maintenance.
- **Every change reaches `main` through a pull request** with green CI and one teammate's review. Nobody merges their own PR.
- **Tags:** `v0.1-plaintext`, `v0.2-attack` and `v0.3-e2ee` as each stage works, then `v1.0` at the Nov 16 code freeze.
- **Every stage stays in the code** behind `--mode` (client: `plain` / `e2ee`; mitm: `log` / `tamper` / `swap-keys`), so the demo can show the vulnerable and fixed versions side by side.
- **Backlog and board:** `E2EEChat_Sprint1_ProductBacklog.xlsx` in our shared OneDrive folder.

## Ethics rule

The attack runs only against our own app on our own machines (localhost, a phone hotspot or our own router). No third-party targets and no attacks on the campus network. Never commit private keys, `.env` files or captured traffic; `.gitignore` blocks them and a test fails if that ever stops working.

## Design decisions (and why)

- **A relay server instead of peer-to-peer:** it's how real chat apps work, and it makes the point of the project. Whoever runs or sits in the middle can read everything unless messages are encrypted end to end.
- **MITM as a relay proxy, not ARP spoofing:** the clients connect to the attacker's port, which is what ARP or DNS spoofing would achieve. It's reliable on any network and keeps the demo legal and contained. We describe this honestly in the report.
- **X25519 instead of RSA:** each side combines its private key with the other's public key and both get the same secret, which never crosses the network. It's modern (Signal uses it), fast, and only a few lines with the `cryptography` library.
- **AES-256-GCM for messages:** it encrypts and adds an authentication tag, so a flipped byte is detected and rejected. That covers confidentiality and integrity in one primitive.
- **Fingerprint verification is required:** without it, our own MITM can swap in its public keys and read the "encrypted" chat. Comparing a short key hash out of band is the same idea as Signal's safety numbers and HTTPS certificates.
- **Standard crypto only:** no homemade algorithms. Every primitive comes from a well-reviewed library.
- **CI on three operating systems:** the team uses Windows and macOS, and socket and path behavior differs. CI catches "works on my machine" bugs before the demo. macOS runs only on merges to `main` because its runner minutes cost about 10x Linux on our free plan.
- **Security checks in the pipeline:** ruff's `S` rules flag risky code (e.g. hardcoded secrets, unsafe calls), and a test guarantees key files stay gitignored. CI only gets read access to the repo.
