# Two-machine test (T6)

Goal: the server and Alice on one laptop, Bob on another, chatting over the network (US-1 AC1-AC2).

**Use a phone hotspot or our own router, not campus Wi-Fi.** Campus Wi-Fi usually blocks laptops from talking to each other directly (client isolation). It's also a shared network we don't own, and the ethics rule keeps our traffic off it.

## 1. Join the same network

Turn on a phone hotspot and connect both laptops to it.

## 2. Find the server laptop's IP address

**Windows:** run `ipconfig` and find **IPv4 Address** under the Wi-Fi adapter, e.g. `172.20.10.3`.

**macOS:** run `ipconfig getifaddr en0`.

## 3. Start the server so the other laptop can reach it

```bash
python -m e2ee_chat.server --host 0.0.0.0
```

`0.0.0.0` means "listen on every network interface", not just this computer. Only do this on a network we control, and stop the server (Ctrl+C) when you're done.

**Firewall prompt:**
- **Windows:** Windows Defender Firewall asks whether to allow Python. Tick **Private networks** only (not Public) and click **Allow**. Then make sure the hotspot is set to *Private* (Settings → Network & internet → Wi-Fi → the hotspot → Network profile type).
- **macOS:** click **Allow** when asked whether Python should accept incoming connections.

## 4. Connect the clients

On the server laptop:

```bash
python -m e2ee_chat.client --user alice --peer bob
```

On the other laptop, using the IP from step 2:

```bash
python -m e2ee_chat.client --host 172.20.10.3 --user bob --peer alice
```

Send a message each way. Each should appear in under a second.

## 5. If it doesn't connect

| Symptom | Likely cause | Try |
|---|---|---|
| `cannot reach server` right away | Wrong IP, or the server isn't using `--host 0.0.0.0` | Re-check step 2 and step 3 |
| `cannot reach server` after a few seconds | Firewall is blocking port 5050, or the network isolates clients | Re-check the firewall prompt; try another hotspot |
| Works on one laptop, not across two | Client isolation on the network | Use a different hotspot or our own router |

**Fallback:** if we can't get two laptops talking, run all three terminals on one laptop and note it in the Scope Changes sheet (US-1 AC1 allows this).

## 6. Clean up

- Stop the server with Ctrl+C.
- **Windows:** if you want to remove the firewall rule, go to Windows Security → Firewall & network protection → *Allow an app through firewall* and untick or remove Python.

## 7. Record the result

- Mark T6 Done (or note the fallback) on the board.
- Save a screenshot to OneDrive `05_Evidence` as `YYYY-MM-DD_UC1_two-machine-chat.png` (T9), and record a 20-second clip (T68).
