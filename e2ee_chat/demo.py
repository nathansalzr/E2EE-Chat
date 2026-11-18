"""One-command demo launcher: the whole project in the browser.

Starts, in a single process on 127.0.0.1:
  - the relay server (port 5050);
  - the attacker (MITM on 6060) with its dashboard on :8000, starting in "off";
  - Alice's chat window on :8001 and Bob's on :8002, both routed through 6060.

Then you drive everything from the browser: flip the attacker's mode, toggle a
window between plain and e2ee, and watch the key-change alarm, all with no
restart. Ctrl+C stops everything.

    python -m e2ee_chat.demo [--reset]

--reset clears trust-on-first-use pins and saved history for a clean first
contact. Private keys are kept, so fingerprints stay stable between runs.

Our own app, our own machines only.
"""

import argparse
import shutil
import threading
import webbrowser
from pathlib import Path

from e2ee_chat import dashboard, mitm, webclient
from e2ee_chat.server import ChatServer

SERVER_PORT = 5050
MITM_PORT = 6060
DASH_PORT = 8000
ALICE_PORT = 8001
BOB_PORT = 8002
HOST = "127.0.0.1"


def _reset(keys_dir: str) -> None:
    """Clear pins and history so Step 7 starts as a fresh contact; keep keypairs."""
    for sub in ("known_peers", "history"):
        shutil.rmtree(Path(keys_dir) / sub, ignore_errors=True)


def _make_window(user, peer, web_port, keys_dir):
    app = webclient.ChatApp(user, peer, mode="plain", host=HOST, port=MITM_PORT, keys_dir=keys_dir)
    app.web_host = HOST
    app.web_port = web_port
    try:
        from e2ee_chat.history import HistoryStore

        app.store = HistoryStore(user, peer, keys_dir=keys_dir)
    except Exception:  # noqa: BLE001 - history is optional
        app.store = None
    return app, webclient.start_window(app)


def launch(keys_dir="keys", log_file="intercepted.log", reset=False):
    """Start the whole stack and return a stop() callable. Does not block.

    Separated from main() so a test can start it, poke the pages, and stop it
    without the Ctrl+C blocking wait.
    """
    if reset:
        _reset(keys_dir)
        # The attacker log appends forever otherwise, mixing every past run
        # (including terminal demos) into what the class sees as "this demo".
        Path(log_file).unlink(missing_ok=True)
        print("[demo] cleared pins, history and the attacker log (fresh start)")

    cleanup = []  # undo steps, newest last; run in reverse on stop or on failure

    def stop():
        while cleanup:
            try:
                cleanup.pop()()
            except Exception:  # noqa: BLE001, S110 - keep tearing the rest down
                pass

    def claim(what, port, start):
        """Run one start step; turn 'port busy' into a clear PortInUse."""
        try:
            return start()
        except OSError as exc:
            stop()  # release whatever already started
            raise PortInUse(what, port) from exc

    server = ChatServer(host=HOST, port=SERVER_PORT)
    claim("relay server", SERVER_PORT, server.start)
    cleanup.append(server.stop)

    listener, state = claim(
        "attacker (MITM)",
        MITM_PORT,
        lambda: mitm.start_listener(HOST, MITM_PORT, HOST, SERVER_PORT, log_file, mode="off"),
    )
    cleanup.append(listener.close)

    dash = dashboard.Dashboard(
        state,
        HOST,
        DASH_PORT,
        f"{HOST}:{MITM_PORT}",
        f"{HOST}:{SERVER_PORT}",
        f"http://{HOST}:{ALICE_PORT}/",
        f"http://{HOST}:{BOB_PORT}/",
    )
    dash_httpd = claim("attacker dashboard", DASH_PORT, lambda: dashboard.serve(dash))
    cleanup.append(lambda: (dash_httpd.shutdown(), dash_httpd.server_close()))

    # Both windows start in plain mode (the "before" picture); route through the MITM.
    for user, peer, port in (("alice", "bob", ALICE_PORT), ("bob", "alice", BOB_PORT)):
        app, httpd = claim(
            f"{user}'s window", port, lambda u=user, p=peer, w=port: _make_window(u, p, w, keys_dir)
        )
        cleanup.append(lambda h=httpd: (h.shutdown(), h.server_close()))
        cleanup.append(app.shutdown)  # quiet teardown: nothing written to history

    return stop


class PortInUse(RuntimeError):
    """A demo port is held by another program (often a leftover demo or terminal MITM)."""

    def __init__(self, what, port):
        self.what = what
        self.port = port
        super().__init__(f"port {port} for the {what} is already in use")


def main(argv=None):
    parser = argparse.ArgumentParser(description="E2EE Chat one-command web demo")
    parser.add_argument("--reset", action="store_true", help="clear pins and saved history first")
    parser.add_argument("--keys-dir", default="keys")
    parser.add_argument("--no-open", action="store_true")
    parser.add_argument("--log-file", default="intercepted.log")
    args = parser.parse_args(argv)

    try:
        stop = launch(keys_dir=args.keys_dir, log_file=args.log_file, reset=args.reset)
    except PortInUse as exc:
        raise SystemExit(
            f"! {exc}.\n"
            "  Usually a demo, server or terminal MITM from an earlier run is still running.\n"
            "  Find it in PowerShell:\n"
            f"    Get-NetTCPConnection -State Listen -LocalPort {exc.port} | "
            "Select-Object OwningProcess\n"
            "  then stop it with Stop-Process -Id <that number>, and run the demo again."
        ) from None
    dash_url = f"http://{HOST}:{DASH_PORT}/"
    print("[demo] ready:")
    print(f"[demo]   attacker dashboard : {dash_url}")
    print(f"[demo]   alice window       : http://{HOST}:{ALICE_PORT}/")
    print(f"[demo]   bob window         : http://{HOST}:{BOB_PORT}/")
    print("[demo] Start on the dashboard. Ctrl+C to stop everything.")
    if not args.no_open:
        threading.Thread(target=lambda: webbrowser.open(dash_url), daemon=True).start()

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n[demo] stopping")
    finally:
        stop()


if __name__ == "__main__":
    main()
