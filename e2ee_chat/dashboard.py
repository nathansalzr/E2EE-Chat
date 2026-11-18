"""Attacker dashboard: a local web console for the MITM (demo only).

Shows intercepted traffic live and lets the presenter switch attack mode
(off / listen / tamper / swap-keys) from the browser, with no restart. It
drives a mitm.AttackState — the same object the relay pumps read per frame.

Served on 127.0.0.1 for the classroom demo. Our own app, our own machines only.
"""

import threading
from http.server import ThreadingHTTPServer  # return type
from pathlib import Path

from e2ee_chat import mitm
from e2ee_chat.webutil import EventHub, QuietThreadingHTTPServer, WebHandler

_PAGE = Path(__file__).with_name("dashboard_page.html").read_text(encoding="utf-8")


class Dashboard:
    """Holds the attack state and the event hub for the dashboard tabs."""

    def __init__(self, state, host, web_port, mitm_addr, server_addr, alice_url, bob_url):
        self.state = state
        self.hub = EventHub()
        self.host = host
        self.web_port = web_port
        self.mitm_addr = mitm_addr
        self.server_addr = server_addr
        self.alice_url = alice_url
        self.bob_url = bob_url
        # The relay pumps call this for every intercepted frame.
        state.on_event = self.hub.publish

    def page(self) -> bytes:
        html = (
            _PAGE.replace("__MITM__", self.mitm_addr)
            .replace("__SERVER__", self.server_addr)
            .replace("__ALICE__", self.alice_url)
            .replace("__BOB__", self.bob_url)
            .replace("__START__", self.state.mode)
        )
        return html.encode("utf-8")


class _Handler(WebHandler):
    @property
    def dash(self) -> Dashboard:
        return self.server.dash  # type: ignore[attr-defined]

    @property
    def app(self):  # WebHandler.check_origin reads host/web_port from here
        return self.dash

    def do_GET(self) -> None:
        if self.path == "/" or self.path.startswith("/index"):
            self.send_bytes(200, "text/html; charset=utf-8", self.dash.page())
        elif self.path == "/events":
            self.stream(self.dash.hub)
        else:
            self.send_bytes(204, "text/plain", b"")

    def do_POST(self) -> None:
        if self.path not in ("/mode", "/clear"):
            self.send_bytes(404, "text/plain", b"not found")
            return
        if not self.check_origin():
            return
        body = self.read_json()
        if self.path == "/clear":
            self.dash.hub.clear()
            self.send_json({"ok": True})
            return
        mode = body.get("mode")
        ok = self.dash.state.set_mode(mode) if isinstance(mode, str) else False
        self.send_json({"ok": ok, "mode": self.dash.state.mode}, status=200 if ok else 400)


def serve(dashboard: Dashboard) -> ThreadingHTTPServer:
    """Start the dashboard HTTP server on a background thread; return it."""
    httpd = QuietThreadingHTTPServer((dashboard.host, dashboard.web_port), _Handler)
    httpd.daemon_threads = True
    httpd.dash = dashboard  # type: ignore[attr-defined]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def main(argv=None):
    """Run the attacker: relay MITM plus the dashboard, standalone."""
    import argparse

    from e2ee_chat.protocol import port_number

    p = argparse.ArgumentParser(description="E2EE Chat attacker dashboard (UC-2/4/5 demo)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=port_number, default=mitm.LISTEN_PORT, help="MITM listen port")
    p.add_argument("--server-host", default=mitm.SERVER_HOST)
    p.add_argument("--server-port", type=port_number, default=mitm.SERVER_PORT)
    p.add_argument("--web-port", type=port_number, default=8000, help="dashboard web port")
    p.add_argument("--log-file", default=mitm.LOG_FILE)
    p.add_argument("--alice-url", default="http://127.0.0.1:8001/")
    p.add_argument("--bob-url", default="http://127.0.0.1:8002/")
    args = p.parse_args(argv)

    listener, state = mitm.start_listener(
        args.host, args.port, args.server_host, args.server_port, args.log_file, mode="off"
    )
    dash = Dashboard(
        state,
        args.host,
        args.web_port,
        f"{args.host}:{args.port}",
        f"{args.server_host}:{args.server_port}",
        args.alice_url,
        args.bob_url,
    )
    httpd = serve(dash)
    print(f"[dashboard] http://{args.host}:{args.web_port}/  (MITM on {args.host}:{args.port})")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n[dashboard] stopping")
    finally:
        listener.close()
        httpd.shutdown()


if __name__ == "__main__":
    main()
