"""Smoke test for the one-command demo launcher."""

import socket
import time
import urllib.request

from e2ee_chat import demo


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _get(port, timeout=3):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1) as r:  # noqa: S310
                return r.status
        except OSError:
            time.sleep(0.05)
    raise AssertionError(f"no page on {port}")


def test_launcher_starts_all_pages_and_stops_clean(tmp_path, monkeypatch):
    for name in ("SERVER_PORT", "MITM_PORT", "DASH_PORT", "ALICE_PORT", "BOB_PORT"):
        monkeypatch.setattr(demo, name, _free_port())

    stop = demo.launch(
        keys_dir=str(tmp_path / "keys"), log_file=str(tmp_path / "x.log"), reset=True
    )
    try:
        assert _get(demo.DASH_PORT) == 200  # attacker dashboard
        assert _get(demo.ALICE_PORT) == 200  # alice window
        assert _get(demo.BOB_PORT) == 200  # bob window
    finally:
        stop()

    # after stop(), the dashboard port is free again
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", demo.DASH_PORT))


def test_reset_clears_the_attacker_log(tmp_path, monkeypatch):
    for name in ("SERVER_PORT", "MITM_PORT", "DASH_PORT", "ALICE_PORT", "BOB_PORT"):
        monkeypatch.setattr(demo, name, _free_port())
    log = tmp_path / "intercepted.log"
    log.write_text("[20:50:16] old run traffic\n", encoding="utf-8")
    stop = demo.launch(keys_dir=str(tmp_path / "keys"), log_file=str(log), reset=True)
    stop()
    assert not log.exists() or "old run traffic" not in log.read_text(encoding="utf-8")


def _hold(port):
    """Listen on a port the way a leftover program would."""
    s = socket.socket()
    s.bind(("127.0.0.1", port))
    s.listen()
    return s


def test_busy_port_fails_loudly_and_releases_what_started(tmp_path, monkeypatch):
    # Regression: on Windows a second listener could share a busy port, so the
    # demo's windows silently talked to an old terminal MITM.
    for name in ("SERVER_PORT", "MITM_PORT", "DASH_PORT", "ALICE_PORT", "BOB_PORT"):
        monkeypatch.setattr(demo, name, _free_port())
    squatter = _hold(demo.MITM_PORT)
    try:
        import pytest

        with pytest.raises(demo.PortInUse) as err:
            demo.launch(keys_dir=str(tmp_path / "keys"), log_file=str(tmp_path / "x.log"))
        assert err.value.port == demo.MITM_PORT
        # the relay server that started first was shut down again
        _hold(demo.SERVER_PORT).close()
    finally:
        squatter.close()


def test_main_names_the_busy_port(tmp_path, monkeypatch, capsys):
    import pytest

    for name in ("SERVER_PORT", "MITM_PORT", "DASH_PORT", "ALICE_PORT", "BOB_PORT"):
        monkeypatch.setattr(demo, name, _free_port())
    squatter = _hold(demo.DASH_PORT)
    try:
        with pytest.raises(SystemExit) as exit_info:
            demo.main(["--no-open", "--keys-dir", str(tmp_path / "keys")])
        assert f"port {demo.DASH_PORT}" in str(exit_info.value)
        assert "Traceback" not in capsys.readouterr().err
    finally:
        squatter.close()
