"""Tests for the encrypted-at-rest chat history (web demo)."""

import pytest

from e2ee_chat.history import HistoryStore


def test_round_trip(tmp_path):
    h = HistoryStore("alice", "bob", keys_dir=str(tmp_path))
    h.append({"kind": "chat", "from": "alice", "text": "meet at 5 🔒", "mine": True})
    h.append({"kind": "event", "level": "alarm", "text": "bob's key changed"})
    loaded = h.load()
    assert [e["text"] for e in loaded] == ["meet at 5 🔒", "bob's key changed"]


def test_file_holds_no_plaintext(tmp_path):
    h = HistoryStore("alice", "bob", keys_dir=str(tmp_path))
    h.append({"kind": "chat", "from": "alice", "text": "transfer the money", "mine": True})
    on_disk = (tmp_path / "history" / "alice" / "bob.log").read_text(encoding="ascii")
    assert "transfer" not in on_disk and "money" not in on_disk


def test_another_user_key_cannot_read_it(tmp_path):
    alice = HistoryStore("alice", "bob", keys_dir=str(tmp_path))
    alice.append({"kind": "chat", "from": "alice", "text": "secret", "mine": True})
    # eve copies alice's history file into her own slot, but has her own key
    eve = HistoryStore("eve", "bob", keys_dir=str(tmp_path))
    import os
    import shutil

    os.makedirs(os.path.dirname(eve.path), exist_ok=True)
    shutil.copy(alice.path, eve.path)
    assert eve.load() == []  # every line fails the auth tag under eve's key


def test_corrupt_line_is_skipped(tmp_path):
    h = HistoryStore("alice", "bob", keys_dir=str(tmp_path))
    h.append({"kind": "chat", "from": "alice", "text": "one", "mine": True})
    with open(h.path, "a", encoding="ascii") as f:
        f.write("!!!not valid!!!\n")
    h.append({"kind": "chat", "from": "alice", "text": "two", "mine": True})
    assert [e["text"] for e in h.load()] == ["one", "two"]


def test_missing_file_loads_empty(tmp_path):
    assert HistoryStore("alice", "bob", keys_dir=str(tmp_path)).load() == []


@pytest.mark.parametrize("bad", ["../evil", "a/b", "", "x" * 21])
def test_rejects_unsafe_names(tmp_path, bad):
    with pytest.raises(ValueError):
        HistoryStore("alice", bad, keys_dir=str(tmp_path))


def test_non_ascii_garbage_line_is_skipped(tmp_path):
    # Regression: one binary byte used to make load() raise for the whole file.
    h = HistoryStore("alice", "bob", keys_dir=str(tmp_path))
    h.append({"kind": "chat", "from": "alice", "text": "one", "mine": True})
    with open(h.path, "ab") as f:
        f.write(b"\xff\xfe\x00garbage\n")
    h.append({"kind": "chat", "from": "alice", "text": "two", "mine": True})
    assert [e["text"] for e in h.load()] == ["one", "two"]
