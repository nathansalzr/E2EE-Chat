"""Fails if .gitignore ever stops protecting private keys, secrets or captured traffic (NFR-4)."""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

MUST_BE_IGNORED = [
    "keys/alice_private.pem",
    "alice.key",
    "server.pem",
    ".env",
    "intercepted.log",
    "capture.pcapng",
]


def in_git_repo() -> bool:
    return shutil.which("git") is not None and (ROOT / ".git").exists()


@pytest.mark.skipif(not in_git_repo(), reason="needs a git checkout")
@pytest.mark.parametrize("path", MUST_BE_IGNORED)
def test_sensitive_files_are_ignored(path):
    result = subprocess.run(
        ["git", "check-ignore", "--no-index", "--quiet", path], cwd=ROOT, check=False
    )
    assert result.returncode == 0, f"{path} is NOT gitignored"


@pytest.mark.skipif(not in_git_repo(), reason="needs a git checkout")
def test_env_example_is_still_committable():
    result = subprocess.run(
        ["git", "check-ignore", "--no-index", "--quiet", ".env.example"], cwd=ROOT, check=False
    )
    assert result.returncode == 1
