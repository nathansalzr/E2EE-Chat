"""Smoke test: proves pytest and CI are wired up before any app code exists."""

import e2ee_chat


def test_package_imports_and_has_version():
    assert e2ee_chat.__version__ == "0.1.0"
