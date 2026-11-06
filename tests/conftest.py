"""Shared test fixtures."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolated_feed_cache(tmp_path, monkeypatch):
    """Point the on-disk feed / RDAP cache at a per-test temp dir so tests never read or write the
    developer's real ~/.cache (and never see each other's entries)."""
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg-cache"))
