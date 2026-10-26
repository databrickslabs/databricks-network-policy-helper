"""Local parquet cache for downloaded feeds, with a TTL.

Replaces the notebooks' Delta-table materialisation. Each feed table (threat_intel_ips,
cloud_provider_ranges, databricks_ranges) is cached as parquet under a platform cache dir. A cached
table is reused when it exists and is younger than the TTL, unless `refresh=True` forces a rebuild.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from pathlib import Path

import pandas as pd

CACHE_TTL_SECONDS = 24 * 3600  # feeds refresh daily by default


def cache_dir() -> Path:
    """Platform cache dir: $XDG_CACHE_HOME or ~/.cache, under dbx-nwp-helper."""
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    d = Path(base) / "dbx-nwp-helper" / "feeds"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _path(name: str) -> Path:
    return cache_dir() / f"{name}.parquet"


def is_fresh(name: str, ttl: int = CACHE_TTL_SECONDS) -> bool:
    p = _path(name)
    return p.exists() and (time.time() - p.stat().st_mtime) < ttl


def load(name: str) -> pd.DataFrame | None:
    p = _path(name)
    if p.exists():
        return pd.read_parquet(p)
    return None


def store(name: str, df: pd.DataFrame) -> None:
    df.to_parquet(_path(name), index=False)


def get_or_build(
    name: str, builder: Callable[[], pd.DataFrame], refresh: bool = False, ttl: int = CACHE_TTL_SECONDS
) -> pd.DataFrame:
    """Return the cached feed table, (re)building via `builder` when missing/stale/forced.

    An empty result is NOT cached: an empty feed almost always means the download failed (network /
    TLS / feed outage), and caching it would make the next run reuse bad data for the whole TTL —
    which previously made all cloud/Databricks membership checks silently return false. Not caching
    it means the next run retries the fetch."""
    if not refresh and is_fresh(name, ttl):
        cached = load(name)
        if cached is not None and not cached.empty:
            return cached
    df = builder()
    if df is not None and not df.empty:
        store(name, df)
    return df


def too_soon(marker: str, min_interval: int) -> bool:
    """True if `marker` was last touched less than `min_interval` seconds ago — a rate-limit guard for
    feeds that ban frequent fetches (e.g. dan.me.uk's Tor list: max once per 30 min). Checked even on
    `--refresh-feeds`, so a forced refresh can't trip the ban. Returns False the first time (no
    marker yet)."""
    p = cache_dir() / f"{marker}.fetch"
    return p.exists() and (time.time() - p.stat().st_mtime) < min_interval


def touch(marker: str) -> None:
    """Record that `marker` was just fetched (see `too_soon`)."""
    (cache_dir() / f"{marker}.fetch").touch()


def clear() -> list[str]:
    """Remove all cached feed files; return the names removed."""
    removed = []
    for p in cache_dir().glob("*.parquet"):
        removed.append(p.stem)
        p.unlink()
    return removed


def status_rows() -> list[tuple[str, str, str]]:
    """(name, rows, age) for each cached feed — for `feeds list`."""
    rows = []
    for p in sorted(cache_dir().glob("*.parquet")):
        try:
            n = len(pd.read_parquet(p, columns=[]))
        except Exception:  # noqa: BLE001
            n = -1
        age_s = int(time.time() - p.stat().st_mtime)
        rows.append((p.stem, f"{n:,}" if n >= 0 else "?", _humanize(age_s)))
    return rows


def _humanize(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"
