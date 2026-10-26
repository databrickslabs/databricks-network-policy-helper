"""Cached feed accessors — the single entry point the core logic uses to get enrichment tables.

Each returns a pandas DataFrame, built fresh when the cache is missing/stale/forced (`refresh`).
"""

from __future__ import annotations

import pandas as pd

from . import cache, cloud, databricks, domains, partners, threat


def threat_intel(selected_feeds: list[str], refresh: bool = False) -> pd.DataFrame:
    # Cache key encodes the selected feeds so a different selection rebuilds rather than reusing.
    suffix = "_".join(sorted(selected_feeds)) if selected_feeds else "none"
    key = f"threat_intel_ips__{suffix}"
    return cache.get_or_build(key, lambda: threat.load_threat_intel(selected_feeds), refresh=refresh)


def threat_domains(
    selected_feeds: list[str], auth_key: str | None = None, refresh: bool = False, note=lambda _m: None
) -> pd.DataFrame:
    """Cached union of domain block feeds. The cache key encodes the selection and whether an abuse.ch
    key is present (so the result differs when the key-gated feeds (de)activate) — the key itself is
    never part of the cache name."""
    suffix = "_".join(sorted(selected_feeds)) if selected_feeds else "none"
    key = f"threat_domains__{suffix}__auth{int(bool(auth_key))}"
    return cache.get_or_build(
        key, lambda: domains.load_block_domains(selected_feeds, auth_key, note), refresh=refresh
    )


def allowlist_domains(selected_feeds: list[str], refresh: bool = False, note=lambda _m: None) -> pd.DataFrame:
    """Cached union of popularity/allowlist sources (MISP warninglists + Tranco), for flag-only review."""
    suffix = "_".join(sorted(selected_feeds)) if selected_feeds else "none"
    key = f"domain_allowlist__{suffix}"
    return cache.get_or_build(
        key, lambda: domains.load_allowlist_domains(selected_feeds, note), refresh=refresh
    )


def cloud_ranges(refresh: bool = False) -> pd.DataFrame:
    return cache.get_or_build("cloud_provider_ranges", cloud.load_cloud_ranges, refresh=refresh)


def databricks_ranges(refresh: bool = False) -> pd.DataFrame:
    return cache.get_or_build("databricks_ranges", databricks.load_databricks_ranges, refresh=refresh)


def partner_ranges(refresh: bool = False) -> pd.DataFrame:
    return cache.get_or_build("partner_ranges", partners.load_partner_ranges, refresh=refresh)
