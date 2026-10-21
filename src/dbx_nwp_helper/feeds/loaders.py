"""Cached feed accessors — the single entry point the core logic uses to get enrichment tables.

Each returns a pandas DataFrame, built fresh when the cache is missing/stale/forced (`refresh`).
"""

from __future__ import annotations

import pandas as pd

from . import cache, cloud, databricks, partners, threat


def threat_intel(selected_feeds: list[str], refresh: bool = False) -> pd.DataFrame:
    # Cache key encodes the selected feeds so a different selection rebuilds rather than reusing.
    suffix = "_".join(sorted(selected_feeds)) if selected_feeds else "none"
    key = f"threat_intel_ips__{suffix}"
    return cache.get_or_build(key, lambda: threat.load_threat_intel(selected_feeds), refresh=refresh)


def cloud_ranges(refresh: bool = False) -> pd.DataFrame:
    return cache.get_or_build("cloud_provider_ranges", cloud.load_cloud_ranges, refresh=refresh)


def databricks_ranges(refresh: bool = False) -> pd.DataFrame:
    return cache.get_or_build("databricks_ranges", databricks.load_databricks_ranges, refresh=refresh)


def partner_ranges(refresh: bool = False) -> pd.DataFrame:
    return cache.get_or_build("partner_ranges", partners.load_partner_ranges, refresh=refresh)
