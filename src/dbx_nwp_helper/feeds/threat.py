"""Threat-intelligence IP feeds → a `threat_intel_ips` DataFrame.

Columns: cidr, source_feed, threat_type, confidence, source_url, loaded_at.
confidence 1 = high, 2 = medium. Ported verbatim from the ingress notebook's feed loaders.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pandas as pd

from .http import http_get
from .util import dedupe, valid_cidr

THREAT_INTEL_COLUMNS = ["cidr", "source_feed", "threat_type", "confidence", "source_url", "loaded_at"]

SPAMHAUS_DROP_V4_URL = "https://www.spamhaus.org/drop/drop_v4.json"
SPAMHAUS_DROP_V6_URL = "https://www.spamhaus.org/drop/drop_v6.json"
TOR_EXIT_URL = "https://check.torproject.org/torbulkexitlist"
# Fallback mirror when the Tor Project's list is unreachable (it's commonly blocked on corporate/cloud
# networks). dan.me.uk BANS clients that fetch more than once per 30 min, so a marker guards it.
TOR_EXIT_FALLBACK_URL = "https://www.dan.me.uk/torlist/?exit"
TOR_DANME_MIN_INTERVAL = 1800  # seconds (dan.me.uk's documented rate limit)
FIREHOL_LEVEL1_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
IPSUM_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
DSHIELD_URL = "https://feeds.dshield.org/block.txt"
CINS_CI_ARMY_URL = "https://cinsscore.com/list/ci-badguys.txt"
# C2IntelFeeds (drb-ra) — validated C2 IPs. The 30-day window; the VPN files are intentionally not used.
C2INTEL_IP_URL = "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv"

IPSUM_MIN_LISTS = 3
IPSUM_HIGH_CONFIDENCE_LISTS = 5


def _feed_spamhaus_drop(now):
    rows = []
    for url, ver in [(SPAMHAUS_DROP_V4_URL, 4), (SPAMHAUS_DROP_V6_URL, 6)]:
        text = http_get(url)
        if not text:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            cidr = valid_cidr(obj.get("cidr", ""), want_version=ver)
            if cidr:
                rows.append((cidr, "spamhaus_drop", "botnet_c2", 1, url, now))
    return rows


def _parse_tor_ips(text, now, source_url):
    rows = []
    for line in text.splitlines():
        ip = line.strip()
        if not ip or ip.startswith("#"):
            continue
        cidr = valid_cidr(f"{ip}/32" if ":" not in ip else f"{ip}/128")
        if cidr:
            rows.append((cidr, "tor_exit", "anonymizer", 2, source_url, now))
    return rows


def _feed_tor_exit(now):
    # Primary: the Tor Project's official bulk exit list. It's frequently blocked on corporate/cloud
    # networks (connection reset), so fall back to dan.me.uk's mirror. dan.me.uk is rate-limited (≤1
    # fetch / 30 min) — a marker guards it even under --refresh-feeds, and we touch it BEFORE fetching
    # so a failed request still counts against the limit (dan.me.uk bans on request, not on success).
    from . import cache

    text = http_get(TOR_EXIT_URL)
    if text:
        rows = _parse_tor_ips(text, now, TOR_EXIT_URL)
        if rows:
            return rows
    if cache.too_soon("tor_danme", TOR_DANME_MIN_INTERVAL):
        from ..console import banner

        banner(
            "warn",
            "Tor exit list unreachable and the dan.me.uk fallback was fetched <30 min ago "
            "(rate-limited) — skipping Tor exits this run.",
        )
        return []
    cache.touch("tor_danme")
    text = http_get(TOR_EXIT_FALLBACK_URL)
    return _parse_tor_ips(text, now, TOR_EXIT_FALLBACK_URL) if text else []


def _feed_c2intel_ips(now):
    rows = []
    text = http_get(C2INTEL_IP_URL)
    if text:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):  # header is `#ip,ioc`
                continue
            ip = line.split(",", 1)[0].strip()
            if not ip:
                continue
            cidr = valid_cidr(f"{ip}/32" if ":" not in ip else f"{ip}/128")
            if cidr:
                rows.append((cidr, "c2intel", "c2", 2, C2INTEL_IP_URL, now))
    return rows


def _feed_firehol_level1(now):
    rows = []
    text = http_get(FIREHOL_LEVEL1_URL)
    if text:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            cidr = valid_cidr(line)
            if cidr:
                rows.append((cidr, "firehol_level1", "aggregated_blocklist", 1, FIREHOL_LEVEL1_URL, now))
    return rows


def _feed_ipsum(now):
    rows = []
    text = http_get(IPSUM_URL)
    if text:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2 or not parts[1].isdigit():
                continue
            count = int(parts[1])
            if count < IPSUM_MIN_LISTS:
                continue
            cidr = valid_cidr(f"{parts[0]}/32", want_version=4)
            if cidr:
                confidence = 1 if count >= IPSUM_HIGH_CONFIDENCE_LISTS else 2
                rows.append((cidr, "ipsum", "aggregated_blocklist", confidence, IPSUM_URL, now))
    return rows


def _feed_dshield(now):
    rows = []
    text = http_get(DSHIELD_URL)
    if text:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 3 or not parts[2].isdigit():
                continue
            cidr = valid_cidr(f"{parts[0]}/{parts[2]}", want_version=4)
            if cidr:
                rows.append((cidr, "dshield", "attacker_subnet", 1, DSHIELD_URL, now))
    return rows


def _feed_cins_ci_army(now):
    rows = []
    text = http_get(CINS_CI_ARMY_URL)
    if text:
        for line in text.splitlines():
            ip = line.strip()
            if not ip or ip.startswith("#"):
                continue
            cidr = valid_cidr(f"{ip}/32", want_version=4)
            if cidr:
                rows.append((cidr, "cins_ci_army", "malicious_host", 2, CINS_CI_ARMY_URL, now))
    return rows


THREAT_FEED_LOADERS = {
    "spamhaus_drop": _feed_spamhaus_drop,
    "tor_exit": _feed_tor_exit,
    "firehol_level1": _feed_firehol_level1,
    "ipsum": _feed_ipsum,
    "dshield": _feed_dshield,
    "cins_ci_army": _feed_cins_ci_army,
    "c2intel": _feed_c2intel_ips,
}


def load_threat_intel(selected_feeds: list[str]) -> pd.DataFrame:
    """Union the selected feeds into a de-duplicated (cidr, feed) DataFrame."""
    now = datetime.now(timezone.utc)
    rows = []
    for feed in selected_feeds:
        loader = THREAT_FEED_LOADERS.get(feed)
        if not loader:
            continue
        feed_rows = loader(now)
        from ..console import console

        console.print(f"  [muted]{feed}: {len(feed_rows):,} rows[/muted]")
        rows.extend(feed_rows)
    rows = dedupe(rows, (0, 1))
    return pd.DataFrame(rows, columns=THREAT_INTEL_COLUMNS)
