"""Egress domain feeds → a known-bad **block** set and a popularity/**allowlist** set.

Two distinct roles:
  * **Block feeds** (C2 / malware domains) back ``--block-threat-domains``:
      - ``c2intel``  — C2IntelFeeds ``domainC2s-30day.csv`` (keyless).
      - ``threatfox``/``urlhaus`` — abuse.ch; these need a free Auth-Key (https://auth.abuse.ch/),
        sent as the ``Auth-Key`` HTTP header. Without a key they're skipped (keyless feeds still load).
  * **Allowlist / popularity** (MISP warninglists + Tranco) are used **flag-only**: a block-candidate
    that also appears here is surfaced for review, NEVER auto-unblocked — popular != benign, these
    lists can contain real C2 (the security guidance is explicit about this).

NOTE: the abuse.ch export endpoints and their CSV layout can only be exercised with a real Auth-Key,
so those parsers are written to abuse.ch's documented column order and validated against synthetic
samples in the tests — confirm against live data once you have a key.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

import pandas as pd

from .http import http_get, http_get_zip_member, http_post_json

# --- block feeds -----------------------------------------------------------------------------------
C2INTEL_DOMAIN_URL = "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s-30day.csv"
# abuse.ch JSON APIs (need the `Auth-Key` header — free key from https://auth.abuse.ch/). The old
# keyless hostfile/export paths were retired (410 Gone).
THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"  # POST {"query":"get_iocs","days":N}
URLHAUS_RECENT_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"  # GET
THREATFOX_DAYS = 7  # get_iocs window (the API allows 1–7)

# --- allowlist / popularity sources ----------------------------------------------------------------
MISP_LIST_URL = "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/{name}/list.json"
TRANCO_ZIP_URL = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_TOP_N = 100_000  # cap the 1M list to the head — the tail isn't meaningfully "popular"

BLOCK_COLUMNS = ["domain", "source"]
ALLOWLIST_COLUMNS = ["domain", "source"]


def _clean_host(host: str) -> str:
    """Lower-cased hostname, no port/trailing dot. '' if it's empty or an IP literal (not a domain)."""
    host = (host or "").strip().strip(".").lower()
    if host.startswith("http://") or host.startswith("https://"):
        host = urlparse(host).hostname or ""
    host = host.split(":", 1)[0]  # drop :port
    if not host or "." not in host:
        return ""
    try:
        ipaddress.ip_address(host)
        return ""  # IP literal — not a valid FQDN block target
    except ValueError:
        return host


def _load_c2intel_domains() -> list[str]:
    text = http_get(C2INTEL_DOMAIN_URL)  # "#domain,ioc"
    if not text:
        return []
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host = _clean_host(line.split(",", 1)[0])
        if host:
            out.append(host)
    return out


def _load_abusech_domains(feed: str, auth_key: str) -> list[str]:
    hdr = {"Auth-Key": auth_key}
    if feed == "threatfox":
        # POST get_iocs → {"query_status":"ok","data":[{"ioc_type","ioc",...}]}. Keep domain/url IOCs
        # (an ip:port ioc is dropped by _clean_host's IP check).
        data = http_post_json(THREATFOX_API_URL, {"query": "get_iocs", "days": THREATFOX_DAYS}, headers=hdr)
        if not isinstance(data, dict) or data.get("query_status") != "ok":
            return []
        out = []
        for row in data.get("data") or []:
            if row.get("ioc_type") in ("domain", "url"):
                host = _clean_host(row.get("ioc", ""))
                if host:
                    out.append(host)
        return out
    # urlhaus: GET recent URLs → {"query_status":"ok","urls":[{"url",...}]}; extract each host.
    data = http_get(URLHAUS_RECENT_URL, as_json=True, headers=hdr)
    if not isinstance(data, dict) or data.get("query_status") != "ok":
        return []
    return [h for row in (data.get("urls") or []) if (h := _clean_host(row.get("url", "")))]


def load_block_domains(feeds: list[str], auth_key: str | None, note=lambda _m: None) -> pd.DataFrame:
    """Union the selected domain block feeds. abuse.ch feeds are skipped (with a note) when no
    Auth-Key is set; the keyless feeds still load."""
    from ..config import ABUSE_CH_FEEDS

    rows: list[tuple[str, str]] = []
    for feed in feeds:
        if feed in ABUSE_CH_FEEDS:
            if not auth_key:
                note(
                    f"'{feed}' is an abuse.ch feed that needs a free Auth-Key (https://auth.abuse.ch/) "
                    "— enter it when prompted or set DBX_NWP_ABUSE_CH_AUTH_KEY. Skipping it."
                )
                continue
            hosts = _load_abusech_domains(feed, auth_key)
        elif feed == "c2intel":
            hosts = _load_c2intel_domains()
        else:
            continue
        rows.extend((h, feed) for h in hosts)
    df = pd.DataFrame(rows, columns=BLOCK_COLUMNS)
    return df.drop_duplicates(subset="domain") if not df.empty else df


def _load_misp_list(name: str) -> list[str]:
    data = http_get(MISP_LIST_URL.format(name=name), as_json=True)
    if not isinstance(data, dict):
        return []
    return [_clean_host(d) for d in (data.get("list") or []) if _clean_host(d)]


def _load_tranco() -> list[str]:
    text = http_get_zip_member(TRANCO_ZIP_URL, ".csv")  # rows: rank,domain
    if not text:
        return []
    out = []
    for line in text.splitlines():
        parts = line.split(",", 1)
        if len(parts) != 2:
            continue
        host = _clean_host(parts[1])
        if host:
            out.append(host)
            if len(out) >= TRANCO_TOP_N:
                break
    return out


def load_allowlist_domains(feeds: list[str], note=lambda _m: None) -> pd.DataFrame:
    """Union the selected popularity/allowlist sources (MISP warninglists + Tranco) into
    (domain, source) rows, for flag-only review of block-candidates."""
    rows: list[tuple[str, str]] = []
    for feed in feeds:
        hosts = _load_tranco() if feed == "tranco" else _load_misp_list(feed)
        if not hosts:
            note(f"allowlist source '{feed}' returned nothing this run (skipped).")
        rows.extend((h, feed) for h in hosts)
    df = pd.DataFrame(rows, columns=ALLOWLIST_COLUMNS)
    return df.drop_duplicates(subset="domain") if not df.empty else df
