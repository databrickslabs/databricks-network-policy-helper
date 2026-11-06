"""RDAP owner lookup (deduplicated, optional) — recovers the registered owner and full assigned
range (the `maximum` framing) for a candidate IP, following referrals. Ported from the notebook.
"""

from __future__ import annotations

import ipaddress
import json
import time
from http.client import RemoteDisconnected
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from . import cache
from .http import FEED_USER_AGENT

RDAP_TIMEOUT_SECONDS = 8
RDAP_MAX_RETRIES = 4  # rdap.org / RIR servers throttle bursts; a couple of retries wasn't enough
RDAP_MAX_REFERRAL_DEPTH = 3
# Note: lookups run concurrently (bounded by --rdap-workers), which caps the request rate; per-call
# throttling/backoff on 429/503 is handled in _fetch (Retry-After + exponential backoff).

_EMPTY = {"rdap_owner_name": None, "rdap_type": None, "maximum_cidrs": None}


# RDAP entity roles ranked best→worst for "who owns this" — the org that holds the allocation
# (registrant/registrar) is the useful name; abuse/technical contacts (often literally "Abuse") are
# a last resort. Lower number = higher priority.
_ROLE_PRIORITY = {"registrant": 0, "registrar": 1, "administrative": 2, "technical": 3, "noc": 4, "abuse": 9}


def _entity_name(entity):
    """The `fn` (full name) from an entity's vCard, or None."""
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) > 1:
        for field in vcard[1]:
            if len(field) >= 4 and field[0] == "fn" and field[3]:
                return field[3]
    return None


def _extract_entity_names(entities):
    """Return owner names ranked by entity role (registrant/registrar first, abuse last) so the
    caller's names[0] is the meaningful org name rather than an abuse-desk contact. Recurses into
    nested entities. De-duplicated while preserving rank order."""
    ranked = []  # (priority, name)
    for entity in entities or []:
        name = _entity_name(entity)
        if name:
            roles = entity.get("roles") or []
            best_role = min((_ROLE_PRIORITY.get(r, 5) for r in roles), default=5)
            ranked.append((best_role, name))
        # Entities can nest (e.g. an org with sub-contacts) — include those too, one rank lower.
        for sub_prio, sub_name in _extract_ranked(entity.get("entities")):
            ranked.append((sub_prio + 0.5, sub_name))
    ranked.sort(key=lambda pn: pn[0])
    seen, out = set(), []
    for _prio, name in ranked:
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def _extract_ranked(entities):
    ranked = []
    for entity in entities or []:
        name = _entity_name(entity)
        if name:
            roles = entity.get("roles") or []
            ranked.append((min((_ROLE_PRIORITY.get(r, 5) for r in roles), default=5), name))
    return ranked


def _should_retry(error):
    if isinstance(error, HTTPError):
        return error.code in {408, 425, 429, 500, 502, 503, 504}
    if isinstance(error, (TimeoutError, RemoteDisconnected)):
        return True
    if isinstance(error, URLError):
        reason = str(error.reason).lower()
        return any(
            p in reason
            for p in [
                "timed out",
                "timeout",
                "temporarily unavailable",
                "connection reset",
                "connection aborted",
                "connection refused",
                "remote end closed connection",
            ]
        )
    return any(
        p in str(error).lower()
        for p in ["timed out", "timeout", "remote end closed connection", "temporarily unavailable"]
    )


def _maximum_cidrs(start_ip, end_ip):
    if not start_ip or not end_ip:
        return None
    try:
        nets = list(
            ipaddress.summarize_address_range(ipaddress.ip_address(start_ip), ipaddress.ip_address(end_ip))
        )
        return [str(n) for n in nets]
    except (ValueError, TypeError):
        return None


def _retry_after_seconds(error) -> float | None:
    """A 429/503 may carry a Retry-After header (delta-seconds). Honour it when present."""
    hdrs = getattr(error, "headers", None)
    if hdrs is None:
        return None
    try:
        return float(hdrs.get("Retry-After"))
    except (TypeError, ValueError):
        return None


def _fetch(url):
    delay, last_error = 1.0, None
    for attempt in range(1, RDAP_MAX_RETRIES + 1):
        request = Request(
            url, headers={"Accept": "application/rdap+json, application/json", "User-Agent": FEED_USER_AGENT}
        )
        try:
            with urlopen(request, timeout=RDAP_TIMEOUT_SECONDS) as response:
                return json.loads(response.read().decode("utf-8")), response.geturl(), None
        except Exception as error:  # noqa: BLE001
            last_error = error
            if attempt < RDAP_MAX_RETRIES and _should_retry(error):
                # Respect Retry-After on throttle responses; otherwise exponential backoff (capped).
                time.sleep(min(_retry_after_seconds(error) or delay, 10.0))
                delay *= 2
                continue
            return None, url, error
    return None, url, last_error


def _referrals(payload, ip_address, current_url):
    urls = []
    for link in payload.get("links") or []:
        href = link.get("href")
        rel = (link.get("rel") or "").lower()
        media = (link.get("type") or "").lower()
        if not href or href == current_url:
            continue
        if media and "json" not in media and "rdap" not in media:
            continue
        if f"/ip/{ip_address}" in href or "type=ip" in href or rel in {"related", "alternate", "up"}:
            if href not in urls:
                urls.append(href)
    return urls


def lookup(ip_address: str) -> dict:
    """Return {rdap_owner_name, rdap_type, maximum_cidrs} for an IP, following referrals."""
    pending, visited, best = [f"https://rdap.org/ip/{ip_address}"], set(), dict(_EMPTY)
    while pending and len(visited) <= RDAP_MAX_REFERRAL_DEPTH:
        url = pending.pop(0)
        if url in visited:
            continue
        visited.add(url)
        payload, final_url, _ = _fetch(url)
        if payload is None:
            continue
        names = _extract_entity_names(payload.get("entities"))
        result = {
            "rdap_owner_name": names[0] if names else payload.get("name") or payload.get("handle"),
            "rdap_type": payload.get("type"),
            "maximum_cidrs": _maximum_cidrs(payload.get("startAddress"), payload.get("endAddress")),
        }
        if any(result.values()):
            return result
        best = result
        for ref in _referrals(payload, ip_address, final_url):
            if ref not in visited and ref not in pending:
                pending.append(ref)
    return best if any(best.values()) else dict(_EMPTY)


# ------------------------------------------------------------------------------ on-disk result cache
# RDAP is the slow, rate-limited step for a large candidate set, and owners/assigned ranges change
# rarely — so successful answers are kept in the local feed cache (same dir / `feeds list` / `feeds
# clear` as the downloaded feeds) and reused for RDAP_CACHE_TTL_SECONDS. Failed / empty lookups are
# never cached, so a throttled run retries them next time.
RDAP_CACHE_NAME = "rdap_owners"
RDAP_CACHE_TTL_SECONDS = 30 * 24 * 3600


def _text_or_none(value):
    """Parquet round-trips a missing string as NaN; the lookup contract is None."""
    if value is None or isinstance(value, float):
        return None
    return str(value) or None


def _cacheable(result: dict) -> bool:
    return bool(result.get("rdap_owner_name") or result.get("maximum_cidrs"))


def load_cached(ttl: int = RDAP_CACHE_TTL_SECONDS) -> dict[str, dict]:
    """{ip: result} for every cached lookup younger than `ttl` seconds (empty when nothing cached)."""
    df = cache.load(RDAP_CACHE_NAME)
    if df is None or df.empty:
        return {}
    cutoff = time.time() - ttl
    out: dict[str, dict] = {}
    for rec in df.to_dict(orient="records"):
        if float(rec.get("looked_up_at") or 0) < cutoff:
            continue
        cidrs = rec.get("maximum_cidrs")
        if cidrs is not None and hasattr(cidrs, "tolist"):
            cidrs = cidrs.tolist()
        out[str(rec["ip"])] = {
            "rdap_owner_name": _text_or_none(rec.get("rdap_owner_name")),
            "rdap_type": _text_or_none(rec.get("rdap_type")),
            "maximum_cidrs": list(cidrs) if cidrs is not None and len(cidrs) else None,
        }
    return out


def store_cached(results: dict[str, dict], ttl: int = RDAP_CACHE_TTL_SECONDS) -> int:
    """Merge `results` ({ip: result}) into the on-disk cache, dropping expired rows and anything
    uncacheable. Existing rows keep their original timestamp so a re-write never extends their
    lifetime. Returns the number of new rows written. Best-effort: a cache write failure never
    affects the run."""
    import pandas as pd

    fresh = {ip: r for ip, r in results.items() if _cacheable(r)}
    if not fresh:
        return 0
    try:
        now = time.time()
        cutoff = now - ttl
        rows: dict[str, dict] = {}
        existing = cache.load(RDAP_CACHE_NAME)
        if existing is not None and not existing.empty:
            for rec in existing.to_dict(orient="records"):
                stamp = float(rec.get("looked_up_at") or 0)
                if stamp < cutoff:
                    continue
                cidrs = rec.get("maximum_cidrs")
                if cidrs is not None and hasattr(cidrs, "tolist"):
                    cidrs = cidrs.tolist()
                rows[str(rec["ip"])] = {
                    "ip": str(rec["ip"]),
                    "rdap_owner_name": _text_or_none(rec.get("rdap_owner_name")),
                    "rdap_type": _text_or_none(rec.get("rdap_type")),
                    "maximum_cidrs": list(cidrs or []),
                    "looked_up_at": stamp,
                }
        for ip, r in fresh.items():
            rows[ip] = {
                "ip": ip,
                "rdap_owner_name": r.get("rdap_owner_name"),
                "rdap_type": r.get("rdap_type"),
                "maximum_cidrs": list(r.get("maximum_cidrs") or []),
                "looked_up_at": now,
            }
        cache.store(RDAP_CACHE_NAME, pd.DataFrame(list(rows.values())))
        return len(fresh)
    except Exception:  # noqa: BLE001 - cache is an optimisation only
        return 0
