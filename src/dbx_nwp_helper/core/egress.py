"""Egress (SEG) engine: classify observed destinations → owner lookup → rule specs → apply.

Ported from `notebooks/egress_helper.py`. analyze() reads outbound_network, classifies destinations
(S3/GCS/Azure storage vs internet FQDN), and optionally matches FQDNs to a cloud owner offline.
build_blocks()/apply() assemble and send the egress block(s).
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections import defaultdict
from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import dataclass, field

import pandas as pd

from ..config import (
    DEFAULT_NAME_PREFIX,
    MAX_INTERNET_DESTINATIONS,
    MAX_STORAGE_DESTINATIONS,
    EgressConfig,
)
from ..feeds import cloud as cloud_feed
from .enrich import as_list

Note = Callable[[str], None]
ALL_WORKSPACES = "__ALL__"

_S3_VH = re.compile(r"^(?P<bucket>[a-z0-9.\-]+)\.s3[.\-](?:(?P<region>[a-z0-9\-]+)\.)?amazonaws\.com$", re.I)
_S3_BARE = re.compile(r"^s3[.\-](?:[a-z0-9\-]+\.)?amazonaws\.com$", re.I)
_GCS = re.compile(r"^(?:(?P<bucket>[a-z0-9._\-]+)\.)?storage\.googleapis\.com$", re.I)
_AZ = re.compile(r"^(?P<acct>[a-z0-9]+)\.(?P<svc>blob|dfs|file)\.core\.windows\.net$", re.I)

# Domain block feeds + the popularity/allowlist flag are loaded (and cached) via feeds.loaders; see
# feeds/domains.py. c2intel is keyless; threatfox/urlhaus are abuse.ch (need an Auth-Key — prompted
# interactively, or DBX_NWP_ABUSE_CH_AUTH_KEY). Feeds/key/allowlist are resolved by
# guided.resolve_threat_domain_feeds behind the single --block-threat-domains flag.

# Databricks-owned domains. The egress API rejects any host in these as an internet destination
# ("Workspace URL '…' not allowed as internet destination: `allowed_internet_destinations`") —
# workspace URLs (which also front model-serving endpoints at a path), Databricks Apps
# (*.databricksapps.com), and control-plane / platform service hosts are all platform-internal, not
# general internet egress. We match on these public, well-known domain suffixes rather than any
# specific hostname; the match is deliberately broad (the whole family) because allow-listing any of
# them fails the apply. Matched hosts are classified separately so they're flagged for the operator
# but never placed in the allow-list.
_DATABRICKS_URL_SUFFIXES = (
    ".databricks.com",  # workspaces (*.cloud/*.gcp[.staging]), docs, and control-plane service hosts
    ".azuredatabricks.net",  # Azure workspaces (adb-*)
    ".databricksapps.com",  # Databricks Apps
)


def _is_databricks_url(host: str) -> bool:
    return host in ("databricks.com", "azuredatabricks.net") or host.endswith(_DATABRICKS_URL_SUFFIXES)


# Feed severity ranking (lower = kept first) used when the block set exceeds the egress cap. C2
# command-and-control domains outrank general malware-URL feeds; unknown feeds sort last. This is one
# input to the prioritised cap in _blocked_domains (alongside matched-in-traffic and popularity),
# mirroring the ingress threat-deny CIDR prioritisation (_deny_sort_key in core/ingress_rules.py).
_DOMAIN_FEED_PRIORITY = {"c2intel": 0, "threatfox": 1, "urlhaus": 2}
_DOMAIN_FEED_DEFAULT_PRIORITY = 3


@dataclass
class EgressAnalysis:
    observed: pd.DataFrame
    targets: dict = field(default_factory=dict)  # policy_target -> {s3,gcs,azure,internet}
    fqdn_ip: dict = field(default_factory=dict)
    fqdn_owner: dict = field(default_factory=dict)
    blocked_domains: list = field(default_factory=list)
    # Block-candidate domains that also appear on a popularity/allowlist (MISP warninglists / Tranco).
    # Flag-only: surfaced for review, NEVER auto-removed from blocked_domains — popular != benign.
    # List of (domain, allowlist_source).
    blocked_but_popular: list = field(default_factory=list)
    skipped_bare_s3: int = 0
    # S3 buckets dropped because a region couldn't be determined (region is required by the API for
    # AWS storage destinations). List of bucket names.
    dropped_s3_no_region: list = field(default_factory=list)
    # Databricks workspace / Apps / model-serving URLs observed in egress but excluded from the
    # allow-list (the API rejects them as internet destinations). List of hostnames — flagged only.
    skipped_databricks_urls: list = field(default_factory=list)
    # Internet FQDNs excluded because they resolve only to non-routable IPs (loopback / private /
    # link-local / reserved). List of (fqdn, ip, reason) — flagged only, never allow-listed.
    skipped_nonglobal_fqdns: list = field(default_factory=list)
    # The workspace's cloud ('aws'/'azure'/'gcp'/None) — used to keep only its storage type.
    workspace_cloud: str | None = None
    # Storage destinations excluded because their cloud != the workspace's (the API rejects them).
    # List of (provider_label, display_name) — flagged only, never allow-listed.
    skipped_cross_cloud_storage: list = field(default_factory=list)
    # Truncation messages recorded when destinations were auto-capped to fit the per-policy egress
    # limits (see _blocked_domains / _warn_egress_limits). Drives the CLI truncation gate.
    truncations: list[str] = field(default_factory=list)


def _classify(host: str) -> tuple[str, dict]:
    h = (host or "").strip().rstrip(".").lower()
    if not h:
        return "skip_bare_s3", {}
    m = _S3_VH.match(h)
    if m and m.group("bucket") != "s3":
        return "s3", {"bucket": m.group("bucket"), "region": m.group("region")}
    if _S3_BARE.match(h):
        return "skip_bare_s3", {"host": h}
    g = _GCS.match(h)
    if g and g.group("bucket"):
        return "gcs", {"bucket": g.group("bucket")}
    a = _AZ.match(h)
    if a:
        return "azure", {"account": a.group("acct"), "service": a.group("svc")}
    if _is_databricks_url(h):
        # A Databricks-owned URL (workspace / Apps / model-serving / platform) — unsupported as an
        # egress internet destination; flagged and excluded rather than added (the API rejects it).
        return "databricks_url", {"host": h}
    return "internet", {"fqdn": h}


def _new_target():
    return {"s3": {}, "gcs": {}, "azure": {}, "internet": {}}


def _infer_s3_region(bucket: str) -> str | None:
    """Best-effort S3 bucket region lookup. A HEAD to the global endpoint returns the bucket's home
    region in the `x-amz-bucket-region` header, no credentials required. Returns the region or None.
    Cached per bucket by the caller."""
    from urllib.request import Request, urlopen

    for url in (f"https://{bucket}.s3.amazonaws.com", f"https://s3.amazonaws.com/{bucket}"):
        try:
            req = Request(url, method="HEAD")
            with urlopen(req, timeout=10) as resp:
                region = resp.headers.get("x-amz-bucket-region")
                if region:
                    return region
        except Exception as e:  # noqa: BLE001 - 301/403/404 all still carry the region header
            hdrs = getattr(getattr(e, "headers", None), "get", lambda _k: None)
            region = hdrs("x-amz-bucket-region") if hdrs else None
            if region:
                return region
    return None


def workspace_cloud_from_host(host: str | None) -> str | None:
    """The workspace's cloud ('aws' / 'azure' / 'gcp') from its host, or None if it can't be told.
    Used to keep only the matching storage-destination type in the egress policy — the API rejects a
    cross-cloud storage destination (e.g. an Azure storage destination on an AWS workspace)."""
    if not host:
        return None
    h = host.lower()
    if "azuredatabricks.net" in h:
        return "azure"
    if "gcp.databricks.com" in h:
        return "gcp"
    if "cloud.databricks.com" in h:
        return "aws"
    return None


# The single storage kind each cloud's egress policy accepts (the typed storage destination must
# match the workspace's own cloud).
_CLOUD_STORAGE_KIND = {"aws": "s3", "azure": "azure", "gcp": "gcs"}


def analyze(
    cfg: EgressConfig,
    sql_conn,
    on_step=lambda _m: None,
    this_workspace_id=None,
    workspace_cloud: str | None = None,
    status=None,
) -> EgressAnalysis:
    """`on_step(msg)` logs a persistent progress line; `status(msg)` (optional) is a context manager
    for an animated spinner around a long blocking step (the query, the RDAP owner sweep)."""
    from .. import queries, sql

    def _phase(msg):
        return status(msg) if status is not None else nullcontext()

    only_ws = this_workspace_id if cfg.policy_scope == "current_workspace" else None
    if only_ws is not None:
        on_step(f"Scope=current_workspace — restricting analysis to workspace {only_ws}.")

    with _phase("Querying observed egress destinations… (large logs can take a few minutes)"):
        observed = sql.query(
            sql_conn,
            queries.observed_egress(
                cfg.lookback_days, cfg.min_events, cfg.source_type_filter, only_workspace_id=only_ws
            ),
        )

    targets = defaultdict(_new_target)
    fqdn_resolved_ips = {}
    skipped_bare_s3 = 0
    skipped_dbx: dict[str, int] = {}  # Databricks workspace/app/serving URL -> events (flagged, excluded)
    s3_region_cache: dict[str, str | None] = {}  # bucket -> region (inferred once), None if unknown
    dropped_s3: dict[str, bool] = {}  # bucket -> True once dropped (dedupe warnings)
    for r in observed.to_dict(orient="records"):
        kind, info = _classify(r["destination"])
        events = int(r["events"])
        if kind == "s3":
            bucket = info["bucket"]
            region = info.get("region")
            if not region:
                # Global endpoint (<bucket>.s3.amazonaws.com) has no region in the host. Region is
                # required by the API, so infer it via a HEAD; drop the bucket if we can't.
                if bucket not in s3_region_cache:
                    on_step(f"Inferring S3 region for bucket '{bucket}'…")
                    s3_region_cache[bucket] = _infer_s3_region(bucket)
                region = s3_region_cache[bucket]
            if not region:
                dropped_s3[bucket] = True
                continue
            key, bucketname = ("s3", (bucket, region))
        elif kind == "gcs":
            key, bucketname = ("gcs", info["bucket"])
        elif kind == "azure":
            key, bucketname = ("azure", (info["account"], info["service"]))
        elif kind == "internet":
            key, bucketname = ("internet", info["fqdn"])
            ips = fqdn_resolved_ips.setdefault(info["fqdn"], [])
            for ip in as_list(r.get("resolved_ips")):
                if ip not in ips:
                    ips.append(ip)
        elif kind == "databricks_url":
            # Unsupported as an egress internet destination — collect for the flag, never allow-list.
            skipped_dbx[info["host"]] = skipped_dbx.get(info["host"], 0) + events
            continue
        else:
            skipped_bare_s3 += 1
            continue
        tgts = (
            ([int(w) for w in as_list(r.get("workspace_ids"))] or [ALL_WORKSPACES])
            if cfg.policy_scope == "per_workspace"
            else [ALL_WORKSPACES]
        )
        for t in tgts:
            d = targets[t][key]
            d[bucketname] = d.get(bucketname, 0) + events

    if not targets:
        targets[ALL_WORKSPACES] = _new_target()

    analysis = EgressAnalysis(
        observed=observed,
        targets=dict(targets),
        skipped_bare_s3=skipped_bare_s3,
        dropped_s3_no_region=sorted(dropped_s3),
        skipped_databricks_urls=sorted(skipped_dbx),
        workspace_cloud=workspace_cloud,
    )

    # Drop + flag storage destinations whose cloud doesn't match the workspace's — the egress API
    # only accepts the workspace-cloud's storage type (e.g. no Azure storage on an AWS workspace).
    _exclude_cross_cloud_storage(analysis, workspace_cloud)

    if cfg.enable_rdap:
        n_fqdns = len(union(analysis.targets, "internet"))
        with _phase(f"Resolving + owner-matching {n_fqdns} internet FQDN(s) (RDAP where needed)…"):
            _owner_lookup(analysis, fqdn_resolved_ips, cfg)

    # Drop + flag FQDNs that resolve only to non-routable IPs (loopback / private / reserved). Runs
    # regardless of RDAP — it uses the DNS-event resolved IPs, falling back to any owner-lookup one.
    _exclude_nonglobal_fqdns(analysis, fqdn_resolved_ips)

    if cfg.block_threat_domains != "off":
        on_step(f"Loading threat-domain feed(s) {', '.join(cfg.threat_feeds)}…")
        _blocked_domains(analysis, cfg, on_step)

    return analysis


_CLOUD_OWNERS = {"AWS", "GCP", "AZURE", "Azure", "ORACLE", "Oracle"}
# Owner values that mean "we couldn't identify it" rather than a real provider name.
_UNKNOWN_OWNERS = {None, "Unknown", "DNS_RESOLUTION_FAILED"}


def recommend(hosting_owner: str | None) -> str:
    """Map an internet-FQDN hosting owner to a recommendation:
      Databricks                     -> ALLOW — Databricks-owned
      AWS / GCP / Azure / Oracle     -> REVIEW — Cloud-owned
      a named RDAP owner             -> REVIEW — Other infra provider
      Unknown / DNS failed / off     -> REVIEW — owner unknown  (don't claim a provider we can't see)
    (Storage destinations — S3/GCS/Azure — are always cloud-owned, so they get REVIEW — Cloud-owned.)"""
    if hosting_owner == "Databricks":
        return "ALLOW — Databricks-owned"
    if hosting_owner in _CLOUD_OWNERS:
        return "REVIEW — Cloud-owned"
    if hosting_owner in _UNKNOWN_OWNERS:
        return "REVIEW — owner unknown"
    # A real, named non-cloud owner from RDAP (Cloudflare, GitHub, Palo Alto, …).
    return "REVIEW — Other infra provider"


def union(targets: dict, key: str) -> dict:
    merged = {}
    for t in targets:
        for k, n in targets[t][key].items():
            merged[k] = merged.get(k, 0) + n
    return merged


def _load_cloud_networks():
    """[(network, owner)] for offline IP membership tests — reuses the cloud feed loader plus
    the Databricks feed."""
    nets = []
    df = cloud_feed.load_cloud_ranges()
    for _, r in df.iterrows():
        try:
            nets.append((ipaddress.ip_network(r["cidr"], strict=False), r["provider"].upper()))
        except (ValueError, KeyError, AttributeError):
            pass
    from ..feeds import databricks as dbx_feed

    ddf = dbx_feed.load_databricks_ranges()
    for _, r in ddf.iterrows():
        try:
            nets.append((ipaddress.ip_network(r["cidr"], strict=False), "Databricks"))
        except (ValueError, KeyError):
            pass
    return nets


def _owner_lookup(analysis: EgressAnalysis, fqdn_resolved_ips: dict, cfg: EgressConfig):
    all_fqdns = union(analysis.targets, "internet")
    if not all_fqdns:
        return
    cloud_nets = _load_cloud_networks()

    def owner_for_ip(ip):
        """Cloud provider name if the IP is in a published range, else None (caller tries RDAP)."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if addr.is_private:
            return "private/internal IP"
        for net, owner in cloud_nets:
            if addr.version == net.version and addr in net:
                return owner
        return None

    from ..feeds import rdap

    rdap_cache: dict[str, str | None] = {}

    def rdap_owner(ip):
        """RDAP fallback for IPs not in a published cloud range — names the real owner (Cloudflare,
        Akamai, DigitalOcean, …). Cached per IP; best-effort (None on failure)."""
        if ip not in rdap_cache:
            rdap_cache[ip] = (rdap.lookup(ip) or {}).get("rdap_owner_name")
        return rdap_cache[ip]

    for fqdn in all_fqdns:
        ip = next(iter(fqdn_resolved_ips.get(fqdn, [])), None)
        if ip is None:
            try:
                ip = socket.gethostbyname(fqdn)
            except OSError:
                ip = None
        analysis.fqdn_ip[fqdn] = ip
        if ip is None:
            # DNS is resolved locally on the CLI host (socket.gethostbyname), so a failure
            # is a local resolution failure — not evidence of the workspace's egress control.
            analysis.fqdn_owner[fqdn] = "DNS_RESOLUTION_FAILED"
            continue
        # Cloud-range match (AWS/GCP/Azure/Oracle/Databricks) wins; else RDAP owner; else Unknown.
        owner = owner_for_ip(ip) or rdap_owner(ip) or "Unknown"
        analysis.fqdn_owner[fqdn] = owner


def _nonglobal_reason(ip_str: str) -> str | None:
    """A short reason if `ip_str` is a non-globally-routable address (so it can't be a real internet
    egress destination), else None. Ordered so the most specific label wins (is_private also covers
    loopback/link-local in the stdlib, so those are checked first)."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    if addr.is_global:
        return None
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_private:
        return "private/internal"
    if addr.is_multicast:
        return "multicast"
    if addr.is_reserved:
        return "reserved"
    if addr.is_unspecified:
        return "unspecified"
    return "non-global"


def _exclude_nonglobal_fqdns(analysis: EgressAnalysis, fqdn_resolved_ips: dict) -> None:
    """Drop (and flag) internet FQDNs whose resolved IP(s) are ALL non-globally-routable — loopback
    (127.0.0.1), RFC1918/CGNAT private ranges, link-local, reserved, etc. These are usually a local
    DNS/hosts artefact on the analysis host rather than a genuine outbound destination, and can't be
    a valid egress internet destination. A FQDN with at least one global IP is kept. Mutates
    analysis.targets and records analysis.skipped_nonglobal_fqdns as (fqdn, ip, reason)."""
    excluded = []
    for fqdn in sorted(union(analysis.targets, "internet")):
        ips = list(fqdn_resolved_ips.get(fqdn) or [])
        single = analysis.fqdn_ip.get(fqdn)  # the owner-lookup-resolved IP (when RDAP ran)
        if single and single not in ips:
            ips.append(single)
        if not ips:
            continue  # nothing resolved — can't judge; leave it for review rather than dropping it
        reasons = [(ip, _nonglobal_reason(ip)) for ip in ips]
        # Exclude only when EVERY resolved IP is non-global — a single global IP means it's reachable.
        if all(reason for _ip, reason in reasons):
            ip, reason = next((ip, r) for ip, r in reasons if r)
            excluded.append((fqdn, ip, reason))
    if not excluded:
        return
    drop = {fqdn for fqdn, _ip, _r in excluded}
    for t in analysis.targets.values():
        for fqdn in drop:
            t["internet"].pop(fqdn, None)
    analysis.skipped_nonglobal_fqdns = excluded


def _storage_display_name(kind: str, name) -> str:
    if kind == "s3":
        bucket, region = name
        return f"{bucket} ({region})" if region else bucket
    if kind == "azure":
        acct, svc = name
        return f"{acct}.{svc}"
    return name  # gcs: bucket name


def _exclude_cross_cloud_storage(analysis: EgressAnalysis, cloud: str | None) -> None:
    """Drop (and flag) storage destinations whose cloud isn't the workspace's — a cloud's egress
    policy only accepts its own storage type (AWS→S3, Azure→Azure, GCP→GCS), so a cross-cloud storage
    destination is rejected by the API. Unknown cloud → no filtering (leave it to the API). Mutates
    analysis.targets and records analysis.skipped_cross_cloud_storage as (provider_label, name).

    NB: for per_workspace scope this filters every target by *this* workspace's cloud; a mixed-cloud
    per_workspace run could over-exclude, but detecting each workspace's cloud needs per-workspace
    account calls — out of scope here."""
    keep = _CLOUD_STORAGE_KIND.get(cloud or "")
    if keep is None:
        return
    labels = {"s3": "AWS S3", "gcs": "GCS", "azure": "Azure"}
    excluded: dict[str, str] = {}  # display_name -> provider_label (deduped across targets)
    for kind in ("s3", "gcs", "azure"):
        if kind == keep:
            continue
        for t in analysis.targets.values():
            d = t[kind]
            for name in list(d):
                d.pop(name)
                excluded[_storage_display_name(kind, name)] = labels[kind]
    if excluded:
        analysis.skipped_cross_cloud_storage = sorted((label, name) for name, label in excluded.items())


def _blocked_domains(analysis: EgressAnalysis, cfg: EgressConfig, note: Note):
    from ..feeds import loaders

    feed_df = loaders.threat_domains(
        cfg.threat_feeds, auth_key=cfg.abuse_ch_auth_key, refresh=cfg.refresh_feeds, note=note
    )
    if feed_df.empty:
        analysis.blocked_domains = []
        return
    source_by_domain = dict(zip(feed_df["domain"], feed_df["source"], strict=False))
    all_fqdns = union(analysis.targets, "internet")
    if cfg.block_threat_domains == "matched_only":
        candidates = [d for d in source_by_domain if d in all_fqdns]
    else:
        candidates = list(source_by_domain)
    # Load the popularity/allowlist once: it both deprioritises popular domains under the cap below
    # and drives the flag-only review note in _flag_popular_block_candidates.
    allow_map = _allowlist_map(cfg, note)

    def _priority(domain: str) -> tuple:
        # Lower sorts first (= kept when capping). Real traffic beats raw feed hits; among equals we
        # drop popularity-allowlisted domains first (riskiest to block) and keep higher-severity feeds.
        return (
            0 if domain in all_fqdns else 1,
            1 if _popularity_source(domain, allow_map) is not None else 0,
            _DOMAIN_FEED_PRIORITY.get(source_by_domain.get(domain, ""), _DOMAIN_FEED_DEFAULT_PRIORITY),
            domain,
        )

    candidates.sort(key=_priority)
    if len(candidates) > MAX_INTERNET_DESTINATIONS:
        _record_truncation(
            analysis,
            f"{len(candidates)} blocked domains > {MAX_INTERNET_DESTINATIONS} limit — prioritising: "
            f"domains seen in your traffic first, then higher-severity feeds, deprioritising "
            f"popularity-allowlisted ones; keeping {MAX_INTERNET_DESTINATIONS}. Use "
            f"--block-threat-domains matched_only to block only domains seen in your traffic, or "
            f"select fewer feeds when prompted.",
            note,
        )
        candidates = candidates[:MAX_INTERNET_DESTINATIONS]
    analysis.blocked_domains = candidates
    _flag_popular_block_candidates(analysis, candidates, allow_map, note)


def _allowlist_map(cfg: EgressConfig, note: Note) -> dict:
    """domain -> popularity/allowlist source (MISP warninglists / Tranco). Empty when the check is
    off (cfg.domain_allowlist is False) or the feeds are unavailable."""
    if not cfg.domain_allowlist:
        return {}
    from ..feeds import loaders

    allow_df = loaders.allowlist_domains(cfg.domain_allowlist_feeds, refresh=cfg.refresh_feeds, note=note)
    if allow_df.empty:
        return {}
    return dict(zip(allow_df["domain"], allow_df["source"], strict=False))


# Common multi-label public suffixes (registrations happen *under* these, e.g. foo.co.uk). The
# allowlist feeds occasionally include one — 'ac.uk' is present in Cloudflare's top-1k — so without a
# full Public Suffix List we skip this curated set in the parent walk: matching a bare suffix would
# wrongly flag every registrable domain beneath it as "popular". Heuristic, not exhaustive; the check
# is flag-only, so a missed entry at worst adds review noise, never an auto-block/unblock.
_PUBLIC_SUFFIXES = frozenset(
    {
        "co.uk",
        "org.uk",
        "me.uk",
        "ac.uk",
        "gov.uk",
        "net.uk",
        "sch.uk",
        "ltd.uk",
        "plc.uk",
        "nhs.uk",
        "com.au",
        "net.au",
        "org.au",
        "edu.au",
        "gov.au",
        "id.au",
        "co.nz",
        "net.nz",
        "org.nz",
        "govt.nz",
        "ac.nz",
        "co.jp",
        "ne.jp",
        "or.jp",
        "go.jp",
        "ac.jp",
        "ad.jp",
        "com.br",
        "net.br",
        "org.br",
        "gov.br",
        "edu.br",
        "co.in",
        "net.in",
        "org.in",
        "gen.in",
        "firm.in",
        "gov.in",
        "co.za",
        "org.za",
        "net.za",
        "gov.za",
        "ac.za",
        "com.cn",
        "net.cn",
        "org.cn",
        "gov.cn",
        "edu.cn",
        "co.kr",
        "or.kr",
        "ne.kr",
        "re.kr",
        "go.kr",
        "com.mx",
        "com.ar",
        "com.co",
        "com.tr",
        "com.sg",
        "com.hk",
        "com.tw",
        "com.ua",
        "com.pl",
        "com.ph",
        "com.my",
        "com.ng",
        "com.sa",
        "com.eg",
        "com.pk",
        "com.vn",
        "com.bd",
        "co.id",
        "co.th",
        "co.il",
        "co.ke",
    }
)


def _popularity_source(domain: str, allow_map: dict) -> str | None:
    """The popularity/allowlist source for a domain *or any of its parent domains*, so a popular
    registrable domain also flags its subdomains (e.g. raw.githubusercontent.com via
    githubusercontent.com — the feeds list the registrable domain, not every subdomain). Walks from
    the full hostname up to the registrable level (2 labels), skipping known public suffixes (so e.g.
    ``ac.uk`` doesn't match every ``*.ac.uk``), and returns the most specific match's source. Returns
    ``None`` only when nothing matched — an empty-string source still counts as a match (membership),
    matching the old ``domain in allow_map`` test. Flag-only, so broader matching never removes a
    block."""
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        suffix = ".".join(labels[i:])
        if suffix in _PUBLIC_SUFFIXES:
            continue
        src = allow_map.get(suffix)
        if src is not None:
            return src
    return None


def _flag_popular_block_candidates(analysis: EgressAnalysis, blocked: list, allow_map: dict, note: Note):
    """Flag-only safety net: mark any block-candidate that also appears on a popularity/allowlist
    (MISP warninglists / Tranco) for review. Never removes it from the block set — popular != benign;
    these lists can contain real C2 (per the security guidance). Empty allow_map = check off."""
    if not allow_map or not blocked:
        return
    flagged = [(d, src) for d in blocked if (src := _popularity_source(d, allow_map)) is not None]
    analysis.blocked_but_popular = flagged
    if flagged:
        note(
            f"{len(flagged)} domain(s) to be blocked are also on a popularity/allowlist "
            "(e.g. Tranco / MISP warninglists) — review before enforcing; popular does NOT mean safe, "
            "but a false-positive block here could break legitimate traffic."
        )


# ------------------------------------------------------------------------------- build + apply
def _build_egress_block(t: dict, blocked_domains: list, policy_mode: str):
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicy as EA,
    )
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicyInternetDestination as InetDest,
    )
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicyInternetDestinationInternetDestinationType as InetType,
    )
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicyPolicyEnforcement as Enforcement,
    )
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicyPolicyEnforcementEnforcementMode as EnforcementMode,
    )
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicyRestrictionMode as RestrictionMode,
    )
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicyStorageDestination as StorDest,
    )
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicyStorageDestinationStorageDestinationType as StorType,
    )
    from databricks.sdk.service.settings import (
        NetworkPolicyEgress,
    )

    # Both destination lists are capped at 100; when there are more, keep the highest-traffic ones
    # (deterministic: events desc, then name asc as a stable tie-break) rather than an arbitrary
    # dict order — the excess is dropped from the allow-list, so it should be the least-used.
    internet_ranked = sorted(t["internet"].items(), key=lambda kv: (-kv[1], kv[0]))
    allowed_internet = [
        InetDest(destination=f, internet_destination_type=InetType.DNS_NAME)
        for f, _events in internet_ranked[:MAX_INTERNET_DESTINATIONS]
    ]
    blocked_internet = [
        InetDest(destination=d, internet_destination_type=InetType.DNS_NAME) for d in blocked_domains
    ] or None

    # (events, tie-break key, StorDest) across all three storage kinds, ranked together so the cap
    # keeps the busiest buckets/accounts regardless of provider.
    storage_ranked = []
    for (bucket, region), events in t["s3"].items():
        if not region:
            continue  # region is required for AWS S3; a region-less entry would be rejected
        storage_ranked.append(
            (
                events,
                f"s3:{bucket}:{region}",
                StorDest(bucket_name=bucket, region=region, storage_destination_type=StorType.AWS_S3),
            )
        )
    for bucket, events in t["gcs"].items():
        storage_ranked.append(
            (
                events,
                f"gcs:{bucket}",
                StorDest(bucket_name=bucket, storage_destination_type=StorType.GOOGLE_CLOUD_STORAGE),
            )
        )
    for (acct, svc), events in t["azure"].items():
        storage_ranked.append(
            (
                events,
                f"azure:{acct}:{svc}",
                StorDest(
                    azure_storage_account=acct,
                    azure_storage_service=svc,
                    storage_destination_type=StorType.AZURE_STORAGE,
                ),
            )
        )
    storage_ranked.sort(key=lambda e: (-e[0], e[1]))
    storage = [sd for _events, _key, sd in storage_ranked[:MAX_STORAGE_DESTINATIONS]]

    enforcement_mode = EnforcementMode.DRY_RUN if policy_mode == "dry_run" else EnforcementMode.ENFORCED
    return NetworkPolicyEgress(
        network_access=EA(
            restriction_mode=RestrictionMode.RESTRICTED_ACCESS,
            allowed_internet_destinations=allowed_internet or None,
            allowed_storage_destinations=storage or None,
            blocked_internet_destinations=blocked_internet,
            policy_enforcement=Enforcement(enforcement_mode=enforcement_mode),
        )
    )


def _target_has_content(t: dict, blocked_domains: list) -> bool:
    return bool(t["s3"] or t["gcs"] or t["azure"] or t["internet"] or blocked_domains)


def _record_truncation(analysis: EgressAnalysis, msg: str, note: Note) -> None:
    """Emit a truncation message via `note` and record it on the analysis (deduped — build_blocks
    runs several times per flow) so the CLI can gate on whether any truncation happened."""
    note(msg)
    if msg not in analysis.truncations:
        analysis.truncations.append(msg)


def _warn_egress_limits(analysis: EgressAnalysis, t: dict, tgt, note: Note) -> None:
    """Warn when a target's destinations exceed the per-policy egress caps (100 internet FQDNs / 100
    storage destinations). The excess is dropped from the allow-list — and would be *blocked* in
    enforce mode — so the operator must be told rather than have it happen silently."""
    where = "" if tgt == ALL_WORKSPACES else f" [workspace {tgt}]"
    n_internet = len(t["internet"])
    if n_internet > MAX_INTERNET_DESTINATIONS:
        _record_truncation(
            analysis,
            f"{n_internet} internet FQDN destinations{where} exceed the "
            f"{MAX_INTERNET_DESTINATIONS}-destination egress limit — keeping the "
            f"{MAX_INTERNET_DESTINATIONS} highest-traffic; the rest won't be allow-listed (and "
            f"would be blocked in enforce mode). Raise --min-events or narrow --lookback-days to "
            f"fit under the cap.",
            note,
        )
    n_storage = len(t["s3"]) + len(t["gcs"]) + len(t["azure"])
    if n_storage > MAX_STORAGE_DESTINATIONS:
        _record_truncation(
            analysis,
            f"{n_storage} storage destinations{where} exceed the "
            f"{MAX_STORAGE_DESTINATIONS}-destination egress limit — keeping the "
            f"{MAX_STORAGE_DESTINATIONS} highest-traffic; the rest won't be allow-listed (and "
            f"would be blocked in enforce mode).",
            note,
        )


def build_blocks(analysis: EgressAnalysis, cfg: EgressConfig, note: Note = lambda _m: None) -> dict:
    """{policy_target -> NetworkPolicyEgress} for each target with content."""
    blocks = {}
    for tgt, t in analysis.targets.items():
        if not _target_has_content(t, analysis.blocked_domains):
            continue
        _warn_egress_limits(analysis, t, tgt, note)
        blocks[tgt] = _build_egress_block(t, analysis.blocked_domains, cfg.policy_mode)
    return blocks


def preview_blocks(analysis: EgressAnalysis, cfg: EgressConfig, note: Note = lambda _m: None) -> dict:
    return {tgt: {"egress": block.as_dict()} for tgt, block in build_blocks(analysis, cfg, note).items()}


def _single_policy_id(cfg: EgressConfig, profile, this_workspace_id) -> str:
    """The policy id for a single-policy scope (current_workspace / all_workspaces): the
    add_to_existing target, else the resolved policy name (profile/workspace-id default)."""
    from . import policy

    if cfg.apply.policy_action == "add_to_existing":
        return cfg.apply.existing_policy_id
    name = cfg.policy_name or profile or str(this_workspace_id)
    return policy.policy_name("", explicit=name)


def _ws_policy_id(cfg: EgressConfig, profile, workspace_id) -> str:
    """The per-workspace policy id ('<prefix>-ws-<id>') apply() writes under per_workspace scope."""
    from . import policy

    prefix = cfg.policy_name or profile or DEFAULT_NAME_PREFIX
    return policy.policy_name(prefix, workspace_id=int(workspace_id))


def planned_policy_ids(blocks: dict, cfg: EgressConfig, profile, this_workspace_id) -> list[str]:
    """The policy id(s) apply() will create/update — one for single-policy scopes, one per workspace
    target (with content) for per_workspace. The CLI overwrite pre-check inspects exactly these ids.
    Pass the preview/blocks dict so per_workspace enumerates only targets that actually get a policy."""
    if cfg.policy_scope != "per_workspace":
        return [_single_policy_id(cfg, profile, this_workspace_id)]
    ws_targets = sorted(t for t in blocks if t != ALL_WORKSPACES and int(t) != 0)
    return [_ws_policy_id(cfg, profile, tgt) for tgt in ws_targets]


def export_payload(
    analysis: EgressAnalysis,
    cfg: EgressConfig,
    account_id: str,
    this_workspace_id,
    profile: str | None = None,
) -> dict:
    """The proposed network policy as a plain dict (for --export / a curl body): the egress block +
    a permissive FULL_ACCESS ingress default. Single-policy scopes only."""
    from databricks.sdk.service.settings import AccountNetworkPolicy

    from . import policy

    blocks = build_blocks(analysis, cfg)
    egress_block = blocks.get(ALL_WORKSPACES) or (next(iter(blocks.values())) if blocks else None)
    np = AccountNetworkPolicy(
        account_id=account_id,
        network_policy_id=_single_policy_id(cfg, profile, this_workspace_id),
        ingress=policy.build_full_access_ingress(),
        egress=egress_block,
    )
    return np.as_dict()


def apply(
    analysis: EgressAnalysis,
    cfg: EgressConfig,
    account,
    account_id: str,
    this_workspace_id,
    profile: str | None = None,
    note: Note = lambda _m: None,
) -> list[dict]:
    from . import policy

    blocks = build_blocks(analysis, cfg)
    add_to_existing = cfg.apply.policy_action == "add_to_existing"
    results = []
    for tgt in sorted(blocks, key=str):
        # per_workspace fans out to <prefix>-ws-<id>; every single-policy case (incl. add_to_existing
        # and --policy-name) resolves via _single_policy_id.
        if tgt == ALL_WORKSPACES:
            pid = _single_policy_id(cfg, profile, this_workspace_id)
        else:
            pid = _ws_policy_id(cfg, profile, tgt)
        bind_ws = this_workspace_id if tgt == ALL_WORKSPACES else int(tgt)
        try:
            action, effective_id = policy.apply_egress(
                account, account_id, pid, blocks[tgt], must_exist=add_to_existing
            )
            result = {"target": tgt, "action": action, "policy_id": effective_id}
            if cfg.apply.auto_assign:
                policy.assign(account, bind_ws, effective_id)
                result["assigned"] = bind_ws
            results.append(result)
        except Exception as e:  # noqa: BLE001
            results.append({"target": tgt, "error": str(e)})
    return results
