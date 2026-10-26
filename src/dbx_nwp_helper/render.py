"""Presentation layer: turn engine results into Rich output.

Kept separate from core/ (pure logic) and cli.py (arg parsing / flow) so the guided wizard and the
flag-driven commands render identically. Each function takes an analysis/result object and prints.
"""

from __future__ import annotations

import pandas as pd

from . import console
from .config import EgressConfig, IngressConfig
from .core import egress as egress_core
from .core.egress import EgressAnalysis
from .core.ingress import ALL_WORKSPACES, IngressAnalysis


# ------------------------------------------------------------------------------------- decisions
def ingress_decisions(cfg: IngressConfig) -> None:
    console.decisions_panel(
        "Ingress (CBI) configuration",
        [
            ("lookback_days", cfg.lookback_days, "Days of system.access.audit history to analyse."),
            ("min_events", cfg.min_events, "Min successful events for an IP to be a candidate."),
            (
                "treat_null_status_as_success",
                cfg.treat_null_status_as_success,
                "Whether NULL status counts as success (false = stricter).",
            ),
            ("include_ipv6", cfg.include_ipv6, "Analyse IPv6 (policy itself is IPv4-only)."),
            ("include_account_level", cfg.include_account_level, "Include workspace_id=0 rows."),
            ("threat_feeds", cfg.threat_feeds, "Threat-intel feeds to load."),
            ("enable_rdap", cfg.enable_rdap, "RDAP owner lookup (needed for 'maximum' framing)."),
            ("policy_framing", cfg.policy_framing, "minimal=/32s, optimal=collapsed, maximum=RDAP range."),
            ("scoping_mode", cfg.scoping_mode, "Whether rules are scoped by destination and/or identity."),
            ("policy_scope", cfg.policy_scope, "current_workspace / per_workspace / all_workspaces."),
            ("policy_mode", cfg.policy_mode, "dry_run=log-only; enforce=blocking."),
            ("threat_deny_rules", cfg.threat_deny_rules, "Add deny rules from threat intel."),
            (
                "policy_name",
                cfg.policy_name,
                "Policy id (single scope) / prefix (per_workspace); blank = profile name.",
            ),
            ("deny_denied_ips", cfg.deny_denied_ips, "Deny source IPs recently seen blocked (403)."),
            (
                "disable_existing_ip_acls",
                cfg.disable_existing_ip_acls,
                "After apply, turn off the workspace's IP access lists (needs create + assign).",
            ),
            ("create_policy", cfg.apply.create_policy, "Master switch: nothing is written unless true."),
            ("policy_action", cfg.apply.policy_action, "create_new or add_to_existing."),
            ("existing_policy_id", cfg.apply.existing_policy_id, "Target id for add_to_existing."),
            ("auto_assign", cfg.apply.auto_assign, "Bind the workspace(s) to the policy."),
        ],
    )


def egress_decisions(cfg: EgressConfig) -> None:
    console.decisions_panel(
        "Egress (SEG) configuration",
        [
            ("lookback_days", cfg.lookback_days, "Days of outbound_network history."),
            ("min_events", cfg.min_events, "Min events per destination."),
            ("source_type_filter", cfg.source_type_filter, "network_source_type filter (blank=all)."),
            ("enable_rdap", cfg.enable_rdap, "Cloud-owner lookup for internet FQDNs."),
            ("policy_scope", cfg.policy_scope, "current_workspace / per_workspace / all_workspaces."),
            ("policy_mode", cfg.policy_mode, "dry_run=log-only; enforce=blocking."),
            ("block_threat_domains", cfg.block_threat_domains, "off / matched_only / all."),
            ("threat_feeds", ",".join(cfg.threat_feeds), "Domain block feeds (c2intel/threatfox/urlhaus)."),
            (
                "abuse_ch_auth_key",
                "set" if cfg.abuse_ch_auth_key else "(unset)",
                "Enables abuse.ch feeds (threatfox/urlhaus).",
            ),
            (
                "domain_allowlist",
                cfg.domain_allowlist,
                "Flag block-candidates on a popularity/allowlist for review.",
            ),
            (
                "policy_name",
                cfg.policy_name,
                "Policy id (single scope) / prefix (per_workspace); blank = profile name.",
            ),
            ("create_policy", cfg.apply.create_policy, "Master switch: nothing is written unless true."),
            ("policy_action", cfg.apply.policy_action, "create_new or add_to_existing."),
            ("existing_policy_id", cfg.apply.existing_policy_id, "Target id for add_to_existing."),
            ("auto_assign", cfg.apply.auto_assign, "Bind the workspace(s) to the policy."),
        ],
    )


# ------------------------------------------------------------------------------- ingress tables
def ingress_analysis(analysis: IngressAnalysis, cfg: IngressConfig | None = None) -> None:
    console.rule("Candidate public source IPs")
    console.dataframe(
        _trim(
            analysis.candidates,
            [
                "public_ip",
                "events",
                "principals",
                "services",
                "active_days",
                "first_active_date",
                "last_active_date",
            ],
        ),
        f"Frequent public source IPs ({len(analysis.candidates):,})",
    )
    if analysis.candidates.empty and analysis.funnel is not None:
        _explain_empty_candidates(analysis.funnel, cfg)

    console.rule("Proposed CIDR groups")
    if analysis.suggestions.empty:
        console.banner("warn", "No candidate IP groups produced suggestions — check thresholds.")
    else:
        framing = getattr(cfg, "policy_framing", "minimal") if cfg else "minimal"
        console.dataframe(
            _suggestions_display(analysis.suggestions, framing),
            f"Ranked suggestions ({framing} framing; grouped into per-owner allow "
            "rules — threat-intel groups excluded)",
        )

    console.rule("⚠️  Threat-intelligence matches")
    if analysis.threat_matches.empty:
        console.banner("success", "No observed source IPs matched any threat-intelligence feed.")
    else:
        n = analysis.threat_matches["observed_ip"].nunique()
        console.banner(
            "warn",
            f"{n} observed IP(s) matched threat intel — investigate regardless "
            "of the allow-list (may indicate a compromised identity).",
        )
        console.dataframe(
            _trim(
                analysis.threat_matches,
                [
                    "observed_ip",
                    "matched_cidr",
                    "source_feed",
                    "threat_type",
                    "confidence",
                    "events",
                    "principals",
                ],
            ),
            "Observed IPs on a threat feed",
        )

    if not analysis.denied_requests.empty:
        console.rule("Recently denied inbound requests (IP ACL 403 + CBI policy)")
        console.dataframe(
            _trim(
                analysis.denied_requests,
                ["source_ip", "denied_events", "principals", "first_denied", "last_denied"],
            ),
            "Source IPs recently blocked inbound (IP access list and/or CBI network policy)",
        )
        if cfg is not None and cfg.deny_denied_ips:
            console.banner("info", "These will be added as deny rules (--deny-denied-ips is on).")
        else:
            console.banner(
                "info",
                "Shown for context — these are NOT added as deny rules. Pass "
                "--deny-denied-ips to block them.",
            )


def _explain_empty_candidates(funnel: dict, cfg: IngressConfig | None) -> None:
    """Turn the diagnostic funnel into a readable table + targeted hints, so an empty candidate set
    tells the user *where* their IPs were dropped and which knob would help."""

    def _n(key):
        return int(funnel.get(key) or 0)

    rows = [
        ("total audit rows", _n("total_rows"), ""),
        ("… with a source IP", _n("with_source_ip"), "rows carrying a usable source_ip_address"),
        ("… IPv4 / IPv6", f"{_n('ipv4'):,} / {_n('ipv6'):,}", "CBI policies are IPv4-only"),
        ("… successful", _n("successful"), "status_code < 400 (or NULL if you opted in)"),
        (
            "… workspace-level / account-level",
            f"{_n('workspace_level'):,} / {_n('account_level'):,}",
            "workspace_id <> 0 vs = 0",
        ),
        ("… public IPv4", _n("public_ipv4"), "private/CGNAT/reserved ranges excluded"),
        (
            "distinct public IPs (successful)",
            _n("distinct_public_ok"),
            "candidates if account-level is included",
        ),
        (
            "distinct public IPs (successful, workspace-level)",
            _n("distinct_public_ok_ws"),
            "candidates under the default filters",
        ),
    ]
    df = pd.DataFrame([{"filter stage": s, "rows / count": v, "meaning": m} for s, v, m in rows])
    console.banner("warn", "No candidate public source IPs survived the filters. Here's the funnel:")
    console.dataframe(df, "Why the candidate set is empty", max_rows=50)

    # Targeted, ordered hints — most likely cause first.
    hints = []
    include_account = getattr(cfg, "include_account_level", False) if cfg else False
    if _n("distinct_public_ok_ws") == 0 and _n("distinct_public_ok") > 0 and not include_account:
        hints.append(
            "Public IPs appear only on ACCOUNT-LEVEL rows (workspace_id=0) — e.g. account "
            "console / SCIM traffic. Re-run with --include-account-level to use them."
        )
    if _n("with_source_ip") > 0 and _n("public_ipv4") == 0 and _n("ipv4") > 0:
        hints.append(
            "Source IPs are all private/reserved — this workspace likely uses PrivateLink "
            "or a NAT gateway, so the audit log records the relay's private IP, not the "
            "user's public IP. A source-IP allow-list can't be built from this traffic."
        )
    if _n("successful") == 0 and _n("with_source_ip") > 0:
        hints.append(
            "No rows counted as successful — try --treat-null-status-as-success if your "
            "audit rows have NULL status_code."
        )
    if _n("ipv4") == 0 and _n("ipv6") > 0:
        hints.append("Traffic is IPv6-only; CBI policies are IPv4-only, so nothing can be proposed.")
    if _n("total_rows") == 0:
        hints.append(
            "No audit rows in the window at all — widen --lookback-days, or confirm the "
            "warehouse can read system.access.audit."
        )
    if not hints:
        hints.append("Try widening --lookback-days, lowering --min-events, or --include-account-level.")
    for h in hints:
        console.banner("info", h)


def ingress_preview(previews: dict, cfg: IngressConfig, analysis: IngressAnalysis) -> None:
    console.rule("Proposed policy — JSON preview")
    console.mode_banner(cfg.policy_mode)
    if not previews:
        console.banner("warn", "No rule specs to preview — revisit framing/scoping/threat options.")
        return
    for tgt in sorted(previews, key=str):
        label = _target_label(tgt, cfg.policy_scope, ALL_WORKSPACES)
        console.json_panel(f"{label} — `{cfg.policy_mode_target}` block", previews[tgt])
    if analysis.excluded_flagged:
        console.banner(
            "info",
            f"Excluded {analysis.excluded_flagged} threat-intel-matched group(s) from the "
            "allow-list (see the threat-match table).",
        )
    if analysis.excluded_unresolved:
        console.banner(
            "warn",
            f"Excluded {analysis.excluded_unresolved} group(s) from the allow-list: identity "
            "scoping is on but none of their principals resolved (likely users who've left "
            "the workspace/org). Allow-listing their IPs for ALL_USERS would defeat identity "
            "scoping — add them manually if the traffic is still expected.",
        )
    if analysis.skipped_ipv6:
        console.banner("info", f"{analysis.skipped_ipv6} IPv6 CIDR(s) omitted (CBI is IPv4-only).")


# -------------------------------------------------------------------------------- egress tables
def egress_analysis(analysis: EgressAnalysis) -> None:
    console.rule("Observed egress destinations")
    if analysis.observed.empty:
        console.banner(
            "warn",
            "outbound_network is empty for this window. Stand up an egress policy "
            "in dry_run (restricted, log-only) first, let it observe, then re-run.",
        )
    targets = analysis.targets
    internet = egress_core.union(targets, "internet")
    s3 = egress_core.union(targets, "s3")
    gcs = egress_core.union(targets, "gcs")
    azure = egress_core.union(targets, "azure")

    console.dataframe(
        pd.DataFrame(
            [
                {
                    "fqdn": f,
                    "events": n,
                    "resolved_ip": analysis.fqdn_ip.get(f),
                    "hosting_owner": analysis.fqdn_owner.get(f),
                    "recommendation": egress_core.recommend(analysis.fqdn_owner.get(f)),
                }
                for f, n in sorted(internet.items(), key=lambda kv: kv[1], reverse=True)
            ]
        ),
        f"Observed FQDNs to review ({len(internet)})",
    )
    # Storage destinations are inherently cloud-owned buckets/accounts -> cloud-owned recommendation.
    console.dataframe(
        pd.DataFrame(
            [
                {"bucket": b, "region": reg, "events": n, "recommendation": "REVIEW — Cloud-owned"}
                for (b, reg), n in sorted(s3.items(), key=lambda kv: kv[1], reverse=True)
            ]
        ),
        f"AWS S3 buckets ({len(s3)})",
    )
    console.dataframe(
        pd.DataFrame(
            [
                {"bucket": b, "events": n, "recommendation": "REVIEW — Cloud-owned"}
                for b, n in sorted(gcs.items(), key=lambda kv: kv[1], reverse=True)
            ]
        ),
        f"GCS buckets ({len(gcs)})",
    )
    console.dataframe(
        pd.DataFrame(
            [
                {"account": a, "service": s, "events": n, "recommendation": "REVIEW — Cloud-owned"}
                for (a, s), n in sorted(azure.items(), key=lambda kv: kv[1], reverse=True)
            ]
        ),
        f"Azure storage ({len(azure)})",
    )
    if analysis.blocked_domains:
        console.dataframe(
            pd.DataFrame(
                [{"blocked_domain": d, "observed_in_egress": d in internet} for d in analysis.blocked_domains]
            ),
            f"Threat-intel blocked domains ({len(analysis.blocked_domains)})",
        )
    if analysis.blocked_but_popular:
        console.dataframe(
            pd.DataFrame(
                [{"domain": d, "popularity_source": src} for d, src in analysis.blocked_but_popular]
            ),
            f"⚠️ Block-candidates on a popularity/allowlist — REVIEW ({len(analysis.blocked_but_popular)})",
        )
        console.banner(
            "warn",
            "The domains above are on a popularity/allowlist (Tranco / MISP warninglists) yet a threat "
            "feed flags them as bad. They are STILL in the block set — popular does not mean safe — but "
            "verify them: a false positive here would block legitimate traffic. Remove any you trust "
            "from the block feed or narrow with --block-threat-domains matched_only.",
        )
    if analysis.skipped_bare_s3:
        console.banner("info", f"Skipped {analysis.skipped_bare_s3} bare/path-style S3 endpoint(s).")
    if analysis.dropped_s3_no_region:
        buckets = ", ".join(analysis.dropped_s3_no_region)
        console.banner(
            "warn",
            f"Excluded {len(analysis.dropped_s3_no_region)} S3 bucket(s) whose "
            f"region could not be determined (region is required for an AWS "
            f"storage rule): {buckets}. Add them manually with their region if "
            f"needed.",
        )
    if analysis.skipped_databricks_urls:
        hosts = ", ".join(analysis.skipped_databricks_urls)
        console.banner(
            "warn",
            f"Excluded {len(analysis.skipped_databricks_urls)} Databricks workspace / Apps / "
            f"model-serving URL(s) — these are platform-internal and can't be set as egress internet "
            f"destinations (the API rejects them), so they're flagged here but NOT added to the "
            f"policy: {hosts}.",
        )
    if analysis.skipped_nonglobal_fqdns:
        items = ", ".join(
            f"{fqdn} → {ip} ({reason})" for fqdn, ip, reason in analysis.skipped_nonglobal_fqdns
        )
        console.banner(
            "warn",
            f"Excluded {len(analysis.skipped_nonglobal_fqdns)} FQDN(s) that resolve only to "
            f"non-routable IPs (loopback / private / link-local / reserved) — these can't be real "
            f"internet egress (often a local DNS/hosts artefact on the analysis host), so they're "
            f"flagged here but NOT added to the policy: {items}.",
        )
    if analysis.skipped_cross_cloud_storage:
        items = ", ".join(f"{name} ({label})" for label, name in analysis.skipped_cross_cloud_storage)
        ctx = (analysis.workspace_cloud or "this").upper()
        console.banner(
            "warn",
            f"Excluded {len(analysis.skipped_cross_cloud_storage)} cross-cloud storage destination(s) "
            f"— a {ctx}-context egress policy only supports its own cloud's storage type, so the API "
            f"rejects these; they're flagged here but NOT added to the policy (allow-list them "
            f"another way if the workload genuinely needs them): {items}.",
        )


def egress_preview(previews: dict, cfg: EgressConfig) -> None:
    console.rule("Proposed egress policy — JSON preview")
    console.mode_banner(cfg.policy_mode)
    if not previews:
        console.banner("warn", "Nothing to propose — no classified destinations.")
        return
    for tgt in sorted(previews, key=str):
        label = _target_label(tgt, cfg.policy_scope, egress_core.ALL_WORKSPACES)
        console.json_panel(f"{label} — egress block", previews[tgt])


# ------------------------------------------------------------------------------- apply results
def policy_url(account_host: str, account_id: str, policy_id: str) -> str:
    """The account-console URL for a network policy."""
    host = (account_host or "").rstrip("/")
    return f"{host}/security/networking/network-access-policies/{policy_id}?account_id={account_id}"


def apply_results(results: list[dict], account_host: str = "", account_id: str = "") -> None:
    console.rule("Apply results")
    for r in results:
        if "error" in r:
            console.banner("danger", f"target {r['target']}: {r['error']}")
            continue
        msg = f"{r['action']} network policy"
        if r.get("assigned") is not None:
            msg += f" and bound workspace {r['assigned']}"
        console.banner("success", msg)
        console.console.print(f"   [key]network policy id:[/key] {r['policy_id']}")
        if account_host and account_id:
            url = policy_url(account_host, account_id, r["policy_id"])
            # soft_wrap keeps the URL on one logical line (terminals still soft-wrap the display,
            # but it stays a single copy-pasteable string and isn't hard-broken mid-token).
            console.console.print(f"   [key]url:[/key] [info]{url}[/info]", soft_wrap=True)


def _target_label(tgt, policy_scope: str, all_sentinel) -> str:
    """Human label for a policy target. The single-policy sentinel reads differently by scope
    (current_workspace vs all_workspaces); per_workspace targets are the workspace id."""
    if tgt != all_sentinel:
        return f"workspace {tgt}"
    return "this workspace" if policy_scope == "current_workspace" else "all workspaces"


def _trim(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    """Keep only the columns that exist, in the given order (for compact tables)."""
    if df is None or df.empty:
        return df
    keep = [c for c in cols if c in df.columns]
    return df[keep] if keep else df


_FRAMING_COL = {"minimal": "minimal_cidrs", "optimal": "optimal_cidrs", "maximum": "maximum_cidrs"}


def _fmt_flag(value) -> str:
    """Render an enrichment flag (a list of matched feed/provider names, or None) as either the
    matched names or an explicit 'no' — so a blank cell never reads as 'we didn't check'."""
    if value is None:
        return "no"
    if hasattr(value, "tolist"):  # numpy array from a DataFrame cell
        value = value.tolist()
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value) if len(value) else "no"
    return str(value)


def _suggestions_display(suggestions: pd.DataFrame, framing: str) -> pd.DataFrame:
    """Build the human-facing suggestions table: friendly target, the framing-matched CIDRs, and
    unambiguous yes/no-style enrichment flags."""
    cidr_col = _FRAMING_COL.get(framing, "minimal_cidrs")
    rows = []
    for _, r in suggestions.iterrows():
        tgt = r["policy_target"]
        cidrs = r.get(cidr_col)
        cidrs = list(cidrs.tolist()) if hasattr(cidrs, "tolist") else (cidrs or [])
        rows.append(
            {
                "policy_target": "(all workspaces)" if tgt == ALL_WORKSPACES else tgt,
                "rdap_owner": r["rdap_owner"],
                "recommendation": r["recommendation"],
                "distinct_ips": r["distinct_ips"],
                "total_events": r["total_events"],
                "cidrs": ", ".join(cidrs) if cidrs else "(none)",
                "scoped_destination": r["scoped_destination"],
                "threat_feeds": _fmt_flag(r["threat_feeds"]),
                "cloud_provider": _fmt_flag(r["cloud_provider"]),
                "databricks_owned": _fmt_flag(r["databricks_owned"]),
            }
        )
    return pd.DataFrame(rows)
