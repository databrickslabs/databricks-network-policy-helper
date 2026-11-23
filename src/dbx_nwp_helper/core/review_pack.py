"""`ingress --review-pack <dir>`: turn this run's proposed policy into a pack the workspace's owners
can review and TEST (dry-run first): a README with the test plan, exit criteria and rollback, a review
sheet (one row per rule and range, with the traffic it covers and keep/drop + owner columns), the
observed sources enforcing would block, and a daily dry-run check.

Pure: it reads the run's in-memory analysis and export payload and writes local files. It never
calls a Databricks API and never applies anything.
"""

from __future__ import annotations

import csv
import ipaddress
import json
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

from ..config import CONSOLIDATED_RULE_LABEL, IngressConfig
from . import posture

BROAD_PREFIX = 16  # allow CIDRs at least this broad are flagged
DRY_RUN_DAYS = 28
LOW_VOLUME_EVENTS = 10
SHEET_COLS = [
    "section",
    "action",
    "label",
    "origin",
    "category",
    "destination",
    "identities",
    "matched_ips",
    "events",
    "active_days",
    "first_seen",
    "last_seen",
    "services",
    "sample_identities",
    "flags",
    "guidance",
    "decision (keep / drop)",
    "owner",
    "notes",
]
UNCOVERED_COLS = [
    "source_ip",
    "events",
    "active_days",
    "first_seen",
    "last_seen",
    "services",
    "sample_identities",
    "reason",
    "hint",
    "decision (add / accept block)",
    "owner",
    "notes",
]
_ALL = "ALL public IPv4"
_HIDDEN = "source not visible through the API"
_NO_RANGES = "no IP ranges set"
_FULL_DEST, _FULL_IDS = "all", "all users and service principals"


@dataclass
class RuleRow:
    section: str  # public / private / cross_workspace
    action: str  # allow / deny
    label: str
    origin: str  # CIDR, "ALL public IPv4", endpoint ids, workspace ids
    destination: str = "all"
    identities: str = "all users and service principals"
    category: str = "observed"
    guidance: str = ""
    matched_ips: int = 0
    events: int = 0
    active_days: int = 0
    first_seen: str = ""
    last_seen: str = ""
    services: str = ""
    sample_identities: str = ""
    flags: list[str] = field(default_factory=list)


@dataclass
class Context:
    """What the pack needs from the run, beyond the payload and the candidates."""

    workspace_id: str
    cfg: IngressConfig
    profile: str | None = None
    warehouse_http_path: str | None = None
    assigned_policy_id: str | None = None
    existing_egress_restrictive: bool = False
    acl_labels: set[str] = field(default_factory=set)
    partner_labels: set[str] = field(default_factory=set)


# ------------------------------------------------------------------------------------- the policy
def active_ingress(policy: dict) -> tuple[dict, str]:
    if policy.get("ingress"):
        return policy["ingress"], "enforce"
    if policy.get("ingress_dry_run"):
        return policy["ingress_dry_run"], "dry_run"
    return {}, "none"


def _destination(rule: dict) -> str:
    c = posture.classify_rule(rule)
    if "all" in c["reach"]:
        return "all"
    parts = [x for x in c["reach"] if x != "api"]
    if "api" in c["reach"]:
        scopes = ", ".join(c["scopes"])
        parts.append(
            {
                "all": "api (all)",
                "all_except": f"api (all except {scopes})",
                "read": f"api read-only ({scopes})",
                "unstated": "api (no scopes stated: treat as all)",
            }.get(c["api"], f"api ({scopes})")
        )
    return ", ".join(parts) or "none"


def _identities(rule: dict) -> str:
    auth = rule.get("authentication") or {}
    it = str(auth.get("identity_type") or "")
    if "SELECTED" in it:
        return f"{len(auth.get('identities') or [])} selected identities"
    if "SERVICE_PRINCIPALS" in it:
        return "all service principals"
    if "USERS" in it:
        return "all users"
    return "all users and service principals"


def flatten(policy: dict) -> list[RuleRow]:
    """One row per rule and range of the active ingress block."""
    ing, _mode = active_ingress(policy)
    rows: list[RuleRow] = []
    for action in ("allow", "deny"):
        for r in (ing.get("public_access") or {}).get(f"{action}_rules") or []:
            origin, label = r.get("origin") or {}, r.get("label") or "(unlabelled)"
            inc = (origin.get("included_ip_ranges") or {}).get("ip_ranges") or []
            exc = (origin.get("excluded_ip_ranges") or {}).get("ip_ranges") or []
            dest, ids = _destination(r), _identities(r)
            if origin.get("all_ip_ranges"):
                rows.append(RuleRow("public", action, label, _ALL, dest, ids))
            elif exc and not inc:
                rows.append(RuleRow("public", action, label, f"{_ALL} except " + ", ".join(exc), dest, ids))
            elif not origin:
                rows.append(RuleRow("public", action, label, _HIDDEN, dest, ids))
            else:
                rows += [RuleRow("public", action, label, str(c), dest, ids) for c in inc] or [
                    RuleRow("public", action, label, _NO_RANGES, dest, ids)
                ]
    for action in ("allow", "deny"):
        for r in (ing.get("private_access") or {}).get(f"{action}_rules") or []:
            o = r.get("origin") or {}
            eps = (o.get("endpoints") or {}).get("endpoint_ids") or []
            origin = (
                ", ".join(eps)
                if eps
                else "all registered endpoints" if o.get("all_registered_endpoints") else "private"
            )
            rows.append(
                RuleRow(
                    "private",
                    action,
                    r.get("label") or "(unlabelled)",
                    origin,
                    _destination(r),
                    _identities(r),
                )
            )
    for action in ("allow", "deny"):
        for r in (ing.get("cross_workspace_access") or {}).get(f"{action}_rules") or []:
            ids = ((r.get("origin") or {}).get("selected_workspaces") or {}).get("workspace_ids") or []
            origin = ", ".join(map(str, ids)) if ids else "all source workspaces"
            rows.append(RuleRow("cross_workspace", action, r.get("label") or "(unlabelled)", origin))
    return rows


def classify(row: RuleRow, ctx: Context) -> None:
    lab = row.label.lower()
    if row.section == "private":
        row.category = "private-endpoint"
        row.guidance = (
            "Carried from the workspace's PrivateLink settings. Confirm the endpoint ids are still in use."
        )
    elif row.section == "cross_workspace":
        row.category, row.guidance = "cross-workspace", "Carried forward unchanged from the current policy."
    elif row.origin == _HIDDEN:
        row.category = "console-source"
        row.guidance = (
            "The API doesn't describe this rule's source (often Partner platforms or an app integration). "
            "Review it in the account console."
        )
    elif row.origin.startswith(_ALL):
        row.category = "catch-all"
        row.guidance = (
            "Allows every public IPv4 source. With this rule the policy only blocks its deny rules."
        )
    elif row.action == "deny" and lab == "deny-recently-denied":
        row.category = "deny-recently-denied"
        row.guidance = (
            "Sources blocked recently (IP access list or enforced CBI). Confirm none is a legitimate client."
        )
    elif row.action == "deny":
        row.category = "deny-threat-intel"
        row.guidance = (
            "From an open threat-intel feed. Feeds have false positives; keep unless an owner recognises it."
        )
    elif lab.startswith("databricks-"):
        row.category = "databricks"
        row.guidance = (
            "Databricks-owned range seen in your traffic (platform callbacks). Keep. Only ranges seen in the "
            "window are listed, so confirm the platform ranges the workspace needs are covered before "
            "enforcing."
        )
    elif row.label in ctx.partner_labels:
        row.category = "partner"
        row.guidance = (
            "A partner platform (BI / transformation SaaS). Its IPs rotate; prefer the managed 'Partner "
            "platforms' source in the account console over pinning these CIDRs."
        )
    elif lab.startswith(CONSOLIDATED_RULE_LABEL.lower()):
        row.category = "consolidated"
        row.guidance = (
            "Low-traffic owners folded together to stay under the rule cap. Review the sources individually."
        )
    elif lab in ctx.acl_labels:
        row.category = "ip-acl"
        row.guidance = "Migrated from the workspace's existing IP access list. Confirm it is still needed."
    else:
        row.category = "observed"
        row.guidance = (
            "Derived from successful traffic in the lookback window. Observed isn't trusted: an owner must "
            "recognise this source."
        )


# ------------------------------------------------------------------------------- traffic matching
def _net(s: str):
    try:
        n = ipaddress.ip_network(str(s).strip(), strict=False)
    except ValueError:
        return None
    return n if n.version == 4 else None


def _as_list(v) -> list[str]:
    if v is None or (isinstance(v, float) and v != v):
        return []
    if isinstance(v, str):
        return [v] if v else []
    return [str(x) for x in v]


def _text(v) -> str:
    """A cell as text, with None / NaN / NaT as "" (pandas fills missing dates with NaN)."""
    if v is None or v != v or str(v) in ("NaT", "nan"):
        return ""
    return str(v)


def _int(v) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


def source_profile(candidates: pd.DataFrame) -> list[dict]:
    """The analysed public IPv4 sources, one dict per IP. Rows that came only from inbound_network
    dry-run denials (no audit services) are marked `dry_run_only`."""
    out = []
    if candidates is None or candidates.empty:
        return out
    for r in candidates.to_dict(orient="records"):
        try:
            ip = ipaddress.ip_address(str(r.get("public_ip")).strip())
        except ValueError:
            continue
        if ip.version != 4:
            continue
        services = _as_list(r.get("service_list"))
        out.append(
            {
                "active_days": _int(r.get("active_days")),
                "dry_run_only": not services,
                "events": _int(r.get("events")),
                "first_seen": _text(r.get("first_active_date")),
                "ip": ip,
                "last_seen": _text(r.get("last_active_date")),
                "principals": _as_list(r.get("principal_list")),
                "services": services,
            }
        )
    return out


def _excluded(origin: str) -> list:
    if " except " not in origin:
        return []
    return [n for n in (_net(c) for c in origin.split(" except ", 1)[1].split(", ")) if n]


def attach_traffic(rows: list[RuleRow], profile: list[dict]) -> None:
    for row in rows:
        if row.section != "public" or row.origin == _HIDDEN:
            continue
        if row.origin.startswith(_ALL):
            excl = _excluded(row.origin)
            hits = [p for p in profile if not any(p["ip"] in n for n in excl)]
        else:
            n = _net(row.origin)
            hits = [p for p in profile if n is not None and p["ip"] in n]
        row.matched_ips = len(hits)
        row.events = sum(p["events"] for p in hits)
        row.active_days = max((p["active_days"] for p in hits), default=0)
        firsts = [p["first_seen"] for p in hits if p["first_seen"]]
        lasts = [p["last_seen"] for p in hits if p["last_seen"]]
        row.first_seen, row.last_seen = min(firsts, default=""), max(lasts, default="")
        row.services = ", ".join(sorted({s for p in hits for s in p["services"]})[:8])
        ids: list[str] = []
        for p in sorted(hits, key=lambda p: -p["events"]):
            ids += [x for x in p["principals"] if x not in ids]
        row.sample_identities = ", ".join(ids[:5])
        if row.action == "allow" and hits and all(p["dry_run_only"] for p in hits):
            row.flags.append("seen only as a dry-run denial: a current dry-run policy would block it")


def flag(row: RuleRow) -> None:
    if row.section != "public" or row.origin in (_HIDDEN, _NO_RANGES):
        if row.origin == _NO_RANGES:
            row.flags.append("the rule lists no IP ranges: confirm what it's meant to admit")
        return
    n = _net(row.origin)
    if row.action == "allow" and n is not None and n.prefixlen <= BROAD_PREFIX:
        row.flags.append(
            f"broad range /{n.prefixlen} ({n.num_addresses:,} addresses): confirm it isn't a whole cloud or "
            "ISP block"
        )
    if row.category == "catch-all":
        row.flags.append("allows every public source")
    if row.action != "allow" or row.category == "catch-all":
        return
    if row.events == 0:
        why = ": confirm still needed" if row.category in ("ip-acl", "partner") else ""
        row.flags.append("no successful traffic in the window" + why)
    elif row.active_days <= 1:
        row.flags.append("seen on one day only")
    elif row.events < LOW_VOLUME_EVENTS:
        row.flags.append(f"low volume ({row.events} events)")


def _uncovered_hint(p: dict) -> str:
    if len(p["principals"]) == 1 and p["active_days"] >= 5:
        return (
            "one identity, recurring: likely a roaming user or a job host; confirm, then add the network or "
            "route it via an approved one"
        )
    if p["active_days"] <= 1:
        return "seen on one day only: likely safe to leave blocked, confirm with the identity's owner"
    return "confirm with the identities' owners"


def _matches(row: RuleRow, ip) -> bool:
    if row.origin == _ALL:
        return True
    if row.origin.startswith(f"{_ALL} except "):
        return not any(ip in n for n in _excluded(row.origin))
    n = _net(row.origin)
    return n is not None and ip in n


def uncovered(profile: list[dict], rows: list[RuleRow]) -> list[dict]:
    """Observed public sources the policy would block if enforced: a deny rule matches, no allow rule
    covers them, or only rules scoped to some destinations / identities do (so requests outside that
    scope would be blocked; the traffic profile doesn't say which requests those are)."""
    allows = [r for r in rows if r.section == "public" and r.action == "allow"]
    deny_nets = [
        (r.label, n)
        for r in rows
        if r.section == "public" and r.action == "deny"
        for n in [_net(r.origin)]
        if n
    ]
    out = []
    for p in profile:
        denied = next((lab for lab, n in deny_nets if p["ip"] in n), None)
        hits = [r for r in allows if _matches(r, p["ip"])]
        if denied:
            reason = f"matches deny rule '{denied}'"
        elif not hits:
            reason = "no allow rule covers it"
        elif not any(r.destination == _FULL_DEST and r.identities == _FULL_IDS for r in hits):
            scopes = "; ".join(sorted({f"{r.label}: {r.destination} / {r.identities}" for r in hits}))
            reason = f"only scoped rules cover it ({scopes}); requests outside that scope would be blocked"
        else:
            continue
        out.append(
            {
                "active_days": p["active_days"],
                "decision (add / accept block)": "",
                "events": p["events"],
                "first_seen": p["first_seen"],
                "hint": _uncovered_hint(p),
                "last_seen": p["last_seen"],
                "notes": "",
                "owner": "",
                "reason": reason,
                "sample_identities": ", ".join(p["principals"][:5]),
                "services": ", ".join(p["services"][:8]),
                "source_ip": str(p["ip"]),
            }
        )
    return sorted(out, key=lambda r: -r["events"])


# ---------------------------------------------------------------------------- warnings + commands
def build_warnings(policy: dict, rows: list[RuleRow], ctx: Context) -> list[str]:
    W: list[str] = []
    cfg = ctx.cfg
    _ing, mode = active_ingress(policy)
    if mode == "enforce":
        W.append(
            "**The proposal writes the ENFORCED block, not dry-run.** `ingress` inherits enforce mode when "
            "the "
            "workspace's assigned policy already enforces CBI (or `--policy-mode enforce` was passed). "
            "Applying "
            "it is a live change, not a test: review `uncovered-sources.csv` first, or trial it in a "
            "non-production workspace."
        )
    if mode == "none":
        W.append("The proposal has no ingress block; there may have been no traffic to propose from.")
    new_egress = posture.summarise_policy({"egress": policy.get("egress")})
    if ctx.existing_egress_restrictive and not new_egress["egress_restrictive"]:
        W.append(
            "**Don't apply `policy.json` by hand.** The workspace's current policy "
            f"`{ctx.assigned_policy_id}` "
            "restricts serverless egress, but this file carries a FULL_ACCESS egress default. Applying it as "
            "a "
            "new policy would open egress. Apply through `ingress` (below), which keeps the existing egress."
        )
    if cfg.public_access_disabled:
        W.append(
            "Private Access Settings disable public access, so public rules have no effect: the policy "
            "carries "
            "a deny-all public block. Review the private-endpoint rows only."
        )
    allow_rules = {(r.label, r.section) for r in rows if r.action == "allow"}
    cidrs = sum(1 for r in rows if r.section == "public" and _net(r.origin) is not None)
    if len(allow_rules) >= int(cfg.max_rules * posture.NEAR_LIMIT_RATIO) or cidrs >= int(
        cfg.max_cidrs * posture.NEAR_LIMIT_RATIO
    ):
        W.append(
            f"Close to platform limits ({len(allow_rules)} rules / {cidrs} CIDRs of {cfg.max_rules} / "
            f"{cfg.max_cidrs}). Prefer partner-platform and identity-based sources over more CIDRs."
        )
    if cfg.lookback_days < 30:
        W.append(
            f"The traffic window is only {cfg.lookback_days} days. Monthly and quarterly clients are "
            "probably "
            "missing; re-run with `--lookback-days 90`."
        )
    if any(r.category == "catch-all" for r in rows):
        W.append("The policy contains a catch-all allow, so enforcing it blocks only the deny rules.")
    return W


def build_apply(policy: dict, ctx: Context) -> tuple[str, str, str]:
    wid, prof = ctx.workspace_id, ctx.profile or "<workspace-profile>"
    wh = ctx.warehouse_http_path or "<sql-warehouse-http-path>"
    base = (
        f"dbx-nwp-helper ingress --profile {prof} --lookback-days {ctx.cfg.lookback_days} "
        f"--warehouse-http-path {wh} --create-policy --policy-mode dry_run"
    )
    pid = ctx.assigned_policy_id
    if pid and pid != "default-policy":
        cmd = f"{base} --policy-action add_to_existing --existing-policy-id {pid}"
        note = (
            f"Updates the ingress of the workspace's own policy `{pid}` and leaves its egress as it is. If "
            "that "
            "policy is assigned to other workspaces too, they change as well: create a new policy instead "
            "(`--policy-action create_new --auto-assign`)."
        )
    else:
        new_id = policy.get("network_policy_id") or f"dbx-nwp-ws-{wid}"
        cmd = f"{base} --policy-action create_new --policy-name {new_id} --auto-assign"
        note = (
            f"Creates `{new_id}` and assigns it to workspace {wid}, replacing `{pid or 'default-policy'}`. "
            "`ingress` checks first and aborts if that would drop an enforced egress policy."
        )
    rollback = (
        f"databricks account workspace-network-configuration update-workspace-network-option-rpc {wid} "
        f"--network-policy-id {pid or 'default-policy'} -p <account-profile>"
    )
    return cmd, note, rollback


def monitor_sql(wid: str) -> str:
    return f"""-- Daily dry-run check for workspace {wid}: requests the policy WOULD block if enforced.
-- Read-only. Change INTERVAL 1 DAYS to 7 for a weekly check. Older releases name the outcome
-- DENY_DRY_RUN instead of DRY_RUN_DENIAL.
SELECT CAST(workspace_id AS STRING) AS workspace_id, rule_label, source.ip AS source_ip,
  authenticated_as, COUNT(*) AS events,
  slice(sort_array(collect_set(request_path)), 1, 5) AS sample_paths,
  MAX(event_time) AS last_seen
FROM system.access.inbound_network
WHERE event_time >= current_date() - INTERVAL 1 DAYS
  AND policy_outcome IN ('DRY_RUN_DENIAL', 'DENY_DRY_RUN')
  AND CAST(workspace_id AS STRING) = '{wid}'
GROUP BY ALL
ORDER BY events DESC;
"""


# ----------------------------------------------------------------------------------------- output
def _md_table(head: list[str], body: list[list]) -> list[str]:
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    return out + ["| " + " | ".join(str(x).replace("|", "/") for x in b) + " |" for b in body]


def render_readme(policy: dict, rows, profile, unc, warnings, apply, ctx: Context) -> str:
    cmd, note, rollback = apply
    _ing, mode = active_ingress(policy)
    cats: dict[str, list[RuleRow]] = {}
    for r in rows:
        cats.setdefault(r.category, []).append(r)
    total = sum(p["events"] for p in profile)
    unc_ev = sum(u["events"] for u in unc)
    flagged = [r for r in rows if r.flags]
    pct = (100 * (total - unc_ev) / total) if total else 0
    L = [
        f"# Review pack: `{policy.get('network_policy_id') or 'proposed policy'}` for workspace "
        f"`{ctx.workspace_id}`",
        "",
        f"_Built by `dbx-nwp-helper ingress --review-pack` from {ctx.cfg.lookback_days} days of this "
        "workspace's "
        "own audit logs. Building the pack applies nothing (if the same run passed `--create-policy`, "
        "check what that run wrote)._",
        "",
        "> **This is a starting point to test, not a recommendation.** It reflects the traffic seen in the "
        "window. "
        "Observed traffic can include sources you don't want, including an attacker, so the workspace's "
        "owners "
        "confirm every source before anything is enforced. Test in dry-run (log-only) first.",
        "",
        "## What's in this folder",
        "",
        "- `policy.json`: the proposed policy (the same body `--export` writes). Apply it through `ingress`.",
        "- `review-sheet.csv`: one row per rule and range, with the traffic it covers. Fill in **keep / "
        "drop** "
        "and an **owner**.",
        "- `uncovered-sources.csv`: observed sources no rule fully covers. Enforcing would block these "
        "(or, for sources only scoped rules cover, the requests outside that scope).",
        "- `monitor.sql`: the daily dry-run check.",
        "",
        "## The proposal at a glance",
        "",
    ]
    L += _md_table(
        ["Category", "Rules", "Ranges", "Events covered", "What to do"],
        [
            [
                c,
                len({r.label for r in rs}),
                len(rs),
                f"{sum(r.events for r in rs):,}",
                rs[0].guidance.split(". ")[0] + ".",
            ]
            for c, rs in sorted(cats.items())
        ],
    )
    L += [
        "",
        f"- Mode: **{mode}**.",
        f"- Coverage: the allow rules cover **{pct:.1f}%** of {total:,} successful public-IPv4 events from "
        f"{len(profile):,} sources. **{len(unc):,} sources ({unc_ev:,} events)** would be blocked if "
        "enforced.",
        f"- Rows flagged for a closer look: **{len(flagged)}** (the `flags` column).",
        "- For the rollout pattern that fits (browser-only, API families, partner sources) and the checks a "
        "policy doesn't fix, run `dbx-nwp-helper posture`.",
    ]
    if warnings:
        L += ["", "## Read before testing", ""] + [f"- {w}" for w in warnings]
    if flagged:
        L += ["", "### Flagged rows", ""]
        L += _md_table(
            ["Label", "Range", "Category", "Events", "Flags"],
            [[r.label, r.origin, r.category, r.events, "; ".join(r.flags)] for r in flagged[:25]],
        )
        if len(flagged) > 25:
            L += ["", f"_…and {len(flagged) - 25} more in `review-sheet.csv`._"]
    if unc:
        L += ["", "### Largest uncovered sources", ""]
        L += _md_table(
            ["Source", "Events", "Days", "Identities", "Suggested handling"],
            [
                [u["source_ip"], u["events"], u["active_days"], u["sample_identities"], u["hint"]]
                for u in unc[:15]
            ],
        )
    L += [
        "",
        "## How to test it",
        "",
        "1. **Review.** Fill in `review-sheet.csv` (keep / drop, owner) and `uncovered-sources.csv` (add / "
        "accept "
        "block). Every kept row needs an owner who recognises the source.",
        "2. **Apply in dry-run, through `ingress`**, run by an account admin. It re-reads current traffic "
        "and shows "
        "the rule selector: untick the rows marked *drop*. It keeps existing egress and checks the assigned "
        "policy before writing.",
        "",
        "   ```",
        f"   {cmd}",
        "   ```",
        "",
        f"   {note}",
        "   If the workspace's assigned policy already enforces CBI, `ingress` inherits enforce mode and "
        "ignores `--policy-mode dry_run`: check the mode it prints before you confirm the write.",
        "   Add partner platforms flagged in the sheet as the managed *Partner platforms* source on the "
        "policy's "
        "Ingress tab in the account console (the SDK can't set it yet).",
        "",
        f"3. **Watch for {DRY_RUN_DAYS} days** (at least 14, and long enough to include a month-end). Run "
        "`monitor.sql` daily. Each row is a request the policy would block: add it if legitimate, or record "
        "why "
        "it should stay blocked.",
        "4. **Re-run `ingress` propose-only weekly** to fold in legitimate misses; dry-run denials are "
        "picked up "
        "automatically.",
        "5. **Acceptance tests during dry-run:**",
        "   - Browser sign-in from an approved network: no new would-block rows.",
        "   - A scheduled job, a BI refresh and each named automation identity: no would-block rows.",
        "   - A request from an unapproved network (e.g. a phone hotspot) **does** appear as a would-block "
        "row. "
        "This proves the policy is evaluating.",
        "",
        "## Ready to enforce when",
        "",
        f"- It has run in dry-run for {DRY_RUN_DAYS}+ days, including a month-end.",
        "- There have been no would-block events from sources marked *keep* for the last 7 days.",
        "- Every kept rule has an owner, and every uncovered source has a decision.",
        "- A recovery path is in place: at least one admin can reach the workspace from a confirmed source, "
        "and "
        "the account console is reachable (it's governed separately).",
        "- The rollback below has been rehearsed.",
        "",
        "Enforce by re-running `ingress` with `--policy-mode enforce`. The owners decide when; this pack "
        "never does.",
        "",
        "## Rollback",
        "",
        "Reassign the workspace to the policy it had before the test:",
        "",
        "```",
        rollback,
        "```",
        "",
        "Allow time for the change to propagate before re-testing. IP access lists, if enabled, keep "
        "applying "
        "throughout the test.",
        "",
        "## Sign-off",
        "",
    ]
    L += _md_table(
        ["Role", "Name", "Date", "Decision"],
        [["Workspace owner", "", "", ""], ["Security", "", "", ""], ["Account admin (applies)", "", "", ""]],
    )
    return "\n".join(L) + "\n"


def write(out_dir: str, policy: dict, candidates: pd.DataFrame, ctx: Context) -> dict:
    """Build the pack into `out_dir` and return a small summary for the CLI."""
    rows = flatten(policy)
    for r in rows:
        classify(r, ctx)
    profile = source_profile(candidates)
    attach_traffic(rows, profile)
    for r in rows:
        flag(r)
    unc = uncovered(profile, rows)
    warnings = build_warnings(policy, rows, ctx)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "policy.json").write_text(json.dumps(policy, indent=2) + "\n")
    with (out / "review-sheet.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(SHEET_COLS)
        for r in rows:
            w.writerow(
                [
                    r.section,
                    r.action,
                    r.label,
                    r.origin,
                    r.category,
                    r.destination,
                    r.identities,
                    r.matched_ips,
                ]
                + [r.events, r.active_days, r.first_seen, r.last_seen, r.services, r.sample_identities]
                + ["; ".join(r.flags), r.guidance, "", "", ""]
            )
    with (out / "uncovered-sources.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=UNCOVERED_COLS)
        w.writeheader()
        w.writerows(unc)
    (out / "monitor.sql").write_text(monitor_sql(ctx.workspace_id))
    readme = render_readme(policy, rows, profile, unc, warnings, build_apply(policy, ctx), ctx)
    (out / "README.md").write_text(readme)
    return {
        "dir": str(out),
        "flagged": sum(1 for r in rows if r.flags),
        "ranges": len(rows),
        "uncovered_sources": len(unc),
        "warnings": len(warnings),
    }
