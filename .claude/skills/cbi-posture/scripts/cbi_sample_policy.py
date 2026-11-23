#!/usr/bin/env python3
"""Sample policy: turn a dbx-nwp-helper policy proposal so an account team can hand it to a
customer to TEST (dry-run first).

Inputs (all produced in the customer's own account, by the customer or with them):
  * --posture   posture.json from cbi_posture.py (ideally run with --warehouse-id so the
                `source_ips_by_workspace` traffic profile is present)
  * --export    WORKSPACE_ID=PATH to the JSON written by
                `dbx-nwp-helper ingress ... --export <dir>` (propose-only; writes nothing)

Output, one folder per workspace under --out:
  README.md             the sample policy: what the policy does, warnings, how to test it, exit criteria, rollback
  review-sheet.csv      one row per proposed rule/CIDR with the traffic it covers, flags, and blank
                        keep/drop + owner columns for the customer to fill in
  uncovered-sources.csv observed public sources NO allow rule covers (what enforcing would block)
  monitor.sql           the daily dry-run check for this workspace
  policy.json           the helper's export, unchanged

This script is pure: it reads files and writes files. It never calls a Databricks API, never applies
a policy, and never runs the helper with --create-policy.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import ipaddress
import json
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cbi_posture as cp  # noqa: E402
import cbi_sql  # noqa: E402

DEFAULT_DRY_RUN_DAYS = 28
BROAD_PREFIX = 16           # allow CIDRs at least this broad get flagged
LOW_VOLUME_EVENTS = 10
PARTNER_HINTS = ("powerbi", "power-bi", "tableau", "dbt", "fivetran", "looker")


# ------------------------------------------------------------------------------------------ model
@dataclass
class RuleRow:
    section: str            # public / private / cross_workspace
    action: str             # allow / deny
    label: str
    origin: str             # CIDR, "ALL public IPv4", endpoint id, workspace ids
    destination: str = "all"
    identities: str = "all users and service principals"
    category: str = "observed"
    guidance: str = ""
    matched_ips: int = 0
    events: int = 0
    active_days: int = 0
    first_seen: str = ""
    last_seen: str = ""
    clients: str = ""
    sample_identities: str = ""
    flags: list[str] = field(default_factory=list)


def _as_list(v) -> list[str]:
    """JSON_ARRAY results carry arrays either as lists or as JSON-encoded strings."""
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v]
    s = str(v).strip()
    if s.startswith("["):
        try:
            return [str(x) for x in json.loads(s)]
        except ValueError:
            pass
    return [s] if s else []


def _int(v) -> int:
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


# ----------------------------------------------------------------------------------- the export
def export_mode(policy: dict) -> str:
    if policy.get("ingress"):
        return "enforce"
    if policy.get("ingress_dry_run"):
        return "dry_run"
    return "none"


def active_ingress(policy: dict) -> dict:
    return policy.get("ingress") or policy.get("ingress_dry_run") or {}


def _destination(rule: dict) -> str:
    c = cp.classify_rule(rule)
    if "all" in c["reach"]:
        return "all"
    parts = [x for x in c["reach"] if x != "api"]
    if "api" in c["reach"]:
        parts.append({"unstated": "api (no scopes stated: treat as all)", "all": "api (all)",
                      "all_except": f"api (all except {', '.join(c['scopes'])})",
                      "read": f"api read-only ({', '.join(c['scopes'])})"}.get(c["api"], f"api ({', '.join(c['scopes'])})"))
    return ", ".join(parts) or "none"


def _identities(rule: dict) -> str:
    auth = rule.get("authentication") or {}
    it = str(auth.get("identity_type") or "")
    if "SELECTED" in it:
        ids = auth.get("identities") or []
        return f"{len(ids)} selected identities"
    if "SERVICE_PRINCIPALS" in it:
        return "all service principals"
    if "USERS" in it:
        return "all users"
    return "all users and service principals"


def flatten(policy: dict) -> list[RuleRow]:
    ing = active_ingress(policy)
    rows: list[RuleRow] = []
    pub = ing.get("public_access") or {}
    for action in ("allow", "deny"):
        for r in pub.get(f"{action}_rules") or []:
            origin = r.get("origin") or {}
            label = r.get("label") or "(unlabelled)"
            if origin.get("all_ip_ranges"):
                rows.append(RuleRow("public", action, label, "ALL public IPv4", _destination(r), _identities(r)))
                continue
            exc = (origin.get("excluded_ip_ranges") or {}).get("ip_ranges") or []
            if exc and not (origin.get("included_ip_ranges") or {}).get("ip_ranges"):
                rows.append(RuleRow("public", action, label, "ALL public IPv4 except " + ", ".join(exc),
                                    _destination(r), _identities(r)))
                continue
            if not origin:
                rows.append(RuleRow("public", action, label, "source not visible through the API",
                                    _destination(r), _identities(r)))
                continue
            for c in (origin.get("included_ip_ranges") or {}).get("ip_ranges") or []:
                rows.append(RuleRow("public", action, label, str(c), _destination(r), _identities(r)))
    prv = ing.get("private_access") or {}
    for action in ("allow", "deny"):
        for r in prv.get(f"{action}_rules") or []:
            o = r.get("origin") or {}
            eps = (o.get("endpoints") or {}).get("endpoint_ids") or []
            origin = ", ".join(eps) if eps else ("all registered endpoints" if o.get("all_registered_endpoints") else "private")
            rows.append(RuleRow("private", action, r.get("label") or "(unlabelled)", origin, _destination(r), _identities(r)))
    xws = ing.get("cross_workspace_access") or {}
    for action in ("allow", "deny"):
        for r in xws.get(f"{action}_rules") or []:
            o = r.get("origin") or {}
            ids = (o.get("selected_workspaces") or {}).get("workspace_ids") or []
            origin = ", ".join(map(str, ids)) if ids else "all source workspaces"
            rows.append(RuleRow("cross_workspace", action, r.get("label") or "(unlabelled)", origin))
    return rows


def classify(row: RuleRow, acl_labels: set[str]) -> None:
    lab = row.label.lower()
    if row.section == "private":
        row.category, row.guidance = "private-endpoint", (
            "Carried from the workspace's PrivateLink settings. Confirm the endpoint ids are still in use.")
    elif row.section == "cross_workspace":
        row.category, row.guidance = "cross-workspace", "Carried forward unchanged from the current policy."
    elif row.origin == "source not visible through the API":
        row.category, row.guidance = "console-source", (
            "The API doesn't describe this rule's source (often Partner platforms or an app integration). Review it in "
            "the account console.")
    elif row.origin.startswith("ALL public IPv4"):
        row.category, row.guidance = "catch-all", (
            "Allows every public IPv4 source. With this rule the policy only blocks its deny rules.")
    elif row.action == "deny" and lab == "deny-recently-denied":
        row.category, row.guidance = "deny-recently-denied", (
            "Sources that were blocked recently (IP access list or enforced CBI). Confirm none is a legitimate client.")
    elif row.action == "deny":
        row.category, row.guidance = "deny-threat-intel", (
            "From an open threat-intel feed. Feeds have false positives; keep unless an owner recognises the source.")
    elif lab.startswith("databricks-"):
        row.category, row.guidance = "databricks", (
            "Databricks-owned range seen in your traffic (platform callbacks). Keep. Only ranges seen in the "
            "window are listed, so confirm the platform ranges your workspace needs are covered before enforcing.")
    elif any(h in lab.replace("_", "-") for h in PARTNER_HINTS):
        row.category, row.guidance = "partner", (
            "A partner platform (BI / transformation SaaS). Its IPs rotate; prefer the managed 'Partner platforms' "
            "source in the account console over pinning these CIDRs.")
    elif lab.startswith("consolidated-observed-ips"):
        row.category, row.guidance = "consolidated", (
            "Low-traffic owners folded together to stay under the 50-rule limit. Review the sources individually.")
    elif lab in acl_labels:
        row.category, row.guidance = "ip-acl", (
            "Migrated from the workspace's existing IP access list. Confirm it is still needed.")
    else:
        row.category, row.guidance = "observed", (
            "Derived from successful traffic in the lookback window. Observed is not trusted: an owner must "
            "recognise this source.")


# ------------------------------------------------------------------------------ traffic matching
def _ip(s: str):
    try:
        a = ipaddress.ip_address(str(s).strip())
        return a if a.version == 4 else None
    except ValueError:
        return None


def _net(s: str):
    try:
        n = ipaddress.ip_network(str(s).strip(), strict=False)
        return n if n.version == 4 else None
    except ValueError:
        return None


def source_profile(posture: dict, wid: str) -> list[dict] | None:
    rows = cp._rows(posture.get("sql") or {}, "source_ips_by_workspace")
    if rows is None:
        return None
    out = []
    for r in rows:
        if str(r.get("workspace_id")) != wid:
            continue
        ip = _ip(r.get("source_ip"))
        if ip is None:
            continue
        out.append({**r, "_ip": ip, "_events": _int(r.get("events")), "_days": _int(r.get("active_days")),
                    "_clients": _as_list(r.get("client_families")),
                    "_principals": _as_list(r.get("sample_principals"))})
    return out


def attach_traffic(rows: list[RuleRow], profile: list[dict], would_block: set[str]) -> None:
    for row in rows:
        if row.section != "public":
            continue
        if row.origin.startswith("ALL public IPv4"):
            excl = [n for n in (_net(c) for c in row.origin.split(" except ", 1)[1].split(", ")) if n] \
                if " except " in row.origin else []
            hits = [p for p in profile if not any(p["_ip"] in n for n in excl)]
        elif row.origin == "source not visible through the API":
            hits = []
        else:
            n = _net(row.origin)
            hits = [p for p in profile if n is not None and p["_ip"] in n]
        row.matched_ips = len(hits)
        row.events = sum(p["_events"] for p in hits)
        row.active_days = max((p["_days"] for p in hits), default=0)
        firsts = [str(p.get("first_seen")) for p in hits if p.get("first_seen")]
        lasts = [str(p.get("last_seen")) for p in hits if p.get("last_seen")]
        row.first_seen, row.last_seen = (min(firsts) if firsts else ""), (max(lasts) if lasts else "")
        row.clients = ", ".join(sorted({c for p in hits for c in p["_clients"]}))
        ids: list[str] = []
        for p in sorted(hits, key=lambda p: -p["_events"]):
            for x in p["_principals"]:
                if x not in ids:
                    ids.append(x)
        row.sample_identities = ", ".join(ids[:5])
        if row.action == "allow" and any(str(p["_ip"]) in would_block for p in hits):
            row.flags.append("a current dry-run policy would block this source")


def flag(row: RuleRow, have_profile: bool) -> None:
    if row.section != "public":
        return
    n = _net(row.origin)
    if row.action == "allow" and n is not None and n.prefixlen <= BROAD_PREFIX:
        row.flags.append(f"broad range /{n.prefixlen} ({n.num_addresses:,} addresses): confirm it isn't a whole cloud or ISP block")
    if row.category == "catch-all":
        row.flags.append("allows every public source")
    if not have_profile or row.action != "allow" or row.category == "catch-all":
        return
    if row.events == 0:
        row.flags.append("no successful traffic in the window" + (": confirm still needed" if row.category in ("ip-acl", "partner") else ""))
    elif row.active_days <= 1:
        row.flags.append("seen on one day only")
    elif row.events < LOW_VOLUME_EVENTS:
        row.flags.append(f"low volume ({row.events} events)")


def _uncovered_hint(p: dict) -> str:
    clients = {c.lower() for c in p["_clients"]}
    if any(h.replace("-", " ") in c or h in c for c in clients for h in PARTNER_HINTS):
        return "partner client: use the managed Partner platforms source if it covers this partner, otherwise the vendor's published ranges"
    if len(p["_principals"]) == 1 and p["_days"] >= 5 and not clients & {"browser"}:
        return "one identity, recurring: likely a roaming user or a job host; confirm, then add the network or route it via an approved one"
    if p["_days"] <= 1:
        return "seen on one day only: likely safe to leave blocked, confirm with the identity's owner"
    return "confirm with the identities' owners"


def uncovered(profile: list[dict], rows: list[RuleRow]) -> list[dict]:
    """Observed public sources the policy would block if enforced: not inside any allow rule (unless a
    catch-all exists), or inside a deny rule."""
    allows = [r for r in rows if r.section == "public" and r.action == "allow"]
    catch_all = any(r.origin == "ALL public IPv4" for r in allows)  # "except" rules are handled per IP below
    except_rules = [[n for n in (_net(c) for c in r.origin.split(" except ", 1)[1].split(", ")) if n]
                    for r in allows if r.origin.startswith("ALL public IPv4 except ")]
    allow_nets = [n for n in (_net(r.origin) for r in allows) if n is not None]
    deny_nets = [(r.label, n) for r in rows if r.section == "public" and r.action == "deny"
                 for n in [_net(r.origin)] if n is not None]
    out = []
    for p in profile:
        denied = next((lab for lab, n in deny_nets if p["_ip"] in n), None)
        if denied:
            reason = f"matches deny rule '{denied}'"
        elif not catch_all and not any(p["_ip"] in n for n in allow_nets) \
                and not any(not any(p["_ip"] in n for n in ex) for ex in except_rules):
            reason = "no allow rule covers it"
        else:
            continue
        out.append({"source_ip": str(p["_ip"]), "events": p["_events"], "active_days": p["_days"],
                    "hint": _uncovered_hint(p),
                    "first_seen": p.get("first_seen") or "", "last_seen": p.get("last_seen") or "",
                    "clients": ", ".join(p["_clients"]), "sample_identities": ", ".join(p["_principals"][:5]),
                    "reason": reason, "decision (add / accept block)": "", "owner": "", "notes": ""})
    return sorted(out, key=lambda r: -r["events"])


# ------------------------------------------------------------------------------------- warnings
@dataclass
class SamplePolicy:
    wid: str
    ws: dict
    policy: dict
    policy_path: Path
    rows: list[RuleRow]
    profile: list[dict] | None
    uncovered: list[dict]
    warnings: list[str]
    findings: list[cp.Finding]
    apply_cmd: str
    apply_note: str
    rollback: str
    dry_run_days: int
    lookback_days: int


def build_warnings(posture: dict, ws: dict, policy: dict, rows: list[RuleRow], profile, findings) -> list[str]:
    W: list[str] = []
    wid = str(ws.get("workspace_id"))
    cur = cp.summarise_policy(ws.get("policy"))
    mode = export_mode(policy)
    if mode == "enforce":
        W.append("**The export writes the ENFORCED block, not dry-run.** The helper inherits enforce mode when the "
                 "workspace's assigned policy already enforces CBI (or `--policy-mode enforce` was passed). Applying "
                 "it is a live change, not a test: review `uncovered-sources.csv` first, or trial it in a "
                 "non-production workspace.")
    if mode == "none":
        W.append("The export has no ingress block. Re-run the helper; there may have been no traffic to propose from.")
    new_egress = cp.summarise_policy({"egress": policy.get("egress")})
    if cur.get("egress_restrictive") and not new_egress.get("egress_restrictive"):
        W.append(f"**Don't apply `policy.json` by hand.** The workspace's current policy `{cur.get('policy_id')}` "
                 "restricts serverless egress, but this export carries a FULL_ACCESS egress default. Applying the file "
                 "as a new policy would open egress. Apply through the helper (below), which keeps existing egress.")
    pid = ws.get("effective_policy_id")
    sharing = [str(w.get("workspace_id")) for w in posture.get("workspaces") or []
               if w.get("effective_policy_id") == pid and str(w.get("workspace_id")) != wid]
    if pid and pid != "default-policy" and sharing:
        W.append(f"The current policy `{pid}` is also assigned to workspace(s) {', '.join(sharing)}. Changing that "
                 "policy changes them too, so the sample policy creates a separate policy for this workspace.")
    if (ws.get("pas") or {}).get("public_access_enabled") is False:
        W.append("Private access settings disable public access, so public rules have no effect. The helper writes "
                 "a deny-all public block; review the private-endpoint rows only.")
    allow_rules = {(r.label, r.section) for r in rows if r.action == "allow"}
    cidrs = sum(1 for r in rows if r.section == "public" and _net(r.origin) is not None)
    if len(allow_rules) >= int(cp.MAX_INGRESS_RULES * cp.NEAR_LIMIT_RATIO) or cidrs >= int(cp.MAX_CIDRS * cp.NEAR_LIMIT_RATIO):
        W.append(f"Close to platform limits ({len(allow_rules)} rules / {cidrs} CIDRs of {cp.MAX_INGRESS_RULES} / "
                 f"{cp.MAX_CIDRS}). Prefer partner-platform and identity-based sources over more CIDRs.")
    lb = _int(posture.get("lookback_days"))
    if lb and lb < 30:
        W.append(f"The traffic window is only {lb} days. Monthly and quarterly clients are probably missing; "
                 "re-run with `--lookback-days 90`.")
    if profile is None:
        W.append("No per-workspace traffic profile in `posture.json` (the collector ran without `--warehouse-id`), so "
                 "the review sheet has no traffic columns and `uncovered-sources.csv` is empty. Re-run the collector "
                 "with a warehouse, or run `sql/13_source_ips_by_workspace.sql` and review alongside.")
    ids = {f.id for f in findings}
    if "CBI-025" in ids:
        W.append("Verbose audit logging was turned off during the window (CBI-025), so the traffic sample has a gap.")
    if any(f.id == "CBI-009" for f in findings):
        W.append("The account console and account APIs aren't covered by a workspace policy (CBI-009). That needs "
                 "the account-level policy, set in the account console.")
    if any(r.category == "catch-all" for r in rows):
        W.append("The policy contains a catch-all allow, so enforcing it blocks only the deny rules.")
    return W


def build_apply(ws: dict, posture: dict, policy: dict, warehouse_hint: str) -> tuple[str, str, str]:
    wid = str(ws.get("workspace_id"))
    prof = ws.get("profile") or "<workspace-profile>"
    lb = _int(posture.get("lookback_days")) or 90
    pid = ws.get("effective_policy_id")
    sharing = [w for w in posture.get("workspaces") or []
               if w.get("effective_policy_id") == pid and str(w.get("workspace_id")) != wid]
    base = (f"uv run dbx-nwp-helper ingress --profile {prof} --lookback-days {lb} "
            f"--warehouse-http-path {warehouse_hint} --create-policy --policy-mode dry_run")
    if pid and pid != "default-policy" and not sharing:
        cmd = f"{base} --policy-action add_to_existing --existing-policy-id {pid}"
        note = (f"Updates the ingress of the workspace's own policy `{pid}` and leaves its egress as it is. If that "
                "policy already enforces CBI, the helper keeps enforce mode (see warnings).")
    else:
        new_id = policy.get("network_policy_id") or f"cbi-sample-{wid}"
        cmd = f"{base} --policy-action create_new --policy-name {new_id} --auto-assign"
        note = (f"Creates `{new_id}` and assigns it to workspace {wid}, replacing `{pid or 'default-policy'}`. The helper "
                "checks first and aborts if that would drop an enforced egress policy.")
    prev = pid or "default-policy"
    rollback = (f"databricks account workspace-network-configuration update-workspace-network-option-rpc {wid} "
                f"--network-policy-id {prev} -p <account-profile>")
    return cmd, note, rollback


# --------------------------------------------------------------------------------------- output
SHEET_COLS = ["section", "action", "label", "origin", "category", "destination", "identities", "matched_ips",
              "events", "active_days", "first_seen", "last_seen", "clients", "sample_identities", "flags",
              "guidance", "decision (keep / drop)", "owner", "notes"]


def write_sheet(path: Path, rows: list[RuleRow]) -> None:
    with path.open("w", newline="") as fh:
        wr = csv.writer(fh)
        wr.writerow(SHEET_COLS)
        for r in rows:
            wr.writerow([r.section, r.action, r.label, r.origin, r.category, r.destination, r.identities,
                         r.matched_ips, r.events, r.active_days, r.first_seen, r.last_seen, r.clients,
                         r.sample_identities, "; ".join(r.flags), r.guidance, "", "", ""])


def write_uncovered(path: Path, rows: list[dict]) -> None:
    cols = ["source_ip", "events", "active_days", "first_seen", "last_seen", "clients", "sample_identities",
            "reason", "hint", "decision (add / accept block)", "owner", "notes"]
    with path.open("w", newline="") as fh:
        wr = csv.DictWriter(fh, fieldnames=cols)
        wr.writeheader()
        for r in rows:
            wr.writerow(r)


def monitor_sql(wid: str) -> str:
    desc, stmt = cbi_sql.QUERIES["dry_run_would_block"]
    return (f"-- Daily dry-run check for workspace {wid}: requests the sample policy WOULD block if enforced.\n"
            "-- Read-only. Set :lookback_days to 1 for a daily check, or 7 for a weekly one.\n"
            "-- If system.access.inbound_network names the outcome column access_type, replace policy_outcome.\n"
            f"-- {desc}\n"
            f"SELECT * FROM (\n{stmt.strip()}\n) WHERE workspace_id = '{wid}';\n")


def _md_table(head: list[str], body: list[list]) -> list[str]:
    L = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for b in body:
        L.append("| " + " | ".join(str(x).replace("|", "/") for x in b) + " |")
    return L


def render_readme(k: SamplePolicy, posture: dict) -> str:
    ws, rows = k.ws, k.rows
    name = ws.get("workspace_name") or k.wid
    mode = export_mode(k.policy)
    cats: dict[str, list[RuleRow]] = {}
    for r in rows:
        cats.setdefault(r.category, []).append(r)
    total_ev = sum(p["_events"] for p in k.profile) if k.profile else 0
    unc_ev = sum(u["events"] for u in k.uncovered)
    flagged = [r for r in rows if r.flags]
    pattern = next((f for f in k.findings if f.id == "CBI-026"), None)
    other = [f for f in k.findings if f.severity in ("critical", "high", "medium") and f.layer != "Limit"]
    L = [f"# Sample CBI policy: {name} (`{k.wid}`)", "",
         f"_Built {posture.get('generated_at', '')} from {k.lookback_days} days of this workspace's own audit logs, by "
         f"cbi-posture v{cp.TOOL_VERSION}. Nothing has been applied._", "",
         "> **This is a starting point to test, not a recommendation.** It reflects the traffic seen in the window. "
         "Observed traffic can include sources you don't want, including an attacker, so the customer's owners "
         "confirm every source before anything is enforced. Test in dry-run (log-only) first.", "",
         "## What's in this folder", "",
         "- `policy.json`: the proposed policy as exported by `dbx-nwp-helper` (for reference; apply it through the helper).",
         "- `review-sheet.csv`: one row per proposed rule and range, with the traffic it covers. Fill in **keep / drop** and an **owner**.",
         "- `uncovered-sources.csv`: observed sources no rule covers. Enforcing would block these.",
         "- `monitor.sql`: the daily dry-run check.", "",
         "## The proposal at a glance", ""]
    L += _md_table(["Category", "Rules", "Ranges", "Events covered", "What to do"], [
        [c, len({r.label for r in rs}), len(rs), f"{sum(r.events for r in rs):,}" if k.profile is not None else "n/a",
         rs[0].guidance.split(". ")[0] + "."] for c, rs in sorted(cats.items())])
    L += ["", f"- Mode in the export: **{mode}**."]
    if k.profile is not None:
        pct = (100 * (total_ev - unc_ev) / total_ev) if total_ev else 0
        L += [f"- Coverage: the allow rules cover **{pct:.1f}%** of {total_ev:,} successful public-IPv4 events from "
              f"{len(k.profile):,} sources. **{len(k.uncovered):,} sources ({unc_ev:,} events)** would be blocked if enforced."]
    L += [f"- Rows flagged for a closer look: **{len(flagged)}** (see the `flags` column)."]
    if pattern:
        L += ["", "### Suggested rollout pattern", "", pattern.detail, "", pattern.recommendation, "",
              "_The helper proposes IP-based rules only. Use the dry-run baseline from this sample policy first, then make the "
              "pattern's identity, API-scope or partner changes in the account console and re-test in dry-run._"]
    if k.warnings:
        L += ["", "## Read before testing", ""] + [f"- {w}" for w in k.warnings]
    if flagged:
        L += ["", "### Flagged rows", ""]
        L += _md_table(["Label", "Range", "Category", "Events", "Flags"],
                       [[r.label, r.origin, r.category, r.events, "; ".join(r.flags)] for r in flagged[:25]])
        if len(flagged) > 25:
            L += ["", f"_…and {len(flagged) - 25} more in `review-sheet.csv`._"]
    if k.uncovered:
        L += ["", "### Largest uncovered sources", ""]
        L += _md_table(["Source", "Events", "Days", "Clients", "Identities", "Suggested handling"],
                       [[u["source_ip"], u["events"], u["active_days"], u["clients"], u["sample_identities"], u["hint"]]
                        for u in k.uncovered[:15]])
    L += ["", "## How to test it", "",
          "1. **Review.** Fill in `review-sheet.csv` (keep / drop, owner) and `uncovered-sources.csv` (add / accept block). "
          "Every kept row needs an owner who recognises the source.",
          "2. **Apply in dry-run, through the helper**, run by the customer's account admin. The helper re-reads current "
          "traffic and shows a rule selector: untick the rows marked *drop*. It also keeps existing egress and checks the "
          "assigned policy before writing.", "",
          "   ```", f"   {k.apply_cmd}", "   ```", "",
          f"   {k.apply_note}",
          "   Add partner platforms flagged in the sheet as the managed *Partner platforms* source on the policy's Ingress "
          "tab in the account console. The SDK can't set it yet.", "",
          f"3. **Watch for {k.dry_run_days} days** (at least 14, and long enough to include a month-end). Run `monitor.sql` "
          "daily. Each row is a request the policy would block: add it if legitimate, or record why it should be blocked.",
          "4. **Re-run the helper propose-only weekly** to fold in legitimate misses; dry-run denials are picked up automatically.",
          "5. **Acceptance tests during dry-run:**",
          "   - Browser sign-in from an approved network: no new would-block rows.",
          "   - A scheduled job, a BI refresh and each named automation identity: no would-block rows.",
          "   - A request from an unapproved network (e.g. a phone hotspot) **does** appear as a would-block row. "
          "This proves the policy is evaluating.", "",
          "## Ready to enforce when", "",
          f"- It has run in dry-run for {k.dry_run_days}+ days, including a month-end.",
          "- There have been no would-block events from sources marked *keep* for the last 7 days.",
          "- Every kept rule has an owner, and every uncovered source has a decision.",
          "- A recovery path is in place: at least one admin can reach the workspace from a confirmed source, and the "
          "account console is reachable (it's governed separately).",
          "- The rollback below has been rehearsed.", "",
          "Enforce by re-running the helper with `--policy-mode enforce`. The customer decides when; this sample policy never does.", "",
          "## Rollback", "",
          "Reassign the workspace to the policy it had before the test:", "", "```", k.rollback, "```", "",
          "Allow time for the change to propagate before re-testing. IP access lists, if enabled, keep applying throughout the test."]
    if other:
        L += ["", "## Not fixed by this policy", "",
              "A network policy limits where a credential works. These findings for the same workspace need their own fixes:", ""]
        L += [f"- **{f.id}** ({f.severity}, {f.layer}): {f.title}." for f in other]
    L += ["", "## Sign-off", ""]
    L += _md_table(["Role", "Name", "Date", "Decision"], [["Workspace owner", "", "", ""], ["Security", "", "", ""],
                                                          ["Account admin (applies)", "", "", ""]])
    return "\n".join(L) + "\n"


def build_sample_policy(posture: dict, wid: str, export_path: Path, dry_run_days: int = DEFAULT_DRY_RUN_DAYS,
              warehouse_hint: str = "<sql-warehouse-http-path>") -> SamplePolicy:
    ws = next((w for w in posture.get("workspaces") or [] if str(w.get("workspace_id")) == wid), None)
    if ws is None:
        raise SystemExit(f"workspace {wid} is not in posture.json")
    policy = json.loads(export_path.read_text())
    rows = flatten(policy)
    acl_labels = {str(l.get("label") or "").lower() for l in ((ws.get("ip_acl") or {}).get("lists") or [])}
    for r in rows:
        classify(r, acl_labels)
    profile = source_profile(posture, wid)
    wb_rows = cp._rows(posture.get("sql") or {}, "dry_run_would_block") or []
    would_block = {str(r.get("source_ip")) for r in wb_rows if str(r.get("workspace_id")) == wid}
    if profile is not None:
        attach_traffic(rows, profile, would_block)
    for r in rows:
        flag(r, profile is not None)
    findings, maturity = cp.evaluate(posture)
    cp.finalize_levels(findings, maturity)
    ws_findings = [f for f in findings if str(f.workspace_id) == wid]
    warnings = build_warnings(posture, ws, policy, rows, profile, ws_findings)
    cmd, note, rollback = build_apply(ws, posture, policy, warehouse_hint)
    return SamplePolicy(wid, ws, policy, export_path, rows, profile, uncovered(profile, rows) if profile else [], warnings,
               ws_findings, cmd, note, rollback, dry_run_days, _int(posture.get("lookback_days")) or 90)


def write_sample_policy(k: SamplePolicy, posture: dict, out: Path) -> Path:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", str(k.policy.get("network_policy_id") or "policy"))
    d = out / f"{k.wid}-{slug}"
    d.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(k.policy_path, d / "policy.json")
    write_sheet(d / "review-sheet.csv", k.rows)
    write_uncovered(d / "uncovered-sources.csv", k.uncovered)
    (d / "monitor.sql").write_text(monitor_sql(k.wid))
    (d / "README.md").write_text(render_readme(k, posture))
    return d


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Turn a dbx-nwp-helper proposal into a dry-run sample policy (read-only).")
    ap.add_argument("--posture", type=Path, required=True, help="posture.json from cbi_posture.py")
    ap.add_argument("--export", action="append", required=True, metavar="WORKSPACE_ID=PATH",
                    help="helper --export JSON for a workspace (repeatable)")
    ap.add_argument("--out", type=Path, default=Path("cbi-sample-policy"))
    ap.add_argument("--dry-run-days", type=int, default=DEFAULT_DRY_RUN_DAYS)
    ap.add_argument("--warehouse-http-path", default="<sql-warehouse-http-path>",
                    help="shown in the apply command so the helper doesn't create its own warehouse")
    a = ap.parse_args(argv)
    if a.dry_run_days < 14:
        ap.error("--dry-run-days must be at least 14")
    posture = json.loads(a.posture.read_text())
    written = []
    for spec in a.export:
        if "=" not in spec:
            ap.error(f"--export expects WORKSPACE_ID=PATH, got {spec!r}")
        wid, path = spec.split("=", 1)
        k = build_sample_policy(posture, wid.strip(), Path(path), a.dry_run_days, a.warehouse_http_path)
        d = write_sample_policy(k, posture, a.out)
        written.append({"workspace_id": k.wid, "dir": str(d), "rules": len({(r.label, r.action) for r in k.rows}),
                        "ranges": len(k.rows), "flagged": sum(1 for r in k.rows if r.flags),
                        "uncovered_sources": len(k.uncovered), "warnings": len(k.warnings)})
    print(json.dumps(written, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
