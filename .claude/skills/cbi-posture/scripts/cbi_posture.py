#!/usr/bin/env python3
"""CBI posture diagnostic: a READ-ONLY assessment of a Databricks account's context-based ingress.

Collects (best-effort, every failure is recorded rather than fatal):
  * account   - network policies, workspace→policy assignments, private access settings (PAS),
                pricing tier, account IP access lists            (AccountClient, account admin)
  * workspace - IP access lists + enableIpAccessLists for each --workspace-profile   (WorkspaceClient)
  * traffic   - the diagnostic SQL in cbi_sql.py over system.access.audit / inbound_network
                (needs --warehouse-id; the tool never creates a warehouse)

then evaluates the checks in references/findings.md, assigns each workspace a maturity level
(L0 Open → L4 Hardened) and writes posture.json, report.md and findings.csv to --out.

Nothing is written to Databricks unless you pass --uc-schema, which (opt-in) appends the snapshot
to two Delta tables so a Genie agent can answer questions over it. In a notebook, system.access.audit is read
once into a cached rollup (events counted per date, workspace, principal, source IP and client; nothing
written to a schema), and the audit queries run over that instead of scanning the audit log each time. On a SQL warehouse, --stage-schema (opt-in) does the same with a temporary table.

Remediation is delegated to databricks-network-policy-helper (`dbx-nwp-helper`), and every finding
carries the propose-only command to run next.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import ipaddress
import json
import re
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cbi_sql  # noqa: E402

TOOL_VERSION = "0.3.0"

# Platform limits (docs + dbx-nwp-helper core/limits.py).
MAX_INGRESS_RULES = 50
MAX_CIDRS = 2000
NEAR_LIMIT_RATIO = 0.8

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

HELPER_REPO = "https://github.com/databrickslabs/databricks-network-policy-helper"
MIGRATE_REPO = "https://github.com/databrickslabs/migrate-ip-acls"


# --------------------------------------------------------------------------------------- data model
ROLLUP_MIN_WORKSPACES = 10  # above this, the report groups findings by check instead of per workspace
ROLLUP_LIST = 15  # workspace ids listed per grouped finding


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    detail: str
    recommendation: str
    workspace_id: str = "account"
    next_step: str = ""
    docs: str = ""
    layer: str = "Limit"  # defense-in-depth layer: Avoid | Expire | Scope | Limit | Detect | Respond | Posture


@dataclass
class Thresholds:
    broad_prefix_high: int = 8  # allow CIDR /0../8 → high
    broad_prefix_medium: int = 16  # /9../15 → medium (strictly broader than /16)
    spread_24s: int = 10  # principal seen from >= this many public /24s
    max_enforced_denials_ok: int = 0
    max_token_lifetime_days: int = 90  # a lifetime policy above this (or none) is flagged
    stale_token_days: int = 90
    b1_max_programmatic_principals: int = 25  # "browser yes, APIs no" is practical below this


LAYER_BY_ID = {
    "CBI-011": "Detect", "CBI-012": "Respond", "CBI-013": "Limit", "CBI-016": "Posture", "CBI-017": "Limit",
    "CBI-018": "Posture", "CBI-020": "Expire", "CBI-021": "Expire", "CBI-022": "Avoid", "CBI-023": "Scope",
    "CBI-024": "Expire", "CBI-025": "Detect", "CBI-026": "Limit", "CBI-027": "Limit", "CBI-028": "Limit", "CBI-029": "Limit",
}
LAYERS = ["Avoid", "Expire", "Scope", "Limit", "Detect", "Respond", "Posture"]
CRED_DOCS = "https://docs.databricks.com/aws/en/admin/access-control/tokens"


def _ms_to_date(ms) -> dt.date | None:
    try:
        ms = int(ms)
    except (TypeError, ValueError):
        return None
    if ms <= 0:
        return None
    return dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc).date()


def summarise_tokens(tok: dict | None, today: dt.date, th: "Thresholds") -> dict | None:
    """Counts over a workspace's PAT inventory (token-management list). Never holds token values,
    which the API does not return. Empty/None `scopes` means ALL APIs."""
    if not tok or "tokens" not in tok:
        return None
    toks = tok["tokens"]
    never = [t for t in toks if _ms_to_date(t.get("expiry_time")) is None]
    long_left = [t for t in toks if (d := _ms_to_date(t.get("expiry_time"))) and (d - today).days > th.max_token_lifetime_days]
    stale = [t for t in toks if (d := _ms_to_date(t.get("last_used_day"))) and (today - d).days > th.stale_token_days]
    unscoped = [t for t in toks if not t.get("scopes")]
    return {"total": len(toks), "never_expire": len(never), "long_lived": len(long_left), "stale": len(stale),
            "unscoped": len(unscoped),
            "never_expire_ids": [t.get("token_id") for t in never][:20],
            "never_expire_owners": sorted({t.get("created_by_username") or "?" for t in never})[:10]}


# ------------------------------------------------------------------------------- policy summarising
def _mode(v: Any) -> str | None:
    if v is None:
        return None
    return str(getattr(v, "value", v))


_UI_LIKE = {"ui", "apps", "lakebase", "account_ui"}


def classify_rule(r: dict) -> dict:
    """What one public ingress rule matches: where from (origin), to what (reach / API breadth), and for whom.

    origin:   all (every IP) | all_except (every public IP except some) | ranges | unknown (none of the three
              set: e.g. a source configured in the console that the API doesn't describe)
    api:      none | scoped (named scopes) | read (read-only variants) | all | all_except | unstated
              (`workspace_api: {}`: no scopes given; treated as all APIs, conservatively)
    identity: all | users | service_principals | selected"""
    o = r.get("origin") or {}
    inc = (o.get("included_ip_ranges") or {}).get("ip_ranges") or []
    exc = (o.get("excluded_ip_ranges") or {}).get("ip_ranges") or []
    origin = "all" if o.get("all_ip_ranges") else "ranges" if inc else "all_except" if exc else "unknown"
    d = r.get("destination") or {}
    reach: set[str] = set()
    api, scopes = "none", []
    if d.get("all_destinations") or not d:
        reach, api = {"all"}, "all"
    else:
        for key, name in (("workspace_ui", "ui"), ("apps_runtime", "apps"), ("lakebase_runtime", "lakebase"),
                          ("account_ui", "account_ui"), ("account_api", "account_api"),
                          ("account_databricks_one", "account_databricks_one")):
            if d.get(key) is not None:
                reach.add(name)
        wa = d.get("workspace_api")
        if wa is not None:
            reach.add("api")
            scopes = list(wa.get("scopes") or [])
            qual = str(wa.get("scope_qualifier") or "")
            if wa.get("excluded_scopes"):
                api, scopes = "all_except", list(wa["excluded_scopes"])
            elif not scopes:
                api = "unstated"
            elif "all-apis" in scopes:
                api = "read" if qual.endswith("READ") else "all"
            else:
                api = "read" if qual.endswith("READ") else "scoped"
    auth = r.get("authentication") or {}
    it = str(auth.get("identity_type") or "")
    identity = ("selected" if "SELECTED" in it else "service_principals" if "SERVICE_PRINCIPALS" in it
                else "users" if "USERS" in it else "all")
    return {"label": r.get("label") or "(unlabelled)", "origin": origin, "cidrs": inc, "excluded": exc,
            "reach": sorted(reach), "api": api, "scopes": scopes, "identity": identity,
            "identities": len(auth.get("identities") or [])}


def _block_summary(blk: dict | None) -> dict:
    """Summarise one ingress sub-block (public_access / private_access / cross_workspace_access)."""
    empty = {"present": False, "restriction_mode": None, "allow_rules": 0, "deny_rules": 0,
             "restrictive": False, "cidrs": [], "all_ip_allow_rules": [], "labels": [], "rules": [],
             "open_api_rules": [], "open_identity_rules": [], "open_scoped_api_rules": [],
             "open_ui_only_rules": [], "unknown_origin_rules": [], "unstated_api_rules": [],
             "effectively_open": False}
    if not blk:
        return empty
    allow = blk.get("allow_rules") or []
    deny = blk.get("deny_rules") or []
    rules = [classify_rule(r) for r in allow]
    for i, r in enumerate(rules, start=1):
        if r["label"] == "(unlabelled)":
            r["label"] = f"allow rule {i} (unlabelled)"
    cidrs = [c for r in rules for c in r["cidrs"]]
    anywhere = [r for r in rules if r["origin"] in ("all", "all_except")]
    broad_api = ("all", "all_except", "unstated")
    open_api = [r["label"] for r in anywhere if r["api"] in broad_api and r["identity"] == "all"]
    open_ident = [r["label"] for r in anywhere if r["api"] in broad_api and r["identity"] != "all"]
    open_scoped = [r["label"] for r in anywhere if r["api"] in ("scoped", "read")]
    open_ui = [r["label"] for r in anywhere if r["api"] == "none" and set(r["reach"]) <= _UI_LIKE]
    mode = _mode(blk.get("restriction_mode"))
    return {
        **empty,
        "present": True,
        "restriction_mode": mode,
        "allow_rules": len(allow),
        "deny_rules": len(deny),
        "restrictive": mode == "RESTRICTED_ACCESS" or bool(allow or deny),
        "cidrs": cidrs,
        "all_ip_allow_rules": [r["label"] for r in anywhere],
        "labels": [r["label"] for r in rules],
        "rules": rules,
        "open_api_rules": open_api,
        "open_identity_rules": open_ident,
        "open_scoped_api_rules": open_scoped,
        "open_ui_only_rules": open_ui,
        "unknown_origin_rules": [r["label"] for r in rules if r["origin"] == "unknown"],
        "unstated_api_rules": [r["label"] for r in rules if r["api"] == "unstated"],
        # Any IP may call all workspace APIs as any identity: restricted on paper, open in effect.
        "effectively_open": bool(open_api),
    }


def summarise_policy(policy: dict | None) -> dict:
    """Effective CBI posture of one AccountNetworkPolicy (as_dict()).

    A policy runs in one enforcement mode at a time: its rules live in `ingress` (enforced) or
    `ingress_dry_run` (log-only). Same precedence as dbx-nwp-helper core/acl._active_ingress."""
    if not policy:
        return {"policy_id": None, "mode": None, "public": _block_summary(None),
                "private": _block_summary(None), "cross_workspace": _block_summary(None),
                "egress_restrictive": False, "egress_enforced": False}

    def dims(ing: dict | None) -> dict:
        ing = ing or {}
        return {
            "public": _block_summary(ing.get("public_access")),
            "private": _block_summary(ing.get("private_access")),
            "cross_workspace": _block_summary(ing.get("cross_workspace_access")),
        }

    enf, dry = dims(policy.get("ingress")), dims(policy.get("ingress_dry_run"))
    if any(d["restrictive"] for d in enf.values()):
        mode, active = "enforce", enf
    elif any(d["restrictive"] for d in dry.values()):
        mode, active = "dry_run", dry
    else:
        mode, active = None, enf if policy.get("ingress") else dry

    na = (policy.get("egress") or {}).get("network_access") or {}
    egress_restrictive = _mode(na.get("restriction_mode")) == "RESTRICTED_ACCESS" or bool(
        na.get("allowed_internet_destinations") or na.get("allowed_storage_destinations")
        or na.get("blocked_internet_destinations")
    )
    egress_enforced = _mode((na.get("policy_enforcement") or {}).get("enforcement_mode")) == "ENFORCED"
    return {"policy_id": policy.get("network_policy_id"), "mode": mode, **active,
            "egress_restrictive": egress_restrictive,
            "egress_enforced": egress_restrictive and egress_enforced}


def broad_cidrs(cidrs: list[str], max_prefix: int) -> list[str]:
    """IPv4 CIDRs at least as broad as /`max_prefix` (prefixlen <= max_prefix). Invalid entries skipped."""
    out = []
    for c in cidrs:
        try:
            n = ipaddress.ip_network(str(c).strip(), strict=False)
        except ValueError:
            continue
        if n.version == 4 and n.prefixlen <= max_prefix:
            out.append(str(n))
    return out


# ------------------------------------------------------------------------------------- evaluation
def _cmd(profile: str | None, extra: str = "") -> str:
    p = profile or "<workspace-profile>"
    return f"uv run dbx-nwp-helper ingress --profile {p} --lookback-days 90{(' ' + extra) if extra else ''}"


def _rows(sql: dict, name: str) -> list[dict] | None:
    r = sql.get(name)
    if not isinstance(r, dict) or "rows" not in r:
        return None
    return r["rows"]


def evaluate(posture: dict, th: Thresholds | None = None) -> tuple[list[Finding], dict[str, dict]]:
    """Pure function: posture snapshot → (findings, maturity per workspace). No I/O."""
    th = th or Thresholds()
    F: list[Finding] = []
    maturity: dict[str, dict] = {}
    sql = posture.get("sql") or {}
    acct = posture.get("account") or {}
    docs = "https://docs.databricks.com/aws/en/security/network/front-end/context-based-ingress"

    # ---- account-wide
    if acct.get("error"):
        F.append(Finding("CBI-018", "medium", "Account configuration could not be read",
                         f"Account API error: {acct['error']}. Policy, PAS and assignment checks are UNKNOWN.",
                         "Re-run with account-admin credentials (--account-profile / --account-id). "
                         "See docs/account-admin-setup.md in the network-policy helper.",
                         docs=f"{HELPER_REPO}/blob/main/docs/account-admin-setup.md"))

    inbound = sql.get("inbound_policy_outcomes") or {}
    if inbound.get("error"):
        F.append(Finding("CBI-011", "medium", "No CBI denial observability (system.access.inbound_network unreadable)",
                         f"Query failed: {inbound['error'][:240]}",
                         "Enable the `access` system schema on the metastore and grant SELECT on "
                         "system.access.inbound_network to the security team. Without it, dry-run cannot be "
                         "evaluated and enforced breakage is invisible.",
                         docs="https://docs.databricks.com/aws/en/admin/system-tables/network"))

    acct_policy = acct.get("account_policy")
    acct_rows = _rows(sql, "account_level_public_access") or []
    if acct.get("policies_read") and acct_policy is not None:
        s = summarise_policy(acct_policy)
        if not s["public"]["restrictive"]:
            F.append(Finding("CBI-009", "high" if acct_rows else "medium",
                             "Account console / account APIs reachable from any public IP",
                             f"`account-policy` public access is {s['public']['restriction_mode'] or 'unrestricted'}; " +
                             (f"{len(acct_rows)}{'+' if len(acct_rows) >= 200 else ''} distinct public IPs reached account-level endpoints "
                              "in the lookback" + (" (the query returns at most 200)." if len(acct_rows) >= 200 else ".")),
                             "Account-level CBI (Beta) protects the account console, account APIs and account-level "
                             "Genie One. Derive the admin source IPs with the helper (propose-only; it reads "
                             "workspace_id=0 rows but does not write `account-policy`), then configure `account-policy` "
                             "in dry-run in the account console (Security → Networking → account level policies).",
                             next_step=_cmd(posture.get("workspace_profile"), "--include-account-level --export .")
                             + "   # candidate IPs only; apply to account-policy in the console",
                             docs="https://docs.databricks.com/aws/en/security/network/front-end/manage-ingress-account"))

    acl_acct = acct.get("account_ip_acl") or {}
    if acl_acct.get("enabled") and acct_policy is not None and summarise_policy(acct_policy)["public"]["restrictive"]:
        F.append(Finding("CBI-005", "low", "Account IP access lists still enabled alongside account-level CBI",
                         "Account IP ACLs and the account-level policy are combined with AND; both must allow.",
                         "Once account-level CBI is enforced and validated, retire the account IP access lists so "
                         "CBI is the single policy engine.", docs=docs))

    today = dt.date.fromisoformat(str(posture.get("generated_at") or dt.date.today().isoformat())[:10])
    saas_present = any(r.get("client_family") in {"Power BI", "Tableau", "dbt", "ChatGPT", "Claude", "Fivetran", "Looker"}
                       for r in (_rows(sql, "client_families_on_public_ips") or []))

    # ---- per workspace
    for ws in posture.get("workspaces") or []:
        wid = str(ws.get("workspace_id"))
        prof = ws.get("profile") or posture.get("workspace_profile")
        tier = (ws.get("pricing_tier") or "").upper()
        pas = ws.get("pas")
        acl = ws.get("ip_acl")  # None = not collected
        traffic = next((r for r in (_rows(sql, "traffic_by_ip_class") or []) if str(r.get("workspace_id")) == wid), None)
        pol_err = ws.get("policy_error")
        s = summarise_policy(ws.get("policy"))
        explicit = bool(ws.get("assigned_policy_id"))
        pid = ws.get("assigned_policy_id") or ws.get("effective_policy_id") or "default-policy"

        if tier and tier not in ("ENTERPRISE", "UNKNOWN"):
            F.append(Finding("CBI-016", "info", f"Pricing tier {tier}: context-based ingress requires Enterprise",
                             "CBI policies are an Enterprise-tier feature.",
                             "Use IP access lists / PrivateLink for now; plan the tier change before a CBI rollout.",
                             workspace_id=wid, docs="https://databricks.com/product/pricing/platform-addons"))

        if pol_err:
            F.append(Finding("CBI-018", "medium", "Assigned network policy could not be read",
                             pol_err, "Re-run with account-admin credentials.", workspace_id=wid))
            maturity[wid] = {"level": None, "label": "Unknown", "why": "policy unreadable"}
            continue

        acl_enabled = bool(acl and acl.get("enabled"))
        allow_lists = [l for l in (acl or {}).get("lists", []) if l.get("enabled") and l.get("list_type") == "ALLOW"]
        acl_cidrs = [ip for l in allow_lists for ip in (l.get("ip_addresses") or [])]
        public_blocked = pas is not None and pas.get("public_access_enabled") is False
        pub = s["public"]

        # Maturity. A block that is RESTRICTED_ACCESS on paper but lets any IP call all APIs as anyone is open.
        restricts = pub["restrictive"] and not pub["effectively_open"]
        open_note = (f"; rule(s) {pub['open_api_rules']} let any IP call all workspace APIs"
                     if pub["restrictive"] and pub["effectively_open"] else "")
        if public_blocked:
            level, label, why = 3, "Private-only", "PAS blocks public network access (ingress policies not evaluated for public)"
        elif s["mode"] == "enforce" and restricts:
            level, label, why = 3, "Enforced", f"`{pid}` enforces a restricted public allow-list"
        elif s["mode"] == "dry_run" and restricts:
            level, label, why = 2, "Observing", f"`{pid}` restricts public access in dry-run only (log-only)"
        elif acl_enabled and allow_lists:
            level, label, why = 1, "Legacy perimeter", "IP access lists only; no restrictive CBI public block" + open_note
        elif acl is None:
            level, label, why = None, "CBI open, IP ACL unchecked", (
                "CBI public access open (L0 or L1). IP access lists are readable only from inside that workspace; "
                "run there, or scope to it from its own notebook, to settle the level" + open_note)
        else:
            level, label, why = 0, "Open", "No restrictive CBI public block and no enabled allow IP access list" + open_note

        # ---- public dimension findings
        if level == 0:
            F.append(Finding("CBI-001", "high", "Public ingress is unrestricted",
                             f"Governed by `{pid}` with public access {pub['restriction_mode'] or 'FULL_ACCESS'}; no enabled "
                             f"allow IP access list. "
                             + (f"{traffic.get('distinct_public_ips')} distinct public IPs / "
                                f"{traffic.get('public_principals')} principals seen." if traffic else ""),
                             "Generate an allow-list from observed traffic, apply it in DRY-RUN, review "
                             "`dry_run_would_block`, then enforce.",
                             workspace_id=wid, next_step=_cmd(prof), docs=docs))
        elif level is None and not public_blocked:
            F.append(Finding("CBI-001", "medium", "Public ingress open at the CBI layer (IP ACL state unknown)",
                             (f"`{pid}` is RESTRICTED_ACCESS on paper, but rule(s) {pub['open_api_rules']} let any IP "
                              "call all workspace APIs (CBI-004)." if pub["restrictive"] and pub["effectively_open"]
                              else f"`{pid}` public access is {pub['restriction_mode'] or 'FULL_ACCESS'}.")
                             + " IP access lists weren't read for this workspace: run the notebook in that workspace "
                               "(or add --workspace-profile) to check them.",
                             "Same as CBI-001 once IP ACL state is confirmed.", workspace_id=wid,
                             next_step=_cmd(prof), docs=docs))
        if level == 1:
            F.append(Finding("CBI-002", "medium", "Only legacy IP access lists protect this workspace",
                             f"{len(allow_lists)} enabled ALLOW list(s), {len(acl_cidrs)} entries; CBI public access is open.",
                             "Migrate to CBI (Databricks recommends CBI as the single policy engine). The helper "
                             "auto-detects the IP ACLs and folds them in with observed traffic; for a verbatim "
                             f"migration use dbx-migrate-ip-acls ({MIGRATE_REPO}).",
                             workspace_id=wid, next_step=_cmd(prof),
                             docs="https://docs.databricks.com/aws/en/security/network/front-end/migrate-to-context-based-ingress"))
        if level == 2:
            would_block = [r for r in (_rows(sql, "dry_run_would_block") or []) if str(r.get("workspace_id")) == wid]
            F.append(Finding("CBI-003", "medium", "CBI policy is dry-run only (not blocking)",
                             f"`{pid}` restricts public access in log-only mode. "
                             f"{len(would_block)} source/identity/rule combinations would be blocked if enforced.",
                             "Close the gap: re-run the helper (it folds dry-run denials into the candidate set by "
                             "default), re-apply in dry-run, and switch to enforce once `dry_run_would_block` is clean.",
                             workspace_id=wid,
                             next_step=_cmd(prof, f"--policy-action add_to_existing --existing-policy-id {pid}"),
                             docs="https://docs.databricks.com/aws/en/security/network/front-end/manage-ingress-workspace"))

        # broad CIDRs in CBI or IP ACL
        hi = broad_cidrs(pub["cidrs"], th.broad_prefix_high) + broad_cidrs(acl_cidrs, th.broad_prefix_high)
        med = [c for c in broad_cidrs(pub["cidrs"] + acl_cidrs, th.broad_prefix_medium - 1) if c not in hi]
        unstated = pub["unstated_api_rules"]
        unstated_note = (f" Rule(s) {unstated} name the workspace API without scopes; that's treated as all APIs. "
                         "Confirm in the account console." if unstated else "")
        if pub["open_api_rules"]:
            F.append(Finding("CBI-004", "high", "Allow rule lets any IP call all workspace APIs",
                             f"Rule(s) {pub['open_api_rules']} match every source IP (or every public IP except a few) "
                             "and reach all workspace APIs for every identity, so a stolen token works from anywhere. "
                             "The policy restricts nothing for API callers." + unstated_note,
                             "Narrow the source to owned ranges, or keep 'from anywhere' only for the workspace UI "
                             "(pattern B1) and allow the API families you need (B2) or named identities (B4).",
                             workspace_id=wid, next_step=_cmd(prof), docs=docs))
        if pub["open_identity_rules"]:
            F.append(Finding("CBI-004", "medium", "Named identities can call all APIs from any IP",
                             f"Rule(s) {pub['open_identity_rules']} let the selected users / service principals call all "
                             "workspace APIs from anywhere." + unstated_note,
                             "Prefer source ranges for automation. For people who roam, make the rule time-boxed "
                             "(pattern B4) and pair it with short token lifetimes.",
                             workspace_id=wid, docs=docs))
        if pub["open_scoped_api_rules"]:
            F.append(Finding("CBI-028", "low", "Some API families are reachable from any IP",
                             f"Rule(s) {pub['open_scoped_api_rules']} allow specific API scopes from anywhere: "
                             + ", ".join(sorted({sc for r in pub["rules"] if r["label"] in pub["open_scoped_api_rules"]
                                                 for sc in r["scopes"]})) + ". "
                             "This is pattern B2 (allow only the API families you need).",
                             "Fine if intended. Check each scope has an owner, and that tokens with those scopes are "
                             "short-lived (CBI-020/021).", workspace_id=wid, docs=docs))
        if pub["open_ui_only_rules"]:
            F.append(Finding("CBI-029", "info", "Browser access from anywhere, APIs restricted (pattern B1)",
                             f"Rule(s) {pub['open_ui_only_rules']} allow every IP to the workspace UI / Apps / Lakebase "
                             "only. API calls must match another rule.",
                             "A sound no-VPN pattern. Pair it with SSO + MFA, and watch `public_browser_vs_api` for "
                             "API callers that start failing.", workspace_id=wid, docs=docs))
        if pub["unknown_origin_rules"]:
            F.append(Finding("CBI-027", "info", "Rule source not visible through the API",
                             f"Rule(s) {pub['unknown_origin_rules']} have no IP source in the API response. They are "
                             "probably sources configured in the account console that the API doesn't describe "
                             "(e.g. Partner platforms or app integrations), so this report can't judge who they admit.",
                             "Review these rules in the account console (policy → Ingress).", workspace_id=wid, docs=docs))
        if hi or med:
            F.append(Finding("CBI-004", "high" if hi else "medium", "Overly broad allow CIDRs",
                             f"/0–/{th.broad_prefix_high}: {hi[:10]}; /{th.broad_prefix_high + 1}–/{th.broad_prefix_medium - 1}: {med[:10]}",
                             "Broad ranges often cover a whole cloud provider or ISP. Re-frame from observed traffic "
                             "(`--policy-framing minimal|optimal`) and keep only owned ranges.",
                             workspace_id=wid, next_step=_cmd(prof, "--policy-framing optimal --enable-rdap"), docs=docs))

        if acl_enabled and allow_lists and s["mode"] == "enforce" and pub["restrictive"]:
            F.append(Finding("CBI-005", "low", "IP access lists still enabled alongside enforced CBI",
                             "Workspace IP ACLs and CBI combine with AND, so two lists must be kept in sync.",
                             "After validating the enforced policy, disable the IP access lists (they are preserved "
                             "and the change is reversible).", workspace_id=wid,
                             next_step=_cmd(prof, "--create-policy --auto-assign --policy-mode enforce --disable-existing-ip-acls")
                             + "   # only after explicit approval", docs=docs))

        if not explicit and not pol_err and ws.get("assignment_read"):
            F.append(Finding("CBI-006", "info", "Workspace relies on the account default policy",
                             "No explicit network-policy assignment; `default-policy` governs this workspace.",
                             "Databricks advises against editing default-policy ingress. Create a named policy and "
                             "attach it to specific workspaces.", workspace_id=wid,
                             docs="https://docs.databricks.com/aws/en/security/network/front-end/manage-ingress-workspace"))

        n_rules = pub["allow_rules"] + pub["deny_rules"]
        if n_rules >= MAX_INGRESS_RULES * NEAR_LIMIT_RATIO or len(pub["cidrs"]) >= MAX_CIDRS * NEAR_LIMIT_RATIO:
            F.append(Finding("CBI-010", "medium", "Policy is close to platform limits",
                             f"{n_rules}/{MAX_INGRESS_RULES} public rules, {len(pub['cidrs'])}/{MAX_CIDRS} CIDRs.",
                             "Consolidate low-traffic owners (`--consolidate-rules`) and move partner SaaS to the "
                             "managed Partner platforms source.", workspace_id=wid,
                             next_step=_cmd(prof, "--consolidate-rules"), docs=docs))

        # ---- private dimension
        has_private = pas is not None and pas.get("private_access_level") is not None
        priv = s["private"]
        if has_private and not priv["restrictive"]:
            F.append(Finding("CBI-007", "medium", "Front-end private access allows ALL registered endpoints",
                             f"PAS `{pas.get('private_access_settings_name') or pas.get('private_access_settings_id')}` "
                             f"(level {pas.get('private_access_level')}); CBI private_access is "
                             f"{priv['restriction_mode'] or 'ALLOW_ALL_REGISTERED_ENDPOINTS (default)'}. Any endpoint "
                             "registered to the account can reach this workspace if the PAS allows it.",
                             "Restrict private_access to the workspace's own endpoints (the helper recreates the "
                             "PAS posture in a private_access block on AWS/GCP).", workspace_id=wid,
                             next_step=_cmd(prof),
                             docs="https://docs.databricks.com/aws/en/security/network/front-end/front-end-private-connect#private-access"))
        if has_private and pas.get("public_access_enabled") and level is not None and level < 2:
            F.append(Finding("CBI-008", "info", "PrivateLink workspace still accepts public traffic",
                             "PAS public access is enabled, so public ingress is governed only by CBI / IP ACLs.",
                             "Confirm hybrid access is intended; otherwise restrict public via CBI or block public "
                             "network access in the PAS.", workspace_id=wid,
                             docs="https://docs.databricks.com/aws/en/security/network/classic/private-access-settings"))

        xws = s["cross_workspace"]
        if not xws["restrictive"] and level is not None and level >= 2:
            F.append(Finding("CBI-019", "info", "Cross-workspace (serverless) ingress not restricted",
                             f"cross_workspace_access is {xws['restriction_mode'] or 'unset (compatibility mode)'}.",
                             "If other workspaces should not reach this one over serverless, add a cross-workspace "
                             "allow-list (Beta).", workspace_id=wid,
                             docs="https://docs.databricks.com/aws/en/security/network/front-end/cross-workspace-access"))

        if not s["egress_restrictive"]:
            F.append(Finding("CBI-017", "low", "Serverless egress is unrestricted",
                             "Ingress-only posture: serverless workloads can reach any destination.",
                             "Pair CBI with serverless egress control (the helper's `egress` command).",
                             workspace_id=wid,
                             next_step=f"uv run dbx-nwp-helper egress --profile {prof or '<workspace-profile>'} --lookback-days 90",
                             docs="https://docs.databricks.com/aws/en/security/network/serverless-network-security/network-policies"))

        # ---- traffic-derived
        if traffic and int(traffic.get("ipv6_events") or 0) > 0:
            F.append(Finding("CBI-015", "info", "IPv6 client traffic observed",
                             f"{traffic.get('distinct_ipv6_ips')} distinct IPv6 sources. CBI public rules are IPv4-only.",
                             "Identify these clients before enforcing (they cannot be allow-listed by CIDR).",
                             workspace_id=wid, docs=docs))
        denials = [r for r in (_rows(sql, "enforced_denials") or []) if str(r.get("workspace_id")) == wid]
        n_denied = sum(int(r.get("denied_events") or 0) for r in denials)
        if n_denied > th.max_enforced_denials_ok:
            F.append(Finding("CBI-012", "high" if s["mode"] == "enforce" else "medium",
                             "Requests are being blocked by an enforced CBI policy",
                             f"{n_denied} denied requests across {len(denials)} day/rule buckets in the lookback.",
                             "Triage with `enforced_denials`; legitimate sources go back into the allow-list "
                             "(`--deny-denied-ips` is the opposite: turning them into explicit deny rules).",
                             workspace_id=wid, next_step=_cmd(prof), docs=docs))

        # ---- credential layers (Avoid / Expire / Scope): what a stolen token is worth
        pat = ws.get("pat") or {}
        ts = summarise_tokens(pat, today, th)
        open_public = level in (0, 1, None) and not public_blocked
        if pat and pat.get("tokens_enabled") is not False:
            mtl = pat.get("max_token_lifetime_days")
            try:
                mtl_i = int(mtl) if mtl not in (None, "") else 0
            except ValueError:
                mtl_i = 0
            if "max_token_lifetime_days" in pat and (mtl_i <= 0 or mtl_i > th.max_token_lifetime_days):
                F.append(Finding("CBI-021", "medium", "No short maximum lifetime for new PATs",
                                 f"maxTokenLifetimeDays = {mtl or 'unset'} (flag above {th.max_token_lifetime_days}).",
                                 "Set a maximum lifetime your integrations can sustain (one or seven days is a useful "
                                 "starting point to evaluate). Existing tokens keep their expiry, so revoke old ones explicitly.",
                                 workspace_id=wid,
                                 next_step=f"databricks workspace-conf set-status --profile {prof or '<ws-admin>'} "
                                           "--json '{\"maxTokenLifetimeDays\":\"7\"}'   # after compatibility testing",
                                 docs=CRED_DOCS))
            if pat.get("all_users_can_use"):
                F.append(Finding("CBI-022", "medium", "Every user may create and use PATs",
                                 "The `users` group has CAN_USE on tokens.",
                                 "Move people to OAuth U2M (browser sign-in) and automation to workload identity "
                                 "federation or OAuth M2M; then grant PAT use only to an approved exception group or "
                                 "specific service principals.", workspace_id=wid,
                                 docs="https://docs.databricks.com/aws/en/security/auth/api-access-permissions"))
        if pat.get("permissions_customised") is False and pat.get("tokens_enabled") is not False:
            F.append(Finding("CBI-022", "info", "PAT permissions were never customised",
                             "This workspace has no token permissions set, so the default applies, and the API doesn't "
                             "say who that includes.",
                             "Check Settings → Advanced → Personal Access Tokens → Permission settings. Grant PAT use "
                             "only to an approved exception group or specific service principals; move people to OAuth "
                             "U2M and automation to OAuth M2M or workload identity federation.", workspace_id=wid,
                             docs="https://docs.databricks.com/aws/en/security/auth/api-access-permissions"))
        if ts:
            if ts["never_expire"]:
                F.append(Finding("CBI-020", "high" if open_public else "medium", "PATs that never expire",
                                 f"{ts['never_expire']} of {ts['total']} tokens have no expiry "
                                 f"(owners: {', '.join(ts['never_expire_owners'])}). "
                                 + ("Public ingress is open, so each one is single-factor access from anywhere."
                                    if open_public else "CBI limits where they work, but not for how long."),
                                 "Replace with OAuth or short-lived tokens and revoke these explicitly (account console → "
                                 "Security → Token report covers every workspace). A new lifetime maximum does not "
                                 "shorten existing tokens.", workspace_id=wid,
                                 next_step=f"databricks token-management list --profile {prof or '<ws-admin>'} -o json",
                                 docs=CRED_DOCS))
            if ts["unscoped"] and ts["total"]:
                F.append(Finding("CBI-023", "low", "PATs without API scopes",
                                 f"{ts['unscoped']} of {ts['total']} tokens can call every API family (an empty scope "
                                 "list means all APIs, not none).",
                                 "Scope each token to the API families its job needs, or enable PAT auto-scoping "
                                 "(preview) so long-lived tokens are narrowed to what they actually use after 30 days. "
                                 "Exercise rare and failover paths during the observation window.", workspace_id=wid,
                                 docs="https://docs.databricks.com/aws/en/dev-tools/auth/pat"))
            if ts["stale"]:
                F.append(Finding("CBI-024", "info", "Unused PATs",
                                 f"{ts['stale']} tokens not used in {th.stale_token_days}+ days.",
                                 "Revoke them; unused credentials carry risk and no value.", workspace_id=wid,
                                 docs=CRED_DOCS))

        # ---- visibility (Detect)
        vis = next((r for r in (_rows(sql, "audit_visibility") or []) if str(r.get("workspace_id")) == wid), None)
        if vis and int(vis.get("verbose_audit_disabled_events") or 0) > 0:
            F.append(Finding("CBI-025", "medium", "Verbose audit logging was turned off in the lookback window",
                             f"Last disabled at {vis.get('last_verbose_audit_disabled')}. Notebook/command-level events "
                             "after that point may be missing, so traffic-based conclusions have a gap.",
                             "Confirm who changed it and why, turn it back on, and treat the gap as unknown rather "
                             "than clean.", workspace_id=wid,
                             docs="https://docs.databricks.com/aws/en/admin/account-settings/verbose-logs"))

        # ---- which CBI pattern fits (Limit) - only where public access is still open
        if open_public:
            bva = next((r for r in (_rows(sql, "public_browser_vs_api") or []) if str(r.get("workspace_id")) == wid), None)
            pats = []
            if tier and tier not in ("ENTERPRISE", "UNKNOWN"):
                pats.append("CBI not available on this tier: prioritise credential layers (OAuth, short PAT lifetimes, "
                            "scopes), blast-radius controls (catalog bindings, least privilege, UC secrets, fewer "
                            "admins) and detection")
            else:
                in_use = (["B1 (browser from anywhere)"] if pub["open_ui_only_rules"] else []) + \
                         (["B2 (API families from anywhere)"] if pub["open_scoped_api_rules"] else [])
                if in_use:
                    pats.append(f"Already uses {' and '.join(in_use)}, but an open rule undoes it: remove or narrow "
                                f"{pub['open_api_rules'] or 'the rule that admits all APIs'} first")
                elif pub["open_api_rules"]:
                    pats.append(f"**First narrow {pub['open_api_rules']}**: it lets any IP call all workspace APIs, so "
                                "no other rule in this policy limits a stolen token")
                if bva and not in_use:
                    progs = int(bva.get("programmatic_principals") or 0)
                    if progs <= th.b1_max_programmatic_principals:
                        pats.append(f"**Browser yes, remote APIs no**: only {progs} identities use programmatic "
                                    f"clients from public IPs ({bva.get('browser_pct')}% of public traffic is browser). "
                                    "Allow Workspace UI · all users · all public IPs, plus API rules for the named "
                                    "service principals/identities only")
                    else:
                        pats.append(f"**Allow only the API families you need**: {progs} identities call APIs from "
                                    "public IPs. Use API allow rules with `IN <scopes>` (e.g. `sql`) rather than a "
                                    "general public API rule")
                if saas_present:
                    pats.append("**Narrow partner exceptions**: allow the Partner platforms source for the hosted BI "
                                "tools seen, instead of opening API access to the internet")
                pats.append("Pilot on one workspace in dry-run over a full business cycle before enforcing; use "
                            "time-boxed selected-identity rules for occasional production access")
            F.append(Finding("CBI-026", "info", "Suggested CBI rollout pattern",
                             " · ".join(pats[:1]) if pats else "Not enough traffic data to suggest a pattern.",
                             " ".join(f"({i + 1}) {p}." for i, p in enumerate(pats[1:])) or "See references/credential-theft-layers.md.",
                             workspace_id=wid, next_step=_cmd(prof),
                             docs="https://docs.databricks.com/aws/en/security/network/front-end/manage-ingress-workspace"))

        maturity[wid] = {"level": level, "label": label, "why": why}

    # ---- traffic: principals / SaaS (account-wide tables)
    spread = [r for r in (_rows(sql, "principal_network_spread") or [])
              if int(r.get("distinct_public_24s") or 0) >= th.spread_24s]
    if spread:
        sps = [r for r in spread if r.get("principal_type") == "service_principal"]
        F.append(Finding("CBI-013", "medium", "Principals connect from many public networks",
                         f"{len(spread)} principals from >= {th.spread_24s} distinct public /24s "
                         f"({len(sps)} service principals). Top: "
                         + ", ".join(f"{r.get('principal') or '(no identity)'} ({r['distinct_public_24s']})" for r in spread[:5]),
                         "CIDR allow-lists will not hold for these. Use identity-scoped rules (all service "
                         "principals / selected identities) or a VPN/egress gateway for users.",
                         next_step=_cmd(posture.get("workspace_profile"), "--scoping-mode ip_and_identity"), docs=docs))
    fams = {r.get("client_family") for r in (_rows(sql, "client_families_on_public_ips") or [])}
    saas = sorted(f for f in fams if f in {"Power BI", "Tableau", "dbt", "ChatGPT", "Claude", "Fivetran", "Looker"})
    if saas:
        F.append(Finding("CBI-014", "info", "SaaS / BI partner clients detected on public IPs",
                         f"Client families: {', '.join(saas)}.",
                         "Prefer the managed Partner platforms source (Databricks keeps these IP lists current) "
                         "over hand-maintained CIDRs.",
                         docs="https://docs.databricks.com/aws/en/security/network/front-end/partner-platforms"))

    for f in F:
        f.layer = LAYER_BY_ID.get(f.id, f.layer)
    F.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.id, f.workspace_id))
    return F, maturity


# ------------------------------------------------------------------------------------- collection
def _err(e: Exception) -> str:
    return f"{type(e).__name__}: {' '.join(str(e).split())[:300]}"


API_PARALLEL = 8


def collect_account(a, only_ws: set[str] | None) -> tuple[dict, list[dict]]:
    acct: dict = {"policies_read": False}
    workspaces: list[dict] = []
    try:
        pols = list(a.network_policies.list_network_policies_rpc())
        acct["policies"] = [p.as_dict() for p in pols]
        acct["policies_read"] = True
        acct["account_policy"] = next((p for p in acct["policies"] if p.get("network_policy_id") == "account-policy"), None)
    except Exception as e:  # noqa: BLE001
        acct["error"] = _err(e)
        acct["policies"] = []
    by_id = {p.get("network_policy_id"): p for p in acct.get("policies", [])}

    try:
        acct["account_ip_acl"] = {
            "enabled": bool(a.settings.enable_ip_access_lists.get().acct_ip_acl_enable.value),
            "lists": [l.as_dict() for l in a.ip_access_lists.list()],
        }
    except Exception as e:  # noqa: BLE001
        acct["account_ip_acl"] = {"error": _err(e)}

    pas_cache: dict[str, dict | None] = {}
    try:
        ws_list = list(a.workspaces.list())
    except Exception as e:  # noqa: BLE001  (e.g. Azure: account workspaces API unavailable)
        acct["workspaces_error"] = _err(e)
        ws_list = []
    for w in ws_list:
        wid = str(w.workspace_id)
        if only_ws and wid not in only_ws:
            continue
        rec = {"workspace_id": wid, "workspace_name": w.workspace_name, "cloud": w.cloud,
               "pricing_tier": _mode(w.pricing_tier), "deployment_name": w.deployment_name, "pas": None}
        if w.private_access_settings_id:
            pid = w.private_access_settings_id
            if pid not in pas_cache:
                try:
                    pas_cache[pid] = a.private_access.get(private_access_settings_id=pid).as_dict()
                except Exception as e:  # noqa: BLE001
                    pas_cache[pid] = {"private_access_settings_id": pid, "error": _err(e)}
            rec["pas"] = pas_cache[pid]
        workspaces.append(rec)

    # one assignment lookup per workspace: in parallel (the SDK retries if the account API rate-limits)
    with ThreadPoolExecutor(max_workers=API_PARALLEL, thread_name_prefix="cbi-api") as pool:
        list(pool.map(lambda rec: _attach_policy(a, rec, by_id), workspaces))
    return acct, workspaces


def _attach_policy(a, rec: dict, by_id: dict) -> None:
    try:
        opt = a.workspace_network_configuration.get_workspace_network_option_rpc(workspace_id=int(rec["workspace_id"]))
        rec["assignment_read"] = True
        pid = opt.network_policy_id
        rec["assigned_policy_id"] = pid if pid and pid != "default-policy" else None
        eff = pid or "default-policy"
        rec["effective_policy_id"] = eff
        pol = by_id.get(eff)
        if pol is None:
            pol = a.network_policies.get_network_policy_rpc(network_policy_id=eff).as_dict()
        rec["policy"] = pol
    except Exception as e:  # noqa: BLE001
        rec["policy_error"] = _err(e)


def collect_workspace(w) -> dict:
    out: dict = {}
    try:
        status = w.workspace_conf.get_status(keys="enableIpAccessLists") or {}
        lists = [l.as_dict() for l in w.ip_access_lists.list()]
        out = {"enabled": str(status.get("enableIpAccessLists", "")).lower() == "true", "lists": lists}
    except Exception as e:  # noqa: BLE001
        out = {"error": _err(e)}
    return out


def collect_tokens(w) -> dict:
    """PAT inventory + token settings (workspace admin). Metadata only; the API never returns values."""
    out: dict = {}
    try:
        conf = w.workspace_conf.get_status(keys="maxTokenLifetimeDays,enableTokensConfig") or {}
        out["max_token_lifetime_days"] = conf.get("maxTokenLifetimeDays")
        out["tokens_enabled"] = str(conf.get("enableTokensConfig", "true")).lower() != "false"
    except Exception as e:  # noqa: BLE001
        out["config_error"] = _err(e)
    try:
        keep = ("token_id", "created_by_username", "creation_time", "expiry_time", "last_used_day",
                "scopes", "autoscope_state", "owner_id")
        out["tokens"] = [{k: v for k, v in t.as_dict().items() if k in keep} for t in w.token_management.list()]
    except Exception as e:  # noqa: BLE001
        out["tokens_error"] = _err(e)
    try:
        perms = w.permissions.get(request_object_type="authorization", request_object_id="tokens")
        out["all_users_can_use"] = any(
            acl.group_name == "users" and any(str(getattr(p.permission_level, "value", p.permission_level)) == "CAN_USE"
                                              for p in (acl.all_permissions or []))
            for acl in (perms.access_control_list or []))
    except Exception as e:  # noqa: BLE001
        if type(e).__name__ in ("ResourceDoesNotExist", "NotFound"):
            # No token permissions object: they were never customised, so the workspace default applies.
            # Databricks doesn't document that default, so don't guess; say where to look.
            out["permissions_customised"] = False
        else:
            out["permissions_error"] = _err(e)
    return out


def warehouse_executor(w, warehouse_id: str, lookback_days: int):
    """execute(stmt, params=True) -> rows, via the Statement Execution API on a SQL warehouse."""
    from databricks.sdk.service.sql import Disposition, Format, StatementParameterListItem, StatementState

    def execute(stmt: str, params=True) -> list[dict]:
        resp = w.statement_execution.execute_statement(
            statement=stmt, warehouse_id=warehouse_id, wait_timeout="50s",
            disposition=Disposition.INLINE, format=Format.JSON_ARRAY,
            parameters=[StatementParameterListItem(name="lookback_days", value=str(lookback_days), type="INT")]
            if params else None,
        )
        deadline = time.time() + 3600
        while resp.status.state in (StatementState.PENDING, StatementState.RUNNING) and time.time() < deadline:
            time.sleep(3)
            resp = w.statement_execution.get_statement(resp.statement_id)
        if resp.status.state != StatementState.SUCCEEDED:
            msg = resp.status.error.message if resp.status.error else resp.status.state
            raise RuntimeError(str(msg))
        cols = [c.name for c in resp.manifest.schema.columns] if resp.manifest and resp.manifest.schema else []
        rows = (resp.result.data_array or []) if resp.result else []
        return [dict(zip(cols, r)) for r in rows]

    return execute


def spark_executor(spark, lookback_days: int):
    """execute(stmt, params=True) -> rows, on the notebook's own compute (no SQL warehouse needed)."""
    def execute(stmt: str, params=True) -> list[dict]:
        df = spark.sql(stmt, args={"lookback_days": int(lookback_days)}) if params else spark.sql(stmt)
        return [r.asDict(recursive=True) for r in df.collect()]

    return execute


def stage_audit(execute, log, schema: str, lookback_days: int, workspace_ids=None) -> str | None:
    """Read the audit rollup once into <schema>.cbi_stage_audit_<id>. Returns the table, or None to read directly."""
    if not re.fullmatch(r"[A-Za-z0-9_`-]+\.[A-Za-z0-9_`-]+", schema or ""):
        log(f"  staging skipped: {schema!r} is not catalog.schema")
        return None
    table = f"{schema}.cbi_stage_audit_{uuid.uuid4().hex[:12]}"
    t0 = time.time()
    try:
        execute(cbi_sql.stage_statement(table, lookback_days, workspace_ids), params=False)
    except Exception as e:  # noqa: BLE001
        log(f"  staging copy in {schema} failed ({_err(e)[:120]}); reading system.access.audit per query instead")
        try:
            execute(f"DROP TABLE IF EXISTS {table}", params=False)
        except Exception:  # noqa: BLE001
            pass
        return None
    log(f"  read system.access.audit once into the rollup table {table} ({time.time() - t0:.0f}s); dropped at the end of the run")
    return table


CACHE_HINT = ("On serverless, DataFrame caching needs environment version 5 or later, and isn't available yet on "
              "GovCloud or with the compliance security profile; runs pick it up automatically once it is.")


def _cache_active(df) -> bool:
    lvl = getattr(df, "storageLevel", None)
    flags = [getattr(lvl, a) for a in ("useDisk", "useMemory", "useOffHeap") if hasattr(lvl, a)]
    return any(flags) if flags else True


def cache_probe(spark) -> str | None:
    """Check that DataFrame caching works on a one-row DataFrame. Returns None if it does, else why not.

    Cheap, so a compute without the cache (serverless below environment 5, GovCloud) doesn't pay for a full
    audit scan that it then throws away.
    """
    try:
        p = spark.range(1).cache()
        p.count()
        active = _cache_active(p)
        try:
            p.unpersist()
        except Exception:  # noqa: BLE001
            pass
    except Exception as e:  # noqa: BLE001
        return _err(e)[:120]
    return None if active else "not active on this compute"


def cache_audit(spark, log, lookback_days: int, workspace_ids=None):
    """Read the audit rollup once into a cached DataFrame. Returns it, or None to read the system table per query.

    Serverless needs DataFrame caching (environment version 5+, Public Preview); classic compute always has it.
    Only DataFrames derived from this one read the snapshot, so the queries run over it via spark.sql kwargs.
    """
    why = cache_probe(spark)
    if why:
        log(f"  DataFrame cache unavailable ({why}); reading system.access.audit per query. {CACHE_HINT}")
        return None
    t0 = time.time()
    try:
        df = spark.sql(cbi_sql.rollup_select(lookback_days, workspace_ids)).cache()
        rows = df.count()  # serverless caches eagerly; on classic this materialises the cache
        active = _cache_active(df)
    except Exception as e:  # noqa: BLE001
        log(f"  DataFrame cache unavailable ({_err(e)[:120]}); reading system.access.audit per query. {CACHE_HINT}")
        return None
    if not active:
        log(f"  DataFrame cache not active on this compute; reading system.access.audit per query. {CACHE_HINT}")
        return None
    log(f"  read system.access.audit once into a cached rollup ({rows:,} rows, {time.time() - t0:.0f}s); "
        "released at the end of the run")
    return df


DEFAULT_PARALLEL = 4


def run_sql(execute, log, workspace_ids=None, stage_schema: str | None = None, lookback_days: int = 90,
            spark=None, use_cache: bool = True, parallel: int = DEFAULT_PARALLEL) -> dict:
    """Run the diagnostic queries, up to `parallel` at a time.

    The inbound_network queries start straight away, while the audit rollup is cached or staged; the audit
    queries then run over the rollup (or straight over system.access.audit if neither is available). Results come back in QUERIES order whatever order they finish in.
    """
    # inbound_network column drift: policy_outcome vs access_type
    outcome_col = "policy_outcome"
    try:
        cols = {r.get("col_name") for r in execute("DESCRIBE TABLE system.access.inbound_network", params=False)}
        if "policy_outcome" not in cols and "access_type" in cols:
            outcome_col = "access_type"
    except Exception:  # noqa: BLE001 - the inbound queries will report the real error
        pass

    def prep(stmt: str) -> str:
        stmt = cbi_sql.scope(stmt, workspace_ids)
        if "inbound_network" in stmt and outcome_col != "policy_outcome":
            stmt = stmt.replace("upper(policy_outcome)", f"upper({outcome_col})")
        return stmt

    audit = [n for n, (_d, q) in cbi_sql.QUERIES.items() if cbi_sql.reads_audit(q)]
    other = [n for n in cbi_sql.QUERIES if n not in audit]
    pool = ThreadPoolExecutor(max_workers=max(1, int(parallel)), thread_name_prefix="cbi-sql")
    futs: dict = {}
    stage = cached = None
    try:
        # inbound queries don't touch the audit log: start them while the rollup is cached / staged
        futs.update({n: pool.submit(_run_one, execute, log, n, prep(cbi_sql.QUERIES[n][1])) for n in other})
        stage = stage_audit(execute, log, stage_schema, lookback_days, workspace_ids) if stage_schema else None
        cached = cache_audit(spark, log, lookback_days, workspace_ids) if (spark is not None and use_cache
                                                                           and not stage) else None
        if cached is not None:
            def over_cache(stmt: str, params=True) -> list[dict]:
                df = spark.sql(stmt, **{cbi_sql.DF_SOURCE: cached})
                return [r.asDict(recursive=True) for r in df.collect()]
            jobs = {n: (over_cache, cbi_sql.over_rollup(n, "{" + cbi_sql.DF_SOURCE + "}")) for n in audit}
        elif stage:
            jobs = {n: (execute, cbi_sql.over_rollup(n, stage)) for n in audit}
        else:
            jobs = {n: (execute, prep(cbi_sql.QUERIES[n][1])) for n in audit}
        futs.update({n: pool.submit(_run_one, fn, log, n, q) for n, (fn, q) in jobs.items()})
        return {n: futs[n].result() for n in cbi_sql.QUERIES}
    finally:
        pool.shutdown(wait=True)
        if stage:
            try:
                execute(f"DROP TABLE IF EXISTS {stage}", params=False)
            except Exception as e:  # noqa: BLE001
                log(f"  could not drop {stage} ({_err(e)[:120]}); drop it by hand: it holds audit identities and IPs")
        if cached is not None:
            try:
                cached.unpersist()
            except Exception:  # noqa: BLE001 - the session ending releases it anyway
                pass


def _run_one(execute, log, name: str, stmt: str) -> dict:
    t0 = time.time()
    try:
        rows = execute(stmt)
        log(f"  sql {name}: {len(rows)} rows ({time.time() - t0:.0f}s)")
        return {"rows": rows}
    except Exception as e:  # noqa: BLE001
        log(f"  sql {name}: FAILED {_err(e)[:120]}")
        return {"error": _err(e)}


# ---------------------------------------------------------------------------------------- output
def render_markdown(posture: dict, findings: list[Finding], maturity: dict) -> str:
    L = [f"# CBI security posture report", "",
         f"_Generated {posture['generated_at']} by cbi-posture v{TOOL_VERSION}. Lookback {posture['lookback_days']} days. "
         "Read-only assessment; nothing was changed._", ""]
    if posture.get("sql_scope"):
        sc = posture["sql_scope"]
        sc = sc if isinstance(sc, str) else "workspace(s) " + ", ".join(sc) + " + account level"
        when = posture.get("sql_generated_at") or posture["generated_at"]
        reused = " (reused from an earlier run; configuration re-read now)" if posture.get("sql_reused") else ""
        L += [f"_Traffic data: {sc}, as of {when} UTC{reused}._", ""]
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    L += ["## Summary", "",
          " · ".join(f"**{k}**: {counts[k]}" for k in sorted(counts, key=lambda k: SEVERITY_ORDER[k])) or "No findings.", ""]
    wss = posture.get("workspaces") or []
    names = {str(ws["workspace_id"]): ws.get("workspace_name") or "" for ws in wss}
    rollup = len(wss) > ROLLUP_MIN_WORKSPACES

    def row(ws) -> str:
        wid = str(ws["workspace_id"])
        m = maturity.get(wid, {})
        s = summarise_policy(ws.get("policy"))
        lvl = "?" if m.get("level") is None else f"L{m['level']}"
        return (f"| {wid} | {names[wid]} | {ws.get('effective_policy_id') or '—'} | "
                f"{s['mode'] or 'open'} | {lvl} {m.get('label', '')} | {m.get('why', '')} |")

    head = ["| Workspace | Name | Policy | Mode | Level | Why |", "|---|---|---|---|---|---|"]
    if rollup:
        dist: dict[str, int] = {}
        for ws in wss:
            m = maturity.get(str(ws["workspace_id"]), {})
            k = ("?" if m.get("level") is None else f"L{m['level']}") + " " + m.get("label", "")
            dist[k] = dist.get(k, 0) + 1
        L += ["## Maturity across the account", "",
              f"{len(wss)} workspaces. Per-workspace detail: `maturity.csv` and `findings.csv`.", "",
              "| Level | Workspaces |", "|---|---|"]
        L += [f"| {k} | {v} |" for k, v in sorted(dist.items(), key=lambda kv: -kv[1])]
        notable = [ws for ws in wss if ws.get("policy") and summarise_policy(ws.get("policy"))["mode"]
                   or (maturity.get(str(ws["workspace_id"]), {}).get("level") or 0) >= 1]
        L += ["", f"### Workspaces with a CBI policy or a perimeter ({len(notable)})", ""]
        L += (head + [row(ws) for ws in notable]) if notable else ["None."]
        rest = len(wss) - len(notable)
        if rest:
            L += ["", f"The other {rest} workspaces have no restrictive CBI public block (most are on the account "
                  "default policy). They are listed in `maturity.csv`."]
    else:
        L += ["## Maturity by workspace", ""] + head + [row(ws) for ws in wss]
    L += ["", "Levels: **L0 Open** → **L1 Legacy perimeter** (IP ACLs) → **L2 Observing** (CBI dry-run) → "
          "**L3 Enforced** (CBI enforced, or private-only) → **L4 Hardened** (L3 with no high/medium findings).", ""]
    L += ["## Defense-in-depth coverage", "",
          "CBI is the **Limit** layer: it decides *where* a valid credential works. A stolen token is worth "
          "less when it also expires soon (Expire), can call little (Scope), and its misuse is noticed (Detect).", "",
          "| Layer | High | Medium | Low/Info |", "|---|---|---|---|"]
    for layer in LAYERS:
        fl = [f for f in findings if f.layer == layer]
        if fl:
            c = lambda sev: sum(1 for f in fl if f.severity in sev)  # noqa: E731
            L.append(f"| {layer} | {c(('critical', 'high'))} | {c(('medium',))} | {c(('low', 'info'))} |")
    L += ["", "Checks for layers this tool cannot see (SSO/MFA, OAuth adoption, catalog bindings, UC secrets, admin "
          "counts) are covered by Governance Hub security posture and the Security Analysis Tool.", ""]
    L += ["## Findings", ""]
    if rollup:
        L += ["Grouped by check across workspaces; one example is shown per group. Every finding, with its own "
              "detail and command, is in `findings.csv`. For a full write-up of one workspace, re-run scoped to it.", ""]
        groups: dict[tuple, list[Finding]] = {}
        for f in findings:
            groups.setdefault((f.severity, f.id, f.title), []).append(f)
        for (sev, fid, title), fl in sorted(groups.items(), key=lambda kv: (SEVERITY_ORDER[kv[0][0]], -len(kv[1]), kv[0][1])):
            ids = [f.workspace_id for f in fl]
            ex = fl[0]
            L += [f"### [{sev.upper()}] {fid}: {title}  ·  {len(fl)} workspace(s)  ·  {ex.layer}", ""]
            shown = ", ".join(f"`{i}`" + (f" ({names[i]})" if names.get(i) else "") for i in ids[:ROLLUP_LIST])
            L += [f"**Where:** {shown}" + (f", and {len(ids) - ROLLUP_LIST} more" if len(ids) > ROLLUP_LIST else ""), "",
                  f"**Example** (`{ex.workspace_id}`): {ex.detail}", "", f"**Recommendation:** {ex.recommendation}"]
            if ex.next_step:
                L += ["", "```bash", ex.next_step, "```"]
            if ex.docs:
                L += ["", f"Docs: {ex.docs}"]
            L.append("")
    for f in ([] if rollup else findings):
        L += [f"### [{f.severity.upper()}] {f.id}: {f.title}  ·  workspace `{f.workspace_id}`  ·  {f.layer}", "",
              f.detail, "", f"**Recommendation:** {f.recommendation}"]
        if f.next_step:
            L += ["", "```bash", f.next_step, "```"]
        if f.docs:
            L += ["", f"Docs: {f.docs}"]
        L.append("")
    errs = {k: v["error"] for k, v in (posture.get("sql") or {}).items() if isinstance(v, dict) and "error" in v}
    acct = posture.get("account") or {}
    for k in ("error", "workspaces_error"):
        if acct.get(k):
            errs[f"account API {k.replace('_error', '') if k != 'error' else ''}".strip()] = acct[k]
    for ws in posture.get("workspaces") or []:
        if ws.get("policy_error") and ws["policy_error"] != "account not readable":
            errs[f"policy {ws['workspace_id']}"] = ws["policy_error"]
    if errs or posture.get("collection_notes"):
        L += ["## Collection gaps", ""] + [f"- `{k}`: {v}" for k, v in errs.items()] + \
             [f"- {n}" for n in posture.get("collection_notes", [])] + [""]
    L += ["## Next steps", "",
          f"All remediation runs through **databricks-network-policy-helper** ({HELPER_REPO}). Every command "
          "above is propose-only (writes nothing). Add `--create-policy` (dry-run by default) only after "
          "reviewing the preview, and `--policy-mode enforce` only after dry-run denials are clean.", ""]
    return "\n".join(L)


def finalize_levels(findings: list[Finding], maturity: dict) -> None:
    """Promote L3 → L4 when a workspace has no high/medium findings."""
    for wid, m in maturity.items():
        if m.get("level") == 3 and not any(
            f.workspace_id == wid and f.severity in ("critical", "high", "medium") for f in findings
        ):
            m.update(level=4, label="Hardened")


def _pat_cols(ws: dict, posture: dict) -> list[str]:
    pat = ws.get("pat") or {}
    today = dt.date.fromisoformat(str(posture["generated_at"])[:10])
    ts = summarise_tokens(pat, today, Thresholds()) or {}
    try:
        mtl = str(int(pat["max_token_lifetime_days"])) if pat.get("max_token_lifetime_days") not in (None, "") else "NULL"
    except ValueError:
        mtl = "NULL"
    b = pat.get("all_users_can_use")
    return [str(ts["total"]) if ts else "NULL", str(ts["never_expire"]) if ts else "NULL",
            str(ts["unscoped"]) if ts else "NULL", mtl, "NULL" if b is None else ("true" if b else "false")]


def write_uc(execute, schema: str, run_id: str, posture: dict, findings: list[Finding], maturity: dict, log) -> None:
    """Opt-in: append the snapshot to <schema>.cbi_posture_findings / cbi_posture_workspaces for Genie."""
    def lit(v) -> str:
        if v is None:
            return "NULL"
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return str(v)
        return "'" + str(v).replace("\\", "\\\\").replace("'", "\\'") + "'"

    def ex(stmt: str) -> None:
        execute(stmt, params=False)

    ts = posture["generated_at"]
    ex(f"""CREATE TABLE IF NOT EXISTS {schema}.cbi_posture_findings (
      run_id STRING, run_ts TIMESTAMP, workspace_id STRING, finding_id STRING, severity STRING,
      title STRING, detail STRING, recommendation STRING, next_step STRING, docs STRING, layer STRING)
      COMMENT 'CBI posture diagnostic findings (append-only, one batch per run_id)'""")
    ex(f"""CREATE TABLE IF NOT EXISTS {schema}.cbi_posture_workspaces (
      run_id STRING, run_ts TIMESTAMP, workspace_id STRING, workspace_name STRING, pricing_tier STRING,
      effective_policy_id STRING, policy_mode STRING, public_restriction STRING, public_allow_rules INT,
      public_cidrs INT, private_restriction STRING, has_private_link BOOLEAN, pas_public_access_enabled BOOLEAN,
      ip_acl_enabled BOOLEAN, egress_restricted BOOLEAN, maturity_level INT, maturity_label STRING, maturity_reason STRING,
      pats_total INT, pats_never_expire INT, pats_unscoped INT, max_token_lifetime_days INT, pats_all_users BOOLEAN)
      COMMENT 'CBI posture diagnostic per-workspace snapshot (append-only, one batch per run_id)'""")
    if findings:
        vals = ",\n".join(
            "(" + ", ".join([lit(run_id), f"TIMESTAMP {lit(ts)}", lit(f.workspace_id), lit(f.id), lit(f.severity),
                             lit(f.title), lit(f.detail), lit(f.recommendation), lit(f.next_step), lit(f.docs),
                             lit(f.layer)]) + ")"
            for f in findings)
        ex(f"INSERT INTO {schema}.cbi_posture_findings VALUES {vals}")
    rows = []
    for ws in posture.get("workspaces") or []:
        wid = str(ws["workspace_id"])
        s, m, pas, acl = summarise_policy(ws.get("policy")), maturity.get(wid, {}), ws.get("pas") or {}, ws.get("ip_acl") or {}
        rows.append("(" + ", ".join([
            lit(run_id), f"TIMESTAMP {lit(ts)}", lit(wid), lit(ws.get("workspace_name")), lit(ws.get("pricing_tier")),
            lit(ws.get("effective_policy_id")), lit(s["mode"] or "open"), lit(s["public"]["restriction_mode"]),
            str(s["public"]["allow_rules"]), str(len(s["public"]["cidrs"])), lit(s["private"]["restriction_mode"]),
            "true" if pas.get("private_access_level") else "false",
            "NULL" if "public_access_enabled" not in pas else ("true" if pas["public_access_enabled"] else "false"),
            "NULL" if "enabled" not in acl else ("true" if acl["enabled"] else "false"),
            "true" if s["egress_restrictive"] else "false",
            lit(m.get("level")), lit(m.get("label")), lit(m.get("why")),
            *_pat_cols(ws, posture)]) + ")")
    if rows:
        ex(f"INSERT INTO {schema}.cbi_posture_workspaces VALUES {','.join(rows)}")
    log(f"  wrote snapshot run_id={run_id} to {schema}.cbi_posture_findings / cbi_posture_workspaces")


# ------------------------------------------------------------------------------------------- main
# ------------------------------------------------------------------------------------ SQL cache
# The traffic SQL is the slow part (minutes to an hour on large accounts) and audit history barely moves in
# a day, so a recent result for the SAME scope + lookback + query set is reused. Config (policies, IP ACLs,
# tokens) is always re-read: it's cheap and it's what changes right after someone applies a policy. A wider
# cached run is never reused for a narrower scope, because account-wide LIMITs can crowd workspaces out.
DEFAULT_REUSE_HOURS = 24


def queries_fingerprint() -> str:
    import hashlib
    h = hashlib.sha256()
    for name, (_d, stmt) in cbi_sql.QUERIES.items():
        h.update(name.encode() + b"\0" + stmt.encode() + b"\0")
    return h.hexdigest()[:16]


def _cache_path(out: Path, scope: list[str] | None, lookback_days: int) -> Path:
    import hashlib
    ids = "all" if not scope else "-".join(scope)
    if len(ids) > 80:
        ids = f"{len(scope)}ws-" + hashlib.sha256(ids.encode()).hexdigest()[:12]
    return out / "sql-cache" / f"lb{lookback_days}-{ids}.json"


def load_sql_cache(out: Path, scope, lookback_days: int, max_age_hours: float, now: dt.datetime):
    """(sql, generated_at, age_hours) for a fresh exact match, else None."""
    if max_age_hours <= 0:
        return None
    p = _cache_path(out, scope, lookback_days)
    try:
        c = json.loads(p.read_text())
        ts = dt.datetime.strptime(c["generated_at"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=dt.timezone.utc)
    except Exception:  # noqa: BLE001 - missing / unreadable cache = run the SQL
        return None
    age = (now - ts).total_seconds() / 3600
    same = (c.get("fingerprint") == queries_fingerprint() and c.get("lookback_days") == lookback_days
            and (c.get("scope") or None) == (scope or None))
    if not same or age < 0 or age > max_age_hours or not isinstance(c.get("sql"), dict):
        return None
    if any("error" in v for v in c["sql"].values() if isinstance(v, dict)):
        return None  # don't pin a partial result; retry the queries
    return c["sql"], c["generated_at"], age


def save_sql_cache(out: Path, scope, lookback_days: int, sql: dict, generated_at: str) -> Path:
    p = _cache_path(out, scope, lookback_days)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"generated_at": generated_at, "lookback_days": lookback_days, "scope": scope or None,
                             "fingerprint": queries_fingerprint(), "sql": sql}, default=str))
    return p


def in_databricks() -> bool:
    import os
    return bool(os.environ.get("DATABRICKS_RUNTIME_VERSION"))


def _active_spark():
    try:
        from pyspark.sql import SparkSession
        return SparkSession.getActiveSession()
    except Exception:  # noqa: BLE001
        return None


def read_secret(w, ref: tuple) -> tuple[str | None, str]:
    """Read one secret. ref = ("scope", key) for a workspace secret scope, or ("uc", catalog, schema, name)
    for a Unity Catalog secret. Returns (value, error). The value is never logged."""
    errs = []
    try:
        from databricks.sdk.runtime import dbutils  # notebooks / jobs; redacts in output
        if ref[0] == "uc":
            return dbutils.secrets.get(catalog=ref[1], schema=ref[2], key=ref[3]), ""
        return dbutils.secrets.get(scope=ref[1], key=ref[2]), ""
    except Exception as e:  # noqa: BLE001
        errs.append(f"dbutils: {type(e).__name__}")
    try:
        if ref[0] == "uc":
            full = ".".join(ref[1:])
            r = w.api_client.do("GET", f"/api/2.1/unity-catalog/secrets/{full}", query={"include_value": "true"})
            v = (r or {}).get("effective_value") or (r or {}).get("value")
            if v:
                return str(v), ""
            errs.append("API: no value returned")
        else:
            import base64
            return base64.b64decode(w.secrets.get_secret(scope=ref[1], key=ref[2]).value).decode(), ""
    except Exception as e:  # noqa: BLE001
        errs.append(f"API: {type(e).__name__}: {' '.join(str(e).split())[:120]}")
    return None, "; ".join(errs)


_CRED_ALIASES = {"account_id": ("account_id", "account-id", "accountId"),
                 "client_id": ("client_id", "client-id", "clientId", "application_id"),
                 "client_secret": ("client_secret", "client-secret", "clientSecret", "secret"),
                 "account_host": ("account_host", "account-host", "host")}


def _from_json(v: str) -> dict:
    try:
        d = json.loads(v)
    except ValueError:
        return {}
    if not isinstance(d, dict):
        return {}
    return {k: next((str(d[a]) for a in al if d.get(a)), None) for k, al in _CRED_ALIASES.items()}


def account_creds(w, ref: str, account_id: str | None = None, client_id: str | None = None) -> tuple[dict, str]:
    """Resolve account-admin SP credentials. `ref` is one of:
      * a workspace secret scope name ("cbi-posture"): keys account-id, client-id, client-secret[, account-host]
      * a Unity Catalog schema ("cat.schema"): UC secrets of those names in it
      * a Unity Catalog secret ("cat.schema.name"): JSON {account_id, client_id, client_secret[, account_host]},
        or just the OAuth secret (then pass account_id and client_id)
    account_id / client_id (not secret) fill any gaps. Returns (creds, problem)."""
    parts = [p for p in ref.strip().split(".") if p]
    creds: dict = {"account_id": None, "client_id": None, "client_secret": None, "account_host": None}
    problems: list[str] = []
    if len(parts) == 3:
        v, err = read_secret(w, ("uc", *parts))
        if v is None:
            problems.append(f"UC secret {ref} unreadable ({err}). Needs READ SECRET on it, and serverless "
                            "environment 4+ or DBR 17.3+")
        else:
            j = _from_json(v)
            creds.update({k: x for k, x in j.items() if x}) if j else creds.update(client_secret=v)
    elif len(parts) in (1, 2):
        keys = {"account_id": "account-id", "client_id": "client-id", "client_secret": "client-secret",
                "account_host": "account-host"}
        for k, name in keys.items():
            r = ("uc", parts[0], parts[1], name) if len(parts) == 2 else ("scope", parts[0], name)
            v, err = read_secret(w, r)
            if v:
                creds[k] = v
            elif k != "account_host" and not ({"account_id": account_id, "client_id": client_id}.get(k)):
                problems.append(f"{name} unreadable in {ref} ({err})")
    else:
        problems.append(f"{ref!r} isn't a secret scope, catalog.schema, or catalog.schema.secret")
    creds["account_id"] = creds["account_id"] or account_id
    creds["client_id"] = creds["client_id"] or client_id
    missing = [k for k in ("account_id", "client_id", "client_secret") if not creds[k]]
    if missing and not problems:
        problems.append(f"{ref} gave no {', '.join(missing)}. A UC secret holding only the OAuth secret also needs "
                        "--account-id and --account-client-id (notebook: account_id, account_client_id)")
    return creds, "; ".join(problems)


def accounts_host_for(workspace_host: str) -> tuple[str, bool]:
    """(accounts host, known) for a workspace URL, from the Databricks SDK's own environment table
    (AWS, AWS GovCloud, Azure, Azure Government, Azure China, GCP), plus AWS GovCloud DoD. Unknown domains fall back to AWS
    commercial with known=False, so the caller can tell the user to set --account-host."""
    from urllib.parse import urlparse

    h = urlparse(workspace_host if "//" in (workspace_host or "") else f"https://{workspace_host or ''}").hostname or ""
    if h.endswith(".databricks.mil"):  # AWS GovCloud DoD (not in the SDK's table)
        return "https://accounts-dod.cloud.databricks.mil", True
    try:
        from databricks.sdk.environments import ALL_ENVS

        for env in ALL_ENVS:
            if h.endswith(env.dns_zone):
                return env.deployment_url("accounts"), True
    except Exception:  # noqa: BLE001 - very old SDK: fall back to the public clouds
        for zone in (".cloud.databricks.us", ".azuredatabricks.net", ".databricks.azure.us",
                     ".databricks.azure.cn", ".gcp.databricks.com", ".cloud.databricks.com"):
            if h.endswith(zone):
                return f"https://accounts{zone}", True
    return "https://accounts.cloud.databricks.com", False


def account_client_from_secret(w, ref: str, account_id: str | None = None, client_id: str | None = None,
                                host_override: str | None = None):
    """(AccountClient | None, note) for an account-admin service principal (OAuth M2M)."""
    from databricks.sdk import AccountClient

    creds, problem = account_creds(w, ref, account_id, client_id)
    if problem:
        return None, f"account credentials from {ref}: {problem} (account checks skipped)"
    host, known = host_override or creds["account_host"], True
    if not host:
        host, known = accounts_host_for(w.config.host)
    client = AccountClient(host=host, account_id=creds["account_id"], client_id=creds["client_id"],
                         client_secret=creds["client_secret"])
    note = "" if known else (f"accounts host guessed as {host} (workspace URL {w.config.host} isn't a known "
                             "Databricks cloud domain). If account checks fail, set --account-host (notebook: account_host)")
    return client, note


def main(argv: list[str] | None = None, spark=None) -> int:
    ap = argparse.ArgumentParser(description="Read-only CBI security-posture diagnostic for Databricks.")
    ap.add_argument("--workspace-profile", action="append", default=[],
                    help="~/.databrickscfg workspace profile (repeatable). The first one runs the SQL.")
    ap.add_argument("--account-profile", help="account-admin profile (host = accounts.* console)")
    ap.add_argument("--account-id", help="account id (if not in the account profile)")
    ap.add_argument("--account-host", help="accounts host override (Azure / GCP)")
    ap.add_argument("--account-secret", "--account-secret-scope", dest="account_secret",
                    help="in Databricks: where the account-admin service principal's credentials are. A workspace "
                         "secret scope (keys account-id, client-id, client-secret[, account-host]), a UC schema "
                         "'catalog.schema' with secrets of those names, or one UC secret 'catalog.schema.name' "
                         "holding JSON or just the OAuth secret (then also --account-id / --account-client-id)")
    ap.add_argument("--account-client-id", help="service principal application (client) id, if not in the secret")
    ap.add_argument("--warehouse-id", help="SQL warehouse id for the traffic queries (never auto-created). "
                    "In a notebook, omit it to run the SQL on the notebook's own compute.")
    ap.add_argument("--lookback-days", type=int, default=90,
                    help="audit lookback (default 90, per Databricks guidance for a first CBI draft)")
    ap.add_argument("--workspace-ids",
                    help="comma-separated workspace ids to assess. Also scopes the SQL (plus account-level "
                         "events). Default: the workspaces you have profiles for (in a notebook, this workspace). "
                         "'all' = every workspace, which is slow on large accounts")
    ap.add_argument("--out", type=Path, default=Path("cbi-posture-out"))
    ap.add_argument("--reuse-sql-hours", type=float, default=DEFAULT_REUSE_HOURS,
                    help=f"reuse traffic SQL results from a previous run with the same scope and lookback if "
                         f"younger than this (default {DEFAULT_REUSE_HOURS}; 0 = always re-run). Config is always re-read")
    ap.add_argument("--refresh", action="store_true", help="ignore cached SQL results and re-run the queries")
    ap.add_argument("--uc-schema", help="OPT-IN: catalog.schema to append the snapshot tables for Genie")
    ap.add_argument("--stage-schema", help="OPT-IN, for SQL warehouses: catalog.schema for a temporary table "
                    "holding the audit rollup, so system.access.audit is read once instead of once per query. It "
                    "holds identities and IPs and is dropped at the end of the run. Notebooks don't need it: they "
                    "cache the rollup in the session")
    ap.add_argument("--no-cache", action="store_true",
                    help="in a notebook, don't cache the audit rollup; read system.access.audit in every query")
    ap.add_argument("--parallel", type=int, default=DEFAULT_PARALLEL,
                    help=f"diagnostic queries to run at once (default {DEFAULT_PARALLEL}; 1 = one after another)")
    ap.add_argument("--from-json", type=Path, help="re-evaluate a saved posture.json offline (no API calls)")
    args = ap.parse_args(argv)

    def log(m: str) -> None:
        print(m, file=sys.stderr)

    if args.from_json:
        posture = json.loads(args.from_json.read_text())
    else:
        from databricks.sdk import AccountClient, WorkspaceClient

        all_ws = (args.workspace_ids or "").strip().lower() == "all"
        only = ({s.strip() for s in args.workspace_ids.split(",") if s.strip()}
                if args.workspace_ids and not all_ws else None)
        posture = {"generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                   "lookback_days": args.lookback_days, "tool_version": TOOL_VERSION,
                   "workspace_profile": args.workspace_profile[0] if args.workspace_profile else None,
                   "collection_notes": [], "sql": {}}

        wclients = {}
        for prof in args.workspace_profile:
            try:
                wc = WorkspaceClient(profile=prof)
                wclients[str(wc.get_workspace_id())] = (prof, wc)
            except Exception as e:  # noqa: BLE001
                posture["collection_notes"].append(f"workspace profile {prof}: {_err(e)}")
        if not args.workspace_profile and (in_databricks() or spark is not None):
            try:  # notebook / job: the runtime's own credentials for this workspace
                wc = WorkspaceClient()
                wclients[str(wc.get_workspace_id())] = (None, wc)
                posture["runtime"] = "databricks"
            except Exception as e:  # noqa: BLE001
                posture["collection_notes"].append(f"notebook credentials: {_err(e)}")
        if only is None and not all_ws and posture.get("runtime"):
            only = set(wclients)  # in a notebook, assess this workspace unless told otherwise

        log("Reading account configuration…")
        t_acct = time.time()
        scope_client = None
        if args.account_secret and wclients:
            scope_client, note = account_client_from_secret(next(iter(wclients.values()))[1], args.account_secret,
                                                            args.account_id, args.account_client_id, args.account_host)
            if scope_client is not None:
                posture["account_host"] = scope_client.config.host
            if note:
                posture["collection_notes"].append(note)
                log("  " + note)
        if scope_client is not None or ((args.account_profile or args.account_id) and not args.account_secret):
            try:
                kw = {"profile": args.account_profile} if args.account_profile else {}
                if args.account_id:
                    kw["account_id"] = args.account_id
                if args.account_host:
                    kw["host"] = args.account_host
                a = scope_client or AccountClient(**kw)
                posture["account"], posture["workspaces"] = collect_account(a, only)
                known = {w["workspace_id"] for w in posture["workspaces"]}
                for wid in wclients:  # Azure / filtered: add profile workspaces the list didn't return
                    if wid not in known and (not only or wid in only):
                        rec = {"workspace_id": wid, "pas": None}
                        by_id = {p.get("network_policy_id"): p for p in posture["account"].get("policies", [])}
                        _attach_policy(a, rec, by_id)
                        posture["workspaces"].append(rec)
            except Exception as e:  # noqa: BLE001
                posture["account"] = {"error": _err(e)}
                posture["workspaces"] = [{"workspace_id": wid, "policy_error": "account not readable"} for wid in sorted(set(wclients) | (only or set()))]
        else:
            posture["account"] = {"error": "account credentials unusable (see collection gaps): account checks skipped"
                                  if args.account_secret else
                                  "no account credentials given (--account-profile / --account-id, or "
                                  "--account-secret in Databricks): account checks skipped"}
            posture["workspaces"] = [{"workspace_id": wid, "policy_error": "account not readable"} for wid in sorted(set(wclients) | (only or set()))]

        log(f"  account configuration read for {len(posture['workspaces'])} workspace(s) ({time.time() - t_acct:.0f}s)")
        log("Reading workspace IP access lists…")
        for ws in posture["workspaces"]:
            if ws["workspace_id"] in wclients:
                prof, wc = wclients[ws["workspace_id"]]
                ws["profile"] = prof
                ws["ip_acl"] = collect_workspace(wc)
                ws["pat"] = collect_tokens(wc)
                gaps = [k.replace("_error", "") for k in ws["pat"] if k.endswith("_error")]
                if gaps:
                    posture["collection_notes"].append(
                        f"PAT checks for {ws['workspace_id']} incomplete ({', '.join(gaps)} unreadable; workspace admin needed)")
                if "error" in ws["ip_acl"]:
                    ws["ip_acl"] = None
                    posture["collection_notes"].append(f"IP ACLs for {ws['workspace_id']} unreadable (workspace admin needed)")

        spark = spark or (_active_spark() if in_databricks() else None)
        execute = None
        if args.warehouse_id and wclients:
            execute = warehouse_executor(next(iter(wclients.values()))[1], args.warehouse_id, args.lookback_days)
            posture["sql_engine"] = "warehouse"
        elif spark is not None:
            execute = spark_executor(spark, args.lookback_days)
            posture["sql_engine"] = "notebook compute"
        sql_scope = None if all_ws else sorted(only or set(wclients))
        where = "all workspaces" if not sql_scope else f"workspace(s) {', '.join(sql_scope)} + account level"
        now = dt.datetime.now(dt.timezone.utc)
        cached = None if args.refresh else load_sql_cache(args.out, sql_scope, args.lookback_days,
                                                           args.reuse_sql_hours, now)
        if cached is not None:
            posture["sql"], posture["sql_generated_at"], age = cached
            posture["sql_scope"] = sql_scope or "all workspaces"
            posture["sql_reused"] = True
            msg = (f"Traffic results reused from the run at {posture['sql_generated_at']} UTC ({age:.1f} h ago; same "
                   f"scope and lookback). Configuration was re-read. Re-run the queries with --refresh "
                   f"(notebook: refresh = yes).")
            log(msg)
        elif execute is not None:
            posture["sql_scope"] = sql_scope or "all workspaces"
            log(f"Running {len(cbi_sql.QUERIES)} read-only diagnostic queries (lookback {args.lookback_days}d, {where})…")
            posture["sql"] = run_sql(execute, log, sql_scope, args.stage_schema, args.lookback_days,
                                     spark=spark if posture.get("sql_engine") == "notebook compute" else None,
                                     use_cache=not args.no_cache, parallel=args.parallel)
            log(f"  queries done ({time.time() - now.timestamp():.0f}s)")
            posture["sql_generated_at"] = posture["generated_at"]
            save_sql_cache(args.out, sql_scope, args.lookback_days, posture["sql"], posture["generated_at"])
        else:
            posture["collection_notes"].append(
                "Traffic queries skipped: pass --warehouse-id (or run in a notebook), or run the files in sql/ yourself.")

    findings, maturity = evaluate(posture)
    finalize_levels(findings, maturity)

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "posture.json").write_text(json.dumps(posture, indent=2, default=str))
    (args.out / "report.md").write_text(render_markdown(posture, findings, maturity))
    with (args.out / "findings.csv").open("w", newline="") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(asdict(findings[0]).keys()) if findings else ["id"])
        wr.writeheader()
        for f in findings:
            wr.writerow(asdict(f))
    with (args.out / "maturity.csv").open("w", newline="") as fh:
        wr = csv.writer(fh)
        wr.writerow(["workspace_id", "workspace_name", "policy", "mode", "level", "label", "why", "high", "medium"])
        for ws in posture.get("workspaces") or []:
            wid = str(ws["workspace_id"])
            m = maturity.get(wid, {})
            fl = [f for f in findings if f.workspace_id == wid]
            wr.writerow([wid, ws.get("workspace_name") or "", ws.get("effective_policy_id") or "",
                         summarise_policy(ws.get("policy"))["mode"] or "open", m.get("level"), m.get("label", ""),
                         m.get("why", ""), sum(f.severity == "high" for f in fl), sum(f.severity == "medium" for f in fl)])
    log(f"Wrote {args.out}/report.md, posture.json, findings.csv, maturity.csv ({len(findings)} findings)")

    if args.uc_schema and not args.from_json:
        if execute is None:
            log("--uc-schema needs --warehouse-id (or a notebook); skipped.")
        else:
            write_uc(execute, args.uc_schema, uuid.uuid4().hex[:12], posture, findings, maturity, log)
    for n in posture.get("collection_notes") or []:
        log(f"  gap: {n}")
    acct = posture.get("account") or {}
    for k in ("error", "workspaces_error"):
        if acct.get(k):
            log(f"  gap: account API ({posture.get('account_host') or 'accounts host'}): {acct[k]}")
    for ws in posture.get("workspaces") or []:
        if ws.get("policy_error") and ws["policy_error"] != "account not readable":
            log(f"  gap: policy for {ws['workspace_id']}: {ws['policy_error']}")
    sys.stderr.flush()
    by_level: dict[str, int] = {}
    for m in maturity.values():
        k = ("?" if m.get("level") is None else f"L{m['level']}") + " " + m.get("label", "")
        by_level[k] = by_level.get(k, 0) + 1
    sev: dict[str, int] = {}
    for f in findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
    summary = {"workspaces": len(maturity), "findings": sev, "out": str(args.out)}
    summary["maturity"] = maturity if len(maturity) <= ROLLUP_MIN_WORKSPACES else by_level
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
