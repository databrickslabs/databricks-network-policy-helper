"""Ingress posture: score where each workspace stands on context-based ingress (CBI) before anyone
writes a policy, and hand every fix to `dbx-nwp-helper ingress` as a propose-only command.

Read-only. collect() makes list/get calls and SELECT queries only; evaluate() is a pure function over
the JSON-able snapshot collect() returns (so it's testable offline and re-runnable on a saved
`posture.json`). The policy semantics are this package's own: which ingress block is active and
whether a sub-block restricts anything come from core/acl, and the platform caps from config.

Maturity per workspace:

    L0 Open              no restrictive CBI public block, no enabled ALLOW IP access list
    L1 Legacy perimeter  IP access lists only
    L2 Observing         restrictive public block in ingress_dry_run (log-only)
    L3 Enforced          restrictive public block enforced, or PAS blocks public access
    L4 Hardened          L3 with no high / medium findings

A block that's restrictive on paper but has an allow rule letting any IP call all workspace APIs as
any identity doesn't count as restricting ("open in effect").
"""

from __future__ import annotations

import datetime as dt
import ipaddress
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from typing import Any

from ..config import MAX_CIDRS_PER_POLICY, MAX_INGRESS_RULES_PER_POLICY
from . import acl, tokens

Note = Callable[[str], None]

DOCS = "https://docs.databricks.com/aws/en/security/network/front-end"
HELPER_REPO = "https://github.com/databrickslabs/databricks-network-policy-helper"
MIGRATE_REPO = "https://github.com/databrickslabs/migrate-ip-acls"
NEAR_LIMIT_RATIO = 0.8
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
# Account-API reads run this many at a time (one assignment + policy read per workspace).
API_PARALLEL = 8
_UI_LIKE = {"account_ui", "apps", "lakebase", "ui"}
LEVEL_LABELS = {0: "Open", 1: "Legacy perimeter", 2: "Observing", 3: "Enforced", 4: "Hardened"}


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


@dataclass
class Thresholds:
    b1_max_programmatic_principals: int = 25  # "browser yes, APIs no" is practical below this
    broad_prefix_high: int = 8  # allow CIDR /0../8 → high
    broad_prefix_medium: int = 16  # /9../15 → medium (strictly broader than /16)
    max_enforced_denials_ok: int = 0
    spread_24s: int = 10  # principal seen from >= this many public /24s


# ------------------------------------------------------------------------------- policy summarising
def _val(v: Any) -> str | None:
    if v is None:
        return None
    return str(getattr(v, "value", v))


def _sdk_policy(policy: dict | None):
    """The snapshot's policy dict as an SDK AccountNetworkPolicy, so core/acl's predicates apply."""
    if not policy:
        return None
    from databricks.sdk.service.settings import AccountNetworkPolicy

    return AccountNetworkPolicy.from_dict(policy)


def classify_rule(r: dict) -> dict:
    """What one public ingress allow rule matches: where from (origin), to what (reach / API
    breadth), and for whom.

    origin:   all (every IP) | all_except (every public IP except some) | ranges | unknown (none set:
              e.g. a console-only source such as Partner platforms that the API doesn't describe)
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
        for key, name in (
            ("account_api", "account_api"),
            ("account_databricks_one", "account_databricks_one"),
            ("account_ui", "account_ui"),
            ("apps_runtime", "apps"),
            ("lakebase_runtime", "lakebase"),
            ("workspace_ui", "ui"),
        ):
            if d.get(key) is not None:
                reach.add(name)
        if reach & {"account_api", "account_databricks_one"}:
            api = "all"  # account-level API destinations carry no scopes
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
    it = str((r.get("authentication") or {}).get("identity_type") or "")
    identity = (
        "selected"
        if "SELECTED" in it
        else "service_principals" if "SERVICE_PRINCIPALS" in it else "users" if "USERS" in it else "all"
    )
    return {
        "api": api,
        "cidrs": inc,
        "excluded": exc,
        "identity": identity,
        "label": r.get("label") or "(unlabelled)",
        "origin": origin,
        "reach": sorted(reach),
        "scopes": scopes,
    }


def _block_summary(blk: dict | None, restrictive: bool) -> dict:
    """Summarise one ingress sub-block. `restrictive` comes from core/acl._block_restrictive."""
    allow = (blk or {}).get("allow_rules") or []
    rules = [classify_rule(r) for r in allow]
    for i, r in enumerate(rules, start=1):
        if r["label"] == "(unlabelled)":
            r["label"] = f"allow rule {i} (unlabelled)"
    anywhere = [r for r in rules if r["origin"] in ("all", "all_except")]
    broad_api = ("all", "all_except", "unstated")
    # All users, or all service principals, is still every stolen token of that kind; only selected
    # identities narrow who a rule admits.
    open_api = [r["label"] for r in anywhere if r["api"] in broad_api and r["identity"] != "selected"]
    return {
        "allow_rules": len(allow),
        "cidrs": [c for r in rules for c in r["cidrs"]],
        "deny_rules": len((blk or {}).get("deny_rules") or []),
        # Any IP may call all APIs as any user and/or SP: restricted on paper, open in effect.
        "effectively_open": bool(open_api),
        "open_api_rules": open_api,
        "open_identity_rules": [
            r["label"] for r in anywhere if r["api"] in broad_api and r["identity"] == "selected"
        ],
        "open_scoped_api_rules": [r["label"] for r in anywhere if r["api"] in ("read", "scoped")],
        "open_ui_only_rules": [
            r["label"] for r in anywhere if r["api"] == "none" and set(r["reach"]) <= _UI_LIKE
        ],
        "present": blk is not None,
        "restriction_mode": _val((blk or {}).get("restriction_mode")),
        "restrictive": restrictive,
        "rules": rules,
        "unknown_origin_rules": [r["label"] for r in rules if r["origin"] == "unknown"],
        "unstated_api_rules": [r["label"] for r in rules if r["api"] == "unstated"],
    }


def summarise_policy(policy: dict | None) -> dict:
    """Effective ingress posture of one AccountNetworkPolicy (as_dict()). The active block and its
    mode come from core/acl._active_ingress (the same precedence `ingress` uses when it inherits a
    policy's mode), restrictiveness from core/acl._block_restrictive."""
    pol = _sdk_policy(policy)
    active, mode = acl._active_ingress(pol) if pol is not None else (None, None)
    active_d = active.as_dict() if active is not None else {}
    out = {"mode": mode, "policy_id": (policy or {}).get("network_policy_id")}
    for dim, attr in (
        ("cross_workspace", "cross_workspace_access"),
        ("private", "private_access"),
        ("public", "public_access"),
    ):
        out[dim] = _block_summary(
            active_d.get(attr), acl._block_restrictive(getattr(active, attr, None) if active else None)
        )
    egress = getattr(pol, "egress", None)
    out["egress_restrictive"] = acl.egress_restrictive(egress)
    out["egress_enforced"] = out["egress_restrictive"] and acl.egress_enforced(egress)
    return out


def broad_cidrs(cidrs: list[str], max_prefix: int) -> list[str]:
    """IPv4 CIDRs at least as broad as /`max_prefix`. Invalid entries are skipped."""
    out = []
    for c in cidrs:
        try:
            n = ipaddress.ip_network(str(c).strip(), strict=False)
        except ValueError:
            continue
        if n.version == 4 and n.prefixlen <= max_prefix:
            out.append(str(n))
    return out


def outcome_class(raw: Any) -> str:
    """Normalise a system.access.inbound_network policy_outcome to DENIED / DRY_RUN_DENIAL / <raw>.
    Docs and releases have used DENIED / DENY / DROP and DRY_RUN_DENIAL / DENY_DRY_RUN."""
    v = str(raw or "").upper()
    if "DRY" in v and "RUN" in v:
        return "DRY_RUN_DENIAL"
    if v in ("DENIED", "DENY", "DROP"):
        return "DENIED"
    return v


# ------------------------------------------------------------------------------------- evaluation
def _cmd(profile: str | None, extra: str = "", workspace_id: str | None = None) -> str:
    p = profile or (f"<profile-for-workspace-{workspace_id}>" if workspace_id else "<workspace-profile>")
    return f"dbx-nwp-helper ingress --profile {p} --lookback-days 90{(' ' + extra) if extra else ''}"


def _rows(sql: dict, name: str) -> list[dict]:
    r = sql.get(name)
    return r["rows"] if isinstance(r, dict) and "rows" in r else []


def _for_ws(sql: dict, name: str, wid: str) -> list[dict]:
    return [r for r in _rows(sql, name) if str(r.get("workspace_id")) == wid]


def _maturity(ws: dict, s: dict, pid: str) -> tuple[int | None, str, str]:
    """(level, label, why) before findings are applied (finalize_levels promotes L3 → L4)."""
    pas, ip_acl = ws.get("pas"), ws.get("ip_acl")
    pub = s["public"]
    restricts = pub["restrictive"] and not pub["effectively_open"]
    open_note = (
        f"; rule(s) {pub['open_api_rules']} let any IP call all workspace APIs"
        if pub["restrictive"] and pub["effectively_open"]
        else ""
    )
    allow_lists = [a for a in (ip_acl or []) if a.get("enabled") and a.get("list_type") == "ALLOW"]
    if pas is not None and pas.get("public_access_enabled") is False:
        return 3, "Private-only", "PAS blocks public network access"
    if s["mode"] == "enforce" and restricts:
        return 3, "Enforced", f"`{pid}` enforces a restricted public allow-list"
    if s["mode"] == "dry_run" and restricts:
        return 2, "Observing", f"`{pid}` restricts public access in dry-run only (log-only)"
    if allow_lists:
        return 1, "Legacy perimeter", "IP access lists only; no restrictive CBI public block" + open_note
    if ip_acl is None:
        return (
            None,
            "CBI open, IP ACL unchecked",
            "CBI public access is open (L0 or L1). IP access lists are read per workspace: re-run with "
            "that workspace's --profile to settle the level" + open_note,
        )
    return 0, "Open", "No restrictive CBI public block and no enabled ALLOW IP access list" + open_note


def evaluate(posture: dict, th: Thresholds | None = None) -> tuple[list[Finding], dict[str, dict]]:
    """Pure function: posture snapshot → (findings, maturity per workspace). No I/O."""
    th = th or Thresholds()
    F: list[Finding] = []
    maturity: dict[str, dict] = {}
    sql = posture.get("sql") or {}
    acct = posture.get("account") or {}
    profile = posture.get("workspace_profile")
    cbi_docs = f"{DOCS}/context-based-ingress"
    today = dt.date.fromisoformat(str(posture.get("generated_at") or dt.date.today().isoformat())[:10])

    # ---- account-wide
    if acct.get("error"):
        F.append(
            Finding(
                "CBI-018",
                "medium",
                "Account configuration could not be read",
                f"Account API error: {acct['error']}. Policy, PAS and assignment checks are UNKNOWN.",
                "Re-run with account-admin credentials (--account-id / --account-profile).",
                docs=f"{HELPER_REPO}/blob/main/docs/account-admin-setup.md",
            )
        )
    inbound = sql.get("inbound_policy_outcomes") or {}
    if inbound.get("error"):
        F.append(
            Finding(
                "CBI-011",
                "medium",
                "No CBI denial visibility (system.access.inbound_network unreadable)",
                f"Query failed: {inbound['error'][:240]}",
                "Enable the `access` system schema and grant SELECT on system.access.inbound_network. "
                "Without it a dry-run policy can't be evaluated and enforced breakage is invisible.",
                docs="https://docs.databricks.com/aws/en/admin/system-tables/network",
            )
        )
    acct_policy = acct.get("account_policy")
    acct_rows = _rows(sql, "account_level_public_access")
    if acct.get("policies_read") and acct_policy is not None:
        acct_pub = summarise_policy(acct_policy)["public"]
        if not acct_pub["restrictive"] or acct_pub["effectively_open"]:
            F.append(
                Finding(
                    "CBI-009",
                    "high" if acct_rows else "medium",
                    "Account console / account APIs reachable from any public IP",
                    (
                        f"`account-policy` rule(s) {acct_pub['open_api_rules']} let any IP call the "
                        "account APIs; "
                        if acct_pub["restrictive"]
                        else "`account-policy` public access is "
                        f"{acct_pub['restriction_mode'] or 'unrestricted'}; "
                    )
                    + f"{len(acct_rows)} distinct public IPs reached account-level endpoints in the "
                    "lookback.",
                    "Account-level CBI (Beta) protects the account console, account APIs and account-level "
                    "Genie One. Derive the admin source IPs with `ingress --include-account-level` "
                    "(propose-only; it doesn't write `account-policy`), then set `account-policy` in "
                    "dry-run in the account console.",
                    next_step=_cmd(profile, "--include-account-level --export .")
                    + "   # candidate IPs only; apply to account-policy in the console",
                    docs=f"{DOCS}/manage-ingress-account",
                )
            )
        elif (acct.get("account_ip_acl") or {}).get("enabled"):
            F.append(
                Finding(
                    "CBI-005",
                    "low",
                    "Account IP access lists still enabled alongside account-level CBI",
                    "Account IP access lists and the account-level policy combine with AND; both must allow.",
                    "Once account-level CBI is enforced and validated, retire the account IP access lists "
                    "so CBI is the single policy engine.",
                    docs=cbi_docs,
                )
            )

    saas_seen = sorted(
        {
            r.get("client_family")
            for r in _rows(sql, "client_families_on_public_ips")
            if r.get("client_family") in _saas_families()
        }
    )

    # ---- per workspace
    for ws in posture.get("workspaces") or []:
        wid = str(ws.get("workspace_id"))
        # Only the run's own workspace has a known profile; a command for another workspace must not
        # silently target the run's workspace, so it gets a placeholder (see _cmd).
        prof = ws.get("profile")
        tier = (ws.get("pricing_tier") or "").upper()
        if tier and tier not in ("ENTERPRISE", "UNKNOWN"):
            F.append(
                Finding(
                    "CBI-016",
                    "info",
                    f"Pricing tier {tier}: context-based ingress requires Enterprise",
                    "CBI policies are an Enterprise-tier feature.",
                    "Use IP access lists / PrivateLink for now; plan the tier change before a CBI rollout.",
                    workspace_id=wid,
                    docs="https://databricks.com/product/pricing/platform-addons",
                )
            )
        if ws.get("policy_error"):
            F.append(
                Finding(
                    "CBI-018",
                    "medium",
                    "Assigned network policy could not be read",
                    ws["policy_error"],
                    "Re-run with account-admin credentials.",
                    workspace_id=wid,
                )
            )
            maturity[wid] = {"label": "Unknown", "level": None, "why": "policy unreadable"}
            continue
        F_ws, level, label, why = _evaluate_workspace(ws, sql, prof, th, saas_seen, today)
        F += F_ws
        maturity[wid] = {"label": label, "level": level, "why": why}

    # ---- account-wide traffic signals
    spread = [
        r
        for r in _rows(sql, "principal_network_spread")
        if int(r.get("distinct_public_24s") or 0) >= th.spread_24s
    ]
    if spread:
        sps = [r for r in spread if r.get("principal_type") == "service_principal"]
        F.append(
            Finding(
                "CBI-013",
                "medium",
                "Principals connect from many public networks",
                f"{len(spread)} principals from >= {th.spread_24s} distinct public /24s "
                f"({len(sps)} service principals). Top: "
                + ", ".join(f"{r.get('principal')} ({r['distinct_public_24s']})" for r in spread[:5]),
                "CIDR allow-lists won't hold for these. Use identity-scoped rules (all service principals "
                "/ selected identities), the Partner platforms source, or a VPN/egress gateway for users.",
                next_step=_cmd(profile, "--scoping-mode ip_and_identity"),
                docs=cbi_docs,
            )
        )
    if saas_seen:
        F.append(
            Finding(
                "CBI-014",
                "info",
                "SaaS / BI partner clients seen on public IPs",
                f"Client families: {', '.join(saas_seen)}.",
                "Prefer the managed Partner platforms source (Databricks keeps those IP lists current) over "
                "hand-kept CIDRs; `ingress` labels observed partner ranges too.",
                docs=f"{DOCS}/partner-platforms",
            )
        )
    F.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.id, f.workspace_id))
    return F, maturity


def _saas_families() -> tuple[str, ...]:
    from ..queries import SAAS_CLIENT_FAMILIES

    return SAAS_CLIENT_FAMILIES


def _evaluate_workspace(ws: dict, sql: dict, prof, th: Thresholds, saas_seen: list[str], today: dt.date):
    """Findings + maturity for one workspace whose policy was read."""
    F: list[Finding] = []
    wid = str(ws.get("workspace_id"))
    cbi_docs = f"{DOCS}/context-based-ingress"

    def cmd(extra: str = "") -> str:
        return _cmd(prof, extra, wid)

    s = summarise_policy(ws.get("policy"))
    pub, priv, xws = s["public"], s["private"], s["cross_workspace"]
    pas = ws.get("pas")
    explicit = bool(ws.get("assigned_policy_id"))
    pid = ws.get("assigned_policy_id") or ws.get("effective_policy_id") or "default-policy"
    level, label, why = _maturity(ws, s, pid)
    allow_lists = [a for a in (ws.get("ip_acl") or []) if a.get("enabled") and a.get("list_type") == "ALLOW"]
    acl_cidrs = [ip for a in allow_lists for ip in (a.get("ip_addresses") or [])]
    public_blocked = pas is not None and pas.get("public_access_enabled") is False
    traffic = next(iter(_for_ws(sql, "traffic_by_ip_class", wid)), None)
    tier = (ws.get("pricing_tier") or "").upper()

    def add(fid, sev, title, detail, rec, next_step="", docs=cbi_docs):
        F.append(Finding(fid, sev, title, detail, rec, workspace_id=wid, next_step=next_step, docs=docs))

    # ---- public dimension
    if level == 0:
        add(
            "CBI-001",
            "high",
            "Public ingress is unrestricted",
            f"Governed by `{pid}` with public access {pub['restriction_mode'] or 'FULL_ACCESS'}; no enabled "
            "ALLOW IP access list."
            + (
                f" {traffic.get('distinct_public_ips')} distinct public IPs / "
                f"{traffic.get('public_principals')} principals seen."
                if traffic
                else ""
            ),
            "Build an allow-list from observed traffic, apply it in DRY-RUN, close the dry-run gap, then "
            "enforce.",
            cmd(),
        )
    elif level is None and not public_blocked:
        add(
            "CBI-001",
            "medium",
            "Public ingress open at the CBI layer (IP access list state unknown)",
            (
                f"`{pid}` is RESTRICTED_ACCESS on paper, but rule(s) {pub['open_api_rules']} let any IP "
                "call all workspace APIs (CBI-004)."
                if pub["restrictive"] and pub["effectively_open"]
                else f"`{pid}` public access is {pub['restriction_mode'] or 'FULL_ACCESS'}."
            )
            + " IP access lists weren't read for this workspace.",
            "Re-run with this workspace's --profile to read its IP access lists; then as CBI-001.",
            cmd(),
        )
    if level == 1:
        add(
            "CBI-002",
            "medium",
            "Only legacy IP access lists protect this workspace",
            f"{len(allow_lists)} enabled ALLOW list(s), {len(acl_cidrs)} entries; CBI public access is open.",
            "Migrate to CBI (Databricks recommends CBI as the single policy engine). `ingress` "
            f"auto-detects the IP access lists and folds them in; for a verbatim migration use "
            f"dbx-migrate-ip-acls ({MIGRATE_REPO}).",
            cmd(),
            f"{DOCS}/migrate-to-context-based-ingress",
        )
    if level == 2:
        dry = [
            r
            for r in _for_ws(sql, "inbound_policy_outcomes", wid)
            if outcome_class(r.get("policy_outcome")) == "DRY_RUN_DENIAL"
        ]
        combos = sum(int(r.get("combinations") or 0) for r in dry)
        add(
            "CBI-003",
            "medium",
            "CBI policy is dry-run only (not blocking)",
            f"`{pid}` restricts public access in log-only mode. {combos} source/identity/rule "
            "combinations would be blocked if enforced.",
            "Close the gap: re-run `ingress` (it folds dry-run denials into the candidates by default), "
            "re-apply in dry-run, and enforce once the dry-run denials are clean.",
            cmd(f"--policy-action add_to_existing --existing-policy-id {pid}"),
            f"{DOCS}/manage-ingress-workspace",
        )

    hi = broad_cidrs(pub["cidrs"], th.broad_prefix_high) + broad_cidrs(acl_cidrs, th.broad_prefix_high)
    med = [c for c in broad_cidrs(pub["cidrs"] + acl_cidrs, th.broad_prefix_medium - 1) if c not in hi]
    unstated = (
        f" Rule(s) {pub['unstated_api_rules']} name the workspace API without scopes; that's treated as "
        "all APIs. Confirm in the account console."
        if pub["unstated_api_rules"]
        else ""
    )
    if pub["open_api_rules"]:
        add(
            "CBI-004",
            "high",
            "Allow rule lets any IP call all workspace APIs",
            f"Rule(s) {pub['open_api_rules']} match every source IP (or every public IP except a few) and "
            "reach all workspace APIs for every identity, so a stolen token works from anywhere." + unstated,
            "Narrow the source to owned ranges, or keep 'from anywhere' only for the workspace UI (pattern "
            "B1) and allow just the API families (B2) or named identities (B4) you need.",
            cmd(),
        )
    if pub["open_identity_rules"]:
        add(
            "CBI-004",
            "medium",
            "Named identities can call all APIs from any IP",
            f"Rule(s) {pub['open_identity_rules']} let the selected users / service principals call all "
            "workspace APIs from anywhere." + unstated,
            "Prefer source ranges for automation. For people who roam, time-box the rule (pattern B4).",
        )
    if pub["open_scoped_api_rules"]:
        scopes = sorted(
            {sc for r in pub["rules"] if r["label"] in pub["open_scoped_api_rules"] for sc in r["scopes"]}
        )
        add(
            "CBI-028",
            "low",
            "Some API families are reachable from any IP",
            f"Rule(s) {pub['open_scoped_api_rules']} allow these API scopes from anywhere: "
            f"{', '.join(scopes)}. This is pattern B2.",
            "Fine if intended. Check each scope has an owner and that tokens carrying it are short-lived.",
        )
    if pub["open_ui_only_rules"]:
        add(
            "CBI-029",
            "info",
            "Browser access from anywhere, APIs restricted (pattern B1)",
            f"Rule(s) {pub['open_ui_only_rules']} allow every IP to the workspace UI / Apps / Lakebase only.",
            "A sound no-VPN pattern. Pair it with SSO + MFA.",
        )
    if pub["unknown_origin_rules"]:
        add(
            "CBI-027",
            "info",
            "Rule source not visible through the API",
            f"Rule(s) {pub['unknown_origin_rules']} have no IP source in the API response: probably a "
            "console-only source (e.g. Partner platforms or app integrations), so this report can't judge "
            "who they admit.",
            "Review these rules in the account console (policy → Ingress).",
        )
    if hi or med:
        add(
            "CBI-004",
            "high" if hi else "medium",
            "Overly broad allow CIDRs",
            f"/0–/{th.broad_prefix_high}: {hi[:10]}; "
            f"/{th.broad_prefix_high + 1}–/{th.broad_prefix_medium - 1}: {med[:10]}",
            "Broad ranges often cover a whole cloud provider or ISP. Re-frame from observed traffic and "
            "keep only owned ranges.",
            cmd("--policy-framing optimal --enable-rdap"),
        )
    if allow_lists and s["mode"] == "enforce" and pub["restrictive"]:
        add(
            "CBI-005",
            "low",
            "IP access lists still enabled alongside enforced CBI",
            "Workspace IP access lists and CBI combine with AND, so two lists must be kept in sync.",
            "After validating the enforced policy, disable the IP access lists (preserved, reversible).",
            cmd("--create-policy --auto-assign --policy-mode enforce --disable-existing-ip-acls")
            + "   # only after explicit approval",
        )
    if not explicit and ws.get("assignment_read"):
        add(
            "CBI-006",
            "info",
            "Workspace relies on the account default policy",
            "No explicit network-policy assignment; `default-policy` governs this workspace.",
            "Databricks advises against editing default-policy ingress. Create a named policy and assign it.",
            docs=f"{DOCS}/manage-ingress-workspace",
        )
    n_rules = pub["allow_rules"] + pub["deny_rules"]
    if (
        n_rules >= MAX_INGRESS_RULES_PER_POLICY * NEAR_LIMIT_RATIO
        or len(pub["cidrs"]) >= MAX_CIDRS_PER_POLICY * NEAR_LIMIT_RATIO
    ):
        add(
            "CBI-010",
            "medium",
            "Policy is close to platform limits",
            f"{n_rules}/{MAX_INGRESS_RULES_PER_POLICY} public rules, "
            f"{len(pub['cidrs'])}/{MAX_CIDRS_PER_POLICY} CIDRs.",
            "Consolidate low-traffic owners and move partner SaaS to the managed Partner platforms source.",
            cmd("--consolidate-rules"),
        )

    # ---- private / cross-workspace / egress
    has_private = pas is not None and pas.get("private_access_level") is not None
    if has_private and not priv["restrictive"]:
        add(
            "CBI-007",
            "medium",
            "Front-end private access allows ALL registered endpoints",
            f"PAS `{pas.get('private_access_settings_name') or pas.get('private_access_settings_id')}` "
            f"(level {pas.get('private_access_level')}); CBI private_access is "
            f"{priv['restriction_mode'] or 'ALLOW_ALL_REGISTERED_ENDPOINTS (default)'}.",
            "Restrict private_access to this workspace's own endpoints: `ingress` recreates the PAS "
            "posture in a private_access block on AWS/GCP.",
            cmd(),
            f"{DOCS}/front-end-private-connect#private-access",
        )
    # An unset public_access_enabled means enabled (the same default as acl.pas_public_access_enabled).
    if has_private and pas.get("public_access_enabled") is not False and level is not None and level < 2:
        add(
            "CBI-008",
            "info",
            "PrivateLink workspace still accepts public traffic",
            "PAS public access is enabled, so public ingress is governed only by CBI / IP access lists.",
            "Confirm hybrid access is intended; otherwise restrict public via CBI or block it in the PAS.",
            docs="https://docs.databricks.com/aws/en/security/network/classic/private-access-settings",
        )
    if not xws["restrictive"] and level is not None and level >= 2:
        add(
            "CBI-019",
            "info",
            "Cross-workspace (serverless) ingress not restricted",
            f"cross_workspace_access is {xws['restriction_mode'] or 'unset (compatibility mode)'}.",
            "If other workspaces shouldn't reach this one over serverless, add a cross-workspace "
            "allow-list (Beta).",
            docs=f"{DOCS}/cross-workspace-access",
        )
    if not s["egress_restrictive"]:
        add(
            "CBI-017",
            "low",
            "Serverless egress is unrestricted",
            "Ingress-only posture: serverless workloads can reach any destination.",
            "Pair CBI with serverless egress control.",
            f"dbx-nwp-helper egress --profile {prof or f'<profile-for-workspace-{wid}>'} --lookback-days 90",
            "https://docs.databricks.com/aws/en/security/network/serverless-network-security/network-policies",
        )

    # ---- traffic-derived
    if traffic and int(traffic.get("ipv6_events") or 0) > 0:
        add(
            "CBI-015",
            "info",
            "IPv6 client traffic observed",
            f"{traffic.get('distinct_ipv6_ips')} distinct IPv6 sources. CBI public rules are IPv4-only.",
            "Identify these clients before enforcing (they can't be allow-listed by CIDR).",
        )
    denied = [
        r
        for r in _for_ws(sql, "inbound_policy_outcomes", wid)
        if outcome_class(r.get("policy_outcome")) == "DENIED"
    ]
    n_denied = sum(int(r.get("events") or 0) for r in denied)
    if n_denied > th.max_enforced_denials_ok:
        add(
            "CBI-012",
            "high" if s["mode"] == "enforce" else "medium",
            "Requests are being blocked by an enforced CBI policy",
            f"{n_denied} denied requests from {sum(int(r.get('distinct_source_ips') or 0) for r in denied)} "
            "source IP(s) in the lookback.",
            "Triage: an attack being stopped, or a legitimate client being broken. Legitimate sources go "
            "back into the allow-list; `--deny-denied-ips` turns hostile ones into explicit deny rules.",
            cmd(),
        )
    vis = next(iter(_for_ws(sql, "audit_visibility", wid)), None)
    if vis and int(vis.get("verbose_audit_disabled_events") or 0) > 0:
        add(
            "CBI-025",
            "medium",
            "Verbose audit logging was turned off in the lookback window",
            f"Last disabled at {vis.get('last_verbose_audit_disabled')}. Events after that may be missing, "
            "so traffic-based conclusions have a gap.",
            "Confirm who changed it and why, turn it back on, and treat the gap as unknown, not clean.",
            docs="https://docs.databricks.com/aws/en/admin/account-settings/verbose-logs",
        )

    # ---- which CBI pattern fits, where public access is still open
    if level in (0, 1, None) and not public_blocked:
        bva = next(iter(_for_ws(sql, "public_browser_vs_api", wid)), None)
        pats = _suggest_patterns(pub, bva, tier, saas_seen, th)
        add(
            "CBI-026",
            "info",
            "Suggested CBI rollout pattern",
            pats[0] if pats else "Not enough traffic data to suggest a pattern.",
            " ".join(f"({i + 1}) {p}." for i, p in enumerate(pats[1:])) or "See the ingress-helper skill.",
            cmd(),
            f"{DOCS}/manage-ingress-workspace",
        )
    # ---- credentials: how long a stolen token works, what it can call, who can mint one
    open_public = level in (0, 1, None) and not public_blocked
    F += tokens.evaluate(ws.get("pat"), wid, prof, open_public, today)
    return F, level, label, why


def _suggest_patterns(
    pub: dict, bva: dict | None, tier: str, saas_seen: list[str], th: Thresholds
) -> list[str]:
    if tier and tier not in ("ENTERPRISE", "UNKNOWN"):
        return [
            "CBI isn't available on this tier: prioritise short-lived credentials, least privilege and "
            "detection until the tier changes"
        ]
    pats = []
    in_use = (["B1 (browser from anywhere)"] if pub["open_ui_only_rules"] else []) + (
        ["B2 (API families from anywhere)"] if pub["open_scoped_api_rules"] else []
    )
    if in_use:
        pats.append(
            f"Already uses {' and '.join(in_use)}, but an open rule undoes it: remove or narrow "
            f"{pub['open_api_rules'] or 'the rule that admits all APIs'} first"
        )
    elif pub["open_api_rules"]:
        pats.append(
            f"**First narrow {pub['open_api_rules']}**: it lets any IP call all workspace APIs, so no other "
            "rule in this policy limits a stolen token"
        )
    if bva and not in_use:
        progs = int(bva.get("programmatic_principals") or 0)
        if progs <= th.b1_max_programmatic_principals:
            pats.append(
                f"**Browser yes, remote APIs no**: only {progs} identities use programmatic clients from "
                f"public IPs ({bva.get('browser_pct')}% of public traffic is browser). Allow Workspace UI · "
                "all users · all public IPs, plus API rules for the named identities only"
            )
        else:
            pats.append(
                f"**Allow only the API families you need**: {progs} identities call APIs from public IPs. "
                "Use API allow rules with `IN <scopes>` (e.g. `sql`) rather than a general API rule"
            )
    if saas_seen:
        pats.append(
            "**Narrow partner exceptions**: use the Partner platforms source for the hosted BI tools seen, "
            "instead of opening API access to the internet"
        )
    pats.append(
        "Pilot on one workspace in dry-run over a full business cycle before enforcing; use time-boxed "
        "selected-identity rules for occasional production access"
    )
    return pats


def finalize_levels(findings: list[Finding], maturity: dict) -> None:
    """Promote L3 → L4 Hardened when a workspace has no critical/high/medium findings of its own.
    Account-wide findings (CBI-009 account console, CBI-013 roaming principals) are reported on their
    own and don't hold back a workspace's level."""
    for wid, m in maturity.items():
        if m.get("level") == 3 and not any(
            f.workspace_id == wid and f.severity in ("critical", "high", "medium") for f in findings
        ):
            m.update(label=LEVEL_LABELS[4], level=4)


def findings_as_dicts(findings: list[Finding]) -> list[dict]:
    return [asdict(f) for f in findings]


# ------------------------------------------------------------------------------------- collection
def _err(e: Exception) -> str:
    return f"{type(e).__name__}: {' '.join(str(e).split())[:300]}"


def collect_account(
    account, only_ws: set[str] | None, note: Note = lambda _m: None, fallback_workspace_id=None
) -> tuple[dict, list[dict]]:
    """Account-level config: every network policy, the account policy and IP access lists, and per
    workspace its tier, PAS and effective (assigned or default) policy. Errors are recorded, never
    raised, so a partial read still produces a report that says what's UNKNOWN."""
    acct: dict = {"policies": [], "policies_read": False}
    try:
        acct["policies"] = [p.as_dict() for p in account.network_policies.list_network_policies_rpc()]
        acct["policies_read"] = True
    except Exception as e:  # noqa: BLE001 - reported as CBI-018
        acct["error"] = _err(e)
    by_id = {p.get("network_policy_id"): p for p in acct["policies"]}
    acct["account_policy"] = by_id.get("account-policy")
    try:
        acct["account_ip_acl"] = {
            "enabled": bool(account.settings.enable_ip_access_lists.get().acct_ip_acl_enable.value),
            "lists": [a.as_dict() for a in account.ip_access_lists.list()],
        }
    except Exception as e:  # noqa: BLE001
        acct["account_ip_acl"] = {"error": _err(e)}
    try:
        ws_list = [w for w in account.workspaces.list() if not only_ws or str(w.workspace_id) in only_ws]
    except Exception as e:  # noqa: BLE001 - e.g. Azure: the account workspaces API is unavailable
        acct["workspaces_error"] = _err(e)
        ws_list = [_fallback_workspace(account, fallback_workspace_id)] if fallback_workspace_id else []
    note(f"Reading the network-policy assignment of {len(ws_list)} workspace(s)…")
    with ThreadPoolExecutor(max_workers=API_PARALLEL, thread_name_prefix="posture") as pool:
        workspaces = list(pool.map(lambda w: _collect_one(account, w, by_id), ws_list))
    return acct, workspaces


def _fallback_workspace(account, workspace_id):
    """The run's own workspace when the account can't list workspaces (Azure): get it directly, or
    assess it by id alone (the assignment and policy APIs don't need the workspace object)."""
    try:
        return account.workspaces.get(workspace_id=int(workspace_id))
    except Exception:  # noqa: BLE001
        from types import SimpleNamespace

        return SimpleNamespace(
            workspace_id=int(workspace_id),
            workspace_name=None,
            deployment_name=None,
            pricing_tier=None,
            cloud=None,
            private_access_settings_id=None,
        )


def _collect_one(account, w, by_id: dict) -> dict:
    wid = str(w.workspace_id)
    rec = {
        "cloud": acl.workspace_cloud(account, wid, ws=w),
        "deployment_name": w.deployment_name,
        "pricing_tier": _val(w.pricing_tier),
        "workspace_id": wid,
        "workspace_name": w.workspace_name,
    }
    pas, status = acl.read_workspace_pas(account, wid, ws=w)
    rec["pas"] = pas.as_dict() if status == "ok" else None
    if status == "error":
        rec["pas_error"] = "Private Access Settings unreadable"
    pid, pol, read_error = acl.assigned_policy_state(account, wid)
    if read_error:
        rec["policy_error"] = read_error
        return rec
    rec["assignment_read"] = True
    rec["assigned_policy_id"] = pid if pid and pid != "default-policy" else None
    rec["effective_policy_id"] = pid or "default-policy"
    if pol is not None:
        rec["policy"] = pol.as_dict()
    else:
        rec["policy"] = by_id.get("default-policy")
    return rec


def collect_workspace_ip_acl(workspace_client) -> list[dict] | None:
    """The workspace's IP access lists, or None if they couldn't be read. Enforcement off
    (enableIpAccessLists != true) means no list applies, so every list reads as disabled."""
    try:
        status = workspace_client.workspace_conf.get_status(keys="enableIpAccessLists") or {}
        # Not ingress._read_ip_acls: it returns [] on a read error, which would score a workspace whose
        # lists exist but can't be read as L0 Open instead of "IP ACL unchecked".
        lists = [
            {
                "label": a.label,
                "list_type": a.list_type.value if a.list_type else None,
                "enabled": a.enabled,
                "ip_addresses": list(a.ip_addresses or []),
            }
            for a in workspace_client.ip_access_lists.list()
        ]
    except Exception:  # noqa: BLE001 - unknown, not "none"
        return None
    if str(status.get("enableIpAccessLists", "")).lower() != "true":
        return [{**a, "enabled": False} for a in lists]
    return lists


def posture_queries(
    lookback_days: int, use_inet: bool, workspace_ids, table: str | None = None
) -> dict[str, str]:
    """name → SQL for one posture run: the audit checks over the rollup (inlined, or read from a
    staged / persisted `table`), plus the inbound_network outcomes."""
    from .. import queries as q

    ids = sorted(workspace_ids or [])
    out = q.posture_queries_over_rollup(lookback_days, ids, table, use_inet)
    out["inbound_policy_outcomes"] = q.posture_inbound_outcomes(lookback_days, ids)
    return dict(sorted(out.items()))


SQL_STEPS = tuple(sorted(posture_queries(30, False, None)))
DEFAULT_PARALLEL = 4


def run_sql(
    connect,
    lookback_days: int,
    workspace_ids,
    *,
    uc_schema: str = "",
    stage_schema: str = "",
    refresh: bool = False,
    parallel: int = DEFAULT_PARALLEL,
    note: Note = lambda _m: None,
) -> dict:
    """Run the posture queries; each result is {"rows": [...]} or {"error": "..."} (best-effort: the
    inbound_network table, for one, exists only where network monitoring is on).

    `connect()` returns a context manager yielding a SQL connection; each parallel worker opens its
    own (connections aren't shared across threads). Where the rollup comes from:
      * neither schema: inlined in every check (one audit scan per check);
      * `stage_schema`: built once into a temporary table there, dropped at the end;
      * `uc_schema`: the persisted `dbx_nwp_posture_daily`, synced incrementally first."""
    from .. import queries as q
    from .. import sql
    from . import persist
    from .ingress import _detect_inet

    out: dict = {}
    with connect() as c0:
        use_inet = _detect_inet(c0)
        table, staged = None, None
        if uc_schema:
            table = persist.posture_table(uc_schema)
            sql.execute(c0, q.posture_daily_table_ddl(table))
            persist.sync_daily(
                c0,
                table,
                lookback_days=lookback_days,
                refresh=refresh,
                insert_sql=lambda a, b: q.posture_daily_table_insert(table, a, b, use_inet=use_inet),
                note=note,
                source_label="system.access.audit (posture rollup)",
            )
        elif stage_schema:
            staged = table = persist.posture_stage_table(stage_schema)
            note(f"Building this run's audit rollup once into {staged} (dropped at the end)…")
            sql.execute(c0, q.posture_stage_table(staged, lookback_days, use_inet, workspace_ids))
        try:
            stmts = posture_queries(lookback_days, use_inet, workspace_ids, table)
            if lookback_days < 3:
                stmts.pop("new_source_identity_pairs")
                out["new_source_identity_pairs"] = {"error": "skipped: needs --lookback-days 3 or more"}
            out.update(_run_all(connect, c0, stmts, parallel, note))
        finally:
            if staged:
                try:
                    sql.execute(c0, f"DROP TABLE IF EXISTS {staged}")
                except Exception as e:  # noqa: BLE001 - say so; the table holds identities and IPs
                    note(f"⚠️  Couldn't drop {staged} ({_err(e)}); drop it by hand.")
    return dict(sorted(out.items()))


def _run_all(connect, c0, stmts: dict[str, str], parallel: int, note: Note) -> dict:
    from .. import sql

    def one(name: str, stmt: str, conn) -> tuple[str, dict]:
        try:
            return name, {"rows": _jsonable(sql.query(conn, stmt).to_dict(orient="records"))}
        except Exception as e:  # noqa: BLE001 - recorded, shown under "Collection gaps"
            return name, {"error": _err(e)}

    def worker(item):
        with connect() as c:
            return one(*item, c)

    out: dict = {}
    if parallel <= 1:
        results = (one(n, st, c0) for n, st in stmts.items())
    else:
        pool = ThreadPoolExecutor(max_workers=parallel, thread_name_prefix="posture-sql")
        results = pool.map(worker, stmts.items())
    try:
        for name, res in results:
            out[name] = res
            note(f"{name}: " + (f"{len(res['rows'])} row(s)" if "rows" in res else res["error"]))
    finally:
        if parallel > 1:
            pool.shutdown()
    return out


def _jsonable(v: Any) -> Any:
    """Arrow/pandas values (numpy scalars and arrays, timestamps) as plain JSON types."""
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)) or type(v).__name__ == "ndarray":
        return [_jsonable(x) for x in v]
    if isinstance(v, (dt.date, dt.datetime)) or type(v).__name__ == "Timestamp":
        return v.isoformat()
    if hasattr(v, "item"):
        return v.item()
    if v != v:  # NaN
        return None
    return v
