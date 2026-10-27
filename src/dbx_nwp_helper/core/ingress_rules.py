"""Ingress rule assembly + apply — the second half of the ingress engine.

Takes an IngressAnalysis and turns it into per-target allow/deny rule specs (with identity scoping,
ACL migration, denied-IP deny rules, and threat-intel deny rules), enforces the policy limits, then
builds/previews/applies the SDK blocks. Ported from the ingress notebook's build + apply cells.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Callable

from ..config import DEFAULT_NAME_PREFIX, MAX_DENY_CIDRS, MAX_POLICIES_PER_ACCOUNT, IngressConfig
from . import limits, policy
from .ingress import ALL_WORKSPACES, IngressAnalysis

Note = Callable[[str], None]

_FRAMING_COL = {"minimal": "minimal_cidrs", "optimal": "optimal_cidrs", "maximum": "maximum_cidrs"}


def _slug(text) -> str:
    """Normalise an owner/provider name into a readable, label-safe slug."""
    import re

    return re.sub(r"[^A-Za-z0-9]+", "-", str(text or "")).strip("-")


def _group_label(row) -> str:
    """Owner-grouped allow-rule label (the policy name already identifies the policy, so rule
    labels don't repeat it):
      (a) databricks-<cloud>     when the group is Databricks-owned
      (b) <cloud>-<rdap_owner>   when it's in a cloud-provider range and the owner doesn't already
                                 name the cloud; otherwise just <rdap_owner>
      (c) <rdap_owner>           otherwise (non-cloud candidate)
    `rdap_owner` may be a bare CIDR when RDAP didn't resolve — still a valid, readable label."""
    owner = _slug(row["rdap_owner"])
    if row["databricks_owned"]:
        cloud = _slug((row["databricks_owned"] or ["databricks"])[0])
        base = f"databricks-{cloud}"
    elif row.get("partners"):
        # A partner-platform group (Power BI / dbt / Tableau) — label it by the partner, not the
        # cloud whose range it also sits in (the owner is already the partner name).
        base = _slug((row["partners"] or ["partner"])[0])
    elif row["cloud_provider"]:
        # For cloud-owned IPs the owner is already the friendly cloud label (see
        # ingress._known_owner), so prefixing the cloud token would double it up
        # ("aws-Amazon-Web-Services-AWS"). Only add the prefix when the owner doesn't already
        # name the cloud.
        cloud = _slug((row["cloud_provider"] or [""])[0])
        base = owner if cloud.lower() in owner.lower() else f"{cloud}-{owner}"
    else:
        base = owner
    return base[:250]


def resolve_identities(analysis: IngressAnalysis, account, note: Note = lambda _m: None) -> dict:
    """Resolve principals to numeric account ids via SCIM (account admin required). Returns
    {principal string -> {principal_id, principal_type}}. Unresolved principals are dropped."""
    identity_resolution, unresolved = {}, set()

    def _resolve_user(email):
        if not email:
            return None
        try:
            for u in account.users.list(filter=f'userName eq "{email}"', count=1):
                if u.id:
                    return int(u.id)
        except Exception as e:  # noqa: BLE001
            note(f"user lookup failed for {email}: {e}")
        return None

    def _resolve_sp(app_or_name):
        if not app_or_name:
            return None
        try:
            for sp in account.service_principals.list(filter=f'applicationId eq "{app_or_name}"', count=1):
                if sp.id:
                    return int(sp.id)
        except Exception as e:  # noqa: BLE001
            note(f"SP lookup failed for {app_or_name}: {e}")
        return None

    all_emails = {e for row in analysis.suggestion_rows for e in row["principal_emails"]}
    all_subjects = {s for row in analysis.suggestion_rows for s in row["subject_names"]}
    for email in all_emails:
        pid = _resolve_user(email)
        if pid is not None:
            identity_resolution[email] = {"principal_id": pid, "principal_type": "USER"}
        else:
            unresolved.add(email)
    for subj in all_subjects:
        pid = _resolve_sp(subj)
        if pid is not None:
            identity_resolution[subj] = {"principal_id": pid, "principal_type": "SERVICE_PRINCIPAL"}
        else:
            unresolved.add(subj)
    note(f"Resolved {len(identity_resolution)} principal(s); {len(unresolved)} unresolved.")
    return identity_resolution


def build_rules(
    analysis: IngressAnalysis,
    cfg: IngressConfig,
    identity_resolution: dict | None = None,
    note: Note = lambda _m: None,
) -> dict:
    """Turn the analysis into `policies`: {policy_target -> {"allow": [...], "deny": [...]}} with
    limits enforced. identity_resolution is required only when scoping_mode includes identity."""
    identity_resolution = identity_resolution or {}
    framing_col = _FRAMING_COL[cfg.policy_framing]
    suggestions = analysis.suggestions

    target_specs = defaultdict(list)
    skipped_ipv6 = 0
    excluded_flagged = 0
    excluded_unresolved = 0
    identity_scoped_rules = 0

    if not suggestions.empty:
        for _, row in suggestions.iterrows():
            # Threat-intel-matched groups are never allow-listed (they only appear in the threat
            # table for investigation). Cloud-provider-owned groups ARE included, as labeled rules
            # (b), so they're reviewable rather than silently dropped. Databricks-owned always wins.
            if not row["databricks_owned"] and row["threat_feeds"]:
                excluded_flagged += 1
                continue
            ipv4_cidrs = []
            for cidr in row[framing_col] or []:
                try:
                    if ipaddress.ip_network(cidr, strict=False).version != 4:
                        skipped_ipv6 += 1
                        continue
                except ValueError:
                    continue
                ipv4_cidrs.append(cidr)
            if not ipv4_cidrs:
                continue

            spec = {
                "label": _group_label(row),
                "cidrs": ipv4_cidrs,
                "destination": (
                    row["scoped_destination"]
                    if (cfg.scope_destination and not row["databricks_owned"])
                    else "all_destinations"
                ),
                "identity_type": "ALL_USERS",
                "identities": [],
            }
            if cfg.scope_identity and not row["databricks_owned"]:
                resolved = []
                for p in row["principal_emails"] + row["subject_names"]:
                    if p in identity_resolution:
                        resolved.append(identity_resolution[p])
                seen, deduped = set(), []
                for r in resolved:
                    key = (r["principal_id"], r["principal_type"])
                    if key not in seen:
                        seen.add(key)
                        deduped.append(r)
                if deduped:
                    spec["identity_type"] = "SELECTED_IDENTITIES"
                    spec["identities"] = deduped
                    identity_scoped_rules += 1
                else:
                    # Identity scoping was requested but none of this group's principals resolved
                    # (they've likely left the workspace/org). Falling back to ALL_USERS would open
                    # the CIDR to everyone — the opposite of scoping by identity — so exclude the
                    # group from the allow-list entirely and flag it for the operator.
                    excluded_unresolved += 1
                    continue
            target_specs[row["policy_target"]].append(spec)

    # (Previously ip_only collapsed all groups into one blanket rule; now every owner group becomes
    # its own labeled allow rule in all scoping modes — see _group_label.)

    acl_allow_specs, acl_deny_specs = _acl_specs(analysis, cfg)
    denied_deny_specs = _denied_specs(analysis, cfg)

    if acl_allow_specs:
        if not target_specs:
            target_specs[ALL_WORKSPACES] = []
        for tgt in target_specs:
            target_specs[tgt].extend(acl_allow_specs)

    # Capture limit/cap warnings so the CLI can surface a truncation decision-point gate, while still
    # emitting them inline via `note` exactly as before. Defined before the deny-spec build so the
    # threat-deny CIDR-cap prioritisation (which also drops rules) is gated like the per-policy caps.
    truncations: list[str] = []

    def _limit_warn(m):
        truncations.append(m)
        note(m)

    deny_specs = _threat_deny_specs(analysis, cfg, _limit_warn)
    for spec in acl_deny_specs + denied_deny_specs:
        deny_specs.append(spec)

    # Deny rules apply to every target, but if the run produced no allow-derived targets (e.g.
    # threat_deny_rules=all, or an ACL with only BLOCK lists and no observed traffic), seed a single
    # account-wide target so the deny rules aren't silently dropped. build_ingress_block then adds a
    # catch-all allow so the policy means "block these, allow the rest".
    if deny_specs and not target_specs:
        target_specs[ALL_WORKSPACES] = []

    policies = {}
    for tgt in sorted(target_specs, key=str):
        label = "single policy" if tgt == ALL_WORKSPACES else f"workspace {tgt}"
        allow, deny = limits.enforce_limits(list(target_specs[tgt]), list(deny_specs), label, _limit_warn)
        policies[tgt] = {"allow": allow, "deny": deny}

    # When the public analysis produced no targets (no observed traffic, no IP ACLs) but we still
    # have a block to carry/migrate into some dimension (private_access, an existing public to
    # preserve, or cross-workspace), seed a single target so those blocks are still built, previewed,
    # and applied.
    if not policies and (cfg.private_access or cfg.existing_public or cfg.existing_xws):
        policies[ALL_WORKSPACES] = {"allow": [], "deny": []}

    if cfg.policy_scope == "per_workspace" and len(policies) > MAX_POLICIES_PER_ACCOUNT:
        note(
            f"{len(policies)} per-workspace policies > {MAX_POLICIES_PER_ACCOUNT} account limit — "
            "consider all_workspaces or consolidating workspaces."
        )

    if identity_scoped_rules:
        note(
            f"Identity scoping matched specific principals for {identity_scoped_rules} rule(s), but "
            "the CBI API can't attach per-identity authentication to Apps / Lakebase / "
            "all-destinations rules — those rules will allow all users & service principals from "
            "the listed IPs. The IP allow-list still applies, and groups whose principals couldn't "
            "be resolved were still excluded."
        )

    analysis.excluded_flagged = excluded_flagged
    analysis.excluded_unresolved = excluded_unresolved
    analysis.skipped_ipv6 = skipped_ipv6
    analysis.truncations = truncations
    return policies


def _acl_ipv4(cidrs):
    out = []
    for c in cidrs:
        v = c if "/" in c else f"{c}/32"
        try:
            if ipaddress.ip_network(v, strict=False).version == 4 and v not in out:
                out.append(v)
        except ValueError:
            pass
    return out


def _acl_specs(analysis: IngressAnalysis, cfg: IngressConfig):
    allow_specs, deny_specs = [], []
    if not cfg.migrate_ip_acls or not analysis.ip_acls:
        return allow_specs, deny_specs
    for a in analysis.ip_acls:
        if not a["enabled"]:
            continue
        cidrs = _acl_ipv4(a["ip_addresses"])
        if not cidrs:
            continue
        label = (a["label"] or "acl")[:250]
        if a["list_type"] == "ALLOW":
            allow_specs.append(
                {
                    "label": label,
                    "cidrs": cidrs,
                    "destination": "all_destinations",
                    "identity_type": "ALL_USERS",
                    "identities": [],
                }
            )
        elif a["list_type"] == "BLOCK":
            deny_specs.append({"label": label, "cidrs": cidrs})
    return allow_specs, deny_specs


def _denied_specs(analysis: IngressAnalysis, cfg: IngressConfig):
    if not cfg.deny_denied_ips:
        return []
    denied_cidrs = []
    for r in analysis.denied_requests.to_dict(orient="records"):
        ip = r["source_ip"]
        try:
            if ipaddress.ip_address(ip).version == 4:
                c = f"{ip}/32"
                if c not in denied_cidrs:
                    denied_cidrs.append(c)
        except ValueError:
            pass
    if denied_cidrs:
        return [{"label": "deny-recently-denied", "cidrs": denied_cidrs}]
    return []


_DENY_TYPE_PRIORITY = {"attacker_subnet": 0}


def _deny_sort_key(rec):
    return (
        _DENY_TYPE_PRIORITY.get(rec["threat_type"], 1),
        rec["confidence"],
        rec["source_feed"],
        rec["cidr"],
    )


def _threat_deny_specs(analysis: IngressAnalysis, cfg: IngressConfig, note: Note):
    if cfg.threat_deny_rules == "off":
        return []
    by_cidr = {}
    if cfg.threat_deny_rules == "matched_only":
        src = [
            {
                "cidr": m["matched_cidr"],
                "source_feed": m["source_feed"],
                "threat_type": m["threat_type"],
                "confidence": m["confidence"],
            }
            for m in analysis.threat_match_rows
        ]
    else:  # all
        src = [
            {
                "cidr": str(net),
                "source_feed": meta["source_feed"],
                "threat_type": meta["threat_type"],
                "confidence": meta["confidence"],
            }
            for net, meta in analysis.threat_ranges
            if net.version == 4
        ]
    for rec in src:
        try:
            if ipaddress.ip_network(rec["cidr"], strict=False).version != 4:
                continue
        except ValueError:
            continue
        cur = by_cidr.get(rec["cidr"])
        if cur is None or _deny_sort_key(rec) < _deny_sort_key(cur):
            by_cidr[rec["cidr"]] = rec

    all_records = list(by_cidr.values())
    total = len(all_records)
    if total > MAX_DENY_CIDRS:
        conf1 = [r for r in all_records if r["confidence"] == 1]
        pool = conf1 if conf1 else all_records
        pool.sort(key=_deny_sort_key)
        selected = pool[:MAX_DENY_CIDRS]
        note(
            f"Threat-intel deny list has {total:,} CIDRs (> cap {MAX_DENY_CIDRS:,}) — prioritising: "
            f"kept confidence-1, attacker_subnet first, top {MAX_DENY_CIDRS:,}. "
            f"Including {len(selected):,} of {total:,}. To curate rather than truncate, use "
            f"--block-threat-ips matched_only (deny only CIDRs seen in your traffic) or select fewer "
            f"feeds when prompted."
        )
    else:
        selected = sorted(all_records, key=_deny_sort_key)

    by_feed = defaultdict(list)
    for rec in selected:
        if rec["cidr"] not in by_feed[rec["source_feed"]]:
            by_feed[rec["source_feed"]].append(rec["cidr"])
    return [{"label": f"deny-{feed}"[:250], "cidrs": by_feed[feed]} for feed in sorted(by_feed)]


# ------------------------------------------------------------------------------- preview + apply
def _ingress_block(allow, deny, cfg: IngressConfig, note: Note = lambda _m: None):
    """Compose the generated policy's ingress from independent dimensions, so preview / export / apply
    all emit the same shape:
      * public — built net-new from this target's observed-traffic + IP-ACL specs; when there are
        none, an existing restrictive CBI public_access is carried forward (cfg.existing_public);
      * private — a migrated non-allow-all PAS or an existing private_access carried forward
        (cfg.private_access);
      * cross-workspace — never built, always carried forward verbatim (cfg.existing_xws)."""
    if allow or deny:
        public = policy.build_public_access_block(allow, deny, note)
    else:
        public = cfg.existing_public  # nothing to build → preserve any existing restrictive public
    return policy.assemble_ingress(public, cfg.private_access, cfg.existing_xws)


def _single_policy_id(cfg: IngressConfig, profile: str | None, this_workspace_id) -> str:
    """The policy id for a single-policy scope (current_workspace / all_workspaces): the
    add_to_existing target, else the resolved policy name (profile/workspace-id default)."""
    if cfg.apply.policy_action == "add_to_existing":
        return cfg.apply.existing_policy_id
    name = cfg.policy_name or profile or str(this_workspace_id)
    return policy.policy_name("", explicit=name)


def _ws_policy_id(cfg: IngressConfig, profile: str | None, workspace_id) -> str:
    """The per-workspace policy id ('<prefix>-ws-<id>') apply() writes under per_workspace scope."""
    prefix = cfg.policy_name or profile or DEFAULT_NAME_PREFIX
    return policy.policy_name(prefix, workspace_id=workspace_id)


def planned_policy_ids(
    policies: dict, cfg: IngressConfig, profile: str | None, this_workspace_id
) -> list[str]:
    """The policy id(s) apply() will create/update — one for single-policy scopes, one per workspace
    target for per_workspace. The CLI overwrite pre-check inspects exactly these ids."""
    if cfg.policy_scope != "per_workspace":
        return [_single_policy_id(cfg, profile, this_workspace_id)]
    ws_targets = sorted(t for t in policies if t != ALL_WORKSPACES and int(t) != 0)
    return [_ws_policy_id(cfg, profile, tgt) for tgt in ws_targets]


def export_payload(
    policies: dict,
    cfg: IngressConfig,
    account_id: str,
    this_workspace_id,
    profile: str | None = None,
    note: Note = lambda _m: None,
) -> dict:
    """The proposed network policy as a plain dict (for --export / a curl body): the single-policy
    ingress block + a permissive FULL_ACCESS egress default. Single-policy scopes only."""
    from databricks.sdk.service.settings import AccountNetworkPolicy

    p = policies.get(ALL_WORKSPACES) or next(iter(policies.values()))
    block = _ingress_block(p["allow"], p["deny"], cfg, note)
    pid = _single_policy_id(cfg, profile, this_workspace_id)
    np = AccountNetworkPolicy(
        account_id=account_id, network_policy_id=pid, egress=policy.build_full_access_egress()
    )
    setattr(np, cfg.policy_mode_target, block)
    return np.as_dict()


def preview_blocks(policies: dict, cfg: IngressConfig, note: Note = lambda _m: None) -> dict:
    """Build the SDK ingress block per target and return {target -> block_dict} for display."""
    out = {}
    for tgt in sorted(policies, key=str):
        allow, deny = policies[tgt]["allow"], policies[tgt]["deny"]
        if not (allow or deny or cfg.private_access or cfg.existing_public or cfg.existing_xws):
            continue
        block = _ingress_block(allow, deny, cfg, note)
        out[tgt] = {cfg.policy_mode_target: block.as_dict()}
    return out


def apply(
    policies: dict,
    cfg: IngressConfig,
    account,
    account_id: str,
    this_workspace_id,
    profile: str | None = None,
    note: Note = lambda _m: None,
) -> list[dict]:
    """Create/update policy(ies) and optionally assign. Returns a list of result dicts for display."""
    target_attr = cfg.policy_mode_target
    results = []

    if cfg.policy_scope != "per_workspace":
        # A single policy named from the resolved policy name (current_workspace / all_workspaces).
        p = policies.get(ALL_WORKSPACES) or next(iter(policies.values()))
        add_to_existing = cfg.apply.policy_action == "add_to_existing"
        single_id = _single_policy_id(cfg, profile, this_workspace_id)
        block = _ingress_block(p["allow"], p["deny"], cfg, note)
        action, effective_id, sent = policy.apply_ingress(
            account, account_id, single_id, block, target_attr, must_exist=add_to_existing
        )
        result = {"target": cfg.policy_scope, "action": action, "policy_id": effective_id, "sent": sent}
        if cfg.apply.auto_assign:
            policy.assign(account, this_workspace_id, effective_id)
            result["assigned"] = this_workspace_id
        results.append(result)
    else:
        ws_targets = sorted(t for t in policies if t != ALL_WORKSPACES and int(t) != 0)
        for tgt in ws_targets:
            pid = _ws_policy_id(cfg, profile, tgt)
            p = policies[tgt]
            block = _ingress_block(p["allow"], p["deny"], cfg, note)
            try:
                action, effective_id, _ = policy.apply_ingress(account, account_id, pid, block, target_attr)
                result = {"target": tgt, "action": action, "policy_id": effective_id}
                if cfg.apply.auto_assign:
                    policy.assign(account, tgt, effective_id)
                    result["assigned"] = tgt
                results.append(result)
            except Exception as e:  # noqa: BLE001
                results.append({"target": tgt, "error": str(e)})
    return results
