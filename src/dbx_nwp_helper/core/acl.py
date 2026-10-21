"""Network-policy state queries used by the ingress / egress apply pre-checks.

These helpers inspect the workspace's PrivateLink configuration and the network policy currently
assigned to it — so the `ingress` / `egress` commands can refuse to overwrite an enforced restrictive
policy (or warn about a dry-run one) before they create + assign a new one. Also carries
`disable_ip_access_lists`, which `ingress --disable-existing-ip-acls` uses to turn off the workspace's
old IP access lists once a replacement CBI policy is created and assigned.

The verbatim IP-ACL → CBI *migration* engine now lives in its own tool,
`databricks-migrate-ip-acls` (the `dbx-migrate-ip-acls` command).
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass, field

Note = Callable[[str], None]


@dataclass
class PrivateAccessPlan:
    """A workspace's front-end PrivateLink (its Private Access Settings) mapped to a CBI
    `private_access` block, so AWS/GCP PrivateLink can be recreated when building a CBI policy:
      * private_access_level=ACCOUNT  -> ALLOW_ALL_REGISTERED_ENDPOINTS (any registered endpoint);
      * private_access_level=ENDPOINT -> RESTRICTED_ACCESS listing the PAS's allowed endpoint ids.
    The label is the PAS name verbatim when it has one, else a generic fallback."""

    restriction_mode: str  # "ALLOW_ALL_REGISTERED_ENDPOINTS" | "RESTRICTED_ACCESS"
    endpoint_ids: list[str] = field(default_factory=list)
    label: str = "registered-private-endpoints"
    source_pas_id: str | None = None


def read_workspace_pas(account, workspace_id, ws: object | None = None) -> tuple[object | None, str]:
    """Fetch the workspace's Private Access Settings (PAS) object — the source of truth for AWS/GCP
    front-end PrivateLink. Returns (pas, status) where status is:
      * 'none'  — no PAS attached (no front-end PrivateLink; migrate public only);
      * 'ok'    — PAS read (`pas` is the object to map into a private_access block);
      * 'error' — the account read failed (caller warns; PrivateLink can't be migrated).
    Separating 'none' from 'error' matters: a workspace with genuinely no PrivateLink migrates
    cleanly, while an unreadable account warns rather than silently dropping a private rule. Pass `ws`
    to reuse an already-fetched workspace object. Best-effort."""
    try:
        if ws is None:
            ws = account.workspaces.get(workspace_id=int(workspace_id))
    except Exception:  # noqa: BLE001 - couldn't read the workspace; caller warns
        return None, "error"
    pas_id = getattr(ws, "private_access_settings_id", None)
    if not pas_id:
        return None, "none"
    try:
        return account.private_access.get(private_access_settings_id=pas_id), "ok"
    except Exception:  # noqa: BLE001 - PAS id present but unreadable; caller warns
        return None, "error"


def plan_from_pas(pas) -> PrivateAccessPlan:
    """Map a Private Access Settings object to a PrivateAccessPlan (the CBI private_access block to
    build): ACCOUNT level -> allow-all-registered; ENDPOINT level -> the enumerated allowed endpoint
    ids, with the PAS name kept as the rule label verbatim."""
    level = getattr(pas, "private_access_level", None)
    level_val = str(getattr(level, "value", level) or "").upper()
    pas_id = getattr(pas, "private_access_settings_id", None)
    label = getattr(pas, "private_access_settings_name", None) or "registered-private-endpoints"
    if level_val == "ENDPOINT":
        ids = list(getattr(pas, "allowed_vpc_endpoint_ids", None) or [])
        return PrivateAccessPlan(
            restriction_mode="RESTRICTED_ACCESS", endpoint_ids=ids, label=label, source_pas_id=pas_id
        )
    # ACCOUNT (or an unspecified level) means any endpoint registered in the account is accepted.
    return PrivateAccessPlan(
        restriction_mode="ALLOW_ALL_REGISTERED_ENDPOINTS", label=label, source_pas_id=pas_id
    )


def _block_restrictive(blk) -> bool:
    """True if a single access sub-block restricts traffic — RESTRICTED_ACCESS mode, or any
    allow/deny rules. Permissive defaults (FULL_ACCESS / ALLOW_ALL_REGISTERED_ENDPOINTS / LEGACY_MODE
    with no rules) return False."""
    if blk is None:
        return False
    rm = getattr(blk, "restriction_mode", None)
    if str(getattr(rm, "value", rm) or "") == "RESTRICTED_ACCESS":
        return True
    return bool(getattr(blk, "allow_rules", None) or getattr(blk, "deny_rules", None))


def block_restrictive(block) -> bool:
    """True if a single ingress sub-block (a public_access / private_access / cross_workspace_access
    object) restricts traffic. Used to decide, per dimension, whether an existing CBI block collides
    with what a migration would write (public and private are independent)."""
    return _block_restrictive(block)


def public_restrictive(ingress) -> bool:
    """True if the ingress block's public_access (source-IP) sub-block is restrictive."""
    return ingress is not None and _block_restrictive(getattr(ingress, "public_access", None))


def private_restrictive(ingress) -> bool:
    """True if the ingress block's private_access (front-end PrivateLink) sub-block is restrictive."""
    return ingress is not None and _block_restrictive(getattr(ingress, "private_access", None))


def cross_workspace_restrictive(ingress) -> bool:
    """True if the ingress block's cross_workspace_access sub-block is restrictive. (LEGACY_MODE —
    compatibility — and FULL_ACCESS are not restrictive.)"""
    return ingress is not None and _block_restrictive(getattr(ingress, "cross_workspace_access", None))


def private_or_xws_restrictive(ingress) -> bool:
    """True if the ingress block's private_access (PrivateLink) or cross_workspace_access sub-block
    is restrictive."""
    return private_restrictive(ingress) or cross_workspace_restrictive(ingress)


def _ingress_restrictive(ingress) -> bool:
    """True if an ingress block restricts traffic in any dimension (public / private / cross-ws)."""
    return public_restrictive(ingress) or private_or_xws_restrictive(ingress)


def _active_ingress(pol):
    """The ingress block that carries a policy's rules — prefer a *restrictive* enforced `ingress`,
    then a restrictive `ingress_dry_run` (a policy has one enforcement mode, so its rules live in one
    or the other), else whichever is present. None if neither is."""
    ing = getattr(pol, "ingress", None)
    if ing is not None and _ingress_restrictive(ing):
        return ing
    dry = getattr(pol, "ingress_dry_run", None)
    if dry is not None and _ingress_restrictive(dry):
        return dry
    return ing if ing is not None else dry


def existing_cbi_ingress(
    account, workspace_id
) -> tuple[str | None, object | None, object | None, object | None]:
    """The workspace's currently-assigned CBI policy's ingress sub-blocks, deep-copied so they can be
    carried verbatim into the generated policy for any dimension this run doesn't itself produce.
    Returns (assigned_policy_id, public_access, private_access, cross_workspace_access); (id, None,
    None, None) when nothing is assigned / unreadable. Only *restrictive* sub-blocks are returned —
    a permissive one (FULL_ACCESS / ALLOW_ALL_REGISTERED_ENDPOINTS, e.g. the baseline default-policy)
    is equivalent to omitting it, so dropping it keeps the generated policy clean and never silently
    re-adds an allow-all block. Best-effort."""
    policy_id, pol = assigned_policy(account, workspace_id)
    if pol is None:
        return policy_id, None, None, None
    ing = _active_ingress(pol)
    if ing is None:
        return policy_id, None, None, None
    pub = getattr(ing, "public_access", None)
    priv = getattr(ing, "private_access", None)
    xws = getattr(ing, "cross_workspace_access", None)
    return (
        policy_id,
        copy.deepcopy(pub) if _block_restrictive(pub) else None,
        copy.deepcopy(priv) if _block_restrictive(priv) else None,
        copy.deepcopy(xws) if _block_restrictive(xws) else None,
    )


def egress_restrictive(egress) -> bool:
    """True if a policy's egress block restricts outbound traffic — RESTRICTED_ACCESS mode, or any
    allow/block destination lists. A FULL_ACCESS egress (the permissive default an ingress-only
    policy carries) — or None — returns False."""
    if egress is None:
        return False
    na = getattr(egress, "network_access", None)
    if na is None:
        return False
    rm = getattr(na, "restriction_mode", None)
    if str(getattr(rm, "value", rm) or "") == "RESTRICTED_ACCESS":
        return True
    return bool(
        getattr(na, "allowed_internet_destinations", None)
        or getattr(na, "allowed_storage_destinations", None)
        or getattr(na, "blocked_internet_destinations", None)
    )


def egress_enforced(egress) -> bool:
    """True if a restrictive egress block is ENFORCED (blocking). A DRY_RUN (or unset) enforcement
    mode is log-only. Only meaningful alongside egress_restrictive()."""
    na = getattr(egress, "network_access", None)
    pe = getattr(na, "policy_enforcement", None) if na is not None else None
    mode = getattr(pe, "enforcement_mode", None)
    return str(getattr(mode, "value", mode) or "") == "ENFORCED"


def _ingress_rule_summary(ingress) -> str:
    """'<n> allow / <m> deny rule(s)' for an ingress block's public_access sub-block."""
    pa = getattr(ingress, "public_access", None)
    n_allow = len(getattr(pa, "allow_rules", None) or [])
    n_deny = len(getattr(pa, "deny_rules", None) or [])
    return f"{n_allow} allow / {n_deny} deny rule(s)"


def ingress_content(policy) -> list[str]:
    """Human-readable descriptions of the non-empty ingress blocks on a fetched policy — the enforced
    `ingress` and/or log-only `ingress_dry_run` — i.e. what the `ingress` command would REPLACE.
    Empty list for a policy with no restrictive ingress (a permissive / default policy)."""
    lines = []
    for attr, label in (("ingress", "enforced ingress"), ("ingress_dry_run", "dry-run ingress")):
        blk = getattr(policy, attr, None)
        if public_restrictive(blk):
            lines.append(f"{label}: public — {_ingress_rule_summary(blk)}")
        elif private_or_xws_restrictive(blk):
            lines.append(f"{label}: private-access / cross-workspace rules")
    return lines


def egress_content(policy) -> list[str]:
    """Human-readable description of the non-empty egress block on a fetched policy — what the
    `egress` command would REPLACE. Empty list for a permissive (FULL_ACCESS) / absent egress."""
    egr = getattr(policy, "egress", None)
    if not egress_restrictive(egr):
        return []
    return [f"{'enforced' if egress_enforced(egr) else 'dry-run'} egress: restricted destinations"]


def assigned_policy(account, workspace_id) -> tuple[str | None, object | None]:
    """(assigned_policy_id, full policy object) for the workspace — (id, None) if the policy read
    failed, (None, None) if nothing is assigned. Best-effort."""
    try:
        opt = account.workspace_network_configuration.get_workspace_network_option_rpc(
            workspace_id=int(workspace_id)
        )
        policy_id = getattr(opt, "network_policy_id", None)
    except Exception:  # noqa: BLE001
        return None, None
    if not policy_id:
        return None, None
    try:
        return policy_id, account.network_policies.get_network_policy_rpc(network_policy_id=policy_id)
    except Exception:  # noqa: BLE001
        return policy_id, None


def disable_ip_access_lists(workspace_client, note: Note = lambda _m: None) -> bool:
    """Turn OFF workspace-wide IP access list enforcement via `enableIpAccessLists=false`.

    Disables enforcement of *all* the workspace's IP access lists at once; the lists themselves are
    preserved, so it's reversible by setting the flag back to true. Returns True if it changed state,
    False if enforcement was already off. The caller must ensure a replacement CBI policy has been
    created and assigned first (validate_disable_ip_acls enforces that invariant)."""
    status = workspace_client.workspace_conf.get_status(keys="enableIpAccessLists") or {}
    # Enforcement is only ON when the flag is explicitly "true"; anything else (missing key = never
    # configured, empty, or "false") means there's nothing to disable, so skip the write.
    if str(status.get("enableIpAccessLists", "")).lower() != "true":
        note(
            "Workspace IP access list enforcement is already off (never configured or already "
            "disabled) — no change needed."
        )
        return False
    workspace_client.workspace_conf.set_status({"enableIpAccessLists": "false"})
    note(
        "Disabled workspace IP access list enforcement (enableIpAccessLists=false). The lists "
        "themselves are preserved — set it back to true to re-enable."
    )
    return True
