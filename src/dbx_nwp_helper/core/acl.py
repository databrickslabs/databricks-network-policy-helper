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

from collections.abc import Callable

Note = Callable[[str], None]


def workspace_pas_attached(account, workspace_id) -> bool | None:
    """True if the workspace has a Private Access Settings (PAS) object attached — i.e. it uses
    (AWS/GCP) PrivateLink. None if it couldn't be determined (Azure workspaces have no PAS, so this
    returns False there). Best-effort so a read failure degrades to a warning rather than a crash."""
    try:
        ws = account.workspaces.get(workspace_id=int(workspace_id))
        return bool(getattr(ws, "private_access_settings_id", None))
    except Exception:  # noqa: BLE001 - couldn't determine; caller warns
        return None


def read_private_access_settings(account, workspace_id) -> dict | None:
    """Read the workspace's Private Access Settings (front-end PrivateLink config) so the CLI can
    mirror it into a CBI private_access block. Returns a plain dict, or None if the workspace has no
    PAS (not a PrivateLink workspace) or it couldn't be read (best-effort):

        {"pas_id": str,
         "level": "ACCOUNT" | "ENDPOINT",     # ACCOUNT = any registered endpoint; ENDPOINT = specific
         "endpoint_ids": [str, ...],           # the allowed registered-endpoint ids (ENDPOINT level)
         "public_access_enabled": bool}        # False => private-only workspace (public disabled)

    AWS/GCP only — Azure workspaces have no PAS object (the CLI flags those separately)."""
    try:
        ws = account.workspaces.get(workspace_id=int(workspace_id))
        pas_id = getattr(ws, "private_access_settings_id", None)
        if not pas_id:
            return None
        pas = account.private_access.get(private_access_settings_id=pas_id)
    except Exception:  # noqa: BLE001 - no PAS / no access / API unavailable → best-effort None
        return None
    level = getattr(pas, "private_access_level", None)
    return {
        "pas_id": pas_id,
        "level": str(getattr(level, "value", level) or "ACCOUNT"),
        "endpoint_ids": list(getattr(pas, "allowed_vpc_endpoint_ids", None) or []),
        "public_access_enabled": bool(getattr(pas, "public_access_enabled", True)),
    }


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


def public_restrictive(ingress) -> bool:
    """True if the ingress block's public_access (source-IP) sub-block is restrictive."""
    return ingress is not None and _block_restrictive(getattr(ingress, "public_access", None))


def private_or_xws_restrictive(ingress) -> bool:
    """True if the ingress block's private_access (PrivateLink) or cross_workspace_access sub-block
    is restrictive. A same-id update preserves these untouched (apply_ingress); this flags the case
    where creating a NEW policy id would rebind the workspace and drop them, so the CLI can warn."""
    if ingress is None:
        return False
    return _block_restrictive(getattr(ingress, "private_access", None)) or _block_restrictive(
        getattr(ingress, "cross_workspace_access", None)
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
