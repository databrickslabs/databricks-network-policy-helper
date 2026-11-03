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

from .policy import INBOUND_PRIVATE_LABEL

Note = Callable[[str], None]


@dataclass
class PrivateAccessPlan:
    """A workspace's legacy private access posture (AWS/GCP) mapped to a CBI `private_access` block,
    so it can be recreated faithfully when building a CBI policy:
      * PAS private_access_level=ACCOUNT  -> ALLOW_ALL_REGISTERED_ENDPOINTS (any registered endpoint);
      * PAS private_access_level=ENDPOINT -> RESTRICTED_ACCESS listing the PAS's allowed endpoint ids;
      * NO PAS attached                   -> RESTRICTED_ACCESS with no front-end endpoints: on AWS/GCP a
        workspace without a PAS accepts no private endpoints today, so "no PAS" is private access =
        no endpoints — not "nothing to migrate" (see plan_without_pas).
    The allow rule carries the fixed label "Inbound private endpoints"."""

    restriction_mode: str  # "ALLOW_ALL_REGISTERED_ENDPOINTS" | "RESTRICTED_ACCESS"
    endpoint_ids: list[str] = field(default_factory=list)
    label: str = INBOUND_PRIVATE_LABEL
    source_pas_id: str | None = None  # None for the no-PAS plan
    # The workspace's back-end PrivateLink REST API endpoint id(s), read from its network
    # configuration — NOT the PAS (which only governs front-end/inbound). Legacy allowed endpoints are
    # (PAS endpoints OR the network config's REST API endpoint), and a RESTRICTED_ACCESS private block
    # gates ALL private ingress, so the REST endpoint must be allowed alongside the PAS front-end
    # endpoints or classic compute is blocked. The SCC relay endpoint is NOT included (it doesn't
    # reach the workspace REST API). Empty when the workspace has no back-end PrivateLink (e.g.
    # front-end PrivateLink only, with back-end egressing via the compute-plane NAT gateway). Only
    # populated/relevant for a RESTRICTED_ACCESS plan.
    backend_endpoint_ids: list[str] = field(default_factory=list)


def workspace_cloud(account, workspace_id, host: str | None = None, ws: object | None = None) -> str | None:
    """This workspace's cloud — 'aws', 'azure', or 'gcp'. Prefers the authoritative `cloud` field on
    the account workspaces API; when that's empty (it frequently is — e.g. AWS workspaces report no
    cloud), falls back to inferring it from the workspace `host` URL's domain. None if neither yields
    an answer. Drives the per-cloud private access handling (Azure: nothing to migrate; AWS/GCP: no
    PAS = deny-all private; unknown: don't apply the no-PAS mapping blind). Pass `ws` to reuse an
    already-fetched workspace object. Best-effort — a read failure degrades to the host fallback
    rather than crashing. Mirrors `databricks-migrate-ip-acls`."""
    from .egress import workspace_cloud_from_host

    try:
        if ws is None:
            ws = account.workspaces.get(workspace_id=int(workspace_id))
        cloud = (getattr(ws, "cloud", None) or "").strip().lower()
        if cloud:
            return cloud
    except Exception:  # noqa: BLE001 - couldn't read the API field; fall back to the host below
        pass
    return workspace_cloud_from_host(host)


def read_workspace_pas(account, workspace_id, ws: object | None = None) -> tuple[object | None, str]:
    """Fetch the workspace's Private Access Settings (PAS) object — the source of truth for AWS/GCP
    front-end PrivateLink. Returns (pas, status) where status is:
      * 'none'  — no PAS attached (on AWS/GCP that means private access = no endpoints; see
                  plan_without_pas);
      * 'ok'    — PAS read (`pas` is the object to map into a private_access block);
      * 'error' — the account read failed (caller warns; PrivateLink can't be migrated).
    Separating 'none' from 'error' matters: a workspace with genuinely no PAS gets a faithful
    deny-all private block, while an unreadable account warns rather than silently writing one. Pass
    `ws` to reuse an already-fetched workspace object. Best-effort."""
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
    ids under the fixed "Inbound private endpoints" label."""
    level = getattr(pas, "private_access_level", None)
    level_val = str(getattr(level, "value", level) or "").upper()
    pas_id = getattr(pas, "private_access_settings_id", None)
    if level_val == "ENDPOINT":
        ids = list(getattr(pas, "allowed_vpc_endpoint_ids", None) or [])
        return PrivateAccessPlan(restriction_mode="RESTRICTED_ACCESS", endpoint_ids=ids, source_pas_id=pas_id)
    # ACCOUNT (or an unspecified level) means any endpoint registered in the account is accepted.
    return PrivateAccessPlan(restriction_mode="ALLOW_ALL_REGISTERED_ENDPOINTS", source_pas_id=pas_id)


def pas_public_access_enabled(pas) -> bool:
    """The PAS public-internet toggle. A PAS object may carry public_access_enabled=None (field present
    but unset) — treat unknown as public-ENABLED (the as-is default): never infer "PrivateLink-only /
    deny-all public" from a missing value. Mirrors `databricks-migrate-ip-acls`."""
    pae = getattr(pas, "public_access_enabled", None)
    return True if pae is None else bool(pae)


def plan_without_pas() -> PrivateAccessPlan:
    """The PrivateAccessPlan for an AWS/GCP workspace with NO Private Access Settings attached. Such a
    workspace accepts no front-end private endpoints today, so the faithful CBI equivalent is a
    RESTRICTED_ACCESS private_access block with no front-end allow rule (deny-all private) — plus the
    back-end REST API endpoint rule if the network config has one (the caller fills
    backend_endpoint_ids). It is NOT "nothing to migrate": leaving private_access at the CBI default
    (allow all registered endpoints) would loosen the workspace's posture once CBI is the source of
    truth for private access."""
    return PrivateAccessPlan(restriction_mode="RESTRICTED_ACCESS", endpoint_ids=[], source_pas_id=None)


def backend_private_endpoint_ids(account, workspace_id, ws: object | None = None) -> list[str]:
    """The workspace's back-end PrivateLink REST API endpoint id(s) — the `rest_api` endpoints
    registered in its network configuration (`network.vpc_endpoints`: AWS VPC endpoints / GCP PSC
    endpoints). Unlike the front-end endpoints, these live in the network config, NOT the Private
    Access Settings (the PAS only governs front-end/inbound). Legacy allowed endpoints are (PAS
    endpoints OR the network config's REST API endpoint), and a RESTRICTED_ACCESS CBI private block
    gates ALL private ingress, so a block built only from the PAS would block classic compute — the
    REST endpoint must be allowed alongside the PAS front-end endpoints. The data-plane SCC relay
    endpoint (`dataplane_relay`) is deliberately ignored: it doesn't carry ingress to the workspace's
    REST API, so it has no place in a CBI private_access rule.

    Returns the deduped REST API endpoint ids, or [] when the workspace has no back-end PrivateLink
    (e.g. front-end PrivateLink only, with back-end reaching the control plane via the compute-plane
    NAT gateway) or the read fails. Pass `ws` to reuse an already-fetched workspace object.
    Best-effort — a read failure degrades to [] rather than crashing."""
    try:
        if ws is None:
            ws = account.workspaces.get(workspace_id=int(workspace_id))
    except Exception:  # noqa: BLE001 - couldn't read the workspace; treat as no back-end PrivateLink
        return []
    network_id = getattr(ws, "network_id", None)
    if not network_id:
        return []  # no customer-managed network → no registered back-end endpoints to migrate
    try:
        network = account.networks.get(network_id)
    except Exception:  # noqa: BLE001 - network unreadable; caller notes none were detected
        return []
    vpce = getattr(network, "vpc_endpoints", None)
    if vpce is None:
        return []
    out: list[str] = []
    for ep in list(getattr(vpce, "rest_api", None) or []):
        if ep and ep not in out:
            out.append(ep)
    return out


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


def _active_ingress(pol) -> tuple[object | None, str | None]:
    """(block, mode) for the ingress block that carries a policy's rules — prefer a *restrictive*
    enforced `ingress` (mode "enforce"), then a restrictive `ingress_dry_run` (mode "dry_run"); a
    policy has one enforcement mode, so its rules live in one or the other. Falls back to whichever
    block is present with mode None (nothing restrictive → no mode to inherit). (None, None) if
    neither is present."""
    ing = getattr(pol, "ingress", None)
    if ing is not None and _ingress_restrictive(ing):
        return ing, "enforce"
    dry = getattr(pol, "ingress_dry_run", None)
    if dry is not None and _ingress_restrictive(dry):
        return dry, "dry_run"
    return (ing if ing is not None else dry), None


def existing_cbi_state(
    account, workspace_id
) -> tuple[str | None, object | None, object | None, object | None, str | None, str | None]:
    """The workspace's currently-assigned CBI policy's ingress sub-blocks, deep-copied so they can be
    carried verbatim into the generated policy for any dimension this run doesn't itself produce,
    plus the enforcement mode those rules currently run in. Returns (assigned_policy_id,
    public_access, private_access, cross_workspace_access, mode, read_error):
      * read_error is None when the account API was read successfully — then the other fields are
        authoritative ((id, None, None, None, None, None) = assigned but nothing restrictive;
        (None, …) = nothing assigned);
      * read_error is a short message when the assigned policy could NOT be read; every other field
        is None and MUST NOT be interpreted as "nothing restrictive" (see assigned_policy_state).
    Only *restrictive* sub-blocks are returned — a permissive one (FULL_ACCESS /
    ALLOW_ALL_REGISTERED_ENDPOINTS, e.g. the baseline default-policy) is equivalent to omitting it,
    so dropping it keeps the generated policy clean and never silently re-adds an allow-all block.
    `mode` is "enforce" / "dry_run" when the assigned policy has a restrictive ingress block (the mode
    the generated policy must inherit, so carrying those rules forward never silently promotes dry-run
    rules to blocking or demotes enforced ones to log-only), else None."""
    policy_id, pol, read_error = assigned_policy_state(account, workspace_id)
    if read_error:
        return None, None, None, None, None, read_error
    if pol is None:
        return policy_id, None, None, None, None, None
    ing, mode = _active_ingress(pol)
    if ing is None:
        return policy_id, None, None, None, None, None
    pub = getattr(ing, "public_access", None)
    priv = getattr(ing, "private_access", None)
    xws = getattr(ing, "cross_workspace_access", None)
    return (
        policy_id,
        copy.deepcopy(pub) if _block_restrictive(pub) else None,
        copy.deepcopy(priv) if _block_restrictive(priv) else None,
        copy.deepcopy(xws) if _block_restrictive(xws) else None,
        mode,
        None,
    )


def existing_cbi_ingress(
    account, workspace_id
) -> tuple[str | None, object | None, object | None, object | None]:
    """existing_cbi_state() without the mode — (assigned_policy_id, public_access, private_access,
    cross_workspace_access)."""
    return existing_cbi_state(account, workspace_id)[:4]


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


# Pause between the two attempts to read the assigned policy (transient account-API errors — e.g.
# right after a policy write / rebind — usually clear within a second or two).
ASSIGNED_POLICY_RETRY_DELAY_SECONDS = 2.0


def assigned_policy_state(
    account, workspace_id, retries: int = 1
) -> tuple[str | None, object | None, str | None]:
    """(assigned_policy_id, full policy object, read_error) for the workspace.

    * (id, policy, None)   — read OK, a policy is assigned;
    * (None, None, None)   — read OK, nothing is assigned (the account default-policy governs);
    * (None, None, "<err>") — the account API could NOT be read (after `retries` retries).

    Callers MUST treat the third shape differently from the second: "unreadable" is not "nothing
    restrictive is assigned". A swallowed read failure here used to make the conflict gate and mode
    inheritance silently pass — a transient error could have let a run replace a restrictive
    policy. Create-and-assign paths should refuse to proceed on a read error; propose-only may
    continue with a warning."""
    import time

    last: Exception | None = None
    for attempt in range(retries + 1):
        try:
            opt = account.workspace_network_configuration.get_workspace_network_option_rpc(
                workspace_id=int(workspace_id)
            )
            policy_id = getattr(opt, "network_policy_id", None)
            if not policy_id:
                return None, None, None
            return (
                policy_id,
                account.network_policies.get_network_policy_rpc(network_policy_id=policy_id),
                None,
            )
        except Exception as e:  # noqa: BLE001 - reported to the caller, never swallowed
            last = e
            if attempt < retries:
                time.sleep(ASSIGNED_POLICY_RETRY_DELAY_SECONDS)
    detail = " ".join(str(last).split())[:200] if last else "unknown error"
    return None, None, f"{type(last).__name__ if last else 'Error'}: {detail}"


def assigned_policy(account, workspace_id) -> tuple[str | None, object | None]:
    """assigned_policy_state() without the error — (assigned_policy_id, policy); (None, None) when
    nothing is assigned OR the read failed. Prefer assigned_policy_state() wherever the distinction
    matters (it always does on a write path)."""
    policy_id, pol, _err = assigned_policy_state(account, workspace_id)
    return policy_id, pol


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
