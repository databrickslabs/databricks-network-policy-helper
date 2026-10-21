"""SDK dataclass builders + create/update/assign for account network policies.

Shared by the ingress and ACL engines. The build_* functions turn plain rule-spec dicts into the
`CustomerFacingIngressNetworkPolicy*` / `NetworkPolicyEgress` dataclasses so the JSON you preview is
exactly what gets sent. apply_ingress()/apply_egress() do the gated create-or-update; assign() binds a
workspace. Ported from the notebooks' apply cells.
"""

from __future__ import annotations

from collections.abc import Callable

from ..config import MAX_POLICY_ID_LEN

Note = Callable[[str], None]

# Destinations the CBI API forbids an authentication block on — they implicitly allow all users +
# service principals, so a SELECTED_IDENTITIES block is rejected. These are the only destination
# shapes this tool currently emits (see core/ingress.py), so per-identity auth is effectively
# unsupported today; the ingress engine warns when identity scoping is requested.
_DESTINATIONS_WITHOUT_AUTH = {None, "all_destinations", "apps_runtime", "lakebase_runtime"}


# --------------------------------------------------------------------------- ingress block builders
def build_ingress_rule(spec: dict):
    from databricks.sdk.service.settings import (  # noqa: I001
        CustomerFacingIngressNetworkPolicyAppsRuntimeDestination as AppsDest,
        CustomerFacingIngressNetworkPolicyAuthentication as Auth,
        CustomerFacingIngressNetworkPolicyAuthenticationIdentity as Identity,
        CustomerFacingIngressNetworkPolicyAuthenticationIdentityPrincipalType as PrincipalType,
        CustomerFacingIngressNetworkPolicyAuthenticationIdentityType as IdentityType,
        CustomerFacingIngressNetworkPolicyIpRanges as IpRanges,
        CustomerFacingIngressNetworkPolicyLakebaseRuntimeDestination as LakebaseDest,
        CustomerFacingIngressNetworkPolicyPublicIngressRule as Rule,
        CustomerFacingIngressNetworkPolicyPublicRequestOrigin as Origin,
        CustomerFacingIngressNetworkPolicyRequestDestination as Destination,
    )

    origin = (
        Origin(all_ip_ranges=True)
        if spec.get("catch_all")
        else Origin(included_ip_ranges=IpRanges(ip_ranges=list(spec["cidrs"])))
    )

    if spec.get("destination") == "apps_runtime":
        destination = Destination(apps_runtime=AppsDest(all_destinations=True))
    elif spec.get("destination") == "lakebase_runtime":
        destination = Destination(lakebase_runtime=LakebaseDest(all_destinations=True))
    else:
        destination = Destination(all_destinations=True)

    # The CBI API rejects an authentication block on the broad "runtime"/"all" destinations
    # (Apps / Lakebase / all_destinations support only all users + service principals). Only attach
    # per-identity authentication where the destination can carry it.
    authentication = None
    if (
        spec.get("destination") not in _DESTINATIONS_WITHOUT_AUTH
        and spec.get("identity_type") == "SELECTED_IDENTITIES"
        and spec.get("identities")
    ):
        identities = [
            Identity(
                principal_id=i["principal_id"],
                principal_type=(
                    PrincipalType.PRINCIPAL_TYPE_USER
                    if i["principal_type"] == "USER"
                    else PrincipalType.PRINCIPAL_TYPE_SERVICE_PRINCIPAL
                ),
            )
            for i in spec["identities"]
        ]
        authentication = Auth(
            identity_type=IdentityType.IDENTITY_TYPE_SELECTED_IDENTITIES, identities=identities
        )

    return Rule(
        label=spec["label"],
        origin=origin,
        destination=destination,
        authentication=authentication,
    )


def build_deny_rule(spec: dict):
    from databricks.sdk.service.settings import (  # noqa: I001
        CustomerFacingIngressNetworkPolicyIpRanges as IpRanges,
        CustomerFacingIngressNetworkPolicyPublicIngressRule as Rule,
        CustomerFacingIngressNetworkPolicyPublicRequestOrigin as Origin,
        CustomerFacingIngressNetworkPolicyRequestDestination as Destination,
    )

    return Rule(
        label=spec["label"],
        origin=Origin(included_ip_ranges=IpRanges(ip_ranges=list(spec["cidrs"]))),
        destination=Destination(all_destinations=True),
    )


def build_private_access_block(
    restriction_mode: str, endpoint_ids: list[str] | None = None, label: str = "registered-private-endpoints"
):
    """A CustomerFacingIngressNetworkPolicyPrivateAccess (front-end PrivateLink) sub-block:
      * ALLOW_ALL_REGISTERED_ENDPOINTS -> the mode alone (any endpoint registered to the account);
      * RESTRICTED_ACCESS -> one allow rule whose origin lists the given registered endpoint ids. With
        no ids the block is RESTRICTED_ACCESS with no allow rules — faithfully, no endpoint permitted.
    The ids are the PAS `allowed_vpc_endpoint_ids`, mapped across as-is; `label` is the PAS name
    verbatim (see acl.plan_from_pas)."""
    from databricks.sdk.service.settings import (  # noqa: I001
        CustomerFacingIngressNetworkPolicyEndpoints as Endpoints,
        CustomerFacingIngressNetworkPolicyPrivateAccess as PrivateAccess,
        CustomerFacingIngressNetworkPolicyPrivateAccessRestrictionMode as PrivateMode,
        CustomerFacingIngressNetworkPolicyPrivateIngressRule as PrivateRule,
        CustomerFacingIngressNetworkPolicyPrivateRequestOrigin as PrivateOrigin,
        CustomerFacingIngressNetworkPolicyRequestDestination as Destination,
    )

    if restriction_mode == "ALLOW_ALL_REGISTERED_ENDPOINTS":
        return PrivateAccess(restriction_mode=PrivateMode.ALLOW_ALL_REGISTERED_ENDPOINTS)
    rules = (
        [
            PrivateRule(
                label=label,
                origin=PrivateOrigin(endpoints=Endpoints(endpoint_ids=list(endpoint_ids))),
                destination=Destination(all_destinations=True),
            )
        ]
        if endpoint_ids
        else None
    )
    return PrivateAccess(restriction_mode=PrivateMode.RESTRICTED_ACCESS, allow_rules=rules)


def build_public_access_block(allow: list[dict], deny: list[dict], note: Note = lambda _m: None):
    """The ingress public_access (source-IP) sub-block from allow specs (+ optional deny specs).

    RESTRICTED_ACCESS is default-DENY; if a block ends up with deny rules but no allow rules,
    everything would be blocked — add a catch-all allow (all public IPs) to preserve
    "block these, allow the rest"."""
    from databricks.sdk.service.settings import (  # noqa: I001
        CustomerFacingIngressNetworkPolicyPublicAccess as PublicAccess,
        CustomerFacingIngressNetworkPolicyPublicAccessRestrictionMode as RestrictionMode,
    )

    allow = list(allow)
    if (deny or []) and not allow:
        allow = [
            {
                "label": "allow-all",
                "catch_all": True,
                "destination": "all_destinations",
                "identity_type": "ALL_USERS",
                "identities": [],
            }
        ]
        note(
            "Policy has deny rules but no allow rules — added a catch-all allow (all public IPs) "
            "so non-denied traffic is still permitted (default-allow-except-blocked)."
        )
    return PublicAccess(
        restriction_mode=RestrictionMode.RESTRICTED_ACCESS,
        allow_rules=[build_ingress_rule(s) for s in allow],
        deny_rules=[build_deny_rule(s) for s in (deny or [])] or None,
    )


def assemble_ingress(public_access=None, private_access=None, cross_workspace_access=None):
    """Assemble a CustomerFacingIngressNetworkPolicy from independently built-or-preserved sub-blocks
    (public / private / cross-workspace). Any may be None (omitted). Public and private ingress are
    independent dimensions — each is migrated from observed traffic / a PAS or carried forward from
    the workspace's existing CBI policy; cross-workspace is never built, only carried forward."""
    from databricks.sdk.service.settings import CustomerFacingIngressNetworkPolicy as IngressPolicy

    return IngressPolicy(
        public_access=public_access,
        private_access=private_access,
        cross_workspace_access=cross_workspace_access,
    )


def build_ingress_block(
    allow: list[dict],
    deny: list[dict],
    note: Note = lambda _m: None,
    private_access=None,
):
    """Convenience wrapper: a full ingress block with a built public_access and an optional
    private_access (the engine composes build_public_access_block / preserved blocks via
    assemble_ingress directly when it also needs to carry cross-workspace forward)."""
    return assemble_ingress(
        public_access=build_public_access_block(allow, deny, note), private_access=private_access
    )


def build_full_access_egress():
    """A permissive (FULL_ACCESS) egress block — used when an ingress-only helper creates a new
    policy (the API requires an egress block on create)."""
    from databricks.sdk.service.settings import (  # noqa: I001
        EgressNetworkPolicyNetworkAccessPolicy as EgressAccess,
        EgressNetworkPolicyNetworkAccessPolicyRestrictionMode as EgressRestriction,
        NetworkPolicyEgress,
    )

    return NetworkPolicyEgress(network_access=EgressAccess(restriction_mode=EgressRestriction.FULL_ACCESS))


def build_full_access_ingress():
    """A permissive (public FULL_ACCESS) ingress block — used when an egress-only helper creates a
    new policy so it doesn't leave the policy without a defined (non-restrictive) ingress."""
    from databricks.sdk.service.settings import (  # noqa: I001
        CustomerFacingIngressNetworkPolicy as IngressPolicy,
        CustomerFacingIngressNetworkPolicyPublicAccess as PublicAccess,
        CustomerFacingIngressNetworkPolicyPublicAccessRestrictionMode as RestrictionMode,
    )

    return IngressPolicy(public_access=PublicAccess(restriction_mode=RestrictionMode.FULL_ACCESS))


# --------------------------------------------------------------------------------- policy id naming
def _slug(text: str) -> str:
    """Normalise a free-form label (e.g. a profile name) into a policy-id-safe slug."""
    import re

    return re.sub(r"[^a-z0-9-]+", "-", (text or "").lower()).strip("-")


def policy_name(
    name_prefix: str, workspace_id: int | None = None, suffix: str | None = None, explicit: str | None = None
) -> str:
    """Deterministic policy id, truncated to the id length limit while preserving the suffix:
      all_workspaces   -> <prefix>
      per_workspace    -> <prefix>-ws-<id>       (workspace_id given)
      current_workspace-> <prefix>-<profile>     (suffix given)
    The suffix (workspace id or profile slug) is kept whole; the prefix is trimmed to fit.
    An `explicit` name (the user's --policy-name) overrides all of the above: it's slugified to an
    id-safe form and capped, falling back to the prefix if it slugs away to nothing."""
    if explicit:
        return (_slug(explicit) or _slug(name_prefix) or "policy")[:MAX_POLICY_ID_LEN]
    prefix = _slug(name_prefix) or "policy"
    if workspace_id is not None:
        tail = f"-ws-{workspace_id}"
    elif suffix:
        tail = f"-{_slug(suffix)}"
    else:
        return prefix[:MAX_POLICY_ID_LEN]
    room = MAX_POLICY_ID_LEN - len(tail)
    return f"{prefix[:max(room, 1)].rstrip('-')}{tail}"


# ----------------------------------------------------------------------------------- apply (writes)
def apply_ingress(
    account, account_id: str, policy_id: str, block, target_attr: str, must_exist: bool = False
) -> tuple[str, str, dict]:
    """Create-or-update policy `policy_id`, setting its target ingress block (ingress|ingress_dry_run)
    and leaving other blocks + egress unchanged (update is a full replace). Returns
    (action, effective_id, sent_block_dict)."""
    from databricks.sdk.errors import NotFound
    from databricks.sdk.service.settings import AccountNetworkPolicy

    try:
        existing = account.network_policies.get_network_policy_rpc(network_policy_id=policy_id)
        action = "updated"
    except NotFound:
        if must_exist:
            raise ValueError(
                f"policy_action=add_to_existing but no network policy '{policy_id}' was found. "
                "Check --existing-policy-id (create it first, or use create_new)."
            ) from None
        existing = AccountNetworkPolicy(account_id=account_id, network_policy_id=policy_id)
        action = "created"

    # `ingress` and `ingress_dry_run` are mutually exclusive on the API ("Only one of ingress or
    # ingress_dry_run can be set at a time") — they're the enforce- vs dry-run-mode form of the same
    # ingress config. Setting one must clear the other, or updating a policy that already carries the
    # opposite mode's block would send both and be rejected. Clearing it is how a mode switch
    # (e.g. enforce -> dry_run) actually takes effect.
    opposite_attr = "ingress" if target_attr == "ingress_dry_run" else "ingress_dry_run"
    # Preserve the private-access and cross-workspace sub-blocks that this tool doesn't rebuild: our
    # freshly built block only ever sets public_access (and, for a PrivateLink migration,
    # private_access). Carry over whatever the existing policy already had — from either mode's block,
    # so a mode switch doesn't drop it — unless our new block explicitly sets that sub-block. This is
    # why update is a full replace yet never clobbers a console-configured private-access /
    # cross-workspace (compatibility) config the user didn't ask us to touch.
    for src_attr in (target_attr, opposite_attr):
        src = getattr(existing, src_attr, None)
        if src is None:
            continue
        if block.private_access is None and getattr(src, "private_access", None) is not None:
            block.private_access = src.private_access
        if block.cross_workspace_access is None and getattr(src, "cross_workspace_access", None) is not None:
            block.cross_workspace_access = src.cross_workspace_access
    setattr(existing, target_attr, block)
    setattr(existing, opposite_attr, None)
    # Ensure the opposite direction is defined but never clobbered: only add a permissive egress
    # default when the policy has none (a fresh policy, or one somehow created without egress).
    if getattr(existing, "egress", None) is None:
        existing.egress = build_full_access_egress()
    if action == "created":
        result = account.network_policies.create_network_policy_rpc(network_policy=existing)
        effective_id = result.network_policy_id or policy_id
        sent = getattr(result, target_attr, None) or getattr(existing, target_attr)
    else:
        account.network_policies.update_network_policy_rpc(
            network_policy_id=policy_id, network_policy=existing
        )
        effective_id = policy_id
        sent = getattr(existing, target_attr)
    return action, effective_id, sent.as_dict()


def apply_egress(
    account, account_id: str, policy_id: str, egress_block, must_exist: bool = False
) -> tuple[str, str]:
    """Create-or-update policy `policy_id`, replacing only its egress block (ingress untouched).
    Returns (action, effective_id)."""
    from databricks.sdk.errors import NotFound
    from databricks.sdk.service.settings import AccountNetworkPolicy

    try:
        existing = account.network_policies.get_network_policy_rpc(network_policy_id=policy_id)
        action = "updated"
    except NotFound:
        if must_exist:
            raise ValueError(
                f"policy_action=add_to_existing but no network policy '{policy_id}' was found. "
                "Check --existing-policy-id (create it first, or use create_new)."
            ) from None
        existing = AccountNetworkPolicy(account_id=account_id, network_policy_id=policy_id)
        action = "created"

    existing.egress = egress_block
    # Ensure the opposite direction is defined but never clobbered: only add a permissive ingress
    # default when the policy has no ingress at all (leave an existing ingress / dry-run untouched).
    if getattr(existing, "ingress", None) is None and getattr(existing, "ingress_dry_run", None) is None:
        existing.ingress = build_full_access_ingress()
    if action == "created":
        result = account.network_policies.create_network_policy_rpc(network_policy=existing)
        effective_id = result.network_policy_id or policy_id
    else:
        account.network_policies.update_network_policy_rpc(
            network_policy_id=policy_id, network_policy=existing
        )
        effective_id = policy_id
    return action, effective_id


def assign(account, workspace_id: int, policy_id: str) -> None:
    from databricks.sdk.service.settings import WorkspaceNetworkOption

    account.workspace_network_configuration.update_workspace_network_option_rpc(
        workspace_id=int(workspace_id),
        workspace_network_option=WorkspaceNetworkOption(
            workspace_id=int(workspace_id), network_policy_id=policy_id
        ),
    )
