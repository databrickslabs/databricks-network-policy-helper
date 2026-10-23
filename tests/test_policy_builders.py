"""Unit tests for the SDK policy-block builders + policy_name."""

from __future__ import annotations

from dbx_nwp_helper.core import policy


def _allow(**kw):
    base = {
        "label": "r",
        "cidrs": ["1.2.3.4/32"],
        "destination": "all_destinations",
        "identity_type": "ALL_USERS",
        "identities": [],
    }
    base.update(kw)
    return base


class _CreateAcct:
    """Fake account: the policy doesn't exist yet (create path). Captures the created object."""

    def __init__(self):
        from databricks.sdk.errors import NotFound

        parent = self
        self.created = None

        class _NP:
            def get_network_policy_rpc(self, network_policy_id):
                raise NotFound("no such policy")

            def create_network_policy_rpc(self, network_policy):
                parent.created = network_policy
                return network_policy

        self.network_policies = _NP()


class _UpdateAcct:
    """Fake account: the policy already exists (update path). Captures the updated object."""

    def __init__(self, existing):
        parent = self
        self.updated = None

        class _NP:
            def get_network_policy_rpc(self, network_policy_id):
                return existing

            def update_network_policy_rpc(self, network_policy_id, network_policy):
                parent.updated = network_policy

        self.network_policies = _NP()


def _restricted_egress():
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicy as EA,
    )
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicyRestrictionMode as ER,
    )
    from databricks.sdk.service.settings import NetworkPolicyEgress

    return NetworkPolicyEgress(network_access=EA(restriction_mode=ER.RESTRICTED_ACCESS))


def test_build_full_access_ingress_is_public_full_access():
    assert policy.build_full_access_ingress().as_dict()["public_access"]["restriction_mode"] == "FULL_ACCESS"


def test_apply_egress_create_adds_full_access_ingress_default():
    acct = _CreateAcct()
    policy.apply_egress(acct, "acc", "p", policy.build_full_access_egress())
    d = acct.created.as_dict()
    assert "egress" in d
    # a new egress-only policy gets a defined, permissive ingress rather than none
    assert d["ingress"]["public_access"]["restriction_mode"] == "FULL_ACCESS"


def test_apply_egress_update_leaves_existing_ingress_untouched():
    from databricks.sdk.service.settings import AccountNetworkPolicy

    existing = AccountNetworkPolicy(
        account_id="acc",
        network_policy_id="p",
        egress=policy.build_full_access_egress(),
        ingress=policy.build_ingress_block([_allow()], []),
    )
    acct = _UpdateAcct(existing)
    policy.apply_egress(acct, "acc", "p", _restricted_egress())
    # existing ingress rules preserved; egress replaced with the new (restricted) block
    assert acct.updated.ingress.public_access.allow_rules  # still there
    assert acct.updated.egress.network_access.restriction_mode.value == "RESTRICTED_ACCESS"


def test_apply_ingress_create_adds_full_access_egress_default():
    acct = _CreateAcct()
    block = policy.build_ingress_block([_allow()], [])
    policy.apply_ingress(acct, "acc", "p", block, "ingress")
    assert acct.created.as_dict()["egress"]["network_access"]["restriction_mode"] == "FULL_ACCESS"


def test_apply_ingress_update_leaves_existing_egress_untouched():
    from databricks.sdk.service.settings import AccountNetworkPolicy

    existing = AccountNetworkPolicy(account_id="acc", network_policy_id="p", egress=_restricted_egress())
    acct = _UpdateAcct(existing)
    block = policy.build_ingress_block([_allow()], [])
    policy.apply_ingress(acct, "acc", "p", block, "ingress")
    # the pre-existing restricted egress is preserved, not overwritten with a full-access default
    assert acct.updated.egress.network_access.restriction_mode.value == "RESTRICTED_ACCESS"


def test_apply_ingress_update_clears_opposite_mode_field():
    # Regression: ingress and ingress_dry_run are mutually exclusive on the API. Updating a policy
    # that already has an enforced `ingress` block, in dry_run mode, must CLEAR ingress and set only
    # ingress_dry_run — otherwise both are sent and the API rejects the PUT.
    from databricks.sdk.service.settings import AccountNetworkPolicy

    existing = AccountNetworkPolicy(
        account_id="acc",
        network_policy_id="p",
        egress=policy.build_full_access_egress(),
        ingress=policy.build_ingress_block([_allow()], []),
    )
    acct = _UpdateAcct(existing)
    block = policy.build_ingress_block([_allow()], [])
    policy.apply_ingress(acct, "acc", "p", block, "ingress_dry_run")
    assert acct.updated.ingress is None  # opposite mode cleared
    assert acct.updated.ingress_dry_run is not None  # new dry-run block set


def test_build_private_access_block_allow_all():
    blk = policy.build_private_access_block("ALLOW_ALL_REGISTERED_ENDPOINTS").as_dict()
    assert blk["restriction_mode"] == "ALLOW_ALL_REGISTERED_ENDPOINTS"
    assert not blk.get("allow_rules")  # no per-endpoint rules needed at account level


def test_build_private_access_block_restricted_maps_ids_and_label():
    blk = policy.build_private_access_block(
        "RESTRICTED_ACCESS", ["vpce-aaa", "vpce-bbb"], label="my-pas"
    ).as_dict()
    assert blk["restriction_mode"] == "RESTRICTED_ACCESS"
    rule = blk["allow_rules"][0]
    assert rule["label"] == "my-pas"  # PAS name kept as the rule label verbatim
    assert rule["origin"]["endpoints"]["endpoint_ids"] == ["vpce-aaa", "vpce-bbb"]  # mapped as-is


def test_build_private_access_restricted_without_ids_permits_nothing():
    # RESTRICTED_ACCESS with no endpoint ids → no allow rules (faithfully, no endpoint permitted),
    # NOT a fall-back to allow-all.
    blk = policy.build_private_access_block("RESTRICTED_ACCESS", []).as_dict()
    assert blk["restriction_mode"] == "RESTRICTED_ACCESS"
    assert not blk.get("allow_rules")


def test_build_private_access_restricted_includes_backend_endpoints():
    # A RESTRICTED_ACCESS private block gates ALL private ingress, so the workspace's back-end
    # PrivateLink endpoints (relay + REST — not in the PAS) must ride alongside the front-end ones.
    blk = policy.build_private_access_block(
        "RESTRICTED_ACCESS", ["vpce-frontend"], label="corp-pas",
        backend_endpoint_ids=["vpce-relay", "vpce-rest"],
    ).as_dict()
    rules = blk["allow_rules"]
    assert rules[0]["label"] == "corp-pas"  # front-end verbatim
    assert rules[0]["origin"]["endpoints"]["endpoint_ids"] == ["vpce-frontend"]
    assert rules[1]["label"] == "back-end PrivateLink (data-plane relay + REST)"
    assert rules[1]["origin"]["endpoints"]["endpoint_ids"] == ["vpce-relay", "vpce-rest"]


def test_build_private_access_backend_deduped_against_frontend():
    # a shared endpoint (in both the PAS and the network config) isn't listed twice
    blk = policy.build_private_access_block(
        "RESTRICTED_ACCESS", ["vpce-shared"], label="pas",
        backend_endpoint_ids=["vpce-shared", "vpce-relay"],
    ).as_dict()
    assert blk["allow_rules"][1]["origin"]["endpoints"]["endpoint_ids"] == ["vpce-relay"]  # shared dropped


def test_build_private_access_allow_all_ignores_backend_endpoints():
    # ALLOW_ALL_REGISTERED_ENDPOINTS already permits every registered endpoint — no rules added
    blk = policy.build_private_access_block(
        "ALLOW_ALL_REGISTERED_ENDPOINTS", backend_endpoint_ids=["vpce-relay"]
    ).as_dict()
    assert blk["restriction_mode"] == "ALLOW_ALL_REGISTERED_ENDPOINTS"
    assert not blk.get("allow_rules")


def test_build_private_access_backend_only_when_no_frontend():
    # endpoint-scoped PAS that allows nothing front-end, but the workspace has back-end PrivateLink:
    # the back-end rule still rides (otherwise the restricted block would block the data plane).
    blk = policy.build_private_access_block(
        "RESTRICTED_ACCESS", [], label="pas", backend_endpoint_ids=["vpce-relay"]
    ).as_dict()
    rules = blk["allow_rules"]
    assert len(rules) == 1
    assert rules[0]["label"] == "back-end PrivateLink (data-plane relay + REST)"


def test_assemble_ingress_composes_independent_sub_blocks():
    pub = policy.build_public_access_block([_allow()], [])
    priv = policy.build_private_access_block("ALLOW_ALL_REGISTERED_ENDPOINTS")
    blk = policy.assemble_ingress(public_access=pub, private_access=priv).as_dict()
    assert blk["public_access"]["restriction_mode"] == "RESTRICTED_ACCESS"
    assert blk["private_access"]["restriction_mode"] == "ALLOW_ALL_REGISTERED_ENDPOINTS"
    # cross_workspace omitted when not supplied
    assert "cross_workspace_access" not in blk


def test_build_ingress_block_includes_private_access():
    blk = policy.build_ingress_block(
        [_allow()], [], private_access=policy.build_private_access_block("ALLOW_ALL_REGISTERED_ENDPOINTS")
    ).as_dict()
    assert blk["public_access"]["restriction_mode"] == "RESTRICTED_ACCESS"
    assert blk["private_access"]["restriction_mode"] == "ALLOW_ALL_REGISTERED_ENDPOINTS"


def test_apply_ingress_update_preserves_existing_private_and_cross_workspace():
    # A same-id update that rebuilds only public_access must NOT drop a private_access /
    # cross_workspace_access block the existing policy already carried (full-replace, but preserved).
    from databricks.sdk.service.settings import (
        AccountNetworkPolicy,
    )
    from databricks.sdk.service.settings import (
        CustomerFacingIngressNetworkPolicyCrossWorkspaceAccess as XWS,
    )
    from databricks.sdk.service.settings import (
        CustomerFacingIngressNetworkPolicyCrossWorkspaceAccessRestrictionMode as XWSMode,
    )

    prior = policy.build_ingress_block(
        [_allow()], [], private_access=policy.build_private_access_block("ALLOW_ALL_REGISTERED_ENDPOINTS")
    )
    prior.cross_workspace_access = XWS(restriction_mode=XWSMode.RESTRICTED_ACCESS)
    existing = AccountNetworkPolicy(
        account_id="acc", network_policy_id="p", egress=policy.build_full_access_egress(), ingress=prior
    )
    acct = _UpdateAcct(existing)
    # Rebuild public-only (no private_access, no cross_workspace on the new block).
    policy.apply_ingress(acct, "acc", "p", policy.build_ingress_block([_allow()], []), "ingress")
    assert acct.updated.ingress.private_access is not None  # preserved
    assert acct.updated.ingress.cross_workspace_access.restriction_mode.value == "RESTRICTED_ACCESS"


def test_apply_ingress_update_migration_overwrites_private_access():
    # When we DO build a private_access block (a PrivateLink migration), it replaces the prior one.
    from databricks.sdk.service.settings import AccountNetworkPolicy

    prior = policy.build_ingress_block(
        [_allow()], [], private_access=policy.build_private_access_block("ALLOW_ALL_REGISTERED_ENDPOINTS")
    )
    existing = AccountNetworkPolicy(
        account_id="acc", network_policy_id="p", egress=policy.build_full_access_egress(), ingress=prior
    )
    acct = _UpdateAcct(existing)
    new_block = policy.build_ingress_block(
        [_allow()], [], private_access=policy.build_private_access_block("RESTRICTED_ACCESS", ["vpce-zzz"])
    )
    policy.apply_ingress(acct, "acc", "p", new_block, "ingress")
    d = acct.updated.ingress.private_access.as_dict()
    assert d["restriction_mode"] == "RESTRICTED_ACCESS"
    assert d["allow_rules"][0]["origin"]["endpoints"]["endpoint_ids"] == ["vpce-zzz"]


def test_ingress_content_reports_populated_blocks_and_empty_for_permissive():
    from dbx_nwp_helper.core import acl

    populated = types_ns(
        ingress=policy.build_ingress_block([_allow()], []),
        ingress_dry_run=None,
    )
    assert acl.ingress_content(populated) == ["enforced ingress: public — 1 allow / 0 deny rule(s)"]

    permissive = types_ns(ingress=policy.build_full_access_ingress(), ingress_dry_run=None)
    assert acl.ingress_content(permissive) == []


def test_egress_content_reports_restricted_and_empty_for_full_access():
    from dbx_nwp_helper.core import acl

    assert acl.egress_content(types_ns(egress=_restricted_egress())) == [
        "dry-run egress: restricted destinations"
    ]
    assert acl.egress_content(types_ns(egress=policy.build_full_access_egress())) == []


def types_ns(**kw):
    import types

    return types.SimpleNamespace(**kw)


def test_ingress_rule_ip_ranges_wrapped():
    rule = policy.build_ingress_rule(_allow()).as_dict()
    assert rule["origin"]["included_ip_ranges"]["ip_ranges"] == ["1.2.3.4/32"]
    assert rule["destination"]["all_destinations"] is True
    assert rule["label"] == "r"  # verbatim label, no mode suffix


def test_ingress_rule_apps_and_lakebase_destinations():
    apps = policy.build_ingress_rule(_allow(destination="apps_runtime")).as_dict()
    assert apps["destination"]["apps_runtime"]["all_destinations"] is True
    lb = policy.build_ingress_rule(_allow(destination="lakebase_runtime")).as_dict()
    assert lb["destination"]["lakebase_runtime"]["all_destinations"] is True


def test_ingress_rule_selected_identities_auth_omitted_on_broad_destinations():
    # The CBI API rejects an authentication block on Apps / Lakebase / all_destinations rules, so
    # even with SELECTED_IDENTITIES the builder must omit it (otherwise apply 400s).
    ids = [
        {"principal_id": 42, "principal_type": "USER"},
        {"principal_id": 7, "principal_type": "SERVICE_PRINCIPAL"},
    ]
    for dest in ("all_destinations", "apps_runtime", "lakebase_runtime"):
        spec = _allow(destination=dest, identity_type="SELECTED_IDENTITIES", identities=ids)
        rule = policy.build_ingress_rule(spec).as_dict()
        assert "authentication" not in rule, dest


def test_catch_all_origin():
    rule = policy.build_ingress_rule(_allow(catch_all=True)).as_dict()
    assert rule["origin"]["all_ip_ranges"] is True
    assert "included_ip_ranges" not in rule["origin"]


def test_deny_rule_shape():
    rule = policy.build_deny_rule({"label": "d", "cidrs": ["9.9.9.0/24"]}).as_dict()
    assert rule["origin"]["included_ip_ranges"]["ip_ranges"] == ["9.9.9.0/24"]
    assert rule["destination"]["all_destinations"] is True


def test_deny_without_allow_injects_catch_all():
    notes = []
    block = policy.build_ingress_block(
        allow=[],
        deny=[{"label": "np-deny", "cidrs": ["9.9.9.0/24"]}],
        note=notes.append,
    ).as_dict()
    pub = block["public_access"]
    assert pub["allow_rules"][0]["origin"]["all_ip_ranges"] is True
    assert pub["deny_rules"]
    assert any("catch-all" in n for n in notes)


def test_allow_with_deny_no_catch_all():
    notes = []
    block = policy.build_ingress_block(
        allow=[_allow()],
        deny=[{"label": "d", "cidrs": ["9.9.9.0/24"]}],
        note=notes.append,
    ).as_dict()
    pub = block["public_access"]
    assert len(pub["allow_rules"]) == 1
    assert pub["allow_rules"][0]["origin"].get("all_ip_ranges") is None
    assert not notes  # no catch-all note


def test_restriction_mode_always_restricted():
    block = policy.build_ingress_block([_allow()], []).as_dict()
    assert block["public_access"]["restriction_mode"] == "RESTRICTED_ACCESS"


def test_full_access_egress():
    egr = policy.build_full_access_egress().as_dict()
    assert egr["network_access"]["restriction_mode"] == "FULL_ACCESS"


def test_policy_name_single_truncates_prefix():
    assert policy.policy_name("np-helper") == "np-helper"
    long = policy.policy_name("x" * 50)
    assert len(long) == 30


def test_policy_name_per_workspace_keeps_full_id():
    name = policy.policy_name("np-helper", workspace_id=1234567890123456)
    # the full workspace id is always preserved, even if the prefix must be trimmed
    assert name.endswith("-ws-1234567890123456")


def test_policy_name_per_workspace_trims_long_prefix():
    # a long prefix + a long ws id exceeds the 30-char budget -> prefix trimmed, id kept whole
    name = policy.policy_name("really-long-prefix-name", workspace_id=1234567890123456)
    assert name.endswith("-ws-1234567890123456")
    assert not name.startswith("really-long-prefix-name")


def test_policy_name_long_prefix_per_workspace_within_budget():
    name = policy.policy_name("really-long-prefix-name", workspace_id=42)
    assert name.endswith("-ws-42")


def test_policy_name_current_workspace_uses_profile_suffix():
    assert policy.policy_name("np-helper", suffix="acme-ws") == "np-helper-acme-ws"


def test_policy_name_suffix_is_slugified():
    # a profile with spaces / odd chars is normalised to a policy-id-safe slug
    name = policy.policy_name("np", suffix="My Prod Workspace!")
    assert name == "np-my-prod-workspace"


def test_policy_name_suffix_trims_prefix_to_fit():
    name = policy.policy_name("really-long-prefix-name", suffix="my-workspace-profile")
    assert name.endswith("-my-workspace-profile")
    assert len(name) <= 30


def test_policy_name_explicit_overrides_and_slugifies():
    # an explicit --policy-name wins over the derived id and is normalised to an id-safe slug
    assert policy.policy_name("np", explicit="My Prod Policy!") == "my-prod-policy"
    assert policy.policy_name("np", workspace_id=42, explicit="chosen-name") == "chosen-name"


def test_policy_name_explicit_capped_to_limit():
    assert len(policy.policy_name("np", explicit="x" * 60)) == 30


def test_policy_name_explicit_empty_slug_falls_back_to_prefix():
    # a name that slugs away to nothing falls back to the (slugified) prefix, never an empty id
    assert policy.policy_name("np-helper", explicit="!!!") == "np-helper"
