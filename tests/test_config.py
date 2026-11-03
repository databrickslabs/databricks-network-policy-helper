"""Unit tests for config dataclasses + validation."""

from __future__ import annotations

import pytest

from dbx_nwp_helper.config import (
    ApplyOptions,
    IngressConfig,
    validate_apply,
    validate_disable_ip_acls,
    validate_policy_name,
)


def test_ingress_scope_properties():
    assert IngressConfig(scoping_mode="ip_only").scope_destination is False
    assert IngressConfig(scoping_mode="ip_only").scope_identity is False
    c = IngressConfig(scoping_mode="ip_identity_and_destination")
    assert c.scope_destination and c.scope_identity
    assert IngressConfig(scoping_mode="ip_and_identity").scope_identity
    assert IngressConfig(scoping_mode="ip_and_destination").scope_destination


def test_include_account_level_defaults_false():
    # Account-level (workspace_id=0) rows are account console / SCIM traffic, not workspace-scoped,
    # so they're excluded by default.
    assert IngressConfig().include_account_level is False


def test_no_command_carries_name_prefix():
    # No command carries a name_prefix any more — the policy name is resolved centrally (from
    # --policy-name or the profile name). DEFAULT_NAME_PREFIX is only the final fallback when there's
    # neither a profile nor a workspace id.
    from dbx_nwp_helper.config import DEFAULT_NAME_PREFIX, EgressConfig

    assert DEFAULT_NAME_PREFIX == "dbx-nwp"
    assert not hasattr(IngressConfig(), "name_prefix")
    assert not hasattr(EgressConfig(), "name_prefix")


def test_policy_scope_defaults_to_current_workspace():
    from dbx_nwp_helper.config import EgressConfig

    assert IngressConfig().policy_scope == "current_workspace"
    assert EgressConfig().policy_scope == "current_workspace"


def test_policy_mode_target_maps_to_block():
    assert IngressConfig(policy_mode="dry_run").policy_mode_target == "ingress_dry_run"
    assert IngressConfig(policy_mode="enforce").policy_mode_target == "ingress"


def test_validate_apply_noop_when_not_creating():
    # propose-only, or create_new — nothing to validate.
    validate_apply(
        ApplyOptions(create_policy=False, policy_action="add_to_existing"), "per_workspace", "egress"
    )
    validate_apply(ApplyOptions(create_policy=True, policy_action="create_new"), "per_workspace", "egress")


def test_validate_apply_requires_existing_id():
    with pytest.raises(ValueError, match="existing-policy-id"):
        validate_apply(
            ApplyOptions(create_policy=True, policy_action="add_to_existing"), "current_workspace", "egress"
        )


def test_validate_apply_rejects_per_workspace():
    with pytest.raises(ValueError, match="per_workspace"):
        validate_apply(
            ApplyOptions(create_policy=True, policy_action="add_to_existing", existing_policy_id="p"),
            "per_workspace",
            "egress",
        )


def test_validate_apply_ok_single_scopes_with_id():
    # both single-policy scopes are valid targets for add_to_existing
    for scope in ("current_workspace", "all_workspaces"):
        validate_apply(
            ApplyOptions(create_policy=True, policy_action="add_to_existing", existing_policy_id="p"),
            scope,
            "egress",
        )


def test_validate_disable_ip_acls_noop_when_disabled():
    # not requested — never validated, regardless of create/assign/mode.
    validate_disable_ip_acls(False, create_policy=False, auto_assign=False, policy_mode="dry_run")


def test_validate_disable_ip_acls_requires_create_and_assign():
    # requested without both create AND assign would leave the workspace unprotected -> reject.
    with pytest.raises(ValueError, match="creates AND assigns"):
        validate_disable_ip_acls(True, create_policy=True, auto_assign=False, policy_mode="enforce")
    with pytest.raises(ValueError, match="creates AND assigns"):
        validate_disable_ip_acls(True, create_policy=False, auto_assign=True, policy_mode="enforce")
    with pytest.raises(ValueError, match="creates AND assigns"):
        validate_disable_ip_acls(True, create_policy=False, auto_assign=False, policy_mode="enforce")


def test_validate_disable_ip_acls_rejects_dry_run():
    # a dry-run policy is log-only, so disabling the legacy ACLs alongside it leaves no enforced control.
    with pytest.raises(ValueError, match="dry_run"):
        validate_disable_ip_acls(True, create_policy=True, auto_assign=True, policy_mode="dry_run")


def test_validate_disable_ip_acls_ok_with_create_assign_and_enforce():
    validate_disable_ip_acls(True, create_policy=True, auto_assign=True, policy_mode="enforce")


def test_disable_existing_ip_acls_defaults_false():
    assert IngressConfig().disable_existing_ip_acls is False


def test_validate_policy_name_noop_when_blank():
    validate_policy_name("", "per_workspace", "add_to_existing")  # nothing set -> no validation


def test_validate_policy_name_rejects_add_to_existing():
    with pytest.raises(ValueError, match="existing-policy-id"):
        validate_policy_name("my-pol", "current_workspace", "add_to_existing")


def test_validate_policy_name_allows_per_workspace():
    # per_workspace now uses the name as a prefix (-> <name>-ws-<id>), so it's valid.
    validate_policy_name("my-pol", "per_workspace", "create_new")


def test_validate_policy_name_ok_single_scope_create_new():
    for scope in ("current_workspace", "all_workspaces"):
        validate_policy_name("my-pol", scope, "create_new")


def test_policy_name_defaults_blank():
    from dbx_nwp_helper.config import EgressConfig

    assert IngressConfig().policy_name == ""
    assert EgressConfig().policy_name == ""


def test_validate_export_rejects_per_workspace():
    from dbx_nwp_helper.config import validate_export

    with pytest.raises(ValueError, match="per_workspace"):
        validate_export("out.json", "per_workspace")


def test_validate_export_ok_when_blank_or_single_scope():
    from dbx_nwp_helper.config import validate_export

    validate_export("", "per_workspace")  # not requested -> no validation
    for scope in ("current_workspace", "all_workspaces"):
        validate_export("out.json", scope)


def test_ingress_export_defaults_blank():
    assert IngressConfig().export == ""
