"""Cross-workspace egress destinations (core/xws.py + the egress engine / policy merge) and the
egress hostname validation that replaced the live "'local' is not a valid hostname" apply failure."""

from __future__ import annotations

import types

import pandas as pd
import pytest

from dbx_nwp_helper.config import EgressConfig
from dbx_nwp_helper.core import egress as eg
from dbx_nwp_helper.core import policy, xws

# ------------------------------------------------------------------------------ host → workspace id


@pytest.mark.parametrize(
    "host,expected",
    [
        ("cac-lakebase-mcp-7474659688817102.aws.databricksapps.com", (7474659688817102, "apps-url")),
        ("fox-mcp-server-b-7405617080752524.4.azure.databricksapps.com", (7405617080752524, "apps-url")),
        ("7474659574694750.ai-gateway.cloud.databricks.com", (7474659574694750, "ai-gateway-url")),
        ("adb-1234567890123456.7.azuredatabricks.net", (1234567890123456, "azure-url")),
        ("1234567890123456.3.gcp.databricks.com", (1234567890123456, "gcp-url")),
        ("dbc-3c72c865-78d5.cloud.databricks.com", (None, "aws-deployment-name")),
        ("e2-demo-field-eng.cloud.databricks.com", (None, "aws-deployment-name")),
        ("ep-falling-bread-d258xcy8.database.us-east-1.cloud.databricks.com", (None, "lakebase-endpoint")),
        ("docs.databricks.com", (None, "platform-host")),
        ("www.databricks.com", (None, "platform-host")),
        ("npm-proxy.dev.databricks.com", (None, "platform-host")),
        ("jaeger-collector.privileged.staging.dbns.databricks.com", (None, "platform-host")),
        ("fake-spog.databricks.com", (None, "unknown-host-shape")),
        ("app-v2.aws.databricksapps.com", (None, "unknown-host-shape")),  # short digits ≠ an id
        ("adb-0000000000000000.0.azuredatabricks.net", (None, "unknown-host-shape")),  # zero id
    ],
)
def test_workspace_id_from_host(host, expected):
    assert xws.workspace_id_from_host(host) == expected


class _Acct:
    def __init__(self, workspaces, raise_=False):
        self._ws = workspaces
        self._raise = raise_
        self.workspaces = types.SimpleNamespace(list=self._list)
        self.calls = 0

    def _list(self):
        self.calls += 1
        if self._raise:
            raise RuntimeError("no account access")
        return [types.SimpleNamespace(deployment_name=d, workspace_id=w) for d, w in self._ws]


def test_resolve_groups_hosts_by_workspace_and_excludes_own():
    hosts = {
        "mcp-a-7474650000000001.aws.databricksapps.com": 10,
        "mcp-b-7474650000000001.aws.databricksapps.com": 5,
        "7474650000000002.ai-gateway.cloud.databricks.com": 3,
        "7474650000000009.ai-gateway.cloud.databricks.com": 99,  # this workspace
        "docs.databricks.com": 1,
    }
    res = xws.resolve(hosts, account=None, own_workspace_id=7474650000000009)
    assert res.workspace_ids == [7474650000000001, 7474650000000002]
    assert res.resolved[7474650000000001]["events"] == 15
    assert len(res.resolved[7474650000000001]["hosts"]) == 2
    assert res.own == ["7474650000000009.ai-gateway.cloud.databricks.com"]
    assert res.unresolved == [("docs.databricks.com", "platform-host")]
    assert res.account_lookup is False


def test_resolve_uses_account_workspace_list_for_aws_deployment_names():
    acct = _Acct([("dbc-3c72c865-78d5", 7474650000000003), ("e2-demo-field-eng", 7474650000000004)])
    hosts = {
        "dbc-3c72c865-78d5.cloud.databricks.com": 7,
        "e2-demo-field-eng.cloud.databricks.com": 2,
        "someone-elses.cloud.databricks.com": 1,
    }
    res = xws.resolve(hosts, account=acct)
    assert acct.calls == 1  # listed once, reused for every deployment name
    assert res.account_lookup is True
    assert res.workspace_ids == [7474650000000003, 7474650000000004]
    assert res.resolved[7474650000000003]["methods"] == {"account-workspace-list"}
    assert res.unresolved == [
        ("someone-elses.cloud.databricks.com", "aws-deployment-name-not-in-this-account")
    ]


def test_resolve_without_account_flags_aws_hosts_with_reason():
    res = xws.resolve({"dbc-3c72c865-78d5.cloud.databricks.com": 7})
    assert res.resolved == {}
    assert res.unresolved == [
        ("dbc-3c72c865-78d5.cloud.databricks.com", "aws-deployment-name-needs-account-lookup")
    ]
    assert "aws-deployment-name-needs-account-lookup" in xws.REASON_TEXT


def test_resolve_survives_account_lookup_failure():
    acct = _Acct([], raise_=True)
    res = xws.resolve({"dbc-3c72c865-78d5.cloud.databricks.com": 7}, account=acct)
    assert res.resolved == {} and res.account_lookup is True
    assert res.unresolved[0][1] == "aws-deployment-name-not-in-this-account"


# ------------------------------------------------------------------------------ egress engine
def _observed(rows):
    return pd.DataFrame(
        [
            {
                "destination": d,
                "destination_type": "DNS",
                "events": n,
                "workspace_ids": [1],
                "resolved_ips": [],
            }
            for d, n in rows
        ]
    )


def test_analyze_turns_databricks_hosts_into_cross_workspace_destinations(monkeypatch):
    observed = _observed(
        [
            ("mcp-demo-7474650000000001.aws.databricksapps.com", 20),
            ("7474650000000002.ai-gateway.cloud.databricks.com", 8),
            ("7474650000000009.ai-gateway.cloud.databricks.com", 4),  # own workspace
            ("docs.databricks.com", 2),
            ("api.openai.com", 5),
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off", policy_scope="all_workspaces")
    a = eg.analyze(cfg, sql_conn=None, own_workspace_id=7474650000000009)
    assert eg.union(a.targets, "internet") == {"api.openai.com": 5}
    assert a.xws is not None and a.xws.workspace_ids == [7474650000000001, 7474650000000002]
    assert a.xws_selected == [7474650000000001, 7474650000000002]
    assert a.skipped_databricks_urls == ["docs.databricks.com"]  # only the unresolved host is flagged
    assert a.databricks_hosts["mcp-demo-7474650000000001.aws.databricksapps.com"] == 20
    na = eg.build_blocks(a, cfg)[eg.ALL_WORKSPACES].as_dict()["network_access"]
    assert na["allowed_databricks_destinations"] == [{"workspace_ids": [7474650000000001, 7474650000000002]}]
    assert {d["destination"] for d in na["allowed_internet_destinations"]} == {"api.openai.com"}


def test_cross_workspace_off_leaves_hosts_flagged_only(monkeypatch):
    observed = _observed([("mcp-demo-7474650000000001.aws.databricksapps.com", 20), ("api.openai.com", 5)])
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    cfg = EgressConfig(
        enable_rdap=False,
        block_threat_domains="off",
        policy_scope="all_workspaces",
        cross_workspace_destinations=False,
    )
    a = eg.analyze(cfg, sql_conn=None)
    na = eg.build_blocks(a, cfg)[eg.ALL_WORKSPACES].as_dict()["network_access"]
    assert "allowed_databricks_destinations" not in na
    assert a.xws.workspace_ids == [7474650000000001]  # still reported for the operator


def test_cross_workspace_only_block_still_builds(monkeypatch):
    # A run whose only egress is to another workspace still produces a (restricted) block.
    observed = _observed([("mcp-demo-7474650000000001.aws.databricksapps.com", 20)])
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off", policy_scope="all_workspaces")
    a = eg.analyze(cfg, sql_conn=None)
    blocks = eg.build_blocks(a, cfg)
    assert eg.ALL_WORKSPACES in blocks
    na = blocks[eg.ALL_WORKSPACES].as_dict()["network_access"]
    assert na["allowed_databricks_destinations"][0]["workspace_ids"] == [7474650000000001]


def test_per_workspace_target_never_lists_itself(monkeypatch):
    observed = pd.DataFrame(
        [
            {
                "destination": "mcp-demo-7474650000000001.aws.databricksapps.com",
                "destination_type": "DNS",
                "events": 3,
                "workspace_ids": [7474650000000001, 7474650000000002],
                "resolved_ips": [],
            }
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off", policy_scope="per_workspace")
    a = eg.analyze(cfg, sql_conn=None)
    # target 7474650000000001 is the destination itself → nothing to add → no block for it
    assert eg.xws_ids_for_target(a, cfg, 7474650000000001) == []
    assert eg.xws_ids_for_target(a, cfg, 7474650000000002) == [7474650000000001]


def test_selected_ids_can_be_pruned_before_build(monkeypatch):
    observed = _observed(
        [("a-7474650000000001.aws.databricksapps.com", 1), ("b-7474650000000002.aws.databricksapps.com", 1)]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off", policy_scope="all_workspaces")
    a = eg.analyze(cfg, sql_conn=None)
    a.xws_selected = [7474650000000002]
    na = eg.build_blocks(a, cfg)[eg.ALL_WORKSPACES].as_dict()["network_access"]
    assert na["allowed_databricks_destinations"] == [{"workspace_ids": [7474650000000002]}]


# ------------------------------------------------------------------------------ hostname validation
@pytest.mark.parametrize(
    "host,reason",
    [
        ("local", "single-label"),
        ("databricks", "single-label"),
        ("10.0.0.1", "ip-literal"),
        ("2001:db8::1", "ip-literal"),
        ("bad_host.example.com", "invalid-characters"),
        ("-leading.example.com", "invalid-characters"),
        ("host.123", "numeric-tld"),
        ("", "empty"),
    ],
)
def test_invalid_hostname_reason(host, reason):
    assert eg.invalid_hostname_reason(host) == reason


def test_valid_hostnames_pass():
    for h in ("api.openai.com", "a.b", "xn--bcher-kva.example", "sub-domain.example.co.uk", "Example.COM."):
        assert eg.invalid_hostname_reason(h) is None, h


def test_analyze_excludes_invalid_hostnames_and_flags_them(monkeypatch):
    observed = _observed([("local", 50), ("databricks", 9), ("192.0.2.10", 4), ("api.openai.com", 5)])
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off", policy_scope="all_workspaces")
    a = eg.analyze(cfg, sql_conn=None)
    assert eg.union(a.targets, "internet") == {"api.openai.com": 5}
    assert a.skipped_invalid_hosts == [
        ("192.0.2.10", "ip-literal"),
        ("databricks", "single-label"),
        ("local", "single-label"),
    ]
    na = eg.build_blocks(a, cfg)[eg.ALL_WORKSPACES].as_dict()["network_access"]
    assert {d["destination"] for d in na["allowed_internet_destinations"]} == {"api.openai.com"}


# ------------------------------------------------------------------------------ policy merge on update
def _egress_with_ids(ids):
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicy as EA,
    )
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicyDatabricksDestination as DbxDest,
    )
    from databricks.sdk.service.settings import (
        EgressNetworkPolicyNetworkAccessPolicyRestrictionMode as RM,
    )
    from databricks.sdk.service.settings import NetworkPolicyEgress

    return NetworkPolicyEgress(
        network_access=EA(
            restriction_mode=RM.RESTRICTED_ACCESS,
            allowed_databricks_destinations=[DbxDest(workspace_ids=list(ids))] if ids else None,
        )
    )


def test_merge_keeps_existing_cross_workspace_destinations():
    old, new = _egress_with_ids([1, 2]), _egress_with_ids([2, 3])
    policy._merge_databricks_destinations(old, new)
    assert new.network_access.allowed_databricks_destinations[0].workspace_ids == [1, 2, 3]


def test_merge_noop_without_existing_or_without_new_block():
    new = _egress_with_ids([3])
    policy._merge_databricks_destinations(_egress_with_ids([]), new)
    assert new.network_access.allowed_databricks_destinations[0].workspace_ids == [3]
    policy._merge_databricks_destinations(None, new)
    assert new.network_access.allowed_databricks_destinations[0].workspace_ids == [3]
    new2 = _egress_with_ids([])
    policy._merge_databricks_destinations(_egress_with_ids([7]), new2)
    assert new2.network_access.allowed_databricks_destinations[0].workspace_ids == [7]


def test_apply_egress_update_preserves_console_added_workspaces():
    class _Policies:
        def __init__(self):
            self.sent = None

        def get_network_policy_rpc(self, network_policy_id):
            from databricks.sdk.service.settings import AccountNetworkPolicy

            return AccountNetworkPolicy(
                account_id="a", network_policy_id=network_policy_id, egress=_egress_with_ids([42])
            )

        def update_network_policy_rpc(self, network_policy_id, network_policy):
            self.sent = network_policy

    acct = types.SimpleNamespace(network_policies=_Policies())
    action, pid = policy.apply_egress(acct, "a", "pol", _egress_with_ids([7]))
    assert (action, pid) == ("updated", "pol")
    assert acct.network_policies.sent.egress.network_access.allowed_databricks_destinations[
        0
    ].workspace_ids == [7, 42]
