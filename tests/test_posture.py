"""Offline tests for `posture` (core/posture.py, core/tokens.py, core/posture_report.py, the queries).

No Databricks / network: the evaluator is a pure function over a snapshot dict, the collector runs
against a fake account client, and the SQL runner against a patched sql.query.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest
from typer.testing import CliRunner

from dbx_nwp_helper import cli, queries
from dbx_nwp_helper.core import posture as P
from dbx_nwp_helper.core import posture_report, tokens

FIXTURE = Path(__file__).parent / "fixtures" / "posture_snapshot.json"

OPEN = {
    "network_policy_id": "default-policy",
    "ingress": {"public_access": {"restriction_mode": "FULL_ACCESS"}},
    "egress": {"network_access": {"restriction_mode": "FULL_ACCESS"}},
}
ALL_IPS = {"all_ip_ranges": True}
UI = {"workspace_ui": {"all_destinations": True}}


def restricted(mode_key: str, cidrs: list[str]) -> dict:
    return {
        "network_policy_id": "corp",
        mode_key: {
            "public_access": {
                "restriction_mode": "RESTRICTED_ACCESS",
                "allow_rules": [{"label": "corp", "origin": {"included_ip_ranges": {"ip_ranges": cidrs}}}],
            }
        },
    }


def pol(mode_key="ingress", allow=(), deny=()):
    return {
        "network_policy_id": "p",
        mode_key: {
            "public_access": {
                "restriction_mode": "RESTRICTED_ACCESS",
                "allow_rules": list(allow),
                "deny_rules": list(deny),
            }
        },
        "egress": {"network_access": {"restriction_mode": "FULL_ACCESS"}},
    }


def rule(label, origin, dest, auth=None):
    r = {"label": label, "origin": origin, "destination": dest}
    if auth:
        r["authentication"] = auth
    return r


def ws(policy, **kw):
    base = {
        "workspace_id": "1",
        "pricing_tier": "ENTERPRISE",
        "policy": policy,
        "assignment_read": True,
        "assigned_policy_id": None if policy is OPEN else policy.get("network_policy_id"),
        "effective_policy_id": policy.get("network_policy_id"),
        "ip_acl": [],
        "pas": None,
    }
    base.update(kw)
    return base


def run(*workspaces, sql=None, account=None):
    snap = {"workspaces": list(workspaces), "sql": sql or {}, "account": account or {"policies_read": True}}
    f, m = P.evaluate(snap)
    P.finalize_levels(f, m)
    return {x.id for x in f}, m, f


def score(policy):
    _ids, m, f = run(ws(policy))
    return m["1"]["level"], f


# ------------------------------------------------------------------------------------- maturity
def test_open_workspace_is_l0_high():
    ids, m, f = run(ws(OPEN))
    assert m["1"]["level"] == 0 and {"CBI-001", "CBI-006"} <= ids
    assert next(x for x in f if x.id == "CBI-001").severity == "high"


def test_legacy_ip_acl_is_l1():
    acl = [{"label": "corp", "enabled": True, "list_type": "ALLOW", "ip_addresses": ["203.0.113.0/24"]}]
    ids, m, _ = run(ws(OPEN, ip_acl=acl))
    assert m["1"]["level"] == 1 and "CBI-002" in ids and "CBI-001" not in ids


def test_ip_acl_not_read_is_unknown_level():
    ids, m, f = run(ws(OPEN, ip_acl=None))
    assert m["1"]["level"] is None and m["1"]["label"] == "CBI open, IP ACL unchecked"
    assert next(x for x in f if x.id == "CBI-001").severity == "medium"


def test_dry_run_is_l2_and_counts_the_gap():
    sql = {
        "inbound_policy_outcomes": {
            "rows": [
                {"workspace_id": "1", "policy_outcome": "DRY_RUN_DENIAL", "combinations": 7, "events": 30},
                {"workspace_id": "1", "policy_outcome": "ALLOWED", "combinations": 99, "events": 900},
            ]
        }
    }
    ids, m, f = run(ws(restricted("ingress_dry_run", ["198.51.100.7/32"])), sql=sql)
    assert m["1"]["level"] == 2 and "CBI-003" in ids
    assert "7 source/identity/rule combinations" in next(x for x in f if x.id == "CBI-003").detail


def test_enforced_clean_promotes_to_l4():
    p = restricted("ingress", ["198.51.100.7/32"])
    p["egress"] = {
        "network_access": {
            "restriction_mode": "RESTRICTED_ACCESS",
            "policy_enforcement": {"enforcement_mode": "ENFORCED"},
        }
    }
    ids, m, _ = run(ws(p))
    assert m["1"] == {
        "label": "Hardened",
        "level": 4,
        "why": "`corp` enforces a restricted public allow-list",
    }


def test_mode_precedence_matches_ingress():
    # Enforced restrictive rules win over a dry-run block, as in core/acl._active_ingress.
    p = restricted("ingress", ["198.51.100.7/32"])
    p["ingress_dry_run"] = restricted("ingress_dry_run", ["203.0.113.0/24"])["ingress_dry_run"]
    s = P.summarise_policy(p)
    assert s["mode"] == "enforce" and s["public"]["cidrs"] == ["198.51.100.7/32"]
    assert P.summarise_policy(OPEN)["mode"] is None


def test_private_only_is_l3_and_flags_allow_all_endpoints():
    pas = {
        "private_access_settings_id": "p",
        "private_access_level": "ACCOUNT",
        "public_access_enabled": False,
    }
    ids, m, _ = run(ws(OPEN, pas=pas))
    assert m["1"]["level"] == 3 and "CBI-007" in ids and "CBI-001" not in ids


def test_unreadable_policy_is_unknown():
    ids, m, _ = run({"workspace_id": "9", "policy_error": "403"})
    assert m["9"]["level"] is None and "CBI-018" in ids


# -------------------------------------------------------------------------------------- rules
def test_all_ips_to_all_destinations_is_open_even_when_restricted():
    level, f = score(pol(allow=[rule("everything", ALL_IPS, {"all_destinations": True})]))
    assert level == 0
    assert any(x.id == "CBI-004" and x.severity == "high" for x in f)


def test_browser_only_from_anywhere_is_b1_not_a_high_finding():
    level, f = score(pol(allow=[rule("ui-anywhere", ALL_IPS, {**UI, "apps_runtime": {}})]))
    assert level in (3, 4)
    assert not any(x.id == "CBI-004" for x in f) and any(x.id == "CBI-029" for x in f)


def test_empty_workspace_api_is_treated_as_all_apis_and_called_out():
    level, f = score(pol(allow=[rule("ui+api", ALL_IPS, {**UI, "workspace_api": {}})]))
    assert level == 0
    assert "without scopes" in next(x for x in f if x.id == "CBI-004" and x.severity == "high").detail


def test_scoped_and_read_only_api_from_anywhere_is_b2_low():
    api = {"workspace_api": {"scope_qualifier": "API_SCOPE_QUALIFIER_ALL", "scopes": ["sql"]}, **UI}
    level, f = score(pol(allow=[rule("sql-anywhere", ALL_IPS, api)]))
    hit = next(x for x in f if x.id == "CBI-028")
    assert level in (3, 4) and hit.severity == "low" and "sql" in hit.detail
    read = {"workspace_api": {"scopes": ["all-apis"], "scope_qualifier": "API_SCOPE_QUALIFIER_READ"}}
    assert score(pol(allow=[rule("r", ALL_IPS, read)]))[0] in (3, 4)
    assert score(pol(allow=[rule("a", ALL_IPS, {"workspace_api": {"scopes": ["all-apis"]}})]))[0] == 0


def test_selected_identities_from_anywhere_is_medium():
    auth = {"identity_type": "IDENTITY_TYPE_SELECTED_IDENTITIES", "identities": [{"principal_id": 1}]}
    level, f = score(pol(allow=[rule("sp", ALL_IPS, {"workspace_api": {"scopes": ["all-apis"]}}, auth)]))
    assert level in (3, 4) and any(x.id == "CBI-004" and x.severity == "medium" for x in f)


def test_all_public_except_ranges_counts_as_anywhere():
    origin = {"excluded_ip_ranges": {"ip_ranges": ["192.0.2.0/24"]}}
    assert score(pol(allow=[rule("except", origin, {"all_destinations": True})]))[0] == 0


def test_source_not_visible_through_api_is_flagged_not_judged():
    _level, f = score(pol(allow=[rule("slack-app", {}, {"workspace_api": {"scopes": ["genie"]}, **UI})]))
    assert any(x.id == "CBI-027" for x in f) and not any(x.id == "CBI-004" for x in f)


def test_broad_cidrs_and_unlabelled_rules():
    _ids, _m, f = run(ws(restricted("ingress", ["0.0.0.0/0", "52.0.0.0/12"])))
    assert any(x.id == "CBI-004" and x.severity == "high" for x in f)
    p = pol(
        allow=[
            {"origin": {}, "destination": UI},
            {"origin": ALL_IPS, "destination": {"all_destinations": True}},
        ]
    )
    _level, f = score(p)
    assert "allow rule 2 (unlabelled)" in next(x for x in f if x.id == "CBI-004").detail
    assert "allow rule 1 (unlabelled)" in next(x for x in f if x.id == "CBI-027").detail


def test_near_platform_limits():
    cidrs = [f"198.51.{i // 256}.{i % 256}/32" for i in range(1700)]
    ids, _m, _f = run(ws(restricted("ingress", cidrs)))
    assert "CBI-010" in ids


# ------------------------------------------------------------------------------------ traffic
def test_traffic_findings():
    sql = {
        "traffic_by_ip_class": {"rows": [{"workspace_id": "1", "ipv6_events": 4, "distinct_ipv6_ips": 2}]},
        "principal_network_spread": {
            "rows": [{"principal": "a@x.com", "principal_type": "user", "distinct_public_24s": 40}]
        },
        "client_families_on_public_ips": {"rows": [{"workspace_id": "1", "client_family": "Power BI"}]},
        "inbound_policy_outcomes": {"rows": [{"workspace_id": "1", "policy_outcome": "DENY", "events": 12}]},
        "audit_visibility": {"rows": [{"workspace_id": "1", "verbose_audit_disabled_events": 1}]},
    }
    ids, _, f = run(ws(restricted("ingress", ["198.51.100.7/32"])), sql=sql)
    assert {"CBI-012", "CBI-013", "CBI-014", "CBI-015", "CBI-025"} <= ids
    assert next(x for x in f if x.id == "CBI-012").severity == "high"
    ids, _, _ = run(ws(OPEN), sql={"inbound_policy_outcomes": {"error": "TABLE_OR_VIEW_NOT_FOUND"}})
    assert "CBI-011" in ids


def test_outcome_class_accepts_every_spelling():
    assert {P.outcome_class(v) for v in ("DENIED", "deny", "DROP")} == {"DENIED"}
    assert {P.outcome_class(v) for v in ("DRY_RUN_DENIAL", "DENY_DRY_RUN")} == {"DRY_RUN_DENIAL"}
    assert P.outcome_class("ALLOWED") == "ALLOWED"


def test_account_policy_open_with_traffic():
    acct = {"policies_read": True, "account_policy": {"network_policy_id": "account-policy"}}
    sql = {"account_level_public_access": {"rows": [{"public_ip": "198.51.100.1"}]}}
    _ids, _m, f = run(sql=sql, account=acct)
    assert next(x for x in f if x.id == "CBI-009").severity == "high"


def test_pattern_suggestion_b1_vs_b2_and_only_while_open():
    sql = {
        "public_browser_vs_api": {
            "rows": [{"workspace_id": "1", "programmatic_principals": 4, "browser_pct": 91}]
        }
    }
    _, _, f = run(ws(OPEN), sql=sql)
    assert "Browser yes" in next(x for x in f if x.id == "CBI-026").detail
    sql["public_browser_vs_api"]["rows"][0]["programmatic_principals"] = 300
    _, _, f = run(ws(OPEN), sql=sql)
    assert "API families" in next(x for x in f if x.id == "CBI-026").detail
    ids, _, _ = run(ws(restricted("ingress", ["198.51.100.7/32"])), sql=sql)
    assert "CBI-026" not in ids
    p = pol(allow=[rule("ui-anywhere", ALL_IPS, UI), rule("everything", ALL_IPS, {"all_destinations": True})])
    _level, f = score(p)
    assert "Already uses B1" in next(x for x in f if x.id == "CBI-026").detail


def test_every_next_step_is_propose_only_or_explicitly_gated():
    snap = json.loads(FIXTURE.read_text())
    f, _m = P.evaluate(snap)
    for x in f:
        if "--create-policy" in x.next_step or "set-status" in x.next_step:
            assert "only after explicit approval" in x.next_step
        assert not x.next_step or x.next_step.startswith(("dbx-nwp-helper ", "databricks "))
        assert "token-management delete" not in x.next_step  # revocations are only listed in the CSV


def test_sample_account_snapshot():
    snap = json.loads(FIXTURE.read_text())
    f, m = P.evaluate(snap)
    P.finalize_levels(f, m)
    assert {w: v["level"] for w, v in m.items()} == {"1001": 0, "1002": 1, "1003": 2, "1004": 3}
    assert {"CBI-001", "CBI-002", "CBI-003", "CBI-009", "CBI-012"} <= {x.id for x in f}


# -------------------------------------------------------------------------------------- report
def _snap(*workspaces):
    return {
        "workspaces": list(workspaces),
        "sql": {"traffic_by_ip_class": {"error": "PERMISSION_DENIED"}},
        "account": {"policies_read": True},
        "generated_at": "2026-11-18T00:00:00+00:00",
        "lookback_days": 30,
    }


def test_report_writes_its_files_and_shows_gaps(tmp_path):
    snap = _snap(ws(OPEN))
    f, m = P.evaluate(snap)
    path = posture_report.write(str(tmp_path), snap, f, m)
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "findings.csv",
        "maturity.csv",
        "posture.json",
        "report.md",
        "tokens-to-revoke.csv",
    ]
    md = path.read_text()
    assert "## Maturity by workspace" in md and "·  workspace `1`" in md
    assert "PERMISSION_DENIED" in md
    assert json.loads((tmp_path / "posture.json").read_text())["lookback_days"] == 30


def test_large_account_report_groups_findings_by_check():
    many = [ws(OPEN, workspace_id=str(1000 + i), workspace_name=f"ws-{i}", ip_acl=None) for i in range(14)]
    many.append(ws(restricted("ingress", ["198.51.100.0/24"]), workspace_id="2000", workspace_name="locked"))
    snap = _snap(*many)
    f, m = P.evaluate(snap)
    P.finalize_levels(f, m)
    md = posture_report.render_markdown(snap, f, m)
    assert "## Maturity across the account" in md and "| ? CBI open, IP ACL unchecked | 14 |" in md
    assert "Workspaces with a CBI policy or a perimeter (1)" in md and "| 2000 | locked |" in md
    assert md.count("CBI-001: ") <= 1 and "14 workspace(s)" in md


# -------------------------------------------------------------------------------------- queries
def test_posture_queries_are_select_only_portable_and_scoped():
    for inet in (True, False):
        for table in (None, "`c`.`s`.`dbx_nwp_posture_daily`"):
            qs = P.posture_queries(30, inet, ["123"], table)
            assert set(qs) == set(P.SQL_STEPS)
            for name, q in qs.items():
                assert q.lstrip().upper().startswith(("WITH", "SELECT")), name
                assert not any(w in q.upper() for w in ("INSERT ", "CREATE ", "DELETE ", "UPDATE ", "MERGE "))
                assert "IN ('123', '0')" in q, name
    native = P.posture_queries(30, True, None)["traffic_by_ip_class"]
    assert "ip_cidr_contains" in native
    assert "ip_cidr_contains" not in P.posture_queries(30, False, None)["traffic_by_ip_class"]


def test_rollup_is_read_from_the_table_instead_of_the_audit_log():
    t = "`c`.`s`.`dbx_nwp_posture_daily`"
    for name, q in P.posture_queries(30, False, None, t).items():
        if name != "inbound_policy_outcomes":
            assert f"FROM {t}" in q and "system.access.audit" not in q, name
    direct = P.posture_queries(30, False, None)["traffic_by_ip_class"]
    assert "FROM system.access.audit" in direct


def test_rollup_reuses_the_ingress_definitions_of_public():
    roll = queries.posture_rollup_select("TRUE", use_inet=False)
    assert queries._not_private(False) in roll and "request_params" in roll
    assert "request_params" not in queries._audit_projection(False, "TRUE")  # ingress projection unchanged


def test_rollup_tables_and_scope_validation():
    ddl = queries.posture_daily_table_ddl("t")
    ins = queries.posture_daily_table_insert("t", "2026-11-01", "2026-11-02", use_inet=False)
    assert ddl.strip().startswith("CREATE TABLE IF NOT EXISTS t") and "loaded_at" in ddl
    assert ins.strip().startswith("INSERT INTO t") and "BETWEEN DATE'2026-11-01' AND DATE'2026-11-02'" in ins
    stage = queries.posture_stage_table("s", 30, False, ["5"])
    assert stage.startswith("CREATE OR REPLACE TABLE s AS") and "IN ('5', '0')" in stage
    assert "IN ('5', '0')" in queries.posture_inbound_outcomes(30, ["5"])
    with pytest.raises(ValueError):
        queries.posture_inbound_outcomes(30, ["5 OR 1=1"])


# ------------------------------------------------------------------------------- collection
def _account():
    pol_obj = SimpleNamespace(as_dict=lambda: restricted("ingress", ["198.51.100.7/32"]))
    w = SimpleNamespace(
        workspace_id=11,
        workspace_name="w",
        deployment_name="dbc-x",
        pricing_tier=SimpleNamespace(value="ENTERPRISE"),
        cloud="aws",
        private_access_settings_id=None,
    )
    return SimpleNamespace(
        network_policies=SimpleNamespace(
            list_network_policies_rpc=lambda: [SimpleNamespace(as_dict=lambda: OPEN)],
            get_network_policy_rpc=lambda network_policy_id: pol_obj,
        ),
        settings=SimpleNamespace(
            enable_ip_access_lists=SimpleNamespace(
                get=lambda: SimpleNamespace(acct_ip_acl_enable=SimpleNamespace(value=False))
            )
        ),
        ip_access_lists=SimpleNamespace(list=lambda: []),
        workspaces=SimpleNamespace(list=lambda: [w], get=lambda workspace_id: w),
        workspace_network_configuration=SimpleNamespace(
            get_workspace_network_option_rpc=lambda workspace_id: SimpleNamespace(network_policy_id="corp")
        ),
    )


def test_collect_account_uses_the_ingress_readers():
    acct, wss = P.collect_account(_account(), None)
    assert acct["policies_read"] and acct["account_ip_acl"]["enabled"] is False
    (w,) = wss
    assert w["assigned_policy_id"] == "corp" and w["pas"] is None and w["cloud"] == "aws"
    assert P.summarise_policy(w["policy"])["mode"] == "enforce"
    acct, wss = P.collect_account(_account(), {"999"})
    assert wss == []


def test_collect_account_records_errors_instead_of_raising():
    a = _account()
    a.network_policies.list_network_policies_rpc = lambda: (_ for _ in ()).throw(PermissionError("not admin"))
    acct, _wss = P.collect_account(a, None)
    assert "not admin" in acct["error"]
    ids, _m, _f = run(account=acct)
    assert "CBI-018" in ids


def test_workspace_ip_acl_off_reads_as_disabled():
    wc = SimpleNamespace(
        workspace_conf=SimpleNamespace(get_status=lambda keys: {"enableIpAccessLists": "false"}),
        ip_access_lists=SimpleNamespace(
            list=lambda: [
                SimpleNamespace(
                    label="corp", list_type=SimpleNamespace(value="ALLOW"), enabled=True, ip_addresses=[]
                )
            ]
        ),
    )
    assert P.collect_workspace_ip_acl(wc) == [
        {"label": "corp", "list_type": "ALLOW", "enabled": False, "ip_addresses": []}
    ]


class _FakeSQL:
    """Records every statement per connection; queries return one row, inbound_network fails."""

    def __init__(self):
        self.executed, self.queried, self.connections = [], [], 0

    def connect(self):
        import contextlib

        fake = self

        @contextlib.contextmanager
        def cm():
            fake.connections += 1
            yield object()

        return cm()

    def query(self, _c, stmt):
        self.queried.append(stmt)
        if "inbound_network" in stmt:
            raise RuntimeError("TABLE_OR_VIEW_NOT_FOUND")
        if "MIN(event_date) AS lo" in stmt:
            return pd.DataFrame([{"lo": None, "hi": None, "rows": 0}])
        if "current_date() AS today" in stmt:
            return pd.DataFrame([{"today": "2026-11-20"}])
        return pd.DataFrame([{"workspace_id": "1", "events": 3, "last_seen": pd.Timestamp("2026-11-01")}])

    def execute(self, _c, stmt):
        self.executed.append(stmt)


@pytest.fixture
def fake_sql(monkeypatch):
    from dbx_nwp_helper import sql
    from dbx_nwp_helper.core import ingress

    f = _FakeSQL()
    monkeypatch.setattr(ingress, "_detect_inet", lambda _c: False)
    monkeypatch.setattr(sql, "query", f.query)
    monkeypatch.setattr(sql, "execute", f.execute)
    return f


def test_run_sql_direct_records_each_result_and_error(fake_sql):
    out = P.run_sql(fake_sql.connect, 30, ["1"], parallel=1)
    assert set(out) == set(P.SQL_STEPS) and fake_sql.executed == []
    assert "TABLE_OR_VIEW_NOT_FOUND" in out["inbound_policy_outcomes"]["error"]
    assert out["traffic_by_ip_class"]["rows"] == [
        {"workspace_id": "1", "events": 3, "last_seen": "2026-11-01T00:00:00"}
    ]
    json.dumps(out)  # JSON-able for posture.json


def test_run_sql_parallel_opens_one_connection_per_query(fake_sql):
    out = P.run_sql(fake_sql.connect, 30, None, parallel=4)
    assert set(out) == set(P.SQL_STEPS) and fake_sql.connections == 1 + len(P.SQL_STEPS)


def test_stage_schema_scans_once_reads_the_table_and_drops_it(fake_sql):
    P.run_sql(fake_sql.connect, 30, ["1"], stage_schema="main.tmp", parallel=1)
    create, drop = fake_sql.executed
    assert create.startswith("CREATE OR REPLACE TABLE `main`.`tmp`.`dbx_nwp_posture_stage_")
    table = create.split(" AS ", 1)[0].removeprefix("CREATE OR REPLACE TABLE ")
    assert drop == f"DROP TABLE IF EXISTS {table}"
    audit_reads = [q for q in fake_sql.queried if "system.access.audit" in q]
    assert audit_reads == [] and all(table in q for q in fake_sql.queried if "inbound_network" not in q)


def test_stage_table_is_dropped_even_when_a_query_crashes(fake_sql, monkeypatch):
    monkeypatch.setattr(P, "_run_all", lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        P.run_sql(fake_sql.connect, 30, None, stage_schema="main.tmp")
    assert fake_sql.executed[-1].startswith("DROP TABLE IF EXISTS `main`.`tmp`.`dbx_nwp_posture_stage_")


def test_uc_schema_syncs_the_persisted_rollup_then_reads_it(fake_sql):
    P.run_sql(fake_sql.connect, 30, None, uc_schema="main.sec", parallel=1)
    t = "`main`.`sec`.`dbx_nwp_posture_daily`"
    ddl, insert = fake_sql.executed
    assert ddl.strip().startswith(f"CREATE TABLE IF NOT EXISTS {t}") and insert.strip().startswith(
        f"INSERT INTO {t}"
    )
    checks = [q for q in fake_sql.queried if "MIN(event_date) AS lo" not in q and "today" not in q]
    assert all(f"FROM {t}" in q for q in checks if "inbound_network" not in q)


# ------------------------------------------------------------------------------------------ CLI
def test_cli_registers_posture_and_validates_options():
    for args, msg in (
        (["--workspace-id", "abc"], "must be numeric"),
        (["--stage-schema", "a.b", "--uc-schema", "c.d"], "not both"),
        (["--refresh-persisted"], "only applies together with --uc-schema"),
        (["--parallel", "0"], "between 1 and 8"),
    ):
        r = CliRunner().invoke(cli.app, ["posture", *args])
        assert r.exit_code != 0 and msg.replace(" ", "") in "".join(r.output.split()), (args, r.output)


# ---------------------------------------------------------------- regressions from code review
def test_all_users_from_any_ip_to_all_apis_is_open():
    auth = {"identity_type": "IDENTITY_TYPE_ALL_USERS"}
    level, f = score(pol(allow=[rule("users", ALL_IPS, {"all_destinations": True}, auth)]))
    assert level == 0 and any(x.id == "CBI-004" and x.severity == "high" for x in f)


def test_commands_for_other_workspaces_never_use_the_run_profile():
    snap = {
        "workspace_profile": "mine",
        "workspaces": [ws(OPEN, workspace_id="1", profile="mine"), ws(OPEN, workspace_id="2")],
        "sql": {},
        "account": {"policies_read": True},
    }
    f, _m = P.evaluate(snap)
    other = [x.next_step for x in f if x.workspace_id == "2" and x.next_step]
    assert other and all("--profile <profile-for-workspace-2>" in c for c in other)
    assert any("--profile mine" in x.next_step for x in f if x.workspace_id == "1")


def test_unreadable_ip_access_lists_are_unknown_not_empty():
    def boom():
        raise PermissionError("403")

    wc = SimpleNamespace(
        workspace_conf=SimpleNamespace(get_status=lambda keys: {"enableIpAccessLists": "true"}),
        ip_access_lists=SimpleNamespace(list=boom),
    )
    assert P.collect_workspace_ip_acl(wc) is None


def test_workspace_list_failure_still_assesses_the_run_workspace():
    a = _account()
    a.workspaces.list = lambda: (_ for _ in ()).throw(RuntimeError("not on Azure"))
    acct, wss = P.collect_account(a, None, fallback_workspace_id=11)
    assert "not on Azure" in acct["workspaces_error"] and [w["workspace_id"] for w in wss] == ["11"]


def test_account_policy_open_in_effect_via_account_api():
    acct_pol = pol(allow=[rule("acct-api", ALL_IPS, {"account_api": {}})])
    acct_pol["network_policy_id"] = "account-policy"
    _ids, _m, f = run(account={"policies_read": True, "account_policy": acct_pol})
    assert any(x.id == "CBI-009" and "let any IP call the account APIs" in x.detail for x in f)


def test_short_lookback_skips_the_new_source_query(fake_sql):
    out = P.run_sql(fake_sql.connect, 1, None, parallel=1)
    assert out["new_source_identity_pairs"]["error"].startswith("skipped")


def test_unreadable_policy_mode_is_unknown():
    rows = posture_report.maturity_rows({"workspaces": [{"workspace_id": "9", "policy_error": "403"}]}, {})
    assert rows[0]["mode"] == "unknown"


# ----------------------------------------------------------------------------------------- tokens
NOW_MS = 1795000000000  # 2026-11-18


def _pat(**kw):
    base = {
        "max_token_lifetime_days": None,
        "tokens_enabled": True,
        "all_users_can_use": True,
        "tokens": [
            {"token_id": "t1", "created_by_username": "a@x.com", "expiry_time": -1, "scopes": []},
            {
                "token_id": "t2",
                "created_by_username": "b@x.com",
                "expiry_time": NOW_MS + 5 * 86400000,
                "scopes": ["sql"],
                "last_used_day": NOW_MS - 200 * 86400000,
            },
            {"token_id": "t3", "expiry_time": NOW_MS + 86400000, "scopes": ["sql"], "last_used_day": NOW_MS},
        ],
    }
    base.update(kw)
    return base


def _with_tokens(policy, pat, **kw):
    snap = {
        "generated_at": "2026-11-18T00:00:00+00:00",
        "lookback_days": 30,
        "workspaces": [ws(policy, pat=pat, profile="mine", **kw)],
        "sql": {},
        "account": {"policies_read": True},
    }
    f, m = P.evaluate(snap)
    P.finalize_levels(f, m)
    return snap, {x.id: x for x in f}, m


def test_token_findings_and_urgency_follow_ingress():
    _snap_, by, _m = _with_tokens(OPEN, _pat())
    assert {"CBI-020", "CBI-021", "CBI-022", "CBI-023", "CBI-024"} <= set(by)
    assert by["CBI-020"].severity == "high" and "from anywhere" in by["CBI-020"].detail
    _snap_, by, _m = _with_tokens(restricted("ingress", ["198.51.100.7/32"]), _pat())
    assert by["CBI-020"].severity == "medium"


def test_no_token_findings_when_not_collected_and_never_customised_is_info():
    ids, _m, _f = run(ws(OPEN))
    assert not ids & {"CBI-020", "CBI-021", "CBI-022", "CBI-023", "CBI-024"}
    pat = {
        "max_token_lifetime_days": "30",
        "tokens_enabled": True,
        "tokens": [],
        "permissions_customised": False,
    }
    _snap_, by, _m = _with_tokens(OPEN, pat)
    assert by["CBI-022"].severity == "info" and set(by) & {"CBI-020", "CBI-021"} == set()


def test_unexpiring_tokens_hold_back_l4():
    p = restricted("ingress", ["198.51.100.7/32"])
    p["egress"] = {
        "network_access": {
            "restriction_mode": "RESTRICTED_ACCESS",
            "policy_enforcement": {"enforcement_mode": "ENFORCED"},
        }
    }
    _snap_, _by, m = _with_tokens(p, _pat(all_users_can_use=False, max_token_lifetime_days="7"))
    assert m["1"]["level"] == 3


def test_tokens_to_revoke_lists_reasons_and_commands_but_revokes_nothing(tmp_path):
    snap, _by, m = _with_tokens(OPEN, _pat())
    rows = posture_report.token_rows(snap)
    assert [r["token_id"] for r in rows] == ["t1", "t2"]  # t3 is short-lived, used and scoped
    assert rows[0]["reasons"] == "never expires; no API scopes (all APIs)" and rows[0]["expires"] == "never"
    assert rows[1]["reasons"].startswith("unused for 200 days")
    assert rows[0]["revoke_command"] == "databricks token-management delete t1 -p mine"
    f, _ = P.evaluate(snap)
    posture_report.write(str(tmp_path), snap, f, m)
    assert "t1" in (tmp_path / "tokens-to-revoke.csv").read_text()


def test_token_collection_reads_metadata_and_records_errors():
    perm = SimpleNamespace(
        access_control_list=[
            SimpleNamespace(
                group_name="users",
                all_permissions=[SimpleNamespace(permission_level=SimpleNamespace(value="CAN_USE"))],
            )
        ]
    )
    tok = SimpleNamespace(as_dict=lambda: {"token_id": "t1", "expiry_time": -1, "comment": "drop me"})
    wc = SimpleNamespace(
        workspace_conf=SimpleNamespace(
            get_status=lambda keys: {"maxTokenLifetimeDays": "", "enableTokensConfig": "true"}
        ),
        token_management=SimpleNamespace(list=lambda: [tok]),
        permissions=SimpleNamespace(get=lambda **k: perm),
    )
    out = tokens.collect(wc)
    assert out["tokens"] == [{"token_id": "t1", "expiry_time": -1}] and out["all_users_can_use"] is True

    def denied(**_k):
        raise PermissionError("not admin")

    wc.token_management = SimpleNamespace(list=lambda: denied())
    wc.permissions = SimpleNamespace(get=denied)
    out = tokens.collect(wc)
    assert "not admin" in out["tokens_error"] and "not admin" in out["permissions_error"]
