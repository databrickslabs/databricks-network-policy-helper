"""Unity Catalog persistence (--uc-schema): table naming, incremental sync planning, the daily-table
SQL builders, the suggestions snapshot, and analyze() reading from the persisted table."""

from __future__ import annotations

import datetime as dt

import pandas as pd
import pytest

from dbx_nwp_helper import queries
from dbx_nwp_helper.config import (
    UC_DAILY_TABLE,
    UC_SUGGESTIONS_TABLE,
    EgressConfig,
    IngressConfig,
    validate_limits,
    validate_uc_schema,
)
from dbx_nwp_helper.core import ingress as ing
from dbx_nwp_helper.core import ingress_rules as rules
from dbx_nwp_helper.core import persist
from dbx_nwp_helper.core.ingress import ALL_WORKSPACES, IngressAnalysis

D = dt.date


# --------------------------------------------------------------------------------- config
def test_validate_uc_schema_accepts_two_part_names():
    for ok in ("main.security", "`my-cat`.`net policy`", "cat_1.s2"):
        validate_uc_schema(ok)
    validate_uc_schema("")  # blank = off


@pytest.mark.parametrize("bad", ["main", "a.b.c", "a b.c", ".x", "x."])
def test_validate_uc_schema_rejects_other_shapes(bad):
    with pytest.raises(ValueError):
        validate_uc_schema(bad)


def test_validate_limits_rejects_non_positive():
    validate_limits(50, 2000)
    with pytest.raises(ValueError):
        validate_limits(0, 2000)
    with pytest.raises(ValueError):
        validate_limits(50, -1)


def test_tables_quotes_each_part():
    src = persist.tables("main.security")
    assert src.daily_table == f"`main`.`security`.`{UC_DAILY_TABLE}`"
    assert src.suggestions_table == f"`main`.`security`.`{UC_SUGGESTIONS_TABLE}`"
    src = persist.tables("`my-cat`.`sch`")
    assert src.daily_table.startswith("`my-cat`.`sch`.")


# --------------------------------------------------------------------------------- plan_sync
def test_plan_sync_empty_table_is_one_full_window():
    windows, delete_from = persist.plan_sync(None, None, D(2026, 11, 5), 30, refresh=False)
    assert windows == [(D(2026, 10, 6), D(2026, 11, 5))] and delete_from is None


def test_plan_sync_rereads_tail_only_when_table_is_current():
    windows, delete_from = persist.plan_sync(D(2026, 9, 1), D(2026, 11, 4), D(2026, 11, 5), 30, refresh=False)
    # last two persisted days are re-read (late-arriving audit rows) + today
    assert windows == [(D(2026, 11, 3), D(2026, 11, 5))] and delete_from == D(2026, 11, 3)


def test_plan_sync_backfills_when_lookback_grows():
    windows, delete_from = persist.plan_sync(
        D(2026, 10, 20), D(2026, 11, 4), D(2026, 11, 5), 60, refresh=False
    )
    assert windows[0] == (D(2026, 9, 6), D(2026, 10, 19))  # the older days the table lacks
    assert windows[1] == (D(2026, 11, 3), D(2026, 11, 5))
    assert delete_from == D(2026, 11, 3)


def test_plan_sync_tail_never_precedes_window_start():
    # Stale table (last row 40 days ago) with a 30-day lookback: re-read only from the window start.
    windows, delete_from = persist.plan_sync(D(2026, 1, 1), D(2026, 9, 25), D(2026, 11, 5), 30, refresh=False)
    assert windows == [(D(2026, 10, 6), D(2026, 11, 5))] and delete_from == D(2026, 10, 6)


def test_plan_sync_refresh_is_full_window():
    windows, delete_from = persist.plan_sync(D(2026, 1, 1), D(2026, 11, 4), D(2026, 11, 5), 7, refresh=True)
    assert windows == [(D(2026, 10, 29), D(2026, 11, 5))] and delete_from is None


# --------------------------------------------------------------------------------- sync_daily
class _Recorder:
    """Stands in for the sql module: records statements, answers the bounds / today probes."""

    def __init__(self, lo=None, hi=None, rows=0, today=D(2026, 11, 5)):
        self.executed: list[str] = []
        self.lo, self.hi, self.rows, self.today = lo, hi, rows, today

    def query(self, _conn, text):
        if "MIN(event_date)" in text:
            return pd.DataFrame([{"lo": self.lo, "hi": self.hi, "rows": self.rows}])
        if "current_date()" in text and "today" in text:
            return pd.DataFrame([{"today": self.today}])
        raise AssertionError(f"unexpected query: {text[:80]}")

    def execute(self, _conn, text):
        self.executed.append(" ".join(text.split()))


def _patch_sql(monkeypatch, rec):
    import dbx_nwp_helper.sql as sqlmod

    monkeypatch.setattr(sqlmod, "query", rec.query)
    monkeypatch.setattr(sqlmod, "execute", rec.execute)


def test_sync_daily_first_run_inserts_full_window(monkeypatch):
    rec = _Recorder()
    _patch_sql(monkeypatch, rec)
    src = persist.tables("main.sec")
    notes = []
    out = persist.sync_ingress_daily(
        None, src, IngressConfig(lookback_days=30, uc_schema="main.sec"), True, notes.append
    )
    assert out["rows_before"] == 0 and len(out["windows"]) == 1
    assert len(rec.executed) == 1
    ins = rec.executed[0]
    assert ins.startswith(f"INSERT INTO {src.daily_table}")
    assert "DATE'2026-10-06' AND DATE'2026-11-05'" in ins
    assert "try_ip_host(source_ip_address)" in ins  # native path
    assert "GROUP BY event_date, CAST(workspace_id AS STRING), normalized_ip, outcome" in ins
    assert "DELETE" not in ins


def test_sync_daily_incremental_deletes_tail_then_inserts(monkeypatch):
    rec = _Recorder(lo=D(2026, 9, 1), hi=D(2026, 11, 4), rows=5000)
    _patch_sql(monkeypatch, rec)
    src = persist.tables("main.sec")
    persist.sync_ingress_daily(
        None, src, IngressConfig(lookback_days=30, uc_schema="main.sec"), False, lambda _m: None
    )
    assert len(rec.executed) == 2
    assert rec.executed[0] == f"DELETE FROM {src.daily_table} WHERE event_date >= DATE'2026-11-03'"
    assert "DATE'2026-11-03' AND DATE'2026-11-05'" in rec.executed[1]
    assert "RLIKE" in rec.executed[1]  # portable path when INET isn't available


def test_sync_daily_refresh_clears_then_rebuilds(monkeypatch):
    rec = _Recorder(lo=D(2026, 9, 1), hi=D(2026, 11, 4), rows=5000)
    _patch_sql(monkeypatch, rec)
    src = persist.tables("main.sec")
    cfg = IngressConfig(lookback_days=7, uc_schema="main.sec", refresh_persisted=True)
    persist.sync_ingress_daily(None, src, cfg, True, lambda _m: None)
    assert rec.executed[0] == f"DELETE FROM {src.daily_table}"
    assert "DATE'2026-10-29' AND DATE'2026-11-05'" in rec.executed[1] and len(rec.executed) == 2


# --------------------------------------------------------------------------------- query builders
def test_daily_table_ddl_and_insert_shape():
    ddl = queries.daily_table_ddl("`c`.`s`.`t`")
    assert "CREATE TABLE IF NOT EXISTS `c`.`s`.`t`" in ddl and "ipv4_long BIGINT" in ddl
    ins = queries.daily_table_insert("`c`.`s`.`t`", "2026-01-01", "2026-01-31", use_inet=True)
    assert "WHEN action_name = 'IpAccessDenied' OR status_code = 403 THEN 'denied'" in ins
    assert "WHEN status_code IS NULL THEN 'null_status'" in ins
    assert "WHEN status_code < 400 THEN 'success'" in ins
    assert "AS ipv4_long" in ins  # stored even on the native path so reads never need INET


def test_persisted_frequent_public_ips_applies_run_filters():
    q = queries.persisted_frequent_public_ips("`t`", 14, 3, False, False, False, only_workspace_id=None)
    assert "INTERVAL 14 DAYS" in q and "HAVING SUM(events) >= 3" in q
    assert "outcome IN ('success')" in q and "AND workspace_id <> '0'" in q
    assert "ip_version = 4 )" in q.replace("\n", " ") or "ip_version = 4 " in q
    assert (
        "ipv4_long BETWEEN" in q and "public_ip = '0.0.0.0'" in q
    )  # portable private check on stored column
    assert "normalized_ip" not in q
    q = queries.persisted_frequent_public_ips("`t`", 14, 1, True, True, True, only_workspace_id=42)
    assert "outcome IN ('success', 'null_status')" in q and "OR ip_version = 6" in q
    assert "AND workspace_id = '42'" in q and "<> '0'" not in q
    # same output columns as the live query, so enrichment is unchanged
    for col in ("principal_list", "principal_emails", "subject_names", "service_list", "workspace_ids"):
        assert f"AS {col}" in q


def test_persisted_denied_requests_shape():
    q = queries.persisted_denied_requests("`t`", 30, only_workspace_id=7)
    assert "outcome = 'denied'" in q and "AS denied_events" in q and "workspace_id = '7'" in q


# --------------------------------------------------------------------------------- snapshot
def _row(owner, cidr, target=ALL_WORKSPACES, **kw):
    base = {
        "policy_target": target,
        "rdap_owner": owner,
        "distinct_ips": 1,
        "total_events": 5,
        "principals": [],
        "principal_emails": [],
        "subject_names": [],
        "scoped_destination": "all_destinations",
        "minimal_cidrs": [cidr],
        "optimal_cidrs": [cidr],
        "maximum_cidrs": None,
        "threat_feeds": None,
        "cloud_provider": None,
        "databricks_owned": None,
        "partners": None,
        "recommendation": "REVIEW — Other hosting provider",
    }
    base.update(kw)
    return base


def test_snapshot_rows_classifies_every_group():
    full = [
        _row("Kept Co", "1.1.1.1/32", total_events=100),
        _row("Mid Co", "6.6.6.6/32", total_events=20),
        _row("Folded Co", "2.2.2.2/32", total_events=1),
        _row("Bad Co", "3.3.3.3/32", threat_feeds=["ipsum"]),
        _row("Gone Co", "4.4.4.4/32"),  # deselected by the operator
        _row("Power BI", "5.5.5.5/32", partners=["Power BI"]),
    ]
    selected = [r for r in full if r["rdap_owner"] != "Gone Co"]
    analysis = IngressAnalysis(
        candidates=pd.DataFrame(),
        suggestions=pd.DataFrame(selected),
        threat_matches=pd.DataFrame(),
        denied_requests=pd.DataFrame(columns=["source_ip"]),
        ip_acls=[],
        suggestion_rows=selected,
    )
    cfg = IngressConfig(consolidate_rules=True, exclude_partner_cidrs=True, max_rules=2)
    policies = rules.build_rules(analysis, cfg)
    rows = persist.snapshot_rows(
        analysis,
        cfg,
        policies,
        suggestion_rows_full=full,
        framing_col="minimal_cidrs",
        group_label=rules._group_label,
    )
    status = {r["rdap_owner"]: r["status"] for r in rows}
    assert status["Kept Co"] == "kept"  # highest traffic keeps its named rule (cap = 2 → 1 named + 1 folded)
    assert status["Mid Co"] == "consolidated" and status["Folded Co"] == "consolidated"
    assert status["Bad Co"] == "excluded_threat"
    assert status["Gone Co"] == "deselected"
    assert status["Power BI"] == "excluded_partner"
    folded = next(r for r in rows if r["rdap_owner"] == "Folded Co")
    assert folded["consolidated_into"].startswith("Consolidated-Observed-IPs")
    assert folded["cidrs"] == ["2.2.2.2/32"] and folded["rule_label"] == "Folded-Co"


def test_write_suggestions_emits_batched_literal_inserts(monkeypatch):
    rec = _Recorder()
    _patch_sql(monkeypatch, rec)
    src = persist.tables("main.sec")
    rows = [
        {
            "policy_target": ALL_WORKSPACES,
            "rule_label": "O'Brien-Ltd",
            "rdap_owner": "O'Brien Ltd",
            "recommendation": "REVIEW",
            "distinct_ips": 2,
            "total_events": 9,
            "cidrs": ["1.1.1.1/32", "1.1.1.2/32"],
            "status": "kept",
            "consolidated_into": None,
        }
    ] * 250
    run_id = persist.write_suggestions(
        None, src, rows, cfg=IngressConfig(), workspace_id=123, policy_name="pol", written=False
    )
    assert len(run_id) == 12
    assert len(rec.executed) == 2  # 200 + 50
    first = rec.executed[0]
    assert first.startswith(f"INSERT INTO {src.suggestions_table} (run_id, run_at")
    assert "O\\'Brien-Ltd" in first  # quotes escaped
    assert "array('1.1.1.1/32', '1.1.1.2/32')" in first and "'kept', NULL, FALSE" in first
    assert f"'{run_id}', current_timestamp(), '123', 'pol', 'dry_run', 'minimal', '__ALL__'" in first


def test_lit_handles_empty_array_and_bool():
    assert persist._lit([]) == "CAST(array() AS ARRAY<STRING>)"
    assert persist._lit(True) == "TRUE" and persist._lit(None) == "NULL" and persist._lit(3) == "3"


# --------------------------------------------------------------------------------- analyze() path
class _FakeIpAclApi:
    def list(self):
        return []


class _FakeWorkspaceClient:
    ip_access_lists = _FakeIpAclApi()

    def get_workspace_id(self):
        return 123


def test_analyze_with_uc_schema_reads_from_persisted_table(monkeypatch):
    from dbx_nwp_helper.feeds import loaders

    for name, cols in (
        ("threat_intel", ["cidr", "source_feed", "threat_type", "confidence", "source_url", "loaded_at"]),
        ("partner_ranges", ["cidr", "partner", "region", "source_url", "loaded_at"]),
        ("cloud_ranges", ["cidr", "provider", "service", "region", "loaded_at"]),
        ("databricks_ranges", ["cidr", "platform", "region", "direction", "loaded_at"]),
    ):
        monkeypatch.setattr(loaders, name, lambda *a, _c=cols, **k: pd.DataFrame([], columns=_c))
    import dbx_nwp_helper.sql as sqlmod

    seen = []
    daily = "`main`.`sec`.`dbx_nwp_ingress_daily`"

    def fake_query(_conn, text):
        seen.append(" ".join(text.split()))
        if "ip_cidr_contains('10.0.0.0/8'" in text:
            return pd.DataFrame([{"ok": True}])
        if "AS lo" in text:
            return pd.DataFrame([{"lo": None, "hi": None, "rows": 0}])
        if "AS today" in text:
            return pd.DataFrame([{"today": D(2026, 11, 5)}])
        if "inbound_network" in text:
            return pd.DataFrame()
        if "outcome = 'denied'" in text:
            return pd.DataFrame(columns=["source_ip"])
        if daily in text:
            return pd.DataFrame(
                [
                    {
                        "public_ip": "203.0.55.10",
                        "ip_version": 4,
                        "events": 100,
                        "principals": 1,
                        "services": 1,
                        "actions": 1,
                        "active_days": 2,
                        "sessions": 2,
                        "first_active_date": "2026-11-01",
                        "last_active_date": "2026-11-02",
                        "principal_list": ["a@x.com"],
                        "principal_emails": ["a@x.com"],
                        "subject_names": [],
                        "service_list": ["jobs"],
                        "workspace_ids": ["123"],
                    }
                ]
            )
        raise AssertionError(f"unexpected live query: {text[:120]}")

    executed = []
    monkeypatch.setattr(sqlmod, "query", fake_query)
    monkeypatch.setattr(sqlmod, "execute", lambda _c, t: executed.append(" ".join(t.split())))
    cfg = IngressConfig(enable_rdap=False, policy_scope="all_workspaces", uc_schema="main.sec")
    analysis = ing.analyze(cfg, None, _FakeWorkspaceClient())
    assert set(analysis.candidates["public_ip"]) == {"203.0.55.10"}
    # tables created + the full window inserted, and no live scan of system.access.audit for candidates
    assert any(t.startswith("CREATE TABLE IF NOT EXISTS " + daily) for t in executed)
    assert any(t.startswith("INSERT INTO " + daily) for t in executed)
    assert not any("FROM system.access.audit" in q for q in seen)
    assert any(f"FROM {daily}" in q or f"SELECT * FROM {daily}" in q for q in seen)


# --------------------------------------------------------------------------------- egress persistence
def test_egress_tables_and_ddl():
    src = persist.tables("main.sec")
    assert src.egress_daily_table == "`main`.`sec`.`dbx_nwp_egress_daily`"
    assert src.egress_suggestions_table == "`main`.`sec`.`dbx_nwp_egress_suggestions`"
    ddl = queries.egress_daily_table_ddl(src.egress_daily_table)
    assert "CREATE TABLE IF NOT EXISTS" in ddl and "resolved_ips ARRAY<STRING>" in ddl
    ins = queries.egress_daily_table_insert(src.egress_daily_table, "2026-01-01", "2026-01-31")
    assert "FROM system.access.outbound_network" in ins
    assert "COALESCE(dns_event.domain_name, storage_event.hostname, destination) AS destination" in ins
    assert "GROUP BY 1, 2, 3, 4, 5, 6" in ins


def test_persisted_observed_egress_matches_live_columns():
    q = queries.persisted_observed_egress("`t`", 30, 2, "", only_workspace_id=None)
    for col in (
        "destination",
        "destination_type",
        "AS events",
        "AS distinct_access_types",
        "AS access_types",
        "AS source_types",
        "AS workspace_ids",
        "AS resolved_ips",
        "AS first_seen",
        "AS last_seen",
    ):
        assert col in q
    assert "HAVING SUM(events) >= 2" in q and "INTERVAL 30 DAYS" in q
    q = queries.persisted_observed_egress("`t`", 7, 1, "Apps", only_workspace_id=99)
    assert "network_source_type = 'Apps'" in q and "workspace_id = '99'" in q


def test_ensure_tables_egress_direction(monkeypatch):
    rec = _Recorder()
    _patch_sql(monkeypatch, rec)
    persist.ensure_tables(None, persist.tables("main.sec"), direction="egress")
    assert len(rec.executed) == 2
    assert "dbx_nwp_egress_daily" in rec.executed[0] and "dbx_nwp_egress_suggestions" in rec.executed[1]


def test_sync_egress_daily_uses_outbound_network(monkeypatch):
    rec = _Recorder(lo=D(2026, 10, 1), hi=D(2026, 11, 4), rows=10)
    _patch_sql(monkeypatch, rec)
    src = persist.tables("main.sec")
    notes = []
    persist.sync_egress_daily(None, src, EgressConfig(lookback_days=14, uc_schema="main.sec"), notes.append)
    assert rec.executed[0].startswith(f"DELETE FROM {src.egress_daily_table}")
    assert "FROM system.access.outbound_network" in rec.executed[1]
    assert any("system.access.outbound_network" in n for n in notes)


def test_egress_analyze_with_uc_schema_reads_persisted_table(monkeypatch):
    from dbx_nwp_helper.core import egress as eg

    seen, executed = [], []
    daily = "`main`.`sec`.`dbx_nwp_egress_daily`"

    def fake_query(_conn, text):
        seen.append(" ".join(text.split()))
        if "AS lo" in text:
            return pd.DataFrame([{"lo": None, "hi": None, "rows": 0}])
        if "AS today" in text:
            return pd.DataFrame([{"today": D(2026, 11, 6)}])
        if daily in text:
            return pd.DataFrame(
                [
                    {
                        "destination": "api.openai.com",
                        "destination_type": "DNS",
                        "events": 5,
                        "workspace_ids": ["1"],
                        "resolved_ips": ["1.2.3.4"],
                    }
                ]
            )
        raise AssertionError(f"unexpected live query: {text[:120]}")

    import dbx_nwp_helper.sql as sqlmod

    monkeypatch.setattr(sqlmod, "query", fake_query)
    monkeypatch.setattr(sqlmod, "execute", lambda _c, t: executed.append(" ".join(t.split())))
    cfg = EgressConfig(
        enable_rdap=False, block_threat_domains="off", policy_scope="all_workspaces", uc_schema="main.sec"
    )
    a = eg.analyze(cfg, None)
    assert eg.union(a.targets, "internet") == {"api.openai.com": 5}
    assert any(t.startswith("CREATE TABLE IF NOT EXISTS " + daily) for t in executed)
    assert any(t.startswith("INSERT INTO " + daily) for t in executed)
    assert not any("FROM system.access.outbound_network" in q for q in seen)


def test_egress_snapshot_rows_classify_every_destination(monkeypatch):
    from dbx_nwp_helper.core import egress as eg

    observed = pd.DataFrame(
        [
            {
                "destination": d,
                "destination_type": "DNS",
                "events": n,
                "workspace_ids": [1],
                "resolved_ips": [],
            }
            for d, n in [
                ("api.openai.com", 50),
                ("gone.example.com", 9),
                ("bucket.s3.us-east-1.amazonaws.com", 7),
                ("mcp-x-7474650000000001.aws.databricksapps.com", 6),
                ("other-7474650000000002.aws.databricksapps.com", 2),
                ("docs.databricks.com", 1),
                ("local", 3),
            ]
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off", policy_scope="all_workspaces")
    a = eg.analyze(cfg, None)
    full = {t: {k: dict(v) for k, v in d.items()} for t, d in a.targets.items()}
    # operator deselects one FQDN and one cross-workspace destination
    a.targets[eg.ALL_WORKSPACES]["internet"].pop("gone.example.com")
    a.xws_selected = [7474650000000001]
    blocks = eg.build_blocks(a, cfg)
    rows = persist.egress_snapshot_rows(a, cfg, blocks, targets_full=full)
    status = {(r["kind"], r["destination"]): r["status"] for r in rows}
    assert status[("internet", "api.openai.com")] == "allowed"
    assert status[("internet", "gone.example.com")] == "deselected"
    assert status[("s3", "bucket")] == "allowed"
    assert status[("databricks_workspace", "7474650000000001")] == "allowed"
    assert status[("databricks_workspace", "7474650000000002")] == "deselected"
    assert status[("databricks_workspace", "docs.databricks.com")] == "unresolved_workspace"
    assert status[("internet", "local")] == "excluded_invalid_host"
    s3 = next(r for r in rows if r["kind"] == "s3")
    assert s3["detail"] == "us-east-1" and s3["events"] == 7


def test_write_egress_suggestions_batches_literals(monkeypatch):
    rec = _Recorder()
    _patch_sql(monkeypatch, rec)
    src = persist.tables("main.sec")
    rows = [
        {
            "policy_target": "__ALL__",
            "kind": "internet",
            "destination": "api.openai.com",
            "detail": None,
            "events": 5,
            "status": "allowed",
        }
    ]
    run_id = persist.write_egress_suggestions(
        None,
        src,
        rows,
        cfg=EgressConfig(policy_mode="enforce"),
        workspace_id=None,
        policy_name="p",
        written=True,
    )
    assert len(rec.executed) == 1
    stmt = rec.executed[0]
    assert stmt.startswith(f"INSERT INTO {src.egress_suggestions_table} (run_id, run_at")
    assert f"'{run_id}', current_timestamp(), NULL, 'p', 'enforce', '__ALL__'" in stmt
    assert "'internet', 'api.openai.com', NULL, 5, 'allowed', TRUE" in stmt
