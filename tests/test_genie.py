"""Offline tests for the posture snapshots (`posture --uc-schema`) and `genie-setup` (core/genie.py)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest
from typer.testing import CliRunner

from dbx_nwp_helper import cli
from dbx_nwp_helper.core import genie, persist
from dbx_nwp_helper.core import posture as P

FIXTURE = Path(__file__).parent / "fixtures" / "posture_snapshot.json"
PREFIX = "`main`.`sec`"
runner = CliRunner()
ALL = set(genie.SOURCES)


def _ids(space):
    return (
        [q["id"] for q in space["config"]["sample_questions"]]
        + [t["id"] for t in space["instructions"]["text_instructions"]]
        + [e["id"] for e in space["instructions"]["example_question_sqls"]]
    )


# ------------------------------------------------------------------------------------- the space
def test_space_matches_the_genie_format():
    sp = genie.build_space(PREFIX, ALL)
    assert sp["version"] == 2
    tables = [t["identifier"] for t in sp["data_sources"]["tables"]]
    assert tables == sorted(tables) and all(t.startswith("main.sec.dbx_nwp_") for t in tables)
    ids = _ids(sp)
    assert all(re.fullmatch(r"[0-9a-f]{32}", i) for i in ids) and len(set(ids)) == len(ids)
    for coll in (sp["config"]["sample_questions"], sp["instructions"]["example_question_sqls"]):
        assert [x["id"] for x in coll] == sorted(x["id"] for x in coll)
    ex = sp["instructions"]["example_question_sqls"]
    assert (
        len(ex) == len(genie.parse_trusted_queries((genie.ASSETS / "trusted_queries.sql").read_text())) >= 15
    )
    assert all(e["question"][0] and "SELECT" in "".join(e["sql"]).upper() for e in ex)
    assert any(e.get("parameters") for e in ex) and len(sp["config"]["sample_questions"]) >= 10


def test_examples_needing_a_missing_table_are_left_out():
    minimal = {"dbx_nwp_posture_findings_latest", "dbx_nwp_posture_latest", "dbx_nwp_posture_workspaces"}
    sp = genie.build_space(PREFIX, minimal)
    sqls = ["".join(e["sql"]) for e in sp["instructions"]["example_question_sqls"]]
    assert sqls and not any("dbx_nwp_posture_daily" in s or "dbx_nwp_egress_daily" in s for s in sqls)
    assert {t["identifier"].rsplit(".", 1)[1] for t in sp["data_sources"]["tables"]} == minimal


def test_trusted_queries_only_read_known_sources():
    for _q, sql in genie.parse_trusted_queries((genie.ASSETS / "trusted_queries.sql").read_text()):
        assert set(genie._TABLE_REF.findall(sql)) <= ALL, sql[:80]


def test_inline_params_removes_placeholders():
    body = json.dumps(genie.build_space(PREFIX, ALL, inline_params=True))
    assert ":lookback_days" not in body and '"parameters"' not in body


def test_views_only_over_existing_snapshot_tables():
    stmts = genie.view_statements(PREFIX, {"dbx_nwp_posture_workspaces"})
    assert [v for v, _ in stmts] == ["dbx_nwp_posture_latest", genie.INBOUND_VIEW]
    assert all(s.strip().startswith(f"CREATE OR REPLACE VIEW {PREFIX}.`") for _, s in stmts)
    assert "QUALIFY dense_rank() OVER (PARTITION BY workspace_id ORDER BY run_at DESC) = 1" in stmts[0][1]


# ---------------------------------------------------------------------------------- snapshots
def _evaluated():
    snap = json.loads(FIXTURE.read_text())
    f, m = P.evaluate(snap)
    P.finalize_levels(f, m)
    return snap, f, m


def test_snapshot_rows_describe_each_workspace():
    snap, _f, m = _evaluated()
    rows = {r["workspace_id"]: r for r in persist.posture_workspace_rows(snap, m)}
    assert rows["1002"]["pats_checked"] and rows["1002"]["pats_never_expire"] == 1
    assert rows["1001"]["pats_checked"] is False and rows["1001"]["pats_total"] is None
    assert rows["1003"]["policy_mode"] == "dry_run" and rows["1004"]["maturity_level"] == 3


def test_write_posture_snapshot_creates_and_appends(monkeypatch):
    from dbx_nwp_helper import sql

    done, inserted = [], {}
    monkeypatch.setattr(sql, "execute", lambda _c, st: done.append(st))
    monkeypatch.setattr(
        persist, "_insert_rows", lambda _c, table, cols, rows: inserted.update({table: (cols, rows)})
    )
    snap, f, m = _evaluated()
    run_id = persist.write_posture_snapshot(object(), "main.sec", snap, f, m, note=lambda _m: None)
    assert len([s for s in done if "CREATE TABLE IF NOT EXISTS" in s]) == 3
    t = persist.posture_snapshot_tables("main.sec")
    assert set(inserted) == set(t.values())
    for cols, rows in inserted.values():  # one value per named column, every row stamped with the run
        assert rows and all(len(r) == len(cols.split(", ")) and r[0] == f"'{run_id}'" for r in rows)
    ws_cols, ws_rows = inserted[t["workspaces"]]
    assert len(ws_rows) == len(snap["workspaces"])
    assert len(inserted[t["findings"]][1]) == len(f)
    assert len(inserted[t["tokens"]][1]) == 2  # the fixture's two tokens worth reviewing


def test_posture_uc_schema_writes_the_snapshot(tmp_path, monkeypatch):
    import contextlib

    import dbx_nwp_helper.sql as sqlmod
    from dbx_nwp_helper import auth
    from dbx_nwp_helper.core import tokens

    snap = json.loads(FIXTURE.read_text())
    monkeypatch.setattr(cli, "_available_profiles", lambda: ["p"])
    monkeypatch.setattr(cli, "_step", lambda _m: None)
    monkeypatch.setattr(
        cli, "_confirm_workspace", lambda conn, yes: SimpleNamespace(config=SimpleNamespace())
    )
    monkeypatch.setattr(cli, "_account_client_or_exit", lambda conn, workspace_id=None: object())
    monkeypatch.setattr(auth, "this_workspace_id", lambda conn: 1002)
    monkeypatch.setattr(
        P,
        "collect_account",
        lambda a, o, note=None, fallback_workspace_id=None: (snap["account"], snap["workspaces"]),
    )
    monkeypatch.setattr(P, "collect_workspace_ip_acl", lambda wc: [])
    monkeypatch.setattr(tokens, "collect", lambda wc: {"tokens": [], "tokens_enabled": True})
    monkeypatch.setattr(sqlmod, "resolve_warehouse", lambda conn: "/sql/1.0/warehouses/abc")
    monkeypatch.setattr(sqlmod, "connection", lambda conn, hp: contextlib.nullcontext(object()))
    wrote = []
    monkeypatch.setattr(persist, "write_posture_snapshot", lambda *a, **k: wrote.append(a[1]) or "run1")
    args = ["posture", "--profile", "p", "--account-id", "a", "--skip-traffic", "--uc-schema", "main.sec"]
    r = runner.invoke(cli.app, [*args, "--out", str(tmp_path), "--yes"])
    assert r.exit_code == 0, r.output
    assert wrote == ["main.sec"]


# -------------------------------------------------------------------------------- genie-setup CLI
class _Genie:
    def __init__(self, existing=None):
        self.created, self.updated, self.existing = [], [], existing

    def list_spaces(self, page_token=None):
        return SimpleNamespace(spaces=self.existing or [], next_page_token=None)

    def create_space(self, warehouse_id, body, **kw):
        self.created.append((warehouse_id, json.loads(body), kw))
        return SimpleNamespace(space_id="new1")

    def update_space(self, space_id, **kw):
        self.updated.append((space_id, kw))
        return SimpleNamespace(space_id=space_id)


@pytest.fixture
def setup_env(monkeypatch):
    import contextlib

    import dbx_nwp_helper.sql as sqlmod

    env = SimpleNamespace(
        executed=[],
        genie=_Genie(),
        tables=[
            "dbx_nwp_posture_findings",
            "dbx_nwp_posture_tokens",
            "dbx_nwp_posture_workspaces",
            "dbx_nwp_posture_daily",
        ],
    )
    wc = SimpleNamespace(config=SimpleNamespace(host="https://dbc-1.cloud.databricks.com"), genie=env.genie)
    monkeypatch.setattr(cli, "_available_profiles", lambda: ["p"])
    monkeypatch.setattr(cli, "_confirm_workspace", lambda conn, yes: wc)
    monkeypatch.setattr(sqlmod, "resolve_warehouse", lambda conn: "/sql/1.0/warehouses/wh42")
    monkeypatch.setattr(sqlmod, "connection", lambda conn, hp: contextlib.nullcontext(object()))
    monkeypatch.setattr(
        sqlmod,
        "query",
        lambda _c, st: pd.DataFrame({"database": ["sec"] * len(env.tables), "tableName": env.tables}),
    )

    def execute(_c, st):
        if "inbound_network" in st:
            raise RuntimeError("TABLE_OR_VIEW_NOT_FOUND")
        env.executed.append(st)

    monkeypatch.setattr(sqlmod, "execute", execute)
    return env


def test_genie_setup_creates_views_and_the_space(setup_env):
    r = runner.invoke(cli.app, ["genie-setup", "--uc-schema", "main.sec", "--profile", "p", "--yes"])
    assert r.exit_code == 0, r.output
    assert len(setup_env.executed) == 3 and all(
        s.strip().startswith("CREATE OR REPLACE VIEW") for s in setup_env.executed
    )
    ((wh, space, kw),) = setup_env.genie.created
    names = {t["identifier"].rsplit(".", 1)[1] for t in space["data_sources"]["tables"]}
    assert wh == "wh42" and kw["title"] == "Databricks Security Posture"
    assert "dbx_nwp_posture_daily" in names and genie.INBOUND_VIEW not in names  # inbound view was skipped
    assert "genie/rooms/new1" in "".join(r.output.split())


def test_genie_setup_updates_an_agent_with_the_same_title(setup_env):
    setup_env.genie.existing = [SimpleNamespace(title="Databricks Security Posture", space_id="s9")]
    r = runner.invoke(cli.app, ["genie-setup", "--uc-schema", "main.sec", "--profile", "p", "--yes"])
    assert r.exit_code == 0, r.output
    assert setup_env.genie.updated and setup_env.genie.updated[0][0] == "s9" and not setup_env.genie.created


def test_genie_setup_needs_a_posture_run_first(setup_env):
    setup_env.tables = ["dbx_nwp_ingress_daily"]
    r = runner.invoke(cli.app, ["genie-setup", "--uc-schema", "main.sec", "--profile", "p", "--yes"])
    assert r.exit_code == 1 and "posture--uc-schemamain.sec" in "".join(r.output.split())
    assert setup_env.executed == [] and not setup_env.genie.created


def test_genie_setup_print_only_changes_nothing(setup_env, tmp_path):
    out = tmp_path / "agent.json"
    r = runner.invoke(
        cli.app, ["genie-setup", "--uc-schema", "main.sec", "--profile", "p", "--print-only", str(out)]
    )
    assert r.exit_code == 0, r.output
    assert json.loads(out.read_text())["version"] == 2
    assert setup_env.executed == [] and not setup_env.genie.created


def test_genie_setup_refuses_to_write_non_interactively_without_yes(setup_env):
    r = runner.invoke(cli.app, ["genie-setup", "--uc-schema", "main.sec", "--profile", "p"])
    assert r.exit_code != 0 and setup_env.executed == [] and not setup_env.genie.created


def test_genie_setup_rejects_a_bad_schema():
    r = runner.invoke(cli.app, ["genie-setup", "--uc-schema", "main.sec; DROP TABLE x"])
    assert r.exit_code != 0
