"""Offline tests for `ingress --review-pack` (core/review_pack.py) and the `posture` run."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
from typer.testing import CliRunner

from dbx_nwp_helper import cli
from dbx_nwp_helper.config import IngressConfig
from dbx_nwp_helper.core import review_pack as rp

FIXTURES = Path(__file__).parent / "fixtures"
PROPOSAL = json.loads((FIXTURES / "ingress_proposal_sample.json").read_text())
runner = CliRunner()


def _cand(ip, events, days, principals=("alex@example.com",), services=("sql",)):
    return {
        "public_ip": ip,
        "events": events,
        "active_days": days,
        "first_active_date": "2026-10-20",
        "last_active_date": "2026-11-17",
        "principal_list": list(principals),
        "service_list": list(services),
    }


CANDIDATES = pd.DataFrame(
    [
        _cand("198.51.100.7", 39000, 30),
        _cand("3.33.0.10", 1500, 30, ("6f1c2a9e-0000-4000-8000-000000000001",)),
        _cand("20.40.1.5", 4200, 30, services=("sql", "databrickssql")),
        _cand("165.225.0.10", 2000, 20),
        _cand("192.0.2.10", 40, 3),
        _cand("203.0.113.9", 3, 1),  # covered only by the deny rule
        _cand("34.120.5.6", 2500, 12, ("bob@example.com",)),  # no rule covers it
        _cand("81.2.69.142", 300, 1, ("carol@example.com",)),  # no rule covers it, one day
        {**_cand("45.0.0.1", 5, 1), "service_list": float("nan")},  # inbound dry-run denial only
        _cand("2001:db8::1", 10, 2),  # IPv6 is never in a CBI policy, so not profiled
    ]
)


def _ctx(**kw):
    base = dict(
        workspace_id="1002",
        cfg=IngressConfig(lookback_days=30),
        profile="analytics",
        warehouse_http_path="/sql/1.0/warehouses/abc",
        partner_labels={"Power-BI"},
        acl_labels={"corp"},
    )
    base.update(kw)
    return rp.Context(**base)


def _rows():
    rows = rp.flatten(PROPOSAL)
    ctx = _ctx()
    for r in rows:
        rp.classify(r, ctx)
    profile = rp.source_profile(CANDIDATES)
    rp.attach_traffic(rows, profile)
    for r in rows:
        rp.flag(r)
    return rows, profile


def test_flatten_and_classify_every_rule():
    rows, _ = _rows()
    cats = {(r.label, r.origin): r.category for r in rows}
    assert cats[("corp", "198.51.100.0/24")] == "ip-acl"
    assert cats[("databricks-aws", "3.33.0.10/32")] == "databricks"
    assert cats[("Power-BI", "20.40.1.0/26")] == "partner"
    assert cats[("Consolidated-Observed-IPs", "192.0.2.10/32")] == "consolidated"
    assert cats[("deny-recently-denied", "203.0.113.9/32")] == "deny-recently-denied"
    assert cats[("Example-ISP", "203.0.113.77/32")] == "observed"


def test_traffic_and_flags():
    rows, profile = _rows()
    assert all(p["ip"].version == 4 for p in profile) and len(profile) == 9
    by = {(r.label, r.origin): r for r in rows}
    assert by[("corp", "198.51.100.0/24")].events == 39000
    assert any("broad range /8" in f for f in by[("corp", "52.0.0.0/8")].flags)
    assert "no successful traffic in the window" in by[("Example-ISP", "203.0.113.77/32")].flags
    assert by[("Power-BI", "20.40.1.0/26")].services == "databrickssql, sql"


def test_uncovered_sources():
    rows, profile = _rows()
    unc = {u["source_ip"]: u for u in rp.uncovered(profile, rows)}
    assert set(unc) == {"34.120.5.6", "81.2.69.142", "203.0.113.9", "45.0.0.1"}
    assert unc["203.0.113.9"]["reason"] == "matches deny rule 'deny-recently-denied'"
    assert unc["34.120.5.6"]["hint"].startswith("one identity, recurring")
    assert unc["81.2.69.142"]["hint"].startswith("seen on one day only")


def test_catch_all_covers_everything_but_its_exclusions():
    p = {
        "ingress": {
            "public_access": {
                "allow_rules": [
                    {"label": "any", "origin": {"excluded_ip_ranges": {"ip_ranges": ["34.120.5.0/24"]}}}
                ]
            }
        }
    }
    rows = rp.flatten(p)
    for r in rows:
        rp.classify(r, _ctx())
    assert rows[0].category == "catch-all"
    unc = rp.uncovered(rp.source_profile(CANDIDATES), rows)
    assert [u["source_ip"] for u in unc] == ["34.120.5.6"]


def test_apply_command_and_warnings():
    cmd, note, rollback = rp.build_apply(PROPOSAL, _ctx())
    assert "--create-policy --policy-mode dry_run" in cmd and "--policy-action create_new" in cmd
    assert "--warehouse-http-path /sql/1.0/warehouses/abc" in cmd and "default-policy" in rollback
    cmd, note, _ = rp.build_apply(PROPOSAL, _ctx(assigned_policy_id="analytics"))
    assert "--existing-policy-id analytics" in cmd and "other workspaces" in note
    enforced = {**PROPOSAL, "ingress": PROPOSAL["ingress_dry_run"]}
    enforced.pop("ingress_dry_run")
    w = rp.build_warnings(enforced, rp.flatten(enforced), _ctx(existing_egress_restrictive=True))
    assert any("ENFORCED block" in x for x in w) and any("open egress" in x for x in w)


def test_write_builds_the_pack(tmp_path):
    summary = rp.write(str(tmp_path / "pack"), PROPOSAL, CANDIDATES, _ctx())
    d = Path(summary["dir"])
    names = ["README.md", "monitor.sql", "policy.json", "review-sheet.csv", "uncovered-sources.csv"]
    assert sorted(p.name for p in d.iterdir()) == names
    sheet = list(csv.DictReader((d / "review-sheet.csv").open()))
    assert len(sheet) == summary["ranges"] == 10 and sheet[0]["decision (keep / drop)"] == ""
    readme = (d / "README.md").read_text()
    assert (
        "Building the pack applies nothing" in readme and "## Rollback" in readme and "**dry_run**" in readme
    )
    assert "WHERE event_time >= current_date() - INTERVAL 1 DAYS" in (d / "monitor.sql").read_text()
    assert json.loads((d / "policy.json").read_text()) == PROPOSAL


def test_cli_writes_the_pack_from_the_run(tmp_path, monkeypatch):
    from dbx_nwp_helper import auth
    from dbx_nwp_helper.core import ingress_rules as rules

    monkeypatch.setattr(auth, "this_workspace_id", lambda conn: 1002)
    monkeypatch.setattr(rules, "export_payload", lambda *a, **k: PROPOSAL)
    cfg = IngressConfig(lookback_days=30, review_pack=str(tmp_path / "pack"))
    conn = cli._conn("analytics", "/sql/1.0/warehouses/abc", "acc", None)
    analysis = SimpleNamespace(candidates=CANDIDATES, ip_acls=[{"label": "corp"}])
    policies = {"__ALL__": {"allow": [{"label": "Power-BI", "partner": True}], "deny": []}}
    cli._write_review_pack(cfg, conn, None, "/sql/1.0/warehouses/abc", analysis, policies, None)
    sheet = list(csv.DictReader((tmp_path / "pack" / "review-sheet.csv").open()))
    assert {r["category"] for r in sheet if r["label"] == "Power-BI"} == {"partner"}


def test_review_pack_needs_a_single_policy_scope(monkeypatch):
    monkeypatch.setattr(cli, "_available_profiles", lambda: ["test"])
    args = ["ingress", "--profile", "test", "--review-pack", "x", "--policy-scope", "per_workspace", "--yes"]
    r = runner.invoke(cli.app, args)
    assert r.exit_code != 0 and "--review-packwritesasinglenetwork-policybody" in "".join(r.output.split())


def test_posture_run_end_to_end(tmp_path, monkeypatch):
    import dbx_nwp_helper.sql as sqlmod
    from dbx_nwp_helper import auth
    from dbx_nwp_helper.core import posture, tokens

    snap = json.loads((FIXTURES / "posture_snapshot.json").read_text())
    monkeypatch.setattr(cli, "_step", lambda _m: None)
    monkeypatch.setattr(
        cli, "_confirm_workspace", lambda conn, yes: SimpleNamespace(config=SimpleNamespace())
    )
    monkeypatch.setattr(cli, "_account_client_or_exit", lambda conn, workspace_id=None: object())
    monkeypatch.setattr(auth, "this_workspace_id", lambda conn: 1002)
    monkeypatch.setattr(
        posture,
        "collect_account",
        lambda account, only, note=None, fallback_workspace_id=None: (snap["account"], snap["workspaces"]),
    )
    monkeypatch.setattr(posture, "collect_workspace_ip_acl", lambda wc: [])
    monkeypatch.setattr(tokens, "collect", lambda wc: {"tokens": [], "tokens_enabled": True})
    writes = []
    monkeypatch.setattr(sqlmod, "resolve_warehouse", lambda conn: writes.append("warehouse") or "/x")

    monkeypatch.setattr(cli, "_available_profiles", lambda: ["p"])
    out = tmp_path / "out"
    r = runner.invoke(
        cli.app,
        [
            "posture",
            "--profile",
            "p",
            "--account-id",
            "acc",
            "--skip-traffic",
            "--out",
            str(out),
            "--yes",
        ],
    )
    assert r.exit_code == 0, r.output
    assert writes == []  # --skip-traffic never touches a warehouse
    md = (out / "report.md").read_text()
    assert "# Security posture report" in md and "--skip-traffic" in md
    assert (out / "tokens-to-revoke.csv").exists()
    assert "| 1001 | sandbox-dev |" in md


# ---------------------------------------------------------------- regressions from code review
def _pack_rows(policy):
    rows = rp.flatten(policy)
    for r in rows:
        rp.classify(r, _ctx())
    profile = rp.source_profile(CANDIDATES)
    rp.attach_traffic(rows, profile)
    for r in rows:
        rp.flag(r)
    return rows, profile


def _pub(*allow):
    return {"ingress_dry_run": {"public_access": {"allow_rules": list(allow)}}}


def test_source_covered_only_by_a_scoped_rule_is_listed():
    scoped = {
        "label": "sql-only",
        "origin": {"included_ip_ranges": {"ip_ranges": ["34.120.5.0/24"]}},
        "destination": {"workspace_api": {"scopes": ["sql"]}},
    }
    rows, profile = _pack_rows(_pub(scoped))
    unc = {u["source_ip"]: u for u in rp.uncovered(profile, rows)}
    assert unc["34.120.5.6"]["reason"].startswith("only scoped rules cover it (sql-only: api (sql)")


def test_rule_without_ranges_and_hidden_sources_keep_a_row_without_traffic_flags():
    empty = {"label": "empty", "origin": {"included_ip_ranges": {"ip_ranges": []}}}
    hidden = {"label": "console", "origin": {}}
    rows, _ = _pack_rows(_pub(empty, hidden))
    by = {r.label: r for r in rows}
    assert by["empty"].origin == "no IP ranges set" and "lists no IP ranges" in by["empty"].flags[0]
    assert by["console"].flags == []


def test_missing_dates_are_blank_not_nan():
    df = pd.DataFrame(
        [_cand("198.51.100.7", 5, 2), {**_cand("198.51.100.8", 5, 2), "last_active_date": None}]
    )
    df.loc[1, "last_active_date"] = float("nan")
    assert [p["last_seen"] for p in rp.source_profile(df)] == ["2026-11-17", ""]
