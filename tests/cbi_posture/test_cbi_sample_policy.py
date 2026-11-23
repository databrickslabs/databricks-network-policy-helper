"""Offline tests for the sample policy (no Databricks calls)."""

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / ".claude/skills/cbi-posture/scripts"))

import cbi_sample_policy as sp  # noqa: E402

POSTURE = json.loads((ROOT / ".claude/skills/cbi-posture/examples/sample-report/posture.json").read_text())
EXPORT = ROOT / ".claude/skills/cbi-posture/examples/sample-policy-input/analytics-cbi-sample.json"


def build(posture=None, export=None, tmp_path=None, wid="1002"):
    path = EXPORT
    if export is not None:
        path = tmp_path / "export.json"
        path.write_text(json.dumps(export))
    return sp.build_sample_policy(posture or POSTURE, wid, path)


def test_sample_policy_categories_coverage_and_flags():
    k = build()
    cats = {r.label: r.category for r in k.rows}
    assert (
        cats["corp"] == "ip-acl" and cats["databricks-aws"] == "databricks" and cats["Power-BI"] == "partner"
    )
    assert (
        cats["Consolidated-Observed-IPs"] == "consolidated"
        and cats["deny-recently-denied"] == "deny-recently-denied"
    )
    assert cats["Zscaler-Inc"] == "observed"
    assert {u["source_ip"] for u in k.uncovered} == {"34.120.5.6", "81.2.69.142"}
    tableau = next(u for u in k.uncovered if u["source_ip"] == "34.120.5.6")
    assert "Partner platforms" in tableau["hint"]
    broad = next(r for r in k.rows if r.origin == "52.0.0.0/8")
    assert any("broad range /8" in f for f in broad.flags) and any(
        "no successful traffic" in f for f in broad.flags
    )
    one_day = next(r for r in k.rows if r.origin == "203.0.113.77/32")
    assert "seen on one day only" in one_day.flags
    corp24 = next(r for r in k.rows if r.origin == "198.51.100.0/24")
    assert corp24.matched_ips == 2 and corp24.events == 39000 and not corp24.flags


def test_apply_command_is_dry_run_and_never_enforce():
    k = build()
    assert "--policy-mode dry_run" in k.apply_cmd and "enforce" not in k.apply_cmd
    assert "--policy-action create_new" in k.apply_cmd and "--auto-assign" in k.apply_cmd
    assert "--network-policy-id default-policy" in k.rollback


def test_enforce_mode_export_is_called_out(tmp_path):
    exp = json.loads(EXPORT.read_text())
    exp["ingress"] = exp.pop("ingress_dry_run")
    k = build(export=exp, tmp_path=tmp_path)
    assert any("ENFORCED block" in w for w in k.warnings)


def test_restrictive_egress_and_own_policy_uses_add_to_existing():
    posture = copy.deepcopy(POSTURE)
    ws = next(w for w in posture["workspaces"] if w["workspace_id"] == "1002")
    ws["effective_policy_id"] = "analytics-own"
    ws["policy"] = {
        "network_policy_id": "analytics-own",
        "egress": {"network_access": {"restriction_mode": "RESTRICTED_ACCESS"}},
    }
    k = build(posture=posture)
    assert "--policy-action add_to_existing --existing-policy-id analytics-own" in k.apply_cmd
    assert any("Don't apply `policy.json` by hand" in w for w in k.warnings)
    assert "--network-policy-id analytics-own" in k.rollback


def test_shared_policy_gets_its_own_new_policy():
    posture = copy.deepcopy(POSTURE)
    for w in posture["workspaces"]:
        if w["workspace_id"] in ("1002", "1004"):
            w["effective_policy_id"] = "shared"
    k = build(posture=posture)
    assert "--policy-action create_new" in k.apply_cmd
    assert any("also assigned to workspace(s) 1004" in w for w in k.warnings)


def test_without_traffic_profile_sample_policy_still_builds():
    posture = copy.deepcopy(POSTURE)
    posture["sql"].pop("source_ips_by_workspace")
    k = build(posture=posture)
    assert k.profile is None and k.uncovered == []
    assert any("No per-workspace traffic profile" in w for w in k.warnings)
    assert all(r.events == 0 for r in k.rows)


def test_catch_all_only_blocks_deny_matches(tmp_path):
    exp = {
        "network_policy_id": "x",
        "egress": {"network_access": {"restriction_mode": "FULL_ACCESS"}},
        "ingress_dry_run": {
            "public_access": {
                "restriction_mode": "RESTRICTED_ACCESS",
                "allow_rules": [{"label": "allow-all", "origin": {"all_ip_ranges": True}}],
                "deny_rules": [
                    {"label": "deny-feed", "origin": {"included_ip_ranges": {"ip_ranges": ["81.2.69.0/24"]}}}
                ],
            }
        },
    }
    k = build(export=exp, tmp_path=tmp_path)
    assert [u["source_ip"] for u in k.uncovered] == ["81.2.69.142"]
    assert any("catch-all" in w for w in k.warnings)
    assert next(r for r in k.rows if r.label == "deny-feed").category == "deny-threat-intel"


def test_write_sample_policy_outputs(tmp_path):
    k = build()
    d = sp.write_sample_policy(k, POSTURE, tmp_path)
    assert {p.name for p in d.iterdir()} == {
        "README.md",
        "review-sheet.csv",
        "uncovered-sources.csv",
        "monitor.sql",
        "policy.json",
    }
    assert json.loads((d / "policy.json").read_text()) == json.loads(EXPORT.read_text())
    mon = (d / "monitor.sql").read_text()
    assert "WHERE workspace_id = '1002'" in mon and "DRY_RUN_DENIAL" in mon
    readme = (d / "README.md").read_text()
    assert "not a recommendation" in readme and "Rollback" in readme


def test_sample_policy_is_pure():
    src = (ROOT / ".claude/skills/cbi-posture/scripts/cbi_sample_policy.py").read_text()
    for forbidden in ("WorkspaceClient(", "AccountClient(", "_rpc(", "execute_statement", "subprocess"):
        assert forbidden not in src


def test_sample_policy_reads_except_ranges_api_scopes_and_console_sources(tmp_path):
    exp = {
        "network_policy_id": "x",
        "egress": {"network_access": {"restriction_mode": "FULL_ACCESS"}},
        "ingress_dry_run": {
            "public_access": {
                "restriction_mode": "RESTRICTED_ACCESS",
                "allow_rules": [
                    {
                        "label": "all-but",
                        "origin": {"excluded_ip_ranges": {"ip_ranges": ["34.120.5.0/24"]}},
                        "destination": {
                            "workspace_api": {"scopes": ["sql"]},
                            "workspace_ui": {"all_destinations": True},
                        },
                    },
                    {"label": "slack", "origin": {}, "destination": {"workspace_api": {"scopes": ["genie"]}}},
                ],
            }
        },
    }
    k = build(export=exp, tmp_path=tmp_path)
    allbut = next(r for r in k.rows if r.label == "all-but")
    assert allbut.category == "catch-all" and "api (sql)" in allbut.destination and "ui" in allbut.destination
    assert next(r for r in k.rows if r.label == "slack").category == "console-source"
    assert [u["source_ip"] for u in k.uncovered] == ["34.120.5.6"]  # only the excluded /24 is uncovered
