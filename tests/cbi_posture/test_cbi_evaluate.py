"""Offline tests for the evaluator (no Databricks calls). Run: uv run --with pytest pytest -q tests"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / ".claude/skills/cbi-posture/scripts"))

import cbi_posture as cp  # noqa: E402
import cbi_sql  # noqa: E402

OPEN = {
    "network_policy_id": "default-policy",
    "ingress": {"public_access": {"restriction_mode": "FULL_ACCESS"}},
    "egress": {"network_access": {"restriction_mode": "FULL_ACCESS"}},
}


def restricted(mode_key: str, cidrs: list[str], all_ip: bool = False) -> dict:
    origin = {"all_ip_ranges": True} if all_ip else {"included_ip_ranges": {"ip_ranges": cidrs}}
    return {
        "network_policy_id": "corp",
        mode_key: {
            "public_access": {
                "restriction_mode": "RESTRICTED_ACCESS",
                "allow_rules": [{"label": "corp", "origin": origin}],
            }
        },
    }


def ws(policy, **kw):
    base = {
        "workspace_id": "1",
        "pricing_tier": "ENTERPRISE",
        "policy": policy,
        "assignment_read": True,
        "assigned_policy_id": None if policy is OPEN else "corp",
        "effective_policy_id": policy.get("network_policy_id"),
        "ip_acl": {"enabled": False, "lists": []},
        "pas": None,
    }
    base.update(kw)
    return base


def run(*workspaces, sql=None, account=None):
    posture = {
        "workspaces": list(workspaces),
        "sql": sql or {},
        "account": account or {"policies_read": True},
    }
    f, m = cp.evaluate(posture)
    cp.finalize_levels(f, m)
    return {x.id for x in f}, m, f


def test_open_workspace_is_l0_high():
    ids, m, f = run(ws(OPEN))
    assert m["1"]["level"] == 0 and "CBI-001" in ids and "CBI-006" in ids
    assert next(x for x in f if x.id == "CBI-001").severity == "high"


def test_legacy_ip_acl_is_l1():
    acl = {
        "enabled": True,
        "lists": [{"enabled": True, "list_type": "ALLOW", "ip_addresses": ["203.0.113.0/24"]}],
    }
    ids, m, _ = run(ws(OPEN, ip_acl=acl))
    assert m["1"]["level"] == 1 and "CBI-002" in ids and "CBI-001" not in ids


def test_dry_run_is_l2():
    ids, m, _ = run(ws(restricted("ingress_dry_run", ["198.51.100.7/32"])))
    assert m["1"]["level"] == 2 and "CBI-003" in ids


def test_enforced_clean_promotes_to_l4_except_egress_low():
    p = restricted("ingress", ["198.51.100.7/32"])
    p["egress"] = {
        "network_access": {
            "restriction_mode": "RESTRICTED_ACCESS",
            "policy_enforcement": {"enforcement_mode": "ENFORCED"},
        }
    }
    ids, m, _ = run(ws(p))
    assert m["1"]["level"] == 4, (ids, m)


def test_broad_and_all_ip():
    ids, _, f = run(ws(restricted("ingress", ["0.0.0.0/0", "52.0.0.0/12"])))
    assert "CBI-004" in ids and any(x.severity == "high" for x in f if x.id == "CBI-004")
    ids, _, _ = run(ws(restricted("ingress", [], all_ip=True)))
    assert "CBI-004" in ids


def test_private_link_allow_all_endpoints():
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


def test_traffic_findings():
    sql = {
        "traffic_by_ip_class": {
            "rows": [
                {
                    "workspace_id": "1",
                    "ipv6_events": "4",
                    "distinct_ipv6_ips": "2",
                    "distinct_public_ips": "10",
                    "public_principals": "3",
                }
            ]
        },
        "principal_network_spread": {
            "rows": [{"principal": "a@x.com", "principal_type": "user", "distinct_public_24s": "40"}]
        },
        "client_families_on_public_ips": {"rows": [{"client_family": "Power BI"}]},
        "enforced_denials": {"rows": [{"workspace_id": "1", "denied_events": "12"}]},
        "inbound_policy_outcomes": {"error": "TABLE_OR_VIEW_NOT_FOUND"},
    }
    ids, _, _ = run(ws(restricted("ingress", ["198.51.100.7/32"])), sql=sql)
    assert {"CBI-015", "CBI-013", "CBI-014", "CBI-012", "CBI-011"} <= ids


def test_account_policy_open_with_traffic():
    acct = {"policies_read": True, "account_policy": {"network_policy_id": "account-policy"}}
    sql = {"account_level_public_access": {"rows": [{"source_ip": "198.51.100.1"}]}}
    ids, _, f = run(sql=sql, account=acct)
    assert next(x for x in f if x.id == "CBI-009").severity == "high"


def test_sql_is_read_only_and_parameterised():
    for name, (_d, q) in cbi_sql.QUERIES.items():
        up = q.upper()
        for kw in ("INSERT ", "UPDATE ", "DELETE ", "MERGE ", "DROP ", "CREATE ", "ALTER ", "GRANT "):
            assert kw not in up.replace("DROP_", ""), (name, kw)
        assert ":lookback_days" in q, name


# ---- credential layers / patterns (from the credential-theft & no-VPN guidance)
NOW_MS = 1795000000000  # ~2026-11-18


def test_pat_findings_on_open_workspace():
    pat = {
        "max_token_lifetime_days": None,
        "tokens_enabled": True,
        "all_users_can_use": True,
        "tokens": [
            {"token_id": "t1", "created_by_username": "a@x.com", "expiry_time": -1, "scopes": []},
            {
                "token_id": "t2",
                "expiry_time": NOW_MS + 5 * 86400000,
                "scopes": ["sql"],
                "last_used_day": NOW_MS - 200 * 86400000,
            },
        ],
    }
    posture = {
        "generated_at": "2026-11-18 00:00:00",
        "workspaces": [ws(OPEN, pat=pat)],
        "sql": {},
        "account": {"policies_read": True},
    }
    f, _ = cp.evaluate(posture)
    by = {x.id: x for x in f}
    assert by["CBI-020"].severity == "high" and by["CBI-020"].layer == "Expire"
    assert {"CBI-021", "CBI-022", "CBI-023", "CBI-024"} <= set(by)


def test_no_pat_findings_when_not_collected():
    ids, _, _ = run(ws(OPEN))
    assert not ids & {"CBI-020", "CBI-021", "CBI-022", "CBI-023", "CBI-024"}


def test_pattern_suggestion_b1_vs_b2():
    sql = {
        "public_browser_vs_api": {
            "rows": [{"workspace_id": "1", "programmatic_principals": "4", "browser_pct": "91"}]
        }
    }
    _, _, f = run(ws(OPEN), sql=sql)
    assert "Browser yes" in next(x for x in f if x.id == "CBI-026").detail
    sql["public_browser_vs_api"]["rows"][0]["programmatic_principals"] = "300"
    _, _, f = run(ws(OPEN), sql=sql)
    assert "API families" in next(x for x in f if x.id == "CBI-026").detail
    ids, _, _ = run(ws(restricted("ingress", ["198.51.100.7/32"])), sql=sql)
    assert "CBI-026" not in ids  # only suggested while public access is still open


def test_verbose_audit_gap():
    sql = {"audit_visibility": {"rows": [{"workspace_id": "1", "verbose_audit_disabled_events": "1"}]}}
    ids, _, _ = run(ws(OPEN), sql=sql)
    assert "CBI-025" in ids


# ---------------------------------------------------------------- in-Databricks (notebook) mode
class _Row:
    def __init__(self, d):
        self._d = d

    def asDict(self, recursive=False):  # noqa: N802 - pyspark API
        return dict(self._d)


class _FakeSpark:
    def __init__(self):
        self.calls = []

    def sql(self, stmt, args=None):
        self.calls.append((stmt, args))
        rows = (
            [{"col_name": "access_type"}]
            if stmt.startswith("DESCRIBE")
            else [{"workspace_id": "1", "events": 3}]
        )
        return type("DF", (), {"collect": lambda _self: [_Row(r) for r in rows]})()


def test_spark_executor_binds_lookback_and_runs_every_query():
    spark = _FakeSpark()
    out = cp.run_sql(cp.spark_executor(spark, 45), lambda m: None)
    assert set(out) == set(cbi_sql.QUERIES) and all("rows" in v for v in out.values())
    param_calls = [a for s, a in spark.calls if not s.startswith("DESCRIBE")]
    assert param_calls and all(a == {"lookback_days": 45} for a in param_calls)
    # outcome-column drift is handled on the spark path too
    assert any("upper(access_type)" in s for s, _ in spark.calls)


def test_accounts_host_per_cloud():
    cases = {
        "https://adb-1.11.azuredatabricks.net": "https://accounts.azuredatabricks.net",
        "https://adb-1.1.databricks.azure.us": "https://accounts.databricks.azure.us",  # Azure Government
        "https://adb-1.1.databricks.azure.cn": "https://accounts.databricks.azure.cn",  # Azure China
        "https://1.1.gcp.databricks.com": "https://accounts.gcp.databricks.com",
        "https://x.cloud.databricks.us": "https://accounts.cloud.databricks.us",  # AWS GovCloud
        "https://x.cloud.databricks.mil": "https://accounts-dod.cloud.databricks.mil",  # AWS GovCloud DoD
        "https://x.cloud.databricks.com": "https://accounts.cloud.databricks.com",
    }
    for ws_host, acct in cases.items():
        assert cp.accounts_host_for(ws_host) == (acct, True), ws_host
    host, known = cp.accounts_host_for("https://something.example.com")
    assert known is False and host == "https://accounts.cloud.databricks.com"


def test_write_uc_uses_the_executor_and_only_creates_or_inserts():
    stmts = []
    posture = {
        "generated_at": "2026-11-18 00:00:00",
        "workspaces": [ws(OPEN)],
        "sql": {},
        "account": {"policies_read": True},
    }
    f, m = cp.evaluate(posture)
    cp.write_uc(lambda s, params=True: stmts.append(s) or [], "c.s", "r1", posture, f, m, lambda _m: None)
    assert stmts and all(s.lstrip().startswith(("CREATE TABLE IF NOT EXISTS", "INSERT INTO")) for s in stmts)


def test_sql_scoped_to_assessed_workspaces_plus_account_level():
    spark = _FakeSpark()
    cp.run_sql(cp.spark_executor(spark, 7), lambda m: None, ["1234567890123456"])
    stmts = [s for s, _ in spark.calls if not s.startswith("DESCRIBE")]
    assert len(stmts) == len(cbi_sql.QUERIES)
    assert all("IN ('1234567890123456', '0')" in s for s in stmts)
    assert not any("cbi:workspace-scope" in s for s in stmts)


def test_unscoped_sql_reads_whole_account_and_bad_ids_rejected():
    stmt = cbi_sql.QUERIES["top_public_source_ips"][1]
    assert cbi_sql.scope(stmt, None) == stmt and "cbi:workspace-scope" in stmt
    import pytest

    with pytest.raises(ValueError):
        cbi_sql.scope(stmt, ["1 OR 1=1"])


# ------------------------------------------------------------------------------------ SQL cache
import datetime as _dt  # noqa: E402


def _now(h=0):
    return _dt.datetime(2026, 11, 18, 12, 0, tzinfo=_dt.timezone.utc) + _dt.timedelta(hours=h)


def test_sql_cache_reuses_exact_match_only(tmp_path):
    sql = {"traffic_by_ip_class": {"rows": [{"workspace_id": "1"}]}}
    cp.save_sql_cache(tmp_path, ["1"], 90, sql, "2026-11-18 12:00:00")
    hit = cp.load_sql_cache(tmp_path, ["1"], 90, 24, _now(3))
    assert hit and hit[0] == sql and abs(hit[2] - 3) < 1e-6
    assert cp.load_sql_cache(tmp_path, ["1"], 90, 24, _now(25)) is None  # stale
    assert cp.load_sql_cache(tmp_path, ["1"], 30, 24, _now(1)) is None  # other lookback
    assert cp.load_sql_cache(tmp_path, ["1", "2"], 90, 24, _now(1)) is None  # other scope
    assert cp.load_sql_cache(tmp_path, None, 90, 24, _now(1)) is None  # 'all' isn't 'one'
    assert cp.load_sql_cache(tmp_path, ["1"], 90, 0, _now(1)) is None  # reuse disabled


def test_wider_cached_run_is_not_reused_for_one_workspace(tmp_path):
    cp.save_sql_cache(tmp_path, None, 90, {"q": {"rows": []}}, "2026-11-18 12:00:00")
    assert cp.load_sql_cache(tmp_path, None, 90, 24, _now(1)) is not None
    assert cp.load_sql_cache(tmp_path, ["1"], 90, 24, _now(1)) is None


def test_sql_cache_ignores_partial_results_and_changed_queries(tmp_path, monkeypatch):
    cp.save_sql_cache(tmp_path, ["1"], 90, {"q": {"error": "boom"}}, "2026-11-18 12:00:00")
    assert cp.load_sql_cache(tmp_path, ["1"], 90, 24, _now(1)) is None
    cp.save_sql_cache(tmp_path, ["1"], 90, {"q": {"rows": []}}, "2026-11-18 12:00:00")
    monkeypatch.setattr(cp, "queries_fingerprint", lambda: "different")
    assert cp.load_sql_cache(tmp_path, ["1"], 90, 24, _now(1)) is None


def test_second_notebook_run_reuses_sql_and_rereads_config(tmp_path, monkeypatch):
    import databricks.sdk as sdk

    class _Boom:
        def __getattr__(self, _n):
            def f(*a, **k):
                raise PermissionError("not admin")

            return f

    class _FakeW:
        def __init__(self, *a, **k):
            self.workspace_conf = self.ip_access_lists = self.token_management = self.permissions = _Boom()
            self.config = type("C", (), {"host": "https://x.cloud.databricks.com"})()

        def get_workspace_id(self):
            return 42

    monkeypatch.setattr(sdk, "WorkspaceClient", _FakeW)
    monkeypatch.setattr(cp, "in_databricks", lambda: True)
    out = tmp_path / "out"
    first = _FakeSpark()
    assert cp.main(["--out", str(out)], spark=first) == 0
    assert first.calls and all(
        "IN ('0', '42')" in s or "IN ('42', '0')" in s for s, _ in first.calls if not s.startswith("DESCRIBE")
    )
    second = _FakeSpark()
    assert cp.main(["--out", str(out)], spark=second) == 0
    assert second.calls == []  # SQL reused
    report = (out / "report.md").read_text()
    assert "reused from an earlier run" in report and "workspace(s) 42 + account level" in report
    third = _FakeSpark()
    cp.main(["--out", str(out), "--refresh"], spark=third)
    assert third.calls  # --refresh re-runs


# ------------------------------------------------------------------------------ account secrets
def _secrets(monkeypatch, store):
    def fake(_w, ref):
        key = ".".join(ref[1:]) if ref[0] == "uc" else f"{ref[1]}/{ref[2]}"
        return (store[key], "") if key in store else (None, "NotFound")

    monkeypatch.setattr(cp, "read_secret", fake)


def test_uc_secret_with_json(monkeypatch):
    _secrets(monkeypatch, {"c.s.acc-sp": '{"account_id": "a1", "client_id": "app", "client_secret": "x"}'})
    creds, problem = cp.account_creds(None, "c.s.acc-sp")
    assert (
        problem == ""
        and creds["account_id"] == "a1"
        and creds["client_id"] == "app"
        and creds["client_secret"] == "x"
    )


def test_uc_secret_holding_only_the_oauth_secret(monkeypatch):
    _secrets(monkeypatch, {"c.s.acc-sp": "x"})
    creds, problem = cp.account_creds(None, "c.s.acc-sp")
    assert "--account-id" in problem and "--account-client-id" in problem
    creds, problem = cp.account_creds(None, "c.s.acc-sp", account_id="a1", client_id="app")
    assert problem == "" and creds["client_secret"] == "x"


def test_uc_schema_and_workspace_scope_of_keys(monkeypatch):
    _secrets(
        monkeypatch,
        {
            "c.s.account-id": "a1",
            "c.s.client-id": "app",
            "c.s.client-secret": "x",
            "scope/account-id": "a2",
            "scope/client-id": "app2",
            "scope/client-secret": "y",
        },
    )
    assert cp.account_creds(None, "c.s")[0]["account_id"] == "a1"
    creds, problem = cp.account_creds(None, "scope")
    assert problem == "" and creds["client_secret"] == "y"


def test_unreadable_or_malformed_secret_is_explained(monkeypatch):
    _secrets(monkeypatch, {})
    assert "READ SECRET" in cp.account_creds(None, "c.s.missing")[1]
    assert "isn't a secret scope" in cp.account_creds(None, "a.b.c.d")[1]


def test_account_errors_reach_the_report():
    posture = {
        "generated_at": "2026-11-18 00:00:00",
        "lookback_days": 90,
        "sql": {},
        "account": {"error": "PermissionDenied: not an account admin"},
        "workspaces": [{**ws(OPEN), "policy": None, "policy_error": "Unauthenticated: invalid client"}],
    }
    f, m = cp.evaluate(posture)
    md = cp.render_markdown(posture, f, m)
    assert "not an account admin" in md and "invalid client" in md


def test_never_customised_token_permissions_is_info_not_a_gap():
    pat = {
        "max_token_lifetime_days": "30",
        "tokens_enabled": True,
        "tokens": [],
        "permissions_customised": False,
    }
    ids, m, f = run(ws(OPEN, pat=pat))
    hit = next(x for x in f if x.id == "CBI-022")
    assert hit.severity == "info" and "never customised" in hit.title
    assert not any(x.id == "CBI-022" and x.severity == "medium" for x in f)


# ---------------------------------------------------------------- real-world rule shapes (synthetic)
def pol(mode_key="ingress", allow=(), deny=(), restriction="RESTRICTED_ACCESS"):
    return {
        "network_policy_id": "p",
        mode_key: {
            "public_access": {
                "restriction_mode": restriction,
                "allow_rules": list(allow),
                "deny_rules": list(deny),
            }
        },
        "egress": {"network_access": {"restriction_mode": "FULL_ACCESS"}},
    }


ALL_IPS = {"all_ip_ranges": True}
UI = {"workspace_ui": {"all_destinations": True}}


def rule(label, origin, dest, auth=None):
    r = {"label": label, "origin": origin, "destination": dest}
    if auth:
        r["authentication"] = auth
    return r


def score(policy):
    ids, m, f = run({**ws(policy), "assigned_policy_id": "p", "effective_policy_id": "p"})
    return m["1"]["level"], f


def test_browser_only_from_anywhere_is_b1_not_a_high_finding():
    level, f = score(
        pol(
            allow=[
                rule(
                    "ui-anywhere",
                    ALL_IPS,
                    {"all_destinations": False, **UI, "apps_runtime": {"all_destinations": True}},
                )
            ]
        )
    )
    assert level in (3, 4)
    assert not any(x.id == "CBI-004" for x in f)
    assert any(x.id == "CBI-029" for x in f)


def test_all_ips_to_all_destinations_is_open_even_when_restricted():
    level, f = score(pol(allow=[rule("everything", ALL_IPS, {"all_destinations": True})]))
    assert level == 0
    hit = next(x for x in f if x.id == "CBI-004" and x.severity == "high")
    assert "any IP call all workspace APIs" in hit.title


def test_empty_workspace_api_is_treated_as_all_apis_and_called_out():
    level, f = score(
        pol(allow=[rule("ui+api", ALL_IPS, {"all_destinations": False, **UI, "workspace_api": {}})])
    )
    assert level == 0
    hit = next(x for x in f if x.id == "CBI-004" and x.severity == "high")
    assert "without scopes" in hit.detail


def test_scoped_api_from_anywhere_is_b2_low():
    api = {"workspace_api": {"scope_qualifier": "API_SCOPE_QUALIFIER_ALL", "scopes": ["sql"]}, **UI}
    level, f = score(pol(allow=[rule("sql-anywhere", ALL_IPS, api)]))
    assert level in (3, 4)
    hit = next(x for x in f if x.id == "CBI-028")
    assert hit.severity == "low" and "sql" in hit.detail


def test_all_apis_scope_counts_as_all_but_read_qualifier_does_not():
    allapi = {"workspace_api": {"scopes": ["all-apis"]}}
    assert score(pol(allow=[rule("a", ALL_IPS, allapi)]))[0] == 0
    read = {"workspace_api": {"scopes": ["all-apis"], "scope_qualifier": "API_SCOPE_QUALIFIER_READ"}}
    level, f = score(pol(allow=[rule("r", ALL_IPS, read)]))
    assert level in (3, 4) and any(x.id == "CBI-028" for x in f)


def test_selected_identities_from_anywhere_is_medium():
    auth = {
        "identity_type": "IDENTITY_TYPE_SELECTED_IDENTITIES",
        "identities": [{"principal_id": 1, "principal_type": "PRINCIPAL_TYPE_SERVICE_PRINCIPAL"}],
    }
    level, f = score(pol(allow=[rule("sp", ALL_IPS, {"workspace_api": {"scopes": ["all-apis"]}}, auth)]))
    assert level in (3, 4)
    assert any(x.id == "CBI-004" and x.severity == "medium" for x in f)


def test_all_public_except_ranges_counts_as_anywhere():
    origin = {"excluded_ip_ranges": {"ip_ranges": ["192.0.2.0/24"]}}
    assert score(pol(allow=[rule("except", origin, {"all_destinations": True})]))[0] == 0


def test_source_not_visible_through_api_is_flagged_not_judged():
    level, f = score(pol(allow=[rule("slack-app", {}, {"workspace_api": {"scopes": ["genie"]}, **UI})]))
    assert any(x.id == "CBI-027" for x in f)
    assert not any(x.id == "CBI-004" for x in f)


def test_deny_everything_public_is_restrictive():
    level, f = score(
        pol(deny=[rule("deny-all", ALL_IPS, {"all_destinations": False, **UI, "workspace_api": {}})])
    )
    assert level in (3, 4)


def test_pattern_suggestion_knows_b1_is_already_in_use():
    p = pol(allow=[rule("ui-anywhere", ALL_IPS, UI), rule("everything", ALL_IPS, {"all_destinations": True})])
    level, f = score(p)
    hit = next(x for x in f if x.id == "CBI-026")
    assert "Already uses B1" in hit.detail and "everything" in hit.detail


def test_unlabelled_rules_are_numbered():
    p = pol(
        allow=[
            {"origin": {}, "destination": UI},
            {"origin": ALL_IPS, "destination": {"all_destinations": True}},
        ]
    )
    level, f = score(p)
    assert "allow rule 2 (unlabelled)" in next(x for x in f if x.id == "CBI-004").detail
    assert "allow rule 1 (unlabelled)" in next(x for x in f if x.id == "CBI-027").detail


def test_restricted_but_open_policy_wording_and_pattern():
    p = pol(allow=[{"origin": ALL_IPS, "destination": {"all_destinations": True}}])
    w = {**ws(p), "assigned_policy_id": "p", "effective_policy_id": "p", "ip_acl": None}
    posture = {
        "workspaces": [w],
        "sql": {"account_level_public_access": {"rows": [{"source_ip": "x"}] * 200}},
        "account": {"policies_read": True, "account_policy": OPEN},
    }
    f, m = cp.evaluate(posture)
    c1 = next(x for x in f if x.id == "CBI-001")
    assert "on paper" in c1.detail and "allow rule 1" in c1.detail
    assert "First narrow" in next(x for x in f if x.id == "CBI-026").detail
    assert "200+" in next(x for x in f if x.id == "CBI-009").detail


def test_large_account_report_groups_findings_by_check():
    many = [ws(OPEN, workspace_id=str(1000 + i), workspace_name=f"ws-{i}", ip_acl=None) for i in range(14)]
    many.append(ws(restricted("ingress", ["198.51.100.0/24"]), workspace_id="2000", workspace_name="locked"))
    posture = {
        "workspaces": many,
        "sql": {},
        "account": {"policies_read": True},
        "generated_at": "2026-01-01 00:00:00",
        "lookback_days": 30,
    }
    f, m = cp.evaluate(posture)
    cp.finalize_levels(f, m)
    assert m["1000"]["label"] == "CBI open, IP ACL unchecked" and m["1000"]["level"] is None
    md = cp.render_markdown(posture, f, m)
    assert "## Maturity across the account" in md and "| ? CBI open, IP ACL unchecked | 14 |" in md
    assert "Workspaces with a CBI policy or a perimeter (1)" in md and "| 2000 | locked |" in md
    assert "| 1003 | ws-3 |" not in md  # default-open workspaces are counted, not listed
    # each check appears once, with the workspace count, instead of once per workspace
    assert md.count("CBI-001: ") <= 1 and "14 workspace(s)" in md and "and " in md


def test_small_report_stays_per_workspace():
    posture = {
        "workspaces": [ws(OPEN)],
        "sql": {},
        "account": {"policies_read": True},
        "generated_at": "2026-01-01 00:00:00",
        "lookback_days": 30,
    }
    f, m = cp.evaluate(posture)
    md = cp.render_markdown(posture, f, m)
    assert "## Maturity by workspace" in md and "·  workspace `1`" in md


def test_single_scan_stages_once_and_drops_the_copy():
    calls = []

    def execute(stmt, params=True):
        calls.append(stmt)
        return []

    out = cp.run_sql(execute, lambda m: None, ["1234567890123456"], stage_schema="main.cbi", lookback_days=30)
    stage = [c for c in calls if c.startswith("CREATE OR REPLACE TABLE main.cbi.cbi_stage_audit_")]
    assert (
        len(stage) == 1 and "FROM system.access.audit" in stage[0] and "'1234567890123456', '0'" in stage[0]
    )
    table = stage[0].split()[4]
    queries = [c for c in calls if c not in stage and not c.startswith(("DESCRIBE", "DROP"))]
    assert len(queries) == len(cbi_sql.QUERIES) == len(out)
    # after staging, no query reads the audit system table again
    assert not any("system.access.audit" in q for q in queries)
    assert sum(f"FROM {table}" in q for q in queries) >= 10
    assert calls[-1] == f"DROP TABLE IF EXISTS {table}"


def test_staging_failure_falls_back_to_direct_reads():
    def execute(stmt, params=True):
        if stmt.startswith("CREATE"):
            raise RuntimeError("PERMISSION_DENIED: CREATE TABLE")
        return []

    seen = []
    out = cp.run_sql(
        lambda s, params=True: (seen.append(s), execute(s, params))[1],
        lambda m: None,
        None,
        stage_schema="main.cbi",
        lookback_days=30,
    )
    assert len(out) == len(cbi_sql.QUERIES) and all("error" not in v for v in out.values())
    assert any("FROM system.access.audit" in s for s in seen if not s.startswith(("CREATE", "DROP")))


def test_stage_schema_is_validated():
    calls = []
    cp.run_sql(
        lambda s, params=True: calls.append(s) or [],
        lambda m: None,
        None,
        stage_schema="x; DROP TABLE y",
        lookback_days=30,
    )
    assert not any(c.startswith(("CREATE", "DROP")) for c in calls)


class _CacheDF:
    def __init__(self, spark, stmt):
        self.spark, self.stmt = spark, stmt
        self.storageLevel = type("Lvl", (), {"useDisk": True, "useMemory": False, "useOffHeap": False})()

    def cache(self):
        self.spark.cached.append(self.stmt)
        return self

    def count(self):
        return 7

    def collect(self):
        return []

    def unpersist(self):
        self.spark.released = True


class _CacheSpark:
    def __init__(self, fail_cache=False, inactive=False):
        self.cached, self.sql_calls, self.released, self.fail_cache = [], [], False, fail_cache
        self.inactive, self.probed = inactive, 0

    def range(self, n):
        self.probed += 1
        if self.fail_cache:
            raise RuntimeError("NOT_SUPPORTED_WITH_SERVERLESS: PERSIST TABLE")
        df = _CacheDF(self, "range")
        if self.inactive:
            df.storageLevel = type("Lvl", (), {"useDisk": False, "useMemory": False, "useOffHeap": False})()
        df.cache = lambda: df
        return df

    def sql(self, stmt, args=None, **kw):
        if self.fail_cache and not kw:
            raise RuntimeError("NOT_SUPPORTED_WITH_SERVERLESS: PERSIST TABLE")
        self.sql_calls.append((stmt, kw))
        return _CacheDF(self, stmt)


def test_notebook_reads_audit_once_into_a_cached_dataframe():
    spark, direct = _CacheSpark(), []
    out = cp.run_sql(
        lambda s, params=True, direct=direct: direct.append(s) or [],
        lambda m: None,
        ["1234567890123456"],
        lookback_days=30,
        spark=spark,
    )
    assert len(spark.cached) == 1 and "FROM system.access.audit" in spark.cached[0]
    assert "'1234567890123456', '0'" in spark.cached[0]
    over_cache = [s for s, kw in spark.sql_calls if kw]
    assert len(over_cache) == sum(cbi_sql.reads_audit(q) for _, q in cbi_sql.QUERIES.values()) >= 9
    assert all(
        "{cbi_rollup}" in s and "system.access.audit" not in s and ":lookback_days" not in s
        for s in over_cache
    )
    # nothing written anywhere; only the inbound queries (and DESCRIBE) go to the plain executor
    assert not any(s.startswith(("CREATE", "DROP", "INSERT")) for s in direct)
    assert all("inbound_network" in s for s in direct)
    assert spark.released and len(out) == len(cbi_sql.QUERIES)


def test_no_dataframe_cache_falls_back_to_direct_reads():
    spark, direct = _CacheSpark(fail_cache=True), []
    out = cp.run_sql(
        lambda s, params=True, direct=direct: direct.append(s) or [],
        lambda m: None,
        None,
        lookback_days=30,
        spark=spark,
    )
    assert len(out) == len(cbi_sql.QUERIES) and all("error" not in v for v in out.values())
    assert sum("FROM system.access.audit" in s for s in direct) == sum(
        cbi_sql.reads_audit(q) for _, q in cbi_sql.QUERIES.values()
    )


def test_explicit_stage_schema_wins_over_the_cache():
    spark, direct = _CacheSpark(), []
    cp.run_sql(
        lambda s, params=True, direct=direct: direct.append(s) or [],
        lambda m: None,
        None,
        stage_schema="main.cbi",
        lookback_days=30,
        spark=spark,
    )
    assert not spark.cached and any(s.startswith("CREATE OR REPLACE TABLE main.cbi.") for s in direct)


def test_cache_probe_skips_the_full_scan_when_the_cache_is_off():
    # serverless below env 5 / GovCloud: a one-row probe decides, so the audit slice is never
    # scanned for nothing
    for spark in (_CacheSpark(inactive=True), _CacheSpark(fail_cache=True)):
        logs, direct = [], []
        cp.run_sql(
            lambda s, params=True, direct=direct: direct.append(s) or [],
            logs.append,
            None,
            lookback_days=30,
            spark=spark,
        )
        assert spark.probed == 1 and not spark.sql_calls and not spark.cached
        assert any("cache unavailable" in m for m in logs)


def test_queries_run_in_parallel_and_keep_their_order():
    import threading

    lock, live, peak = threading.Lock(), [0], [0]

    def execute(stmt, params=True):
        with lock:
            live[0] += 1
            peak[0] = max(peak[0], live[0])
        time.sleep(0.05)
        with lock:
            live[0] -= 1
        return [{"n": 1}]

    out = cp.run_sql(execute, lambda m: None, None, lookback_days=30, parallel=4)
    assert list(out) == list(cbi_sql.QUERIES) and all(v == {"rows": [{"n": 1}]} for v in out.values())
    assert 1 < peak[0] <= 4
    peak[0] = 0
    cp.run_sql(execute, lambda m: None, None, lookback_days=30, parallel=1)
    assert peak[0] == 1


def test_account_policy_lookups_run_in_parallel():
    import threading

    seen = set()

    class Opt:
        network_policy_id = None

    class A:
        class network_policies:
            @staticmethod
            def list_network_policies_rpc():
                return []

            @staticmethod
            def get_network_policy_rpc(network_policy_id):
                return type("P", (), {"as_dict": lambda self: {"network_policy_id": network_policy_id}})()

        class workspace_network_configuration:
            @staticmethod
            def get_workspace_network_option_rpc(workspace_id):
                seen.add(threading.current_thread().name)
                time.sleep(0.02)
                return Opt()

        class workspaces:
            @staticmethod
            def list():
                return [
                    type(
                        "W",
                        (),
                        {
                            "workspace_id": i,
                            "workspace_name": f"ws{i}",
                            "cloud": "aws",
                            "pricing_tier": None,
                            "deployment_name": None,
                            "private_access_settings_id": None,
                        },
                    )()
                    for i in range(1, 21)
                ]

    _acct, wss = cp.collect_account(A(), None)
    assert [w["workspace_id"] for w in wss] == [str(i) for i in range(1, 21)]
    assert all(w["effective_policy_id"] == "default-policy" and w["policy"] for w in wss)
    assert len(seen) > 1
