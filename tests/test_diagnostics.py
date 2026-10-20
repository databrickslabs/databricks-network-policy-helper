"""Tests for the empty-candidate diagnostic funnel (query builder, engine wiring, render hints)."""

from __future__ import annotations

import pandas as pd

from dbx_nwp_helper import queries, render
from dbx_nwp_helper.config import IngressConfig
from dbx_nwp_helper.core import ingress as ing


def test_candidate_funnel_query_shape():
    q = queries.candidate_funnel(30, treat_null_status_as_success=False)
    for col in [
        "total_rows",
        "with_source_ip",
        "ipv4",
        "ipv6",
        "successful",
        "workspace_level",
        "account_level",
        "public_ipv4",
        "distinct_public_ok",
        "distinct_public_ok_ws",
    ]:
        assert col in q
    assert "status_code IS NULL AND FALSE" in q
    assert "INTERVAL 30 DAYS" in q


def test_analyze_runs_funnel_only_when_empty(monkeypatch):
    # frequent_public_ips -> empty; funnel query -> a fixture row; feeds stubbed empty.
    from dbx_nwp_helper.feeds import loaders

    monkeypatch.setattr(
        loaders,
        "threat_intel",
        lambda f, refresh=False: pd.DataFrame(
            columns=["cidr", "source_feed", "threat_type", "confidence", "source_url", "loaded_at"]
        ),
    )
    monkeypatch.setattr(
        loaders,
        "cloud_ranges",
        lambda refresh=False: pd.DataFrame(columns=["cidr", "provider", "service", "region", "loaded_at"]),
    )
    monkeypatch.setattr(
        loaders,
        "databricks_ranges",
        lambda refresh=False: pd.DataFrame(columns=["cidr", "platform", "region", "direction", "loaded_at"]),
    )

    funnel_row = pd.DataFrame(
        [
            {
                "total_rows": 100,
                "with_source_ip": 80,
                "ipv4": 80,
                "ipv6": 0,
                "successful": 80,
                "workspace_level": 0,
                "account_level": 80,
                "public_ipv4": 80,
                "distinct_public_ok": 5,
                "distinct_public_ok_ws": 0,
            }
        ]
    )

    def fake_query(_c, text):
        if "candidate_funnel" in text or "distinct_public_ok_ws" in text:
            return funnel_row
        if "IpAccessDenied" in text:
            return pd.DataFrame(columns=["source_ip"])
        return pd.DataFrame()  # frequent_public_ips empty

    monkeypatch.setattr("dbx_nwp_helper.sql.query", fake_query)

    class _WS:
        ip_access_lists = type("A", (), {"list": lambda self=None: []})()

        def get_workspace_id(self):
            return 123

    a = ing.analyze(
        IngressConfig(enable_rdap=False, policy_scope="all_workspaces"), sql_conn=None, workspace_client=_WS()
    )
    assert a.candidates.empty
    assert a.funnel is not None
    assert a.funnel["distinct_public_ok"] == 5
    assert a.funnel["distinct_public_ok_ws"] == 0


def test_enrich_candidates_reports_rdap_progress(monkeypatch):
    # progress is reported per RDAP lookup (the slow, network-bound step) so the spinner tracks it.
    # workers=1 keeps completion order deterministic for the assertion.
    from dbx_nwp_helper.feeds import rdap

    monkeypatch.setattr(rdap, "lookup", lambda ip: dict(rdap._EMPTY))  # no network
    candidates = pd.DataFrame(
        [
            {
                "public_ip": ip,
                "events": 1,
                "principals": 1,
                "principal_list": [],
                "principal_emails": [],
                "subject_names": [],
                "workspace_ids": [],
                "service_list": [],
            }
            for ip in ("8.8.8.8", "1.1.1.1", "9.9.9.9")
        ]
    )
    calls = []
    ing._enrich_candidates(
        candidates,
        IngressConfig(enable_rdap=True, rdap_workers=1),
        [],
        [],
        [],
        [],
        on_progress=lambda done, total, ip: calls.append((done, total, ip)),
    )
    assert calls == [(1, 3, "8.8.8.8"), (2, 3, "1.1.1.1"), (3, 3, "9.9.9.9")]


def test_rdap_lookups_concurrent_dedupes_and_covers_all(monkeypatch):
    # concurrent path: every distinct IP is resolved exactly once, progress counts up to the total.
    from dbx_nwp_helper.feeds import rdap

    seen = []
    monkeypatch.setattr(rdap, "lookup", lambda ip: seen.append(ip) or {"rdap_owner_name": ip})
    ips = ["1.1.1.1", "2.2.2.2", "1.1.1.1", "3.3.3.3"]  # a duplicate to prove de-duping
    progress = []
    cache = ing._rdap_lookups(ips, workers=4, on_progress=lambda d, t, ip: progress.append((d, t)))
    assert set(cache) == {"1.1.1.1", "2.2.2.2", "3.3.3.3"}
    assert sorted(seen) == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]  # deduped -> 3 lookups, not 4
    assert [d for d, _t in progress] == [1, 2, 3] and progress[-1][1] == 3


def test_rdap_lookups_single_failure_degrades(monkeypatch):
    # one lookup raising must not sink the sweep — it becomes the empty result.
    from dbx_nwp_helper.feeds import rdap

    def flaky(ip):
        if ip == "2.2.2.2":
            raise RuntimeError("rdap boom")
        return {"rdap_owner_name": "ok"}

    monkeypatch.setattr(rdap, "lookup", flaky)
    cache = ing._rdap_lookups(["1.1.1.1", "2.2.2.2"], workers=2)
    assert cache["1.1.1.1"]["rdap_owner_name"] == "ok"
    assert cache["2.2.2.2"] == rdap._EMPTY


def test_rdap_lookups_reuse_assigned_range_skips_network(monkeypatch):
    # once an IP resolves to an assigned block, sibling IPs in that block reuse it with NO extra
    # lookup. workers=1 so the first result is cached before the siblings are processed.
    from dbx_nwp_helper.feeds import rdap

    calls = []

    def fake_lookup(ip):
        calls.append(ip)
        return {"rdap_owner_name": "ACME", "rdap_type": None, "maximum_cidrs": ["203.0.113.0/24"]}

    monkeypatch.setattr(rdap, "lookup", fake_lookup)
    ips = ["203.0.113.10", "203.0.113.11", "203.0.113.250", "198.51.100.7"]
    cache = ing._rdap_lookups(ips, workers=1)
    # only ONE lookup for the whole 203.0.113.0/24 block, plus one for the other network
    assert calls == ["203.0.113.10", "198.51.100.7"]
    assert cache["203.0.113.11"]["rdap_owner_name"] == "ACME"  # reused from the range
    assert cache["203.0.113.250"]["rdap_owner_name"] == "ACME"
    assert set(cache) == set(ips)


def test_enrich_skips_rdap_for_known_cloud_and_databricks(monkeypatch):
    # IPs in the offline Databricks/cloud ranges get their owner directly (friendly label) and are
    # NOT sent to RDAP — only the genuinely-unknown IP is looked up.
    import ipaddress

    from dbx_nwp_helper.feeds import rdap

    calls = []
    monkeypatch.setattr(
        rdap,
        "lookup",
        lambda ip: calls.append(ip)
        or {"rdap_owner_name": "Some ISP", "rdap_type": None, "maximum_cidrs": None},
    )
    cloud_ranges = [(ipaddress.ip_network("52.0.0.0/8"), {"provider": "aws"})]
    dbx_ranges = [(ipaddress.ip_network("3.3.3.0/24"), {"platform": "aws"})]
    candidates = pd.DataFrame(
        [
            {
                "public_ip": ip,
                "events": 1,
                "principals": 1,
                "principal_list": [],
                "principal_emails": [],
                "subject_names": [],
                "workspace_ids": [],
                "service_list": [],
            }
            for ip in ("52.1.2.3", "3.3.3.9", "8.8.8.8")
        ]
    )
    enriched, _ = ing._enrich_candidates(
        candidates,
        IngressConfig(enable_rdap=True, rdap_workers=1),
        [],  # threat ranges
        cloud_ranges,
        dbx_ranges,
        [],  # partner ranges
    )
    assert calls == ["8.8.8.8"]  # only the unknown IP hit the network
    owners = {r["public_ip"]: r["rdap_owner_name"] for r in enriched}
    assert owners["52.1.2.3"] == "Amazon Web Services (AWS)"
    assert owners["3.3.3.9"] == "Databricks"
    assert owners["8.8.8.8"] == "Some ISP"


def test_rdap_lookups_no_range_falls_back_to_per_ip(monkeypatch):
    # when RDAP returns no assigned block (maximum_cidrs=None), there's nothing to reuse — each IP
    # is looked up individually (no incorrect cross-IP reuse).
    from dbx_nwp_helper.feeds import rdap

    calls = []
    monkeypatch.setattr(
        rdap,
        "lookup",
        lambda ip: calls.append(ip) or {"rdap_owner_name": ip, "rdap_type": None, "maximum_cidrs": None},
    )
    ips = ["203.0.113.10", "203.0.113.11"]
    ing._rdap_lookups(ips, workers=1)
    assert calls == ips  # both looked up — no range to reuse


def test_render_hint_account_level(capsys):
    # public IPs exist but only account-level -> hint to use --include-account-level.
    funnel = {
        "total_rows": 100,
        "with_source_ip": 80,
        "ipv4": 80,
        "ipv6": 0,
        "successful": 80,
        "workspace_level": 0,
        "account_level": 80,
        "public_ipv4": 80,
        "distinct_public_ok": 5,
        "distinct_public_ok_ws": 0,
    }
    render._explain_empty_candidates(funnel, IngressConfig(include_account_level=False))
    out = capsys.readouterr().out
    assert "--include-account-level" in out


def test_render_hint_privatelink(capsys):
    # source IPs all private -> PrivateLink/NAT hint.
    funnel = {
        "total_rows": 100,
        "with_source_ip": 80,
        "ipv4": 80,
        "ipv6": 0,
        "successful": 80,
        "workspace_level": 80,
        "account_level": 0,
        "public_ipv4": 0,
        "distinct_public_ok": 0,
        "distinct_public_ok_ws": 0,
    }
    render._explain_empty_candidates(funnel, IngressConfig())
    out = capsys.readouterr().out
    assert "PrivateLink" in out or "NAT" in out


def test_render_hint_no_rows(capsys):
    funnel = {
        "total_rows": 0,
        "with_source_ip": 0,
        "ipv4": 0,
        "ipv6": 0,
        "successful": 0,
        "workspace_level": 0,
        "account_level": 0,
        "public_ipv4": 0,
        "distinct_public_ok": 0,
        "distinct_public_ok_ws": 0,
    }
    render._explain_empty_candidates(funnel, IngressConfig())
    out = capsys.readouterr().out
    assert "lookback" in out.lower()
