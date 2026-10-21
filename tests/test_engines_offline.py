"""Offline engine tests using fixture DataFrames + fake enrichment ranges.

No network / no Databricks — patches the feed loaders and SQL to exercise the ingress/egress/acl
engines end-to-end through rule building and SDK-block construction.
"""

from __future__ import annotations

import pandas as pd
import pytest

from dbx_nwp_helper.config import EgressConfig, IngressConfig
from dbx_nwp_helper.core import egress as eg
from dbx_nwp_helper.core import ingress as ing
from dbx_nwp_helper.core import ingress_rules as rules


def _denied(source_ip, events, principals):
    return {
        "source_ip": source_ip,
        "denied_events": events,
        "principals": len(principals),
        "principal_list": principals,
        "first_denied": "2026-01-01",
        "last_denied": "2026-02-01",
    }


def test_merge_denied_combines_audit_and_inbound_by_ip():
    # An IP seen in both the IP-ACL (audit) and CBI (inbound_network) denials collapses to one row
    # with summed events and a unioned principal list; a CBI-only IP is added.
    audit = pd.DataFrame([_denied("1.2.3.4", 3, ["alice"]), _denied("5.6.7.8", 2, ["bob"])])
    inbound = pd.DataFrame([_denied("1.2.3.4", 4, ["carol"]), _denied("9.9.9.9", 1, ["dan"])])
    merged = ing._merge_denied(audit, inbound)

    by_ip = {r["source_ip"]: r for r in merged.to_dict(orient="records")}
    assert set(by_ip) == {"1.2.3.4", "5.6.7.8", "9.9.9.9"}
    assert by_ip["1.2.3.4"]["denied_events"] == 7  # 3 + 4
    assert by_ip["1.2.3.4"]["principal_list"] == ["alice", "carol"]  # unioned + sorted
    assert by_ip["1.2.3.4"]["principals"] == 2
    assert by_ip["9.9.9.9"]["denied_events"] == 1  # CBI-only IP carried through
    # rows ordered by denied_events desc
    assert merged.iloc[0]["source_ip"] == "1.2.3.4"


def test_merge_denied_handles_numpy_array_principal_lists():
    # Real runs (and a frame persisted to a table then read back) hand principal_list back as numpy
    # arrays, not plain lists. A numpy array can't be truth-tested, so the old `lst or []` raised
    # "truth value of an array ... is ambiguous"; as_list normalises it. Regression guard.
    import numpy as np

    def _np_denied(source_ip, events, principals):
        row = _denied(source_ip, events, list(principals))
        row["principal_list"] = np.array(principals, dtype=object)
        return row

    audit = pd.DataFrame([_np_denied("1.2.3.4", 3, ["alice", "eve"])])
    inbound = pd.DataFrame([_np_denied("1.2.3.4", 4, ["carol"])])
    merged = ing._merge_denied(audit, inbound)  # must not raise

    row = merged.to_dict(orient="records")[0]
    assert row["source_ip"] == "1.2.3.4"
    assert row["denied_events"] == 7  # 3 + 4
    assert row["principal_list"] == ["alice", "carol", "eve"]  # unioned + sorted
    assert row["principals"] == 3


def test_read_inbound_network_denied_degrades_when_table_absent(monkeypatch):
    import dbx_nwp_helper.sql as sqlmod

    def _raise(_c, _t):
        raise Exception("TABLE_OR_VIEW_NOT_FOUND: system.access.inbound_network")

    monkeypatch.setattr(sqlmod, "query", _raise)
    assert ing._read_inbound_network_denied(object(), 30) is None  # best-effort → None, no crash


def test_read_inbound_network_candidates_degrades_when_table_absent(monkeypatch):
    import dbx_nwp_helper.sql as sqlmod

    def _raise(_c, _t):
        raise Exception("TABLE_OR_VIEW_NOT_FOUND: system.access.inbound_network")

    monkeypatch.setattr(sqlmod, "query", _raise)
    assert ing._read_inbound_network_candidates(object(), 30, 1) is None  # best-effort → None


def _inbound_candidate(public_ip, events=2, principals=("a@x.com",)):
    return {
        "public_ip": public_ip,
        "events": events,
        "principals": len(principals),
        "active_days": 1,
        "principal_list": list(principals),
        "first_active_date": "2026-01-01",
        "last_active_date": "2026-01-02",
    }


def test_merge_candidates_adds_only_new_public_ips():
    # Dry-run-denial inbound rows fold into the audit candidates as NEW public IPs only; an IP already
    # in the audit set keeps its (richer) audit row; private / reserved IPs are dropped.
    audit = pd.DataFrame([{"public_ip": "203.0.55.10", "events": 100}])
    inbound = pd.DataFrame(
        [
            _inbound_candidate("93.184.216.7"),  # new, public → added
            _inbound_candidate("203.0.55.10"),  # already in audit → not duplicated
            _inbound_candidate("10.0.0.5"),  # private → dropped
        ]
    )
    merged, added = ing._merge_candidates(audit, inbound, include_ipv6=False)
    assert added == 1
    ips = list(merged["public_ip"])
    assert ips.count("203.0.55.10") == 1  # not duplicated
    assert "93.184.216.7" in ips
    assert "10.0.0.5" not in ips  # private filtered out


def test_merge_candidates_respects_ipv6_toggle():
    audit = pd.DataFrame(columns=["public_ip", "events"])
    inbound = pd.DataFrame([_inbound_candidate("2606:4700::1111")])
    _, added_off = ing._merge_candidates(audit, inbound, include_ipv6=False)
    assert added_off == 0  # IPv6 skipped by default
    _, added_on = ing._merge_candidates(audit, inbound, include_ipv6=True)
    assert added_on == 1


def test_analyze_folds_in_inbound_dry_run_candidate(monkeypatch, candidates_df):
    # A public IP that only shows up as a dry-run denial in inbound_network becomes an allow-list
    # candidate (and a suggestion), even though it's absent from the audit candidate set.
    _patch_feeds(monkeypatch)
    import dbx_nwp_helper.sql as sqlmod

    def fake_query(_conn, text):
        if "outbound_network" in text:
            return pd.DataFrame()
        if "DRY_RUN_DENIAL" in text:  # the candidate_ips_from_inbound_network query
            return pd.DataFrame([_inbound_candidate("93.184.216.42", events=9)])
        if "inbound_network" in text:  # the DROP denied-view query
            return pd.DataFrame()
        if "IpAccessDenied" in text:
            return pd.DataFrame(columns=["source_ip"])
        return candidates_df

    monkeypatch.setattr(sqlmod, "query", fake_query)
    cfg = IngressConfig(enable_rdap=False, scoping_mode="ip_only", policy_scope="all_workspaces")
    analysis = ing.analyze(cfg, None, _FakeWorkspaceClient())
    assert "93.184.216.42" in set(analysis.candidates["public_ip"])


def test_analyze_skips_inbound_candidates_when_disabled(monkeypatch, candidates_df):
    _patch_feeds(monkeypatch)
    import dbx_nwp_helper.sql as sqlmod

    seen = {"dry_run_queried": False}

    def fake_query(_conn, text):
        if "outbound_network" in text:
            return pd.DataFrame()
        if "DRY_RUN_DENIAL" in text:
            seen["dry_run_queried"] = True
            return pd.DataFrame([_inbound_candidate("93.184.216.42")])
        if "inbound_network" in text:
            return pd.DataFrame()
        if "IpAccessDenied" in text:
            return pd.DataFrame(columns=["source_ip"])
        return candidates_df

    monkeypatch.setattr(sqlmod, "query", fake_query)
    cfg = IngressConfig(
        enable_rdap=False,
        scoping_mode="ip_only",
        policy_scope="all_workspaces",
        include_inbound_network=False,
    )
    analysis = ing.analyze(cfg, None, _FakeWorkspaceClient())
    assert seen["dry_run_queried"] is False  # the candidate query never ran
    assert "93.184.216.42" not in set(analysis.candidates["public_ip"])


class _FakeIpAclApi:
    def __init__(self, acls):
        self._acls = acls

    def list(self):
        return self._acls


class _FakeWorkspaceClient:
    def __init__(self, acls=None, ws_id=123):
        self.ip_access_lists = _FakeIpAclApi(acls or [])
        self._ws_id = ws_id

    def get_workspace_id(self):
        return self._ws_id


@pytest.fixture
def candidates_df():
    return pd.DataFrame(
        [
            {
                "public_ip": "203.0.55.10",
                "ip_version": 4,
                "events": 100,
                "principals": 2,
                "services": 1,
                "actions": 3,
                "active_days": 5,
                "sessions": 4,
                "first_active_date": "2026-01-01",
                "last_active_date": "2026-01-05",
                "principal_list": ["a@x.com"],
                "principal_emails": ["a@x.com"],
                "subject_names": [],
                "service_list": ["apps"],
                "workspace_ids": [123],
            },
            {
                "public_ip": "8.8.8.8",
                "ip_version": 4,
                "events": 5,
                "principals": 1,
                "services": 1,
                "actions": 1,
                "active_days": 1,
                "sessions": 1,
                "first_active_date": "2026-01-02",
                "last_active_date": "2026-01-02",
                "principal_list": ["b@x.com"],
                "principal_emails": ["b@x.com"],
                "subject_names": [],
                "service_list": ["jobs"],
                "workspace_ids": [123],
            },
        ]
    )


def _patch_feeds(monkeypatch, threat_rows=None, cloud_rows=None, dbx_rows=None, partner_rows=None):
    from dbx_nwp_helper.feeds import loaders

    monkeypatch.setattr(
        loaders,
        "threat_intel",
        lambda feeds, refresh=False: pd.DataFrame(
            threat_rows or [],
            columns=["cidr", "source_feed", "threat_type", "confidence", "source_url", "loaded_at"],
        ),
    )
    monkeypatch.setattr(
        loaders,
        "partner_ranges",
        lambda refresh=False: pd.DataFrame(
            partner_rows or [], columns=["cidr", "partner", "region", "source_url", "loaded_at"]
        ),
    )
    monkeypatch.setattr(
        loaders,
        "cloud_ranges",
        lambda refresh=False: pd.DataFrame(
            cloud_rows or [], columns=["cidr", "provider", "service", "region", "loaded_at"]
        ),
    )
    monkeypatch.setattr(
        loaders,
        "databricks_ranges",
        lambda refresh=False: pd.DataFrame(
            dbx_rows or [], columns=["cidr", "platform", "region", "direction", "loaded_at"]
        ),
    )


def test_ingress_ip_only_dry_run(monkeypatch, candidates_df):
    # 8.8.8.8 is on a threat feed -> excluded from allow rules; 203.0.55.10 stays.
    _patch_feeds(
        monkeypatch,
        threat_rows=[("8.8.8.0/24", "ipsum", "aggregated_blocklist", 1, "http://x", "2026-01-01")],
    )

    # Stub sql.query to return our candidates / empty denied.
    import dbx_nwp_helper.sql as sqlmod

    def fake_query(_conn, text):
        if "outbound_network" in text:
            return pd.DataFrame()
        if "inbound_network" in text:  # CBI-policy denials — table absent in this fixture
            return pd.DataFrame()
        if "IpAccessDenied" in text:
            return pd.DataFrame(columns=["source_ip"])
        return candidates_df

    monkeypatch.setattr(sqlmod, "query", fake_query)

    cfg = IngressConfig(
        min_events=1,
        enable_rdap=False,
        policy_framing="minimal",
        scoping_mode="ip_only",
        policy_scope="all_workspaces",
    )
    analysis = ing.analyze(cfg, sql_conn=None, workspace_client=_FakeWorkspaceClient())
    assert not analysis.suggestions.empty
    # threat match table should include 8.8.8.8
    assert "8.8.8.8" in set(analysis.threat_matches["observed_ip"])

    # A plain (non-flagged) candidate is recommended for review as an unknown hosting provider.
    recs = set(analysis.suggestions["recommendation"])
    assert "REVIEW — Other hosting provider" in recs
    assert "candidate" not in recs

    policies = rules.build_rules(analysis, cfg)
    previews = rules.preview_blocks(policies, cfg)
    # single scope -> one target
    assert "__ALL__" in policies
    block = previews["__ALL__"]["ingress_dry_run"]
    cidrs = block["public_access"]["allow_rules"][0]["origin"]["included_ip_ranges"]["ip_ranges"]
    assert "203.0.55.10/32" in cidrs
    assert all(not c.startswith("8.8.8") for c in cidrs)  # threat IP excluded
    assert analysis.excluded_flagged == 1


def test_ingress_databricks_owned_takes_precedence(monkeypatch, candidates_df):
    # Mark 8.8.8.0/24 as BOTH cloud and databricks-owned -> should be ALLOWED (databricks wins).
    _patch_feeds(
        monkeypatch,
        cloud_rows=[("8.8.8.0/24", "gcp", "svc", "us", "2026-01-01")],
        dbx_rows=[("8.8.8.0/24", "aws", "us", "inbound", "2026-01-01")],
    )
    import dbx_nwp_helper.sql as sqlmod

    def _q(_c, t):
        if "inbound_network" in t:
            return pd.DataFrame()
        if "IpAccessDenied" in t:
            return pd.DataFrame(columns=["source_ip"])
        return candidates_df

    monkeypatch.setattr(sqlmod, "query", _q)
    cfg = IngressConfig(enable_rdap=False, scoping_mode="ip_only", policy_scope="all_workspaces")
    analysis = ing.analyze(cfg, None, _FakeWorkspaceClient())
    recs = {r["rdap_owner"]: r for _, r in analysis.suggestions.iterrows()}
    dbx_group = [r for r in recs.values() if r["databricks_owned"]]
    assert dbx_group and dbx_group[0]["recommendation"] == "ALLOW — Databricks-owned"


def test_ingress_partner_platform_ip_labelled_and_allowed(monkeypatch, candidates_df):
    # 203.0.55.10 falls in a Power BI partner range → labelled as the partner, recommended ALLOW,
    # and included as an allow rule (even though it also sits in a cloud range).
    _patch_feeds(
        monkeypatch,
        cloud_rows=[("203.0.55.0/24", "azure", "svc", "eastus", "2026-01-01")],
        partner_rows=[("203.0.55.0/24", "Power BI", "", "https://x", "2026-01-01")],
    )
    import dbx_nwp_helper.sql as sqlmod

    def _q(_c, t):
        if "inbound_network" in t:
            return pd.DataFrame()
        if "IpAccessDenied" in t:
            return pd.DataFrame(columns=["source_ip"])
        return candidates_df

    monkeypatch.setattr(sqlmod, "query", _q)
    cfg = IngressConfig(enable_rdap=False, scoping_mode="ip_only", policy_scope="all_workspaces")
    analysis = ing.analyze(cfg, None, _FakeWorkspaceClient())
    pbi = [r for r in analysis.suggestion_rows if r.get("partners")]
    assert pbi and pbi[0]["partners"] == ["Power BI"]
    assert pbi[0]["recommendation"] == "ALLOW — Power BI platform"

    policies = rules.build_rules(analysis, cfg)
    previews = rules.preview_blocks(policies, cfg)
    labels = [r["label"] for r in previews["__ALL__"]["ingress_dry_run"]["public_access"]["allow_rules"]]
    assert any("Power-BI" in lbl for lbl in labels)  # clean partner label, not cloud-prefixed


def test_egress_classification_and_block(monkeypatch):
    observed = pd.DataFrame(
        [
            {
                "destination": "mybucket.s3.us-west-2.amazonaws.com",
                "destination_type": "DNS",
                "events": 10,
                "workspace_ids": [123],
                "resolved_ips": [],
            },
            {
                "destination": "api.openai.com",
                "destination_type": "DNS",
                "events": 4,
                "workspace_ids": [123],
                "resolved_ips": ["1.2.3.4"],
            },
        ]
    )
    import dbx_nwp_helper.sql as sqlmod

    monkeypatch.setattr(sqlmod, "query", lambda _c, _t: observed)
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off", policy_scope="all_workspaces")
    analysis = eg.analyze(cfg, None)
    assert eg.union(analysis.targets, "s3")
    assert "api.openai.com" in eg.union(analysis.targets, "internet")
    previews = eg.preview_blocks(analysis, cfg)
    egr = previews["__ALL__"]["egress"]["network_access"]
    assert egr["restriction_mode"] == "RESTRICTED_ACCESS"
    assert any(d["destination"] == "api.openai.com" for d in egr["allowed_internet_destinations"])
