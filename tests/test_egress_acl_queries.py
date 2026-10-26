"""Unit tests for egress analyze/build, ACL analyze/apply, and the SQL query builders."""

from __future__ import annotations

import pandas as pd

from dbx_nwp_helper import queries
from dbx_nwp_helper.config import EgressConfig
from dbx_nwp_helper.core import acl as acl_core
from dbx_nwp_helper.core import egress as eg


# ------------------------------------------------------------------------ egress recommendation
def test_egress_recommend_maps_owner():
    assert eg.recommend("Databricks") == "ALLOW — Databricks-owned"
    assert eg.recommend("AWS") == "REVIEW — Cloud-owned"
    assert eg.recommend("GCP") == "REVIEW — Cloud-owned"
    assert eg.recommend("Azure") == "REVIEW — Cloud-owned"
    # a named non-cloud owner (from RDAP)
    assert eg.recommend("Cloudflare, Inc.") == "REVIEW — Other infra provider"


def test_egress_recommend_unknown_when_no_lookup():
    # owner lookup disabled (None), an explicit Unknown, or DNS failed -> don't claim a provider
    assert eg.recommend(None) == "REVIEW — owner unknown"
    assert eg.recommend("Unknown") == "REVIEW — owner unknown"
    assert eg.recommend("DNS_RESOLUTION_FAILED") == "REVIEW — owner unknown"


# --------------------------------------------------------------------------------- egress
def test_egress_owner_lookup_rdap_fallback(monkeypatch):
    # FQDN resolves to an IP that's NOT in any cloud range -> RDAP fallback names the owner.
    observed = pd.DataFrame(
        [
            {
                "destination": "api.example.com",
                "destination_type": "DNS",
                "events": 5,
                "workspace_ids": [1],
                "resolved_ips": ["104.16.1.1"],
            }
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    monkeypatch.setattr(eg, "_load_cloud_networks", lambda: [])  # nothing matches offline
    from dbx_nwp_helper.feeds import rdap

    monkeypatch.setattr(rdap, "lookup", lambda ip: {"rdap_owner_name": "Cloudflare"})
    cfg = EgressConfig(enable_rdap=True, block_threat_domains="off", policy_scope="all_workspaces")
    a = eg.analyze(cfg, sql_conn=None)
    assert a.fqdn_owner["api.example.com"] == "Cloudflare"  # just the owner, no "non-cloud:" prefix
    assert eg.recommend(a.fqdn_owner["api.example.com"]) == "REVIEW — Other infra provider"


def test_egress_owner_unknown_when_rdap_also_misses(monkeypatch):
    observed = pd.DataFrame(
        [
            {
                "destination": "api.example.com",
                "destination_type": "DNS",
                "events": 5,
                "workspace_ids": [1],
                "resolved_ips": ["104.16.1.1"],
            }
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    monkeypatch.setattr(eg, "_load_cloud_networks", lambda: [])
    from dbx_nwp_helper.feeds import rdap

    monkeypatch.setattr(rdap, "lookup", lambda ip: {"rdap_owner_name": None})
    cfg = EgressConfig(enable_rdap=True, block_threat_domains="off", policy_scope="all_workspaces")
    a = eg.analyze(cfg, sql_conn=None)
    assert a.fqdn_owner["api.example.com"] == "Unknown"


def test_egress_owner_lookup_cloud_match_no_rdap(monkeypatch):
    # An IP in a cloud range is named directly; RDAP must NOT be called.
    observed = pd.DataFrame(
        [
            {
                "destination": "api.example.com",
                "destination_type": "DNS",
                "events": 5,
                "workspace_ids": [1],
                "resolved_ips": ["52.10.0.5"],
            }
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    import ipaddress

    monkeypatch.setattr(eg, "_load_cloud_networks", lambda: [(ipaddress.ip_network("52.10.0.0/16"), "AWS")])
    from dbx_nwp_helper.feeds import rdap

    monkeypatch.setattr(
        rdap,
        "lookup",
        lambda ip: (_ for _ in ()).throw(
            AssertionError("RDAP must not be called when the offline cloud match succeeds")
        ),
    )
    cfg = EgressConfig(enable_rdap=True, block_threat_domains="off", policy_scope="all_workspaces")
    a = eg.analyze(cfg, sql_conn=None)
    assert a.fqdn_owner["api.example.com"] == "AWS"


def test_egress_analyze_targets_and_union(monkeypatch):
    observed = pd.DataFrame(
        [
            {
                "destination": "b.s3.us-west-2.amazonaws.com",
                "destination_type": "DNS",
                "events": 10,
                "workspace_ids": [1],
                "resolved_ips": [],
            },
            {
                "destination": "mb.storage.googleapis.com",
                "destination_type": "DNS",
                "events": 3,
                "workspace_ids": [1],
                "resolved_ips": [],
            },
            {
                "destination": "acct.blob.core.windows.net",
                "destination_type": "DNS",
                "events": 2,
                "workspace_ids": [1],
                "resolved_ips": [],
            },
            {
                "destination": "api.openai.com",
                "destination_type": "DNS",
                "events": 5,
                "workspace_ids": [1],
                "resolved_ips": ["1.2.3.4"],
            },
            {
                "destination": "s3.us-east-1.amazonaws.com",
                "destination_type": "DNS",
                "events": 1,
                "workspace_ids": [1],
                "resolved_ips": [],
            },  # bare S3 -> skipped
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off")
    a = eg.analyze(cfg, sql_conn=None)
    assert eg.union(a.targets, "s3") == {("b", "us-west-2"): 10}
    assert eg.union(a.targets, "gcs") == {"mb": 3}
    assert eg.union(a.targets, "azure") == {("acct", "blob"): 2}
    assert eg.union(a.targets, "internet") == {"api.openai.com": 5}
    assert a.skipped_bare_s3 == 1


def test_egress_excludes_databricks_urls(monkeypatch):
    # Databricks workspace / Apps / model-serving URLs are unsupported as egress internet
    # destinations (the API rejects them) — they must be flagged and excluded, never allow-listed.
    # Hostnames below are synthetic placeholders on the public Databricks domains — not real hosts.
    observed = pd.DataFrame(
        [
            {  # Databricks App
                "destination": "example-app.aws.databricksapps.com",
                "destination_type": "DNS",
                "events": 20,
                "workspace_ids": [1],
                "resolved_ips": [],
            },
            {  # AWS workspace URL (also fronts model-serving endpoints)
                "destination": "example.cloud.databricks.com",
                "destination_type": "DNS",
                "events": 15,
                "workspace_ids": [1],
                "resolved_ips": [],
            },
            {  # Azure workspace URL
                "destination": "adb-0000000000000000.0.azuredatabricks.net",
                "destination_type": "DNS",
                "events": 9,
                "workspace_ids": [1],
                "resolved_ips": [],
            },
            {  # a genuine third-party internet FQDN — must still be allow-listed
                "destination": "api.openai.com",
                "destination_type": "DNS",
                "events": 5,
                "workspace_ids": [1],
                "resolved_ips": [],
            },
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off", policy_scope="all_workspaces")
    a = eg.analyze(cfg, sql_conn=None)
    # only the real third-party FQDN survives into the internet allow-list
    assert eg.union(a.targets, "internet") == {"api.openai.com": 5}
    assert a.skipped_databricks_urls == [
        "adb-0000000000000000.0.azuredatabricks.net",
        "example-app.aws.databricksapps.com",
        "example.cloud.databricks.com",
    ]
    # and the built policy contains none of the excluded Databricks URLs
    block = eg.build_blocks(a, cfg)[eg.ALL_WORKSPACES].as_dict()["network_access"]
    dests = {d["destination"] for d in block["allowed_internet_destinations"]}
    assert dests == {"api.openai.com"}


def test_nonglobal_reason_labels():
    assert eg._nonglobal_reason("127.0.0.1") == "loopback"
    assert eg._nonglobal_reason("10.1.2.3") == "private/internal"
    assert eg._nonglobal_reason("192.168.5.5") == "private/internal"
    assert eg._nonglobal_reason("169.254.1.1") == "link-local"
    assert eg._nonglobal_reason("0.0.0.0") == "unspecified"
    # globally-routable and unparseable both return None (not excluded)
    assert eg._nonglobal_reason("104.16.1.1") is None
    assert eg._nonglobal_reason("not-an-ip") is None


def test_egress_excludes_fqdns_resolving_to_nonglobal_ips(monkeypatch):
    # An FQDN that resolves only to a loopback/private IP (a local DNS/hosts artefact) can't be real
    # egress — flag + exclude it. One with a global IP, and one mixed (global + private), are kept.
    observed = pd.DataFrame(
        [
            {  # pypi.org resolving to localhost — the reported case
                "destination": "pypi.org",
                "destination_type": "DNS",
                "events": 4,
                "workspace_ids": [1],
                "resolved_ips": ["127.0.0.1"],
            },
            {  # internal host resolving to an RFC1918 address
                "destination": "internal.svc.local",
                "destination_type": "DNS",
                "events": 3,
                "workspace_ids": [1],
                "resolved_ips": ["10.1.2.3"],
            },
            {  # genuine third-party — global IP, must be kept
                "destination": "api.openai.com",
                "destination_type": "DNS",
                "events": 5,
                "workspace_ids": [1],
                "resolved_ips": ["104.16.1.1"],
            },
            {  # split-horizon: one private + one global -> reachable, so kept
                "destination": "mixed.example.com",
                "destination_type": "DNS",
                "events": 2,
                "workspace_ids": [1],
                "resolved_ips": ["10.0.0.9", "8.8.8.8"],
            },
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off", policy_scope="all_workspaces")
    a = eg.analyze(cfg, sql_conn=None)
    assert eg.union(a.targets, "internet") == {"api.openai.com": 5, "mixed.example.com": 2}
    skipped = set(a.skipped_nonglobal_fqdns)
    assert skipped == {
        ("pypi.org", "127.0.0.1", "loopback"),
        ("internal.svc.local", "10.1.2.3", "private/internal"),
    }
    # the built policy contains neither excluded FQDN
    block = eg.build_blocks(a, cfg)[eg.ALL_WORKSPACES].as_dict()["network_access"]
    assert {d["destination"] for d in block["allowed_internet_destinations"]} == {
        "api.openai.com",
        "mixed.example.com",
    }


def test_egress_keeps_fqdn_when_no_resolved_ip(monkeypatch):
    # No resolved IP at all -> we can't judge, so keep it for review (never silently drop).
    observed = pd.DataFrame(
        [
            {
                "destination": "unresolved.example.com",
                "destination_type": "DNS",
                "events": 3,
                "workspace_ids": [1],
                "resolved_ips": [],
            }
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off", policy_scope="all_workspaces")
    a = eg.analyze(cfg, sql_conn=None)
    assert eg.union(a.targets, "internet") == {"unresolved.example.com": 3}
    assert a.skipped_nonglobal_fqdns == []


def test_classify_databricks_url_variants():
    # Any Databricks-owned host (workspace, apps, control-plane/platform, docs, apex) classifies as
    # databricks_url — the egress API rejects the whole family, so we never allow-list any of them.
    # All hostnames below are synthetic placeholders on the public Databricks domains, not real hosts.
    for host in (
        "example.cloud.databricks.com",  # AWS workspace
        "example.staging.cloud.databricks.com",  # AWS staging workspace
        "example.gcp.databricks.com",  # GCP workspace
        "adb-0000000000000000.0.azuredatabricks.net",  # Azure workspace
        "example-app.aws.databricksapps.com",  # Databricks App
        "example-service.databricks.com",  # a control-plane / platform service host
        "docs.databricks.com",  # a non-workspace databricks.com host
        "databricks.com",  # apex
    ):
        assert eg._classify(host)[0] == "databricks_url", host
    # a genuine third-party (and a lookalike that only *contains* the string) stay on the internet path
    assert eg._classify("api.openai.com")[0] == "internet"
    assert eg._classify("notdatabricks.com")[0] == "internet"
    assert eg._classify("databricks.com.evil.example")[0] == "internet"


def test_workspace_cloud_from_host():
    assert eg.workspace_cloud_from_host("https://example.cloud.databricks.com") == "aws"
    assert eg.workspace_cloud_from_host("https://example.staging.cloud.databricks.com") == "aws"
    assert eg.workspace_cloud_from_host("https://adb-0000000000000000.0.azuredatabricks.net") == "azure"
    assert eg.workspace_cloud_from_host("https://example.gcp.databricks.com") == "gcp"
    assert eg.workspace_cloud_from_host(None) is None
    assert eg.workspace_cloud_from_host("https://not-databricks.example.com") is None


def test_egress_excludes_cross_cloud_storage_on_aws(monkeypatch):
    # On an AWS workspace the egress API only accepts S3 storage — Azure + GCS storage destinations
    # must be flagged and dropped (they'd otherwise fail the apply), while S3 and internet survive.
    observed = pd.DataFrame(
        [
            {  # S3 — kept (matches AWS)
                "destination": "b.s3.us-west-2.amazonaws.com",
                "destination_type": "DNS",
                "events": 10,
                "workspace_ids": [1],
                "resolved_ips": [],
            },
            {  # GCS — cross-cloud, dropped
                "destination": "mb.storage.googleapis.com",
                "destination_type": "DNS",
                "events": 3,
                "workspace_ids": [1],
                "resolved_ips": [],
            },
            {  # Azure — cross-cloud, dropped (the reported case)
                "destination": "acct.blob.core.windows.net",
                "destination_type": "DNS",
                "events": 2,
                "workspace_ids": [1],
                "resolved_ips": [],
            },
            {  # internet FQDN — unaffected
                "destination": "api.openai.com",
                "destination_type": "DNS",
                "events": 5,
                "workspace_ids": [1],
                "resolved_ips": ["104.16.1.1"],
            },
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off", policy_scope="all_workspaces")
    a = eg.analyze(cfg, sql_conn=None, workspace_cloud="aws")
    assert eg.union(a.targets, "s3") == {("b", "us-west-2"): 10}
    assert eg.union(a.targets, "gcs") == {}
    assert eg.union(a.targets, "azure") == {}
    assert a.skipped_cross_cloud_storage == [("Azure", "acct.blob"), ("GCS", "mb")]
    # the built AWS policy carries only the S3 storage destination
    na = eg.build_blocks(a, cfg)[eg.ALL_WORKSPACES].as_dict()["network_access"]
    stor_types = {d["storage_destination_type"] for d in na["allowed_storage_destinations"]}
    assert stor_types == {"AWS_S3"}


def test_egress_cross_cloud_no_filter_when_cloud_unknown(monkeypatch):
    # Unknown workspace cloud -> don't filter (leave the decision to the API), nothing flagged.
    observed = pd.DataFrame(
        [
            {
                "destination": "mb.storage.googleapis.com",
                "destination_type": "DNS",
                "events": 3,
                "workspace_ids": [1],
                "resolved_ips": [],
            }
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off", policy_scope="all_workspaces")
    a = eg.analyze(cfg, sql_conn=None, workspace_cloud=None)
    assert eg.union(a.targets, "gcs") == {"mb": 3}
    assert a.skipped_cross_cloud_storage == []


def test_egress_global_s3_region_inferred(monkeypatch):
    # <bucket>.s3.amazonaws.com has no region in the host -> infer it, keep the bucket.
    observed = pd.DataFrame(
        [
            {
                "destination": "mybucket.s3.amazonaws.com",
                "destination_type": "DNS",
                "events": 4,
                "workspace_ids": [1],
                "resolved_ips": [],
            }
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    monkeypatch.setattr(eg, "_infer_s3_region", lambda bucket: "us-east-1")
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off")
    a = eg.analyze(cfg, sql_conn=None)
    assert eg.union(a.targets, "s3") == {("mybucket", "us-east-1"): 4}
    assert a.dropped_s3_no_region == []


def test_egress_global_s3_region_uninferable_dropped(monkeypatch):
    # region can't be inferred -> drop the bucket, flag it, and never emit an invalid rule.
    observed = pd.DataFrame(
        [
            {
                "destination": "mybucket.s3.amazonaws.com",
                "destination_type": "DNS",
                "events": 4,
                "workspace_ids": [1],
                "resolved_ips": [],
            }
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    monkeypatch.setattr(eg, "_infer_s3_region", lambda bucket: None)
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off")
    a = eg.analyze(cfg, sql_conn=None)
    assert eg.union(a.targets, "s3") == {}
    assert a.dropped_s3_no_region == ["mybucket"]
    # the built block must contain no S3 storage destination (no invalid region-less entry)
    assert eg.build_blocks(a, cfg) == {}


def test_egress_build_skips_regionless_s3_defensively():
    # Even if a region-less entry somehow reaches the target dict, the builder must skip it.
    a = eg.EgressAnalysis(
        observed=pd.DataFrame(),
        targets={eg.ALL_WORKSPACES: {"s3": {("b", ""): 3}, "gcs": {}, "azure": {}, "internet": {}}},
    )
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off")
    blocks = eg.build_blocks(a, cfg)
    # target has "content" (the s3 dict is non-empty) but the region-less entry is skipped ->
    # no allowed_storage_destinations
    block = blocks[eg.ALL_WORKSPACES].as_dict()["network_access"]
    assert not block.get("allowed_storage_destinations")


def test_egress_per_workspace_fans_out(monkeypatch):
    observed = pd.DataFrame(
        [
            {
                "destination": "api.openai.com",
                "destination_type": "DNS",
                "events": 5,
                "workspace_ids": [1, 2],
                "resolved_ips": [],
            }
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    cfg = EgressConfig(enable_rdap=False, policy_scope="per_workspace", block_threat_domains="off")
    a = eg.analyze(cfg, sql_conn=None)
    assert set(a.targets) == {1, 2}


def test_egress_planned_policy_ids_single_and_per_workspace():
    single = eg.planned_policy_ids({}, EgressConfig(policy_scope="all_workspaces"), "prof", 42)
    assert single == ["prof"]

    # per_workspace: one '<prefix>-ws-<id>' per target with content (blocks/preview keys).
    blocks = {1: object(), 2: object()}
    ids = eg.planned_policy_ids(blocks, EgressConfig(policy_scope="per_workspace"), "prof", None)
    assert ids == ["prof-ws-1", "prof-ws-2"]


def test_egress_build_blocks_restricted_with_enforcement(monkeypatch):
    observed = pd.DataFrame(
        [
            {
                "destination": "api.openai.com",
                "destination_type": "DNS",
                "events": 5,
                "workspace_ids": [1],
                "resolved_ips": [],
            }
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    cfg = EgressConfig(
        enable_rdap=False, policy_mode="enforce", block_threat_domains="off", policy_scope="all_workspaces"
    )
    a = eg.analyze(cfg, sql_conn=None)
    prev = eg.preview_blocks(a, cfg)
    na = prev[eg.ALL_WORKSPACES]["egress"]["network_access"]
    assert na["restriction_mode"] == "RESTRICTED_ACCESS"
    assert na["policy_enforcement"]["enforcement_mode"] == "ENFORCED"


def test_egress_blocked_domains_matched_only(monkeypatch):
    observed = pd.DataFrame(
        [
            {
                "destination": "evil.example.com",
                "destination_type": "DNS",
                "events": 5,
                "workspace_ids": [1],
                "resolved_ips": [],
            },
            {
                "destination": "good.example.com",
                "destination_type": "DNS",
                "events": 5,
                "workspace_ids": [1],
                "resolved_ips": [],
            },
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    monkeypatch.setattr(
        "dbx_nwp_helper.feeds.loaders.threat_domains",
        lambda *a, **k: pd.DataFrame(
            {"domain": ["evil.example.com", "other.bad"], "source": ["c2intel", "c2intel"]}
        ),
    )
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="matched_only", domain_allowlist=False)
    a = eg.analyze(cfg, sql_conn=None)
    # only the observed FQDN that is on the feed is blocked
    assert a.blocked_domains == ["evil.example.com"]


def test_egress_warns_and_caps_over_internet_limit():
    # >100 internet FQDNs must be capped to the limit AND the operator warned (silent truncation
    # would block the dropped destinations in enforce mode).
    internet = {f"h{i}.example.com": 1 for i in range(eg.MAX_INTERNET_DESTINATIONS + 25)}
    a = eg.EgressAnalysis(
        observed=pd.DataFrame(),
        targets={eg.ALL_WORKSPACES: {"s3": {}, "gcs": {}, "azure": {}, "internet": internet}},
    )
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off")
    notes = []
    blocks = eg.build_blocks(a, cfg, note=notes.append)
    dests = blocks[eg.ALL_WORKSPACES].as_dict()["network_access"]["allowed_internet_destinations"]
    assert len(dests) == eg.MAX_INTERNET_DESTINATIONS
    assert any("internet" in n and "egress limit" in n for n in notes)


def test_egress_cap_keeps_highest_traffic_internet():
    # over the cap, the lowest-traffic FQDNs are dropped and the busiest are kept (deterministic).
    n = eg.MAX_INTERNET_DESTINATIONS
    internet = {f"h{i}.example.com": (n + 2 - i) for i in range(n + 2)}  # h0 busiest, h{n+1} quietest
    a = eg.EgressAnalysis(
        observed=pd.DataFrame(),
        targets={eg.ALL_WORKSPACES: {"s3": {}, "gcs": {}, "azure": {}, "internet": internet}},
    )
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off")
    blocks = eg.build_blocks(a, cfg)
    kept = {
        d["destination"]
        for d in blocks[eg.ALL_WORKSPACES].as_dict()["network_access"]["allowed_internet_destinations"]
    }
    assert len(kept) == n
    assert "h0.example.com" in kept  # busiest kept
    assert f"h{n}.example.com" not in kept and f"h{n + 1}.example.com" not in kept  # quietest dropped


def test_egress_cap_keeps_highest_traffic_storage_across_providers():
    # storage is ranked across s3/gcs/azure together, so a busy S3 bucket survives the cap even
    # though it's built after a full page of low-traffic GCS buckets.
    n = eg.MAX_STORAGE_DESTINATIONS
    gcs = {f"bucket{i}": 1 for i in range(n)}  # n low-traffic GCS buckets
    s3 = {("busy-bucket", "us-east-1"): 999}  # one high-traffic S3 bucket
    a = eg.EgressAnalysis(
        observed=pd.DataFrame(),
        targets={eg.ALL_WORKSPACES: {"s3": s3, "gcs": gcs, "azure": {}, "internet": {}}},
    )
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off")
    blocks = eg.build_blocks(a, cfg)
    dests = blocks[eg.ALL_WORKSPACES].as_dict()["network_access"]["allowed_storage_destinations"]
    assert len(dests) == n
    assert any(d.get("bucket_name") == "busy-bucket" for d in dests)


def test_egress_under_internet_limit_does_not_warn():
    a = eg.EgressAnalysis(
        observed=pd.DataFrame(),
        targets={eg.ALL_WORKSPACES: {"s3": {}, "gcs": {}, "azure": {}, "internet": {"api.openai.com": 3}}},
    )
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off")
    notes = []
    eg.build_blocks(a, cfg, note=notes.append)
    assert notes == []


def test_egress_export_payload_builds_full_policy():
    # --export: egress block + a permissive FULL_ACCESS ingress default, single-policy id.
    a = eg.EgressAnalysis(
        observed=pd.DataFrame(),
        targets={eg.ALL_WORKSPACES: {"s3": {}, "gcs": {}, "azure": {}, "internet": {"api.openai.com": 5}}},
    )
    cfg = EgressConfig(
        enable_rdap=False,
        block_threat_domains="off",
        policy_scope="all_workspaces",
        policy_mode="enforce",
        policy_name="my-egress",
    )
    payload = eg.export_payload(a, cfg, "acc-1", this_workspace_id=42)
    assert payload["network_policy_id"] == "my-egress"
    assert payload["account_id"] == "acc-1"
    assert "egress" in payload
    assert payload["ingress"]["public_access"]["restriction_mode"] == "FULL_ACCESS"


def test_egress_empty_produces_no_blocks(monkeypatch):
    monkeypatch.setattr(
        "dbx_nwp_helper.sql.query",
        lambda _c, _t: pd.DataFrame(
            columns=["destination", "destination_type", "events", "workspace_ids", "resolved_ips"]
        ),
    )
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off")
    a = eg.analyze(cfg, sql_conn=None)
    assert eg.preview_blocks(a, cfg) == {}


# ------------------------------------------------------------------------------------- acl
class _FakeWorkspaceConf:
    def __init__(self, initial="true"):
        self._val = initial
        self.set_calls = []

    def get_status(self, keys):
        assert keys == "enableIpAccessLists"
        return {"enableIpAccessLists": self._val}

    def set_status(self, contents):
        self.set_calls.append(contents)
        self._val = contents.get("enableIpAccessLists", self._val)


class _WsWithConf:
    def __init__(self, initial="true"):
        self.workspace_conf = _FakeWorkspaceConf(initial)


def test_disable_ip_access_lists_flips_toggle_off():
    ws = _WsWithConf(initial="true")
    assert acl_core.disable_ip_access_lists(ws) is True
    assert ws.workspace_conf.set_calls == [{"enableIpAccessLists": "false"}]


def test_disable_ip_access_lists_idempotent_when_already_off():
    ws = _WsWithConf(initial="false")
    # already disabled -> no write, reports no change
    assert acl_core.disable_ip_access_lists(ws) is False
    assert ws.workspace_conf.set_calls == []


def test_disable_ip_access_lists_noop_when_never_configured():
    # workspace-conf has no enableIpAccessLists key at all (IP ACLs never set up) -> nothing to
    # disable, no write, graceful.
    class _Conf:
        def __init__(self):
            self.set_calls = []

        def get_status(self, keys):
            return {}

        def set_status(self, contents):
            self.set_calls.append(contents)

    class _WS:
        def __init__(self):
            self.workspace_conf = _Conf()

    ws = _WS()
    assert acl_core.disable_ip_access_lists(ws) is False
    assert ws.workspace_conf.set_calls == []


def _pas_full_account(pas_id, *, level="ACCOUNT", endpoint_ids=None, pas_name=None, raise_ws=False):
    class _WS:
        def get(self, workspace_id):
            if raise_ws:
                raise RuntimeError("no perms")
            return type("W", (), {"private_access_settings_id": pas_id})()

    class _PA:
        def get(self, private_access_settings_id):
            return type(
                "PAS",
                (),
                {
                    "private_access_settings_id": pas_id,
                    "private_access_settings_name": pas_name,
                    "private_access_level": type("E", (), {"value": level})(),
                    "allowed_vpc_endpoint_ids": endpoint_ids,
                },
            )()

    return type("Acct", (), {"workspaces": _WS(), "private_access": _PA()})()


def test_read_workspace_pas_statuses():
    # 'ok' when a PAS is attached, 'none' when not, 'error' when the account read fails.
    pas, status = acl_core.read_workspace_pas(_pas_full_account("pas-1"), 42)
    assert status == "ok" and pas is not None
    _, status_none = acl_core.read_workspace_pas(_pas_full_account(None), 42)
    assert status_none == "none"
    _, status_err = acl_core.read_workspace_pas(_pas_full_account("pas-1", raise_ws=True), 42)
    assert status_err == "error"


def test_plan_from_pas_account_level():
    pas, _ = acl_core.read_workspace_pas(_pas_full_account("pas-1", level="ACCOUNT"), 42)
    plan = acl_core.plan_from_pas(pas)
    assert plan.restriction_mode == "ALLOW_ALL_REGISTERED_ENDPOINTS"
    assert plan.endpoint_ids == []
    assert plan.source_pas_id == "pas-1"


def test_plan_from_pas_endpoint_level_keeps_ids_and_name_label():
    pas, _ = acl_core.read_workspace_pas(
        _pas_full_account("pas-2", level="ENDPOINT", endpoint_ids=["vpce-a", "vpce-b"], pas_name="prod-pas"),
        42,
    )
    plan = acl_core.plan_from_pas(pas)
    assert plan.restriction_mode == "RESTRICTED_ACCESS"
    assert plan.endpoint_ids == ["vpce-a", "vpce-b"]
    assert plan.label == "prod-pas"  # PAS name kept verbatim as the rule label


def _network_account(network_id="net-1", relay=None, rest=None, ws_raises=False, net_raises=False):
    """An account whose workspace carries `network_id` and whose networks.get returns a Network with
    vpc_endpoints.{dataplane_relay, rest_api}."""

    class _WS:
        def get(self, workspace_id):
            if ws_raises:
                raise RuntimeError("no perms")
            return type("W", (), {"network_id": network_id})()

    class _Networks:
        def get(self, network_id):  # noqa: A002 - mirrors the SDK's positional arg name
            if net_raises:
                raise RuntimeError("no perms")
            vpce = type("V", (), {"dataplane_relay": relay, "rest_api": rest})()
            return type("N", (), {"vpc_endpoints": vpce})()

    return type("Acct", (), {"workspaces": _WS(), "networks": _Networks()})()


def test_backend_private_endpoint_ids_reads_relay_and_rest():
    acct = _network_account(relay=["vpce-relay"], rest=["vpce-rest"])
    assert acl_core.backend_private_endpoint_ids(acct, 1) == ["vpce-relay", "vpce-rest"]


def test_backend_private_endpoint_ids_dedupes_preserving_order():
    acct = _network_account(relay=["vpce-a", "vpce-b"], rest=["vpce-b", "vpce-c"])
    assert acl_core.backend_private_endpoint_ids(acct, 1) == ["vpce-a", "vpce-b", "vpce-c"]


def test_backend_private_endpoint_ids_no_network_is_empty():
    # front-end-only PrivateLink (back-end via the compute-plane NAT gateway) → no network id
    assert acl_core.backend_private_endpoint_ids(_network_account(network_id=None), 1) == []


def test_backend_private_endpoint_ids_read_failure_is_empty():
    assert acl_core.backend_private_endpoint_ids(_network_account(net_raises=True), 1) == []
    assert acl_core.backend_private_endpoint_ids(_network_account(ws_raises=True), 1) == []


def test_backend_private_endpoint_ids_empty_vpc_endpoints_is_empty():
    assert acl_core.backend_private_endpoint_ids(_network_account(relay=None, rest=None), 1) == []


def test_existing_cbi_ingress_copies_restrictive_subblocks_only():
    # existing_cbi_ingress returns deep-copied, restrictive-only (public / private / xws) sub-blocks
    # from the workspace's assigned CBI policy; permissive blocks come back as None.
    import types

    restrictive_pub = types.SimpleNamespace(
        restriction_mode=types.SimpleNamespace(value="RESTRICTED_ACCESS"),
        allow_rules=[object()],
        deny_rules=None,
    )
    permissive_priv = types.SimpleNamespace(
        restriction_mode=types.SimpleNamespace(value="ALLOW_ALL_REGISTERED_ENDPOINTS"),
        allow_rules=None,
        deny_rules=None,
    )
    restrictive_xws = types.SimpleNamespace(
        restriction_mode=types.SimpleNamespace(value="RESTRICTED_ACCESS"),
        allow_rules=[object()],
        deny_rules=None,
    )
    ingress = types.SimpleNamespace(
        public_access=restrictive_pub, private_access=permissive_priv, cross_workspace_access=restrictive_xws
    )
    pol = types.SimpleNamespace(ingress=ingress, ingress_dry_run=None)

    import dbx_nwp_helper.core.acl as acl_mod

    acl_core_patched = acl_mod
    # assigned_policy returns (id, pol); patch it for this call
    orig = acl_core_patched.assigned_policy
    acl_core_patched.assigned_policy = lambda a, w: ("p1", pol)
    try:
        pid, pub, priv, xws = acl_core.existing_cbi_ingress(object(), 42)
    finally:
        acl_core_patched.assigned_policy = orig
    assert pid == "p1"
    assert pub is not None  # restrictive public carried
    assert priv is None  # permissive private dropped
    assert xws is not None  # restrictive cross-workspace carried


def _policy_account(assigned_policy_id, policy_obj):
    class _WNC:
        def get_workspace_network_option_rpc(self, workspace_id):
            return type("O", (), {"network_policy_id": assigned_policy_id})()

    class _NP:
        def get_network_policy_rpc(self, network_policy_id):
            return policy_obj

    return type("Acct", (), {"workspace_network_configuration": _WNC(), "network_policies": _NP()})()


def _ingress(
    public_mode="FULL_ACCESS", private_mode="ALLOW_ALL_REGISTERED_ENDPOINTS", xws_mode="LEGACY_MODE"
):
    def _blk(mode):
        return type("B", (), {"restriction_mode": mode, "allow_rules": None, "deny_rules": None})()

    return type(
        "Ing",
        (),
        {
            "public_access": _blk(public_mode),
            "private_access": _blk(private_mode),
            "cross_workspace_access": _blk(xws_mode),
        },
    )()


def test_public_vs_private_restrictive_helpers():
    assert acl_core.public_restrictive(_ingress(public_mode="RESTRICTED_ACCESS")) is True
    assert acl_core.public_restrictive(_ingress()) is False
    # private / cross-workspace restrictiveness is independent of public
    assert acl_core.private_or_xws_restrictive(_ingress(private_mode="RESTRICTED_ACCESS")) is True
    assert acl_core.private_or_xws_restrictive(_ingress(xws_mode="RESTRICTED_ACCESS")) is True
    assert acl_core.private_or_xws_restrictive(_ingress()) is False
    assert acl_core.private_or_xws_restrictive(_ingress(public_mode="RESTRICTED_ACCESS")) is False


def _egress(restricted=True, enforced=True, internet=None, storage=None):
    import types

    na = types.SimpleNamespace(
        restriction_mode="RESTRICTED_ACCESS" if restricted else "FULL_ACCESS",
        allowed_internet_destinations=internet,
        allowed_storage_destinations=storage,
        blocked_internet_destinations=None,
        policy_enforcement=types.SimpleNamespace(enforcement_mode="ENFORCED" if enforced else "DRY_RUN"),
    )
    return types.SimpleNamespace(network_access=na)


def test_egress_restrictive_matches_restricted_mode_and_dest_lists():
    assert acl_core.egress_restrictive(None) is False
    assert acl_core.egress_restrictive(_egress(restricted=False)) is False  # FULL_ACCESS
    assert acl_core.egress_restrictive(_egress(restricted=True)) is True  # RESTRICTED_ACCESS
    # FULL_ACCESS but with an allow list present -> still restrictive
    assert acl_core.egress_restrictive(_egress(restricted=False, internet=["x"])) is True


def test_egress_enforced_reads_enforcement_mode():
    assert acl_core.egress_enforced(_egress(enforced=True)) is True
    assert acl_core.egress_enforced(_egress(enforced=False)) is False  # DRY_RUN
    assert acl_core.egress_enforced(None) is False


def test_assigned_policy_returns_id_and_object():
    pol = object()
    assert acl_core.assigned_policy(_policy_account("p1", pol), 42) == ("p1", pol)
    assert acl_core.assigned_policy(_policy_account(None, None), 42) == (None, None)


# --------------------------------------------------------------------------------- queries
def test_frequent_public_ips_predicate_toggles():
    q_default = queries.frequent_public_ips(
        30, 1, include_ipv6=False, treat_null_status_as_success=False, include_account_level=False
    )
    assert "ip_version = 6" not in q_default
    # workspace_id is a STRING column -> compare against '0', not the integer 0.
    assert "CAST(workspace_id AS STRING) <> '0'" in q_default
    assert "workspace_id <> 0" not in q_default
    assert "status_code IS NULL AND FALSE" in q_default

    q_all = queries.frequent_public_ips(
        7, 5, include_ipv6=True, treat_null_status_as_success=True, include_account_level=True
    )
    assert "OR ip_version = 6" in q_all
    # the account-level filter predicate is omitted when including account-level rows
    assert "CAST(workspace_id AS STRING) <> '0'" not in q_all
    assert "status_code IS NULL AND TRUE" in q_all
    assert "INTERVAL 7 DAYS" in q_all
    assert "COUNT(*) >= 5" in q_all


def test_observed_egress_source_filter():
    assert "network_source_type = 'DBSQL'" in queries.observed_egress(30, 1, "DBSQL")
    assert "network_source_type =" not in queries.observed_egress(30, 1, "")
    # a single quote in the filter is escaped (doubled), not left to break/inject into the query
    assert "network_source_type = 'we''ird'" in queries.observed_egress(30, 1, "we'ird")


def test_denied_requests_query_filters_403():
    q = queries.denied_requests(14)
    assert "IpAccessDenied" in q and "status_code = 403" in q
    assert "INTERVAL 14 DAYS" in q


def test_inbound_network_denied_query_shape():
    q = queries.inbound_network_denied(21)
    assert "system.access.inbound_network" in q
    assert "source.ip AS source_ip" in q  # the CBI source IP lives in the source struct
    assert "INTERVAL 21 DAYS" in q
    assert "access_type = 'DROP'" in q  # only enforced denials feed the recently-denied view
    assert "DRY_RUN_DENIAL" not in q  # dry-run would-be-denials are candidates, not denials
    # same output columns as denied_requests(), so the two frames union cleanly
    for col in ("denied_events", "principals", "principal_list", "first_denied", "last_denied"):
        assert col in q


def test_candidate_ips_from_inbound_network_query_shape():
    q = queries.candidate_ips_from_inbound_network(14, min_events=3)
    assert "system.access.inbound_network" in q
    assert "access_type = 'DRY_RUN_DENIAL'" in q  # would-be-denied under a dry-run policy
    assert "INTERVAL 14 DAYS" in q
    assert "HAVING COUNT(*) >= 3" in q
    # shaped like frequent_public_ips so the rows merge into the candidate set
    assert "source.ip AS public_ip" in q
    for col in ("events", "principals", "principal_list", "first_active_date", "last_active_date"):
        assert col in q


def test_queries_portable_mode_uses_no_inet_functions():
    # The INET built-ins (try_ip_host / ip_version() / ip_cidr_contains / try_ip_cidr) are a
    # non-public preview; a warehouse without them raises INET_FUNCTIONS_NOT_ENABLED. In portable
    # mode (use_inet=False) every query must derive the same info with plain Spark SQL instead.
    generated = [
        queries.frequent_public_ips(30, 1, False, False, False, use_inet=False),
        queries.frequent_public_ips(30, 1, True, True, True, only_workspace_id=42, use_inet=False),
        queries.candidate_funnel(30, treat_null_status_as_success=False, use_inet=False),
        queries.denied_requests(14, use_inet=False),
        queries.observed_egress(30, 1, ""),
        queries.audit_row_count(30, use_inet=False),
        queries.surface_summary(30, use_inet=False),
        queries.principal_network_diversity(30, use_inet=False),
    ]
    for q in generated:
        assert "try_ip_host" not in q
        assert "ip_version(" not in q  # the SQL FUNCTION call; the derived `ip_version` column is fine
        assert "ip_cidr_contains" not in q
        assert "try_ip_cidr" not in q


def test_queries_native_mode_uses_inet_functions():
    # Native mode (use_inet=True, the default) uses the fast INET builtins.
    q = queries.frequent_public_ips(30, 1, False, False, False, use_inet=True)
    assert "try_ip_host(source_ip_address)" in q
    assert "ip_cidr_contains('10.0.0.0/8', normalized_ip)" in q
    assert "ipv4_long" not in q  # the portable-only integer column isn't projected in native mode
    # default is native
    assert queries.frequent_public_ips(30, 1, False, False, False) == q
    assert "ip_cidr_contains" in queries.candidate_funnel(30, treat_null_status_as_success=False)


def test_frequent_public_ips_portable_excludes_private_ranges_by_integer_bounds():
    import ipaddress

    q = queries.frequent_public_ips(30, 1, False, False, False, use_inet=False)
    # the portable private-range exclusion is generated from _PRIVATE_V4_CIDRS as integer BETWEEN
    # checks; spot-check 10.0.0.0/8 and 192.168.0.0/16 bounds match what ipaddress computes.
    for cidr in ("10.0.0.0/8", "192.168.0.0/16"):
        net = ipaddress.ip_network(cidr)
        assert f"ipv4_long BETWEEN {int(net.network_address)} AND {int(net.broadcast_address)}" in q
    assert "normalized_ip = '0.0.0.0'" in q


def test_detect_inet_probe(monkeypatch):
    import pytest

    from dbx_nwp_helper.core import ingress as ing

    # a clean probe -> native INET available
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: pd.DataFrame([{"ok": True}]))
    assert ing._detect_inet(sql_conn=None) is True

    # the INET-disabled error -> fall back to portable
    def raise_inet(_c, _t):
        raise RuntimeError("[INET_FUNCTIONS_NOT_ENABLED] ip_cidr_contains is disabled or unsupported.")

    monkeypatch.setattr("dbx_nwp_helper.sql.query", raise_inet)
    assert ing._detect_inet(sql_conn=None) is False

    # any other error (e.g. a timeout) must propagate, not be swallowed as "no INET"
    def raise_timeout(_c, _t):
        raise RuntimeError("Retry policy max retry duration of 900.0 seconds")

    monkeypatch.setattr("dbx_nwp_helper.sql.query", raise_timeout)
    with pytest.raises(RuntimeError, match="Retry policy"):
        ing._detect_inet(sql_conn=None)


# ---------------------------------------------------------------- egress owner resolution cascade
def _internet_analysis(fqdn):
    t = eg._new_target()
    t["internet"][fqdn] = 1
    return eg.EgressAnalysis(observed=pd.DataFrame(), targets={eg.ALL_WORKSPACES: t})


def test_owner_lookup_private_ip(monkeypatch):
    monkeypatch.setattr(eg, "_load_cloud_networks", lambda: [])
    a = _internet_analysis("host.internal")
    eg._owner_lookup(a, {"host.internal": ["10.0.0.5"]}, EgressConfig())
    assert a.fqdn_owner["host.internal"] == "private/internal IP"


def test_owner_lookup_cloud_range_wins_over_rdap(monkeypatch):
    import ipaddress

    monkeypatch.setattr(eg, "_load_cloud_networks", lambda: [(ipaddress.ip_network("52.0.0.0/8"), "AWS")])
    from dbx_nwp_helper.feeds import rdap

    # a cloud-range hit must short-circuit before RDAP is ever consulted
    monkeypatch.setattr(
        rdap, "lookup", lambda ip: (_ for _ in ()).throw(AssertionError("RDAP must not be called"))
    )
    a = _internet_analysis("aws.example.com")
    eg._owner_lookup(a, {"aws.example.com": ["52.1.2.3"]}, EgressConfig())
    assert a.fqdn_owner["aws.example.com"] == "AWS"


def test_owner_lookup_dns_failure_is_flagged(monkeypatch):
    monkeypatch.setattr(eg, "_load_cloud_networks", lambda: [])
    monkeypatch.setattr(eg.socket, "gethostbyname", lambda h: (_ for _ in ()).throw(OSError("NXDOMAIN")))
    a = _internet_analysis("nxdomain.test")
    eg._owner_lookup(a, {}, EgressConfig())  # no pre-resolved IP -> gethostbyname -> fails
    assert a.fqdn_owner["nxdomain.test"] == "DNS_RESOLUTION_FAILED"


def test_load_cloud_networks_builds_tuples_and_skips_bad_cidrs(monkeypatch):
    from dbx_nwp_helper.feeds import cloud as cloud_feed
    from dbx_nwp_helper.feeds import databricks as dbx_feed

    monkeypatch.setattr(
        cloud_feed,
        "load_cloud_ranges",
        lambda: pd.DataFrame(
            [{"cidr": "52.0.0.0/8", "provider": "aws"}, {"cidr": "junk", "provider": "gcp"}]
        ),
    )
    monkeypatch.setattr(dbx_feed, "load_databricks_ranges", lambda: pd.DataFrame([{"cidr": "3.3.3.0/24"}]))
    nets = eg._load_cloud_networks()
    owners = {o for _n, o in nets}
    assert "AWS" in owners  # provider upper-cased
    assert "Databricks" in owners  # databricks feed tagged
    assert all("junk" not in str(n) for n, _o in nets)  # invalid CIDR silently skipped


# ------------------------------------------------------------------------ S3 region inference
def test_infer_s3_region_from_success_header(monkeypatch):
    class _Resp:
        headers = {"x-amz-bucket-region": "eu-west-1"}

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr("urllib.request.urlopen", lambda req, timeout=10: _Resp())
    assert eg._infer_s3_region("bkt") == "eu-west-1"


def test_infer_s3_region_from_error_response_header(monkeypatch):
    # a 301/403 to the wrong-region endpoint still carries x-amz-bucket-region on the error object
    class _Hdrs:
        def get(self, _k):
            return "us-west-2"

    err = Exception("301 Moved")
    err.headers = _Hdrs()

    def boom(req, timeout=10):
        raise err

    monkeypatch.setattr("urllib.request.urlopen", boom)
    assert eg._infer_s3_region("bkt") == "us-west-2"


def test_infer_s3_region_none_when_no_header(monkeypatch):
    monkeypatch.setattr(
        "urllib.request.urlopen", lambda req, timeout=10: (_ for _ in ()).throw(Exception("no header"))
    )
    assert eg._infer_s3_region("bkt") is None


def test_analyze_drops_s3_bucket_when_region_unknown(monkeypatch):
    # A global-endpoint S3 host has no region; if it can't be inferred the bucket is dropped (region
    # is required by the API) and surfaced in dropped_s3_no_region.
    observed = pd.DataFrame(
        [
            {
                "destination": "globalbucket.s3.amazonaws.com",
                "destination_type": "DNS",
                "events": 3,
                "workspace_ids": [1],
                "resolved_ips": [],
            }
        ]
    )
    monkeypatch.setattr("dbx_nwp_helper.sql.query", lambda _c, _t: observed)
    monkeypatch.setattr(eg, "_infer_s3_region", lambda bucket: None)
    cfg = EgressConfig(enable_rdap=False, block_threat_domains="off", policy_scope="all_workspaces")
    a = eg.analyze(cfg, sql_conn=None)
    assert a.dropped_s3_no_region == ["globalbucket"]
    assert not eg.union(a.targets, "s3")


# ----------------------------------------------------------------- threat-domain block list
def _block_df(domains):
    return pd.DataFrame({"domain": list(domains), "source": ["c2intel"] * len(domains)})


def test_blocked_domains_all_mode_uses_whole_feed(monkeypatch):
    monkeypatch.setattr(
        "dbx_nwp_helper.feeds.loaders.threat_domains", lambda *a, **k: _block_df(["evil.com", "bad.net"])
    )
    a = eg.EgressAnalysis(observed=pd.DataFrame(), targets={eg.ALL_WORKSPACES: eg._new_target()})
    eg._blocked_domains(a, EgressConfig(block_threat_domains="all", domain_allowlist=False), lambda _m: None)
    assert set(a.blocked_domains) == {"bad.net", "evil.com"}  # sorted, whole feed


def test_blocked_domains_capped_at_limit(monkeypatch):
    from dbx_nwp_helper.config import MAX_INTERNET_DESTINATIONS

    feed = [f"d{i}.example" for i in range(MAX_INTERNET_DESTINATIONS + 5)]
    monkeypatch.setattr("dbx_nwp_helper.feeds.loaders.threat_domains", lambda *a, **k: _block_df(feed))
    a = eg.EgressAnalysis(observed=pd.DataFrame(), targets={eg.ALL_WORKSPACES: eg._new_target()})
    notes = []
    eg._blocked_domains(
        a, EgressConfig(block_threat_domains="all", domain_allowlist=False), lambda m: notes.append(m)
    )
    assert len(a.blocked_domains) == MAX_INTERNET_DESTINATIONS
    assert any("limit" in n for n in notes)  # operator warned about the truncation


def test_blocked_domains_flags_popular_without_removing(monkeypatch):
    # A block-candidate that is also on a popularity/allowlist is FLAGGED for review but stays blocked.
    monkeypatch.setattr(
        "dbx_nwp_helper.feeds.loaders.threat_domains",
        lambda *a, **k: _block_df(["evil.com", "cloudflare.com"]),
    )
    monkeypatch.setattr(
        "dbx_nwp_helper.feeds.loaders.allowlist_domains",
        lambda *a, **k: pd.DataFrame({"domain": ["cloudflare.com"], "source": ["tranco"]}),
    )
    a = eg.EgressAnalysis(observed=pd.DataFrame(), targets={eg.ALL_WORKSPACES: eg._new_target()})
    notes = []
    eg._blocked_domains(
        a, EgressConfig(block_threat_domains="all", domain_allowlist=True), lambda m: notes.append(m)
    )
    assert set(a.blocked_domains) == {"cloudflare.com", "evil.com"}  # NOT removed — popular != benign
    assert a.blocked_but_popular == [("cloudflare.com", "tranco")]  # flagged for review
    assert any("popularity" in n or "popular" in n for n in notes)
