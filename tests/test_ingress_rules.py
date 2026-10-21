"""Unit tests for the ingress rule-assembly logic (core/ingress_rules.py).

Builds IngressAnalysis objects directly (no SQL / no network) to exercise build_rules across
scoping modes, ACL handling, denied-IP deny rules, and threat-deny prioritisation, plus
resolve_identities and apply against fake account clients.
"""

from __future__ import annotations

import ipaddress

import pandas as pd

from dbx_nwp_helper.config import IngressConfig
from dbx_nwp_helper.core import ingress_rules as rules
from dbx_nwp_helper.core.ingress import ALL_WORKSPACES, IngressAnalysis


def _suggestion(**kw):
    base = {
        "policy_target": ALL_WORKSPACES,
        "rdap_owner": "Acme",
        "distinct_ips": 1,
        "total_events": 10,
        "principals": [],
        "principal_emails": [],
        "subject_names": [],
        "scoped_destination": "all_destinations",
        "minimal_cidrs": ["203.0.55.10/32"],
        "optimal_cidrs": ["203.0.55.10/32"],
        "maximum_cidrs": None,
        "threat_feeds": None,
        "cloud_provider": None,
        "databricks_owned": None,
        "recommendation": "candidate",
    }
    base.update(kw)
    return base


def _analysis(suggestion_rows=None, ip_acls=None, denied=None, threat_match_rows=None, threat_ranges=None):
    rows = suggestion_rows or []
    sugg = pd.DataFrame(rows) if rows else pd.DataFrame()
    return IngressAnalysis(
        candidates=pd.DataFrame(),
        suggestions=sugg,
        threat_matches=pd.DataFrame(),
        denied_requests=denied if denied is not None else pd.DataFrame(columns=["source_ip"]),
        ip_acls=ip_acls or [],
        suggestion_rows=rows,
        threat_match_rows=threat_match_rows or [],
        threat_ranges=threat_ranges or [],
    )


# ------------------------------------------------------------------- scoping / framing / grouping
def test_owner_groups_become_separate_labeled_rules():
    # Every owner group is its own labeled allow rule now (no single blanket collapse), even ip_only.
    a = _analysis(
        [
            _suggestion(rdap_owner="Acme Corp", minimal_cidrs=["1.1.1.1/32"]),
            _suggestion(rdap_owner="Beta LLC", minimal_cidrs=["2.2.2.2/32"]),
        ]
    )
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only", policy_framing="minimal"))
    allow = pols[ALL_WORKSPACES]["allow"]
    assert len(allow) == 2
    labels = {s["label"] for s in allow}
    # (c) non-cloud -> just the owner slug (no name_prefix on rule labels)
    assert "Acme-Corp" in labels
    assert "Beta-LLC" in labels


def test_cloud_owned_included_with_cloud_label():
    # (b) cloud-provider-owned groups are now INCLUDED, labeled <cloud>-<owner>.
    a = _analysis(
        [
            _suggestion(rdap_owner="Palo Alto", cloud_provider=["aws"], minimal_cidrs=["8.8.8.8/32"]),
        ]
    )
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only"))
    labels = [s["label"] for s in pols[ALL_WORKSPACES]["allow"]]
    assert "aws-Palo-Alto" in labels
    assert a.excluded_flagged == 0


def test_cloud_owned_label_not_redundant_with_friendly_owner():
    # When the owner is the friendly cloud label (the usual case for cloud-owned IPs, set by
    # ingress._known_owner), the <cloud>- prefix would double up ("aws-Amazon-Web-Services-AWS").
    # The label should just be the friendly owner slug — matching the table's owner column.
    for owner, cloud, expected in [
        ("Amazon Web Services (AWS)", "aws", "Amazon-Web-Services-AWS"),
        ("Google Cloud Platform (GCP)", "gcp", "Google-Cloud-Platform-GCP"),
        ("Microsoft Azure", "azure", "Microsoft-Azure"),
    ]:
        a = _analysis([_suggestion(rdap_owner=owner, cloud_provider=[cloud], minimal_cidrs=["8.8.8.8/32"])])
        pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only"))
        labels = [s["label"] for s in pols[ALL_WORKSPACES]["allow"]]
        assert labels == [expected], f"{cloud}: {labels}"


def test_planned_policy_ids_single_and_per_workspace():
    a = _analysis([_suggestion(minimal_cidrs=["1.1.1.1/32"])])

    single = rules.build_rules(a, IngressConfig(scoping_mode="ip_only", policy_scope="all_workspaces"))
    assert rules.planned_policy_ids(single, IngressConfig(policy_scope="all_workspaces"), "prof", 42) == [
        "prof"
    ]

    # per_workspace fans out to one '<prefix>-ws-<id>' id per workspace target (keys only matter).
    pw = {101: {"allow": [], "deny": []}, 202: {"allow": [], "deny": []}}
    ids = rules.planned_policy_ids(pw, IngressConfig(policy_scope="per_workspace"), "prof", None)
    assert ids == ["prof-ws-101", "prof-ws-202"]


def test_only_threat_groups_excluded():
    a = _analysis(
        [
            _suggestion(rdap_owner="clean", minimal_cidrs=["1.1.1.1/32"]),
            _suggestion(rdap_owner="bad", threat_feeds=["ipsum"], minimal_cidrs=["9.9.9.9/32"]),
            _suggestion(rdap_owner="cloud", cloud_provider=["aws"], minimal_cidrs=["8.8.8.8/32"]),
        ]
    )
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only"))
    all_cidrs = {c for s in pols[ALL_WORKSPACES]["allow"] for c in s["cidrs"]}
    assert all_cidrs == {"1.1.1.1/32", "8.8.8.8/32"}  # clean + cloud kept; threat excluded
    assert a.excluded_flagged == 1


def test_databricks_owned_included_despite_cloud_flag():
    a = _analysis(
        [
            _suggestion(
                rdap_owner="dbx",
                cloud_provider=["aws"],
                databricks_owned=["aws"],
                minimal_cidrs=["4.4.4.4/32"],
            )
        ]
    )
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_and_destination"))
    labels = [s["label"] for s in pols[ALL_WORKSPACES]["allow"]]
    # (a) databricks-owned -> databricks-<cloud>
    assert "databricks-aws" in labels
    assert a.excluded_flagged == 0


def test_destination_scoping_applied_for_non_databricks():
    a = _analysis(
        [_suggestion(rdap_owner="apps", scoped_destination="apps_runtime", minimal_cidrs=["5.5.5.5/32"])]
    )
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_and_destination"))
    spec = pols[ALL_WORKSPACES]["allow"][0]
    assert spec["destination"] == "apps_runtime"


def test_optimal_framing_uses_optimal_column():
    a = _analysis([_suggestion(minimal_cidrs=["1.1.1.1/32"], optimal_cidrs=["1.1.1.0/24"])])
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only", policy_framing="optimal"))
    assert pols[ALL_WORKSPACES]["allow"][0]["cidrs"] == ["1.1.1.0/24"]


def test_ipv6_cidrs_skipped_and_counted():
    a = _analysis([_suggestion(minimal_cidrs=["2001:db8::1/128", "1.2.3.4/32"])])
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_and_destination", policy_framing="minimal"))
    spec = pols[ALL_WORKSPACES]["allow"][0]
    assert spec["cidrs"] == ["1.2.3.4/32"]
    assert a.skipped_ipv6 == 1


# --------------------------------------------------------------------------- identity scoping
def test_identity_scoping_selected_identities():
    a = _analysis([_suggestion(principal_emails=["a@x.com"], subject_names=[], minimal_cidrs=["1.1.1.1/32"])])
    ident = {"a@x.com": {"principal_id": 42, "principal_type": "USER"}}
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_and_identity"), identity_resolution=ident)
    spec = pols[ALL_WORKSPACES]["allow"][0]
    assert spec["identity_type"] == "SELECTED_IDENTITIES"
    assert spec["identities"] == [{"principal_id": 42, "principal_type": "USER"}]


def test_identity_scoping_unresolved_group_excluded():
    # Identity scoping on + no principal resolves -> group is dropped, not opened to ALL_USERS.
    a = _analysis([_suggestion(principal_emails=["ghost@x.com"], minimal_cidrs=["1.1.1.1/32"])])
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_and_identity"), identity_resolution={})
    assert pols == {} or not pols.get(ALL_WORKSPACES, {}).get("allow")
    assert a.excluded_unresolved == 1


def test_identity_scoping_warns_and_built_block_omits_authentication():
    # The CBI API rejects a per-identity auth block on all/Apps/Lakebase destinations, so identity
    # scoping warns and the built block carries no authentication (would otherwise 400 on apply).
    a = _analysis([_suggestion(principal_emails=["a@x.com"], subject_names=[], minimal_cidrs=["1.1.1.1/32"])])
    ident = {"a@x.com": {"principal_id": 42, "principal_type": "USER"}}
    notes = []
    cfg = IngressConfig(scoping_mode="ip_and_identity")
    pols = rules.build_rules(a, cfg, identity_resolution=ident, note=notes.append)
    assert any("per-identity authentication" in n for n in notes)
    prev = rules.preview_blocks(pols, cfg)
    rule = prev[ALL_WORKSPACES]["ingress_dry_run"]["public_access"]["allow_rules"][0]
    assert "authentication" not in rule


# ------------------------------------------------------------------------------- ACL handling
def _acl(label, list_type, ips, enabled=True):
    return {"label": label, "list_type": list_type, "enabled": enabled, "ip_addresses": ips}


def test_acl_migrate_adds_acl_allow_to_traffic():
    # migrate_ip_acls (default True) folds the ACL rules in AND keeps the enriched traffic rules.
    a = _analysis(
        [_suggestion(minimal_cidrs=["1.1.1.1/32"])], ip_acls=[_acl("office", "ALLOW", ["8.8.8.8/32"])]
    )
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only", migrate_ip_acls=True))
    labels = [s["label"] for s in pols[ALL_WORKSPACES]["allow"]]
    assert "office" in labels  # migrated ACL rule, verbatim label (no migrated-acl- prefix)
    assert "migrated-acl-office" not in labels
    assert "Acme" in labels  # traffic-derived owner-grouped rule kept alongside


def test_acl_migrate_always_keeps_traffic_rules():
    # There's no longer an ACL-only mode: observed-traffic rules are always included when migrating.
    a = _analysis(
        [_suggestion(minimal_cidrs=["1.1.1.1/32"])], ip_acls=[_acl("office", "ALLOW", ["8.8.8.8/32"])]
    )
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only", migrate_ip_acls=True))
    labels = [s["label"] for s in pols[ALL_WORKSPACES]["allow"]]
    assert "Acme" in labels  # traffic rule present
    assert "office" in labels  # ACL rule present too


def test_acl_not_migrated_excludes_acl():
    a = _analysis(
        [_suggestion(minimal_cidrs=["1.1.1.1/32"])], ip_acls=[_acl("office", "ALLOW", ["8.8.8.8/32"])]
    )
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only", migrate_ip_acls=False))
    labels = [s["label"] for s in pols[ALL_WORKSPACES]["allow"]]
    assert "office" not in labels  # ACL excluded
    assert "Acme" in labels  # but traffic rules still built


def test_acl_block_becomes_deny_rule():
    a = _analysis(ip_acls=[_acl("blocklist", "BLOCK", ["6.6.6.0/24"])])
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only", migrate_ip_acls=True))
    deny = pols[ALL_WORKSPACES]["deny"]
    assert any(s["label"] == "blocklist" for s in deny)  # verbatim label, no prefix


def test_disabled_acl_skipped():
    a = _analysis(ip_acls=[_acl("off", "ALLOW", ["8.8.8.8/32"], enabled=False)])
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only"))
    assert pols == {} or not pols.get(ALL_WORKSPACES, {}).get("allow")


# --------------------------------------------------------------------------- denied-IP deny rules
def test_deny_denied_ips_builds_deny_rule():
    denied = pd.DataFrame(
        [{"source_ip": "70.1.2.3"}, {"source_ip": "70.1.2.3"}, {"source_ip": "2001:db8::1"}]
    )
    a = _analysis([_suggestion(minimal_cidrs=["1.1.1.1/32"])], denied=denied)
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only", deny_denied_ips=True))
    deny = pols[ALL_WORKSPACES]["deny"]
    denied_rule = [s for s in deny if "recently-denied" in s["label"]][0]
    assert denied_rule["cidrs"] == ["70.1.2.3/32"]  # deduped, IPv6 dropped


# ---------------------------------------------------------------------- threat-intel deny rules
def _tr(cidr, feed, ttype, conf):
    return (ipaddress.ip_network(cidr), {"source_feed": feed, "threat_type": ttype, "confidence": conf})


def test_threat_deny_all_one_rule_per_feed():
    a = _analysis(
        threat_ranges=[
            _tr("9.9.9.0/24", "ipsum", "aggregated_blocklist", 1),
            _tr("8.8.8.0/24", "dshield", "attacker_subnet", 1),
            _tr("2001:db8::/32", "ipsum", "x", 1),  # ipv6 skipped
        ]
    )
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only", threat_deny_rules="all"))
    deny = pols.get(ALL_WORKSPACES, {}).get("deny", [])
    feeds = {s["label"].removeprefix("deny-") for s in deny}
    assert feeds == {"ipsum", "dshield"}
    for s in deny:
        assert all(ipaddress.ip_network(c).version == 4 for c in s["cidrs"])


def test_threat_deny_matched_only_uses_match_rows():
    a = _analysis(
        threat_match_rows=[
            {
                "matched_cidr": "9.9.9.0/24",
                "source_feed": "ipsum",
                "threat_type": "aggregated_blocklist",
                "confidence": 2,
            }
        ]
    )
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only", threat_deny_rules="matched_only"))
    deny = pols.get(ALL_WORKSPACES, {}).get("deny", [])
    assert any(s["cidrs"] == ["9.9.9.0/24"] for s in deny)


def test_threat_deny_dedupes_keeping_most_severe():
    # same cidr, one conf2 non-attacker + one conf1 attacker -> attacker/conf1 wins.
    a = _analysis(
        threat_ranges=[
            _tr("9.9.9.0/24", "ipsum", "aggregated_blocklist", 2),
            _tr("9.9.9.0/24", "dshield", "attacker_subnet", 1),
        ]
    )
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only", threat_deny_rules="all"))
    deny = pols[ALL_WORKSPACES]["deny"]
    # only the dshield/attacker entry survives dedupe
    assert len(deny) == 1
    assert "dshield" in deny[0]["label"]


# ----------------------------------------------------------------------------- apply + resolve
class _FakeUser:
    def __init__(self, _id):
        self.id = _id


class _FakeScim:
    def __init__(self, mapping):
        self._m = mapping

    def list(self, filter, count=1):  # noqa: A002 - matches SDK kwarg name
        for key, val in self._m.items():
            if f'"{key}"' in filter:
                return [_FakeUser(val)]
        return []


class _FakeNetworkPolicies:
    def __init__(self):
        self.created, self.updated = [], []

    def get_network_policy_rpc(self, network_policy_id):
        from databricks.sdk.errors import NotFound

        raise NotFound("nope")

    def create_network_policy_rpc(self, network_policy):
        self.created.append(network_policy)
        return network_policy


class _FakeWsNetConfig:
    def __init__(self):
        self.bound = []

    def update_workspace_network_option_rpc(self, workspace_id, workspace_network_option):
        self.bound.append(workspace_id)


class _FakeAccount:
    def __init__(self, user_map=None):
        self.network_policies = _FakeNetworkPolicies()
        self.workspace_network_configuration = _FakeWsNetConfig()
        self.users = _FakeScim(user_map or {})
        self.service_principals = _FakeScim({})


def test_resolve_identities_maps_users():
    a = _analysis([_suggestion(principal_emails=["a@x.com"], subject_names=[])])
    acct = _FakeAccount(user_map={"a@x.com": 99})
    res = rules.resolve_identities(a, acct)
    assert res == {"a@x.com": {"principal_id": 99, "principal_type": "USER"}}


def test_apply_single_create_new_no_assign():
    a = _analysis([_suggestion(minimal_cidrs=["1.1.1.1/32"])])
    cfg = IngressConfig(scoping_mode="ip_only", policy_name="np-smoke", policy_scope="all_workspaces")
    cfg.apply.create_policy = True
    pols = rules.build_rules(a, cfg)
    acct = _FakeAccount()
    results = rules.apply(pols, cfg, acct, account_id="acc", this_workspace_id=123)
    assert results[0]["action"] == "created"
    assert results[0]["policy_id"] == "np-smoke"
    assert "assigned" not in results[0]
    assert acct.workspace_network_configuration.bound == []


def test_apply_single_auto_assign_binds_workspace():
    a = _analysis([_suggestion(minimal_cidrs=["1.1.1.1/32"])])
    cfg = IngressConfig(scoping_mode="ip_only", policy_name="np", policy_scope="all_workspaces")
    cfg.apply.create_policy = True
    cfg.apply.auto_assign = True
    pols = rules.build_rules(a, cfg)
    acct = _FakeAccount()
    results = rules.apply(pols, cfg, acct, account_id="acc", this_workspace_id=555)
    assert results[0]["assigned"] == 555
    assert acct.workspace_network_configuration.bound == [555]


def test_apply_current_workspace_names_policy_from_profile_when_name_blank():
    # With no explicit policy_name, the single-policy id defaults to the profile name (the central
    # resolver's default) — no prefix any more.
    a = _analysis([_suggestion(minimal_cidrs=["1.1.1.1/32"])])
    cfg = IngressConfig(scoping_mode="ip_only", policy_scope="current_workspace")
    cfg.apply.create_policy = True
    pols = rules.build_rules(a, cfg)
    acct = _FakeAccount()
    results = rules.apply(pols, cfg, acct, account_id="acc", this_workspace_id=555, profile="sfe-plain")
    assert results[0]["policy_id"] == "sfe-plain"
    assert results[0]["target"] == "current_workspace"


def test_apply_current_workspace_falls_back_to_ws_id_without_profile():
    a = _analysis([_suggestion(minimal_cidrs=["1.1.1.1/32"])])
    cfg = IngressConfig(scoping_mode="ip_only", policy_scope="current_workspace")
    cfg.apply.create_policy = True
    pols = rules.build_rules(a, cfg)
    acct = _FakeAccount()
    results = rules.apply(pols, cfg, acct, account_id="acc", this_workspace_id=555, profile=None)
    assert results[0]["policy_id"] == "555"


def test_export_payload_builds_full_single_policy():
    # --export produces the full AccountNetworkPolicy: ingress mode block + FULL_ACCESS egress.
    spec = {
        "label": "office",
        "cidrs": ["1.2.3.4/32"],
        "destination": "all_destinations",
        "identity_type": "ALL_USERS",
        "identities": [],
    }
    policies = {ALL_WORKSPACES: {"allow": [spec], "deny": []}}
    cfg = IngressConfig(policy_scope="all_workspaces", policy_mode="enforce", policy_name="my-ingress")
    payload = rules.export_payload(policies, cfg, "acc-1", this_workspace_id=42)
    assert payload["network_policy_id"] == "my-ingress"
    assert payload["account_id"] == "acc-1"
    assert "egress" in payload  # FULL_ACCESS egress default added
    assert "ingress" in payload  # enforce -> ingress (not ingress_dry_run)
    assert payload["ingress"]["public_access"]["allow_rules"]


def test_resolve_identities_maps_sps_and_tracks_unresolved():
    a = _analysis(
        [
            _suggestion(
                principal_emails=["u@x.com", "gone@x.com"],
                subject_names=["app-123", "gone-sp"],
            )
        ]
    )
    acct = _FakeAccount(user_map={"u@x.com": 11})
    acct.service_principals = _FakeScim({"app-123": 22})
    res = rules.resolve_identities(a, acct)
    assert res["u@x.com"] == {"principal_id": 11, "principal_type": "USER"}
    assert res["app-123"] == {"principal_id": 22, "principal_type": "SERVICE_PRINCIPAL"}
    assert "gone@x.com" not in res and "gone-sp" not in res  # unresolved principals dropped


def test_resolve_identities_survives_scim_error(monkeypatch):
    a = _analysis([_suggestion(principal_emails=["u@x.com"], subject_names=[])])
    acct = _FakeAccount()

    class _Boom:
        def list(self, filter, count=1):  # noqa: A002
            raise RuntimeError("SCIM down")

    acct.users = _Boom()
    notes = []
    res = rules.resolve_identities(a, acct, note=notes.append)
    assert res == {}  # lookup failure -> treated as unresolved, not a crash
    assert any("failed" in n for n in notes)


def test_threat_deny_caps_and_prioritises(monkeypatch):
    # cap smaller than the record count: confidence-1 + attacker_subnet must be kept, low-conf dropped.
    monkeypatch.setattr(rules, "MAX_DENY_CIDRS", 2)
    a = _analysis(
        threat_ranges=[
            _tr("1.0.0.0/24", "f", "attacker_subnet", 1),
            _tr("2.0.0.0/24", "f", "aggregated_blocklist", 1),
            _tr("3.0.0.0/24", "f", "aggregated_blocklist", 1),
            _tr("4.0.0.0/24", "f", "aggregated_blocklist", 2),  # low confidence -> dropped first
        ]
    )
    notes = []
    pols = rules.build_rules(
        a, IngressConfig(scoping_mode="ip_only", threat_deny_rules="all"), note=notes.append
    )
    cidrs = [c for s in pols[ALL_WORKSPACES]["deny"] for c in s["cidrs"]]
    assert len(cidrs) == 2
    assert "1.0.0.0/24" in cidrs  # attacker_subnet ranks first
    assert "4.0.0.0/24" not in cidrs  # confidence-2 excluded by the cap
    assert any("cap" in n for n in notes)


def test_denied_specs_skips_ipv6():
    denied = pd.DataFrame([{"source_ip": "1.2.3.4"}, {"source_ip": "2001:db8::1"}])
    a = _analysis([_suggestion(minimal_cidrs=["203.0.55.10/32"])], denied=denied)
    pols = rules.build_rules(a, IngressConfig(scoping_mode="ip_only", deny_denied_ips=True))
    deny = pols[ALL_WORKSPACES]["deny"]
    denied_rule = next(s for s in deny if s["label"] == "deny-recently-denied")
    assert denied_rule["cidrs"] == ["1.2.3.4/32"]  # ipv6 omitted (CBI is IPv4-only)


def test_apply_per_workspace_fans_out_and_binds():
    a = _analysis(
        [
            _suggestion(policy_target=101, minimal_cidrs=["1.1.1.1/32"]),
            _suggestion(policy_target=202, minimal_cidrs=["2.2.2.2/32"]),
        ]
    )
    cfg = IngressConfig(scoping_mode="ip_only", policy_scope="per_workspace", policy_name="pfx")
    cfg.apply.create_policy = True
    cfg.apply.auto_assign = True
    pols = rules.build_rules(a, cfg)
    acct = _FakeAccount()
    results = rules.apply(pols, cfg, acct, account_id="acc", this_workspace_id=999)
    assert {r["target"] for r in results} == {101, 202}
    assert all(r["action"] == "created" for r in results)
    assert sorted(acct.workspace_network_configuration.bound) == [101, 202]  # each workspace bound


def test_ingress_block_builds_public_when_rules_present():
    # With allow/deny specs the public block is built net-new from them; private + xws are composed.
    from dbx_nwp_helper.core import policy

    cfg = IngressConfig()
    cfg.private_access = policy.build_private_access_block("ALLOW_ALL_REGISTERED_ENDPOINTS")
    allow = [
        {
            "label": "r",
            "cidrs": ["1.2.3.4/32"],
            "destination": "all_destinations",
            "identity_type": "ALL_USERS",
            "identities": [],
        }
    ]
    blk = rules._ingress_block(allow, [], cfg).as_dict()
    assert blk["public_access"]["allow_rules"][0]["origin"]["included_ip_ranges"]["ip_ranges"] == [
        "1.2.3.4/32"
    ]
    assert blk["private_access"]["restriction_mode"] == "ALLOW_ALL_REGISTERED_ENDPOINTS"


def test_ingress_block_preserves_existing_public_when_nothing_to_build():
    # No allow/deny specs → the existing restrictive public block is carried forward (not an empty
    # deny-all); private + cross-workspace are carried too.
    from dbx_nwp_helper.core import policy

    cfg = IngressConfig()
    cfg.existing_public = policy.build_public_access_block(
        [
            {
                "label": "keep",
                "cidrs": ["9.9.9.9/32"],
                "destination": "all_destinations",
                "identity_type": "ALL_USERS",
                "identities": [],
            }
        ],
        [],
    )
    cfg.private_access = policy.build_private_access_block("RESTRICTED_ACCESS", ["vpce-x"])
    cfg.existing_xws = object()  # carried verbatim
    blk = rules._ingress_block([], [], cfg)
    assert blk.public_access is cfg.existing_public  # preserved, not rebuilt
    assert blk.private_access is cfg.private_access
    assert blk.cross_workspace_access is cfg.existing_xws
