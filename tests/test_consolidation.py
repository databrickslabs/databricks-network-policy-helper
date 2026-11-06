"""Rule consolidation + configurable policy caps (core/limits.consolidate, enforce_limits overrides)
and their integration into build_rules (consolidate_rules / exclude_partner_cidrs / max_rules)."""

from __future__ import annotations

import pandas as pd

from dbx_nwp_helper import console
from dbx_nwp_helper.config import CONSOLIDATED_RULE_LABEL, IngressConfig
from dbx_nwp_helper.core import ingress_rules as rules
from dbx_nwp_helper.core import limits
from dbx_nwp_helper.core.ingress import ALL_WORKSPACES, IngressAnalysis


def _spec(label, cidrs, events=1, **kw):
    base = {
        "label": label,
        "cidrs": list(cidrs),
        "destination": "all_destinations",
        "identity_type": "ALL_USERS",
        "identities": [],
        "events": events,
        "distinct_ips": len(cidrs),
        "pinned": False,
        "partner": False,
    }
    base.update(kw)
    return base


def _many(n, events_desc=True, **kw):
    # n owner groups, each a single /32, with distinct event counts so ranking is deterministic.
    return [
        _spec(f"owner-{i}", [f"10.{i // 256}.{i % 256}.1/32"], events=(n - i) if events_desc else i, **kw)
        for i in range(n)
    ]


# ----------------------------------------------------------------------------- limits.consolidate
def test_consolidate_noop_when_under_cap():
    specs = _many(10)
    out, summary = limits.consolidate(specs, [], max_rules=50)
    assert out == specs
    assert summary["folded"] == 0 and summary["consolidated"] == 0 and summary["kept_named"] == 10


def test_consolidate_folds_tail_into_one_rule_preserving_every_cidr():
    specs = _many(276)  # the real-world case: 276 owner groups vs a 50-rule cap
    out, summary = limits.consolidate(specs, [], max_rules=50)
    assert len(out) == 50
    folded = [s for s in out if s["label"] == CONSOLIDATED_RULE_LABEL]
    assert len(folded) == 1
    named = [s for s in out if s["label"] != CONSOLIDATED_RULE_LABEL]
    # The 49 highest-traffic groups keep their own rule …
    assert [s["label"] for s in named] == [f"owner-{i}" for i in range(49)]
    # … and the other 227 are all inside the consolidated rule — nothing lost.
    all_cidrs = {c for s in specs for c in s["cidrs"]}
    kept_cidrs = {c for s in out for c in s["cidrs"]}
    assert kept_cidrs == all_cidrs
    assert summary == {"folded": 227, "consolidated": 1, "kept_named": 49, "cidrs": 227, "collapsed": 0}
    assert sorted(folded[0]["consolidated_from"]) == sorted(f"owner-{i}" for i in range(49, 276))
    assert folded[0]["events"] == sum(s["events"] for s in specs[49:])


def test_consolidate_reserves_room_for_deny_rules():
    specs = _many(60)
    deny = [{"label": f"deny-{i}", "cidrs": ["9.9.9.9/32"]} for i in range(5)]
    out, _ = limits.consolidate(specs, deny, max_rules=50)
    assert len(out) + len(deny) == 50  # deny rules aren't pushed out by the cap afterwards


def test_consolidate_never_folds_pinned_rules():
    specs = _many(60)
    specs[59]["pinned"] = True  # lowest traffic, but pinned (Databricks-owned / migrated ACL)
    specs[59]["label"] = "acl-office"
    out, summary = limits.consolidate(specs, [], max_rules=50)
    labels = [s["label"] for s in out]
    assert "acl-office" in labels
    folded = next(s for s in out if s["label"] == CONSOLIDATED_RULE_LABEL)
    assert "acl-office" not in folded["consolidated_from"]
    assert summary["kept_named"] == 49 and len(out) == 50


def test_consolidate_groups_by_destination_and_identity_shape():
    specs = _many(60)
    for s in specs[40:50]:
        s["destination"] = "apps_runtime"
    for s in specs[50:]:
        s["identity_type"] = "SELECTED_IDENTITIES"
        s["identities"] = [{"principal_id": 7, "principal_type": "USER"}]
    out, summary = limits.consolidate(specs, [], max_rules=40)
    assert len(out) <= 40
    folded = [s for s in out if s["label"].startswith(CONSOLIDATED_RULE_LABEL)]
    # three shapes → three consolidated rules, each homogeneous, with distinguishing labels
    assert len(folded) == 3 and len({s["label"] for s in folded}) == 3
    assert f"{CONSOLIDATED_RULE_LABEL}-apps_runtime" in {s["label"] for s in folded}
    apps = next(s for s in folded if s["destination"] == "apps_runtime")
    assert all(m.startswith("owner-4") for m in apps["consolidated_from"])  # only the apps-scoped groups
    ident = next(s for s in folded if s["identity_type"] == "SELECTED_IDENTITIES")
    assert ident["identities"] == [{"principal_id": 7, "principal_type": "USER"}]
    assert ident["destination"] == "all_destinations"
    assert summary["consolidated"] == 3 and summary["kept_named"] + 3 <= 40


def test_consolidate_collapse_merges_a_contiguous_block():
    # Two /32s that form a /31 get merged to one entry when folded together.
    specs = [_spec("big", ["203.0.113.9/32"], events=999)] + [
        _spec("a", ["192.0.2.0/32"], events=1),
        _spec("b", ["192.0.2.1/32"], events=1),
    ]
    out, summary = limits.consolidate(specs, [], max_rules=2)
    folded = next(s for s in out if s["label"] == CONSOLIDATED_RULE_LABEL)
    assert folded["cidrs"] == ["192.0.2.0/31"]
    assert summary["collapsed"] == 1 and summary["cidrs"] == 1


# ----------------------------------------------------------------------- enforce_limits overrides
def test_enforce_limits_honours_raised_caps_and_records_summary():
    specs = _many(80)
    msgs, summary = [], {}
    allow, _ = limits.enforce_limits(specs, [], "x", msgs.append, max_rules=100, summary=summary)
    assert len(allow) == 80 and not msgs and summary == {}  # raised cap → nothing dropped
    allow, _ = limits.enforce_limits(specs, [], "x", msgs.append, max_rules=50, summary=summary)
    assert len(allow) == 50 and summary == {"rules_dropped": 30, "cidrs_dropped": 30}


def test_enforce_limits_cidr_cap_override():
    specs = [_spec("one", [f"10.0.{i // 256}.{i % 256}/32" for i in range(3000)], events=1)]
    msgs, summary = [], {}
    allow, _ = limits.enforce_limits(specs, [], "x", msgs.append, max_cidrs=5000, summary=summary)
    assert len(allow[0]["cidrs"]) == 3000 and not msgs
    allow, _ = limits.enforce_limits(specs, [], "x", msgs.append, max_cidrs=2000, summary=summary)
    assert len(allow[0]["cidrs"]) == 2000 and summary["cidrs_dropped"] == 1000


# ----------------------------------------------------------------------------- build_rules integration
def _suggestion(owner, cidr, events=10, **kw):
    base = {
        "policy_target": ALL_WORKSPACES,
        "rdap_owner": owner,
        "distinct_ips": 1,
        "total_events": events,
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


def _analysis(rows):
    return IngressAnalysis(
        candidates=pd.DataFrame(),
        suggestions=pd.DataFrame(rows),
        threat_matches=pd.DataFrame(),
        denied_requests=pd.DataFrame(columns=["source_ip"]),
        ip_acls=[],
        suggestion_rows=rows,
    )


def _big_rows(n=120):
    return [_suggestion(f"Owner {i}", f"10.{i // 256}.{i % 256}.1/32", events=n - i) for i in range(n)]


def test_build_rules_without_consolidation_truncates_and_records_summary():
    a = _analysis(_big_rows())
    notes = []
    pols = rules.build_rules(a, IngressConfig(consolidate_rules=False), note=notes.append)
    assert len(pols[ALL_WORKSPACES]["allow"]) == 50
    assert a.truncations and a.truncation_summary["rules_dropped"] == 70
    assert a.consolidation == {}
    assert ALL_WORKSPACES in a.precap_specs and len(a.precap_specs[ALL_WORKSPACES][0]) == 120


def test_build_rules_consolidates_instead_of_dropping():
    a = _analysis(_big_rows())
    notes = []
    pols = rules.build_rules(a, IngressConfig(consolidate_rules=True), note=notes.append)
    allow = pols[ALL_WORKSPACES]["allow"]
    assert len(allow) == 50
    assert a.truncations == [] and a.truncation_summary == {}
    assert a.consolidation[ALL_WORKSPACES]["folded"] == 71
    assert any(CONSOLIDATED_RULE_LABEL in m for m in notes)
    folded = next(s for s in allow if s["label"] == CONSOLIDATED_RULE_LABEL)
    assert len(folded["cidrs"]) == 71
    # the consolidated rule renders as an ordinary public allow rule
    preview = rules.preview_blocks(pols, IngressConfig(consolidate_rules=True))
    labels = [r["label"] for r in preview[ALL_WORKSPACES]["ingress_dry_run"]["public_access"]["allow_rules"]]
    assert CONSOLIDATED_RULE_LABEL in labels and len(labels) == 50


def test_build_rules_consolidation_preview_matches_actual():
    a = _analysis(_big_rows())
    cfg = IngressConfig(consolidate_rules=False)
    rules.build_rules(a, cfg)
    preview = rules.consolidation_preview(a, cfg)
    assert preview["folded"] == 71 and preview["consolidated"] == 1 and preview["kept_named"] == 49
    assert preview["cidrs_over"] == 0


def test_build_rules_raised_max_rules_keeps_every_named_rule():
    a = _analysis(_big_rows())
    pols = rules.build_rules(a, IngressConfig(max_rules=200))
    assert len(pols[ALL_WORKSPACES]["allow"]) == 120 and not a.truncations


def test_build_rules_databricks_owned_is_pinned_and_never_folded():
    rows = _big_rows()
    rows.append(_suggestion("Databricks", "44.1.1.1/32", events=1, databricks_owned=["aws"]))
    a = _analysis(rows)
    pols = rules.build_rules(a, IngressConfig(consolidate_rules=True))
    allow = pols[ALL_WORKSPACES]["allow"]
    assert any(s["label"] == "databricks-aws" for s in allow)
    folded = next(s for s in allow if s["label"] == CONSOLIDATED_RULE_LABEL)
    assert "databricks-aws" not in folded["consolidated_from"]


def test_build_rules_exclude_partner_cidrs():
    rows = _big_rows(5)
    rows.append(
        _suggestion("Power BI", "20.1.1.1/32", events=50, partners=["Power BI"], cloud_provider=["azure"])
    )
    a = _analysis(rows)
    cfg = IngressConfig(exclude_partner_cidrs=False)
    pols = rules.build_rules(a, cfg)
    assert any(s["partner"] for s in pols[ALL_WORKSPACES]["allow"])
    assert rules.partner_cidr_count(a) == (1, 1)
    cfg = IngressConfig(exclude_partner_cidrs=True)
    pols = rules.build_rules(a, cfg)
    assert not any(s.get("partner") for s in pols[ALL_WORKSPACES]["allow"])
    assert a.excluded_partner == 1
    assert rules.partner_cidr_count(a) == (0, 0)  # pre-cap specs no longer carry the partner rule


# ---------------------------------------------------------------------------------- panel
def test_truncation_panel_lists_messages_and_counts(capsys):
    console.truncation_panel(
        ["[single policy] 276 rules > 50 — dropped 226"], {"rules_dropped": 226}, stage="x"
    )
    out = capsys.readouterr().out
    assert "POLICY LIMITS APPLIED" in out and "226 rule(s) dropped" in out and "dropped 226" in out
    assert "(x)" in out


def test_truncation_panel_silent_without_messages(capsys):
    console.truncation_panel([], {"rules_dropped": 1})
    assert capsys.readouterr().out == ""
