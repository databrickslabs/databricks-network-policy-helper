"""Unit tests for limit enforcement, the feed cache, egress classification, and TLS setup."""

from __future__ import annotations

import pandas as pd

from dbx_nwp_helper.config import (
    MAX_CIDRS_PER_POLICY,
    MAX_IDENTITIES_PER_POLICY,
    MAX_INGRESS_RULES_PER_POLICY,
)
from dbx_nwp_helper.core import limits
from dbx_nwp_helper.core.egress import _classify
from dbx_nwp_helper.feeds import cache


def _noop(_m):
    pass


def test_limits_caps_identities_per_rule():
    spec = {
        "label": "r",
        "cidrs": ["1.1.1.1/32"],
        "identities": [
            {"principal_id": i, "principal_type": "USER"} for i in range(MAX_IDENTITIES_PER_POLICY + 10)
        ],
    }
    allow, _ = limits.enforce_limits([spec], [], "x", _noop)
    assert len(allow[0]["identities"]) == MAX_IDENTITIES_PER_POLICY


def test_limits_caps_rule_count_prioritising_allow():
    specs = [{"label": f"a{i}", "cidrs": ["1.1.1.1/32"]} for i in range(MAX_INGRESS_RULES_PER_POLICY)]
    deny = [{"label": "d", "cidrs": ["2.2.2.2/32"]}]
    allow, deny_out = limits.enforce_limits(specs, deny, "x", _noop)
    assert len(allow) == MAX_INGRESS_RULES_PER_POLICY
    assert deny_out == []  # no room left for deny


def test_limits_cap_warning_itemises_dropped_rules():
    # When the 50-rule cap drops rules, the warning must name the dropped deny (and allow) rules in a
    # single message — a silent drop would quietly discard requested security rules.
    specs = [{"label": f"a{i}", "cidrs": ["1.1.1.1/32"]} for i in range(MAX_INGRESS_RULES_PER_POLICY + 3)]
    deny = [
        {"label": "deny-c2intel", "cidrs": ["2.2.2.2/32"]},
        {"label": "deny-denied-ips", "cidrs": ["3.3.3.3/32"]},
    ]
    msgs: list[str] = []
    allow, deny_out = limits.enforce_limits(specs, deny, "single policy", msgs.append)
    assert len(allow) == MAX_INGRESS_RULES_PER_POLICY and deny_out == []
    cap = [m for m in msgs if "rules (allow+deny)" in m]
    assert len(cap) == 1  # one message → the truncation gate still counts a single truncation
    m = cap[0]
    assert "dropped 2 deny and 3 allow rule(s)" in m
    assert "DENY rules dropped" in m and "deny-c2intel" in m and "deny-denied-ips" in m
    assert "a50" in m and "a52" in m  # the dropped allow rules are named too


def test_limits_cidr_budget_allow_exceeds_names_dropped():
    # Allow CIDRs alone over the limit → allow trimmed and deny fully dropped; message names both.
    r1 = {
        "label": "allow-big",
        "cidrs": [f"10.0.{i // 256}.{i % 256}/32" for i in range(MAX_CIDRS_PER_POLICY)],
    }
    r2 = {"label": "allow-extra", "cidrs": ["11.0.0.1/32", "11.0.0.2/32"]}
    deny = [{"label": "deny-c2intel", "cidrs": ["2.2.2.2/32"]}]
    msgs: list[str] = []
    allow, deny_out = limits.enforce_limits([r1, r2], deny, "single policy", msgs.append)
    assert sum(len(r["cidrs"]) for r in allow) <= MAX_CIDRS_PER_POLICY and deny_out == []
    cap = [m for m in msgs if "alone exceed" in m]
    assert len(cap) == 1
    m = cap[0]
    assert "DENY rules dropped" in m and "deny-c2intel" in m
    assert "allow-extra" in m  # the allow rule that didn't fit is named


def test_limits_cidr_budget_deny_trim_names_dropped():
    # Allow uses all but one CIDR of the budget; deny exceeds the remainder → partial keep + named drop.
    allow = [
        {"label": "a", "cidrs": [f"10.0.{i // 256}.{i % 256}/32" for i in range(MAX_CIDRS_PER_POLICY - 1)]}
    ]
    deny = [
        {"label": "deny-1", "cidrs": ["2.2.2.1/32", "2.2.2.2/32"]},  # only 1 of 2 fits
        {"label": "deny-2", "cidrs": ["3.3.3.3/32"]},  # fully dropped
    ]
    msgs: list[str] = []
    allow_out, deny_out = limits.enforce_limits(allow, deny, "single policy", msgs.append)
    assert sum(len(r["cidrs"]) for r in allow_out + deny_out) <= MAX_CIDRS_PER_POLICY
    cap = [m for m in msgs if "deny CIDRs trimmed" in m]
    assert len(cap) == 1
    m = cap[0]
    assert "kept 1 of 3 deny CIDR(s)" in m and "deny-2" in m


def test_limits_caps_total_cidrs():
    # One allow rule with more than the CIDR budget -> trimmed.
    big = {"label": "a", "cidrs": [f"10.0.{i // 256}.{i % 256}/32" for i in range(MAX_CIDRS_PER_POLICY + 50)]}
    allow, _ = limits.enforce_limits([big], [], "x", _noop)
    assert sum(len(r["cidrs"]) for r in allow) <= MAX_CIDRS_PER_POLICY


def test_limits_deny_fits_remaining_budget():
    allow = [{"label": "a", "cidrs": [f"10.0.0.{i}/32" for i in range(10)]}]
    deny = [{"label": "d", "cidrs": [f"11.0.0.{i}/32" for i in range(5)]}]
    a_out, d_out = limits.enforce_limits(allow, deny, "x", _noop)
    assert sum(len(r["cidrs"]) for r in a_out + d_out) <= MAX_CIDRS_PER_POLICY
    assert d_out  # fits comfortably


def test_egress_classify_variants():
    assert _classify("b.s3.us-west-2.amazonaws.com") == ("s3", {"bucket": "b", "region": "us-west-2"})
    # global endpoint: no region in host
    kind, info = _classify("b.s3.amazonaws.com")
    assert kind == "s3" and info["bucket"] == "b" and info["region"] is None
    assert _classify("s3.us-east-1.amazonaws.com")[0] == "skip_bare_s3"
    assert _classify("mb.storage.googleapis.com") == ("gcs", {"bucket": "mb"})
    assert _classify("acct.blob.core.windows.net") == ("azure", {"account": "acct", "service": "blob"})
    assert _classify("api.openai.com") == ("internet", {"fqdn": "api.openai.com"})
    assert _classify("")[0] == "skip_bare_s3"


def test_egress_classify_strips_trailing_dot_and_case():
    assert _classify("API.OpenAI.Com.") == ("internet", {"fqdn": "api.openai.com"})


def test_clean_host_normalises_and_rejects_non_domains():
    from dbx_nwp_helper.feeds.domains import _clean_host

    assert _clean_host("Evil.Example.COM.") == "evil.example.com"  # lowercased, trailing dot stripped
    assert _clean_host("https://bad.test/path") == "bad.test"  # host extracted from a URL
    assert _clean_host("bad.test:8080") == "bad.test"  # port dropped
    assert _clean_host("127.0.0.1") == ""  # IP literal is not a domain
    assert _clean_host("just-one-token") == ""  # no dot → not a domain


def test_cache_store_load_roundtrip_and_ttl(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, "cache_dir", lambda: tmp_path)
    df = pd.DataFrame({"cidr": ["1.2.3.0/24"], "x": [1]})
    cache.store("t", df)
    assert cache.is_fresh("t")
    loaded = cache.load("t")
    assert loaded.to_dict(orient="records") == df.to_dict(orient="records")
    # stale when TTL is 0
    assert cache.is_fresh("t", ttl=0) is False


def test_cache_get_or_build_uses_builder_when_stale(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, "cache_dir", lambda: tmp_path)
    calls = {"n": 0}

    def build():
        calls["n"] += 1
        return pd.DataFrame({"a": [calls["n"]]})

    df1 = cache.get_or_build("k", build, refresh=False)
    df2 = cache.get_or_build("k", build, refresh=False)  # cached, builder not called again
    assert calls["n"] == 1
    assert df1.equals(df2)
    cache.get_or_build("k", build, refresh=True)  # forced rebuild
    assert calls["n"] == 2


def test_cache_does_not_persist_empty_results(tmp_path, monkeypatch):
    # A failed download returns an empty frame — it must NOT be cached (else the next run reuses bad
    # data for the whole TTL, which silently made all cloud/Databricks checks false).
    monkeypatch.setattr(cache, "cache_dir", lambda: tmp_path)
    calls = {"n": 0}

    def build_empty():
        calls["n"] += 1
        return pd.DataFrame(columns=["cidr"])

    cache.get_or_build("feed", build_empty, refresh=False)
    assert cache.load("feed") is None  # nothing persisted
    cache.get_or_build("feed", build_empty, refresh=False)
    assert calls["n"] == 2  # so the builder is retried, not served from cache


def test_cache_clear(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, "cache_dir", lambda: tmp_path)
    cache.store("a", pd.DataFrame({"x": [1]}))
    cache.store("b", pd.DataFrame({"x": [1]}))
    removed = cache.clear()
    assert set(removed) == {"a", "b"}
    assert cache.load("a") is None


def test_cache_humanize_thresholds():
    assert cache._humanize(30) == "30s ago"
    assert cache._humanize(120) == "2m ago"
    assert cache._humanize(7200) == "2h ago"
    assert cache._humanize(172800) == "2d ago"


def test_tls_enable_idempotent():
    from dbx_nwp_helper import tls

    # Should return a bool and never raise; second call is a no-op.
    first = tls.enable()
    second = tls.enable()
    assert isinstance(first, bool)
    assert second is True or first is False
