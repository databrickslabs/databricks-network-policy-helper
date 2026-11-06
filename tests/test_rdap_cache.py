"""The on-disk RDAP result cache (feeds/rdap.load_cached / store_cached) and its use by the
concurrent lookup sweep (core/ingress._rdap_lookups)."""

from __future__ import annotations

import time

from dbx_nwp_helper.core import ingress as ing
from dbx_nwp_helper.feeds import cache, rdap


def test_store_and_load_roundtrip_skips_uncacheable():
    n = rdap.store_cached(
        {
            "1.1.1.1": {
                "rdap_owner_name": "Cloudflare",
                "rdap_type": "ASSIGNED",
                "maximum_cidrs": ["1.1.1.0/24"],
            },
            "2.2.2.2": dict(rdap._EMPTY),  # a failed lookup is never cached
            "3.3.3.3": {"rdap_owner_name": None, "rdap_type": None, "maximum_cidrs": ["3.3.3.0/24"]},
        }
    )
    assert n == 2
    got = rdap.load_cached()
    assert set(got) == {"1.1.1.1", "3.3.3.3"}
    assert got["1.1.1.1"] == {
        "rdap_owner_name": "Cloudflare",
        "rdap_type": "ASSIGNED",
        "maximum_cidrs": ["1.1.1.0/24"],
    }
    assert got["3.3.3.3"]["maximum_cidrs"] == ["3.3.3.0/24"] and got["3.3.3.3"]["rdap_owner_name"] is None
    assert "rdap_owners" in [name for name, _r, _a in cache.status_rows()]  # visible to `feeds list`


def test_expired_rows_are_dropped_and_old_stamps_kept(monkeypatch):
    rdap.store_cached({"1.1.1.1": {"rdap_owner_name": "Old", "rdap_type": None, "maximum_cidrs": None}})
    df = cache.load(rdap.RDAP_CACHE_NAME)
    old_stamp = float(df["looked_up_at"].iloc[0])
    # a later write keeps the old row's original timestamp (no lifetime extension) …
    time.sleep(0.01)
    rdap.store_cached({"2.2.2.2": {"rdap_owner_name": "New", "rdap_type": None, "maximum_cidrs": None}})
    df = cache.load(rdap.RDAP_CACHE_NAME).set_index("ip")
    assert float(df.loc["1.1.1.1", "looked_up_at"]) == old_stamp
    assert float(df.loc["2.2.2.2", "looked_up_at"]) > old_stamp
    # … and an expired row is no longer served
    assert set(rdap.load_cached(ttl=0)) == set() or "1.1.1.1" not in rdap.load_cached(ttl=0.001)


def test_rdap_lookups_uses_disk_cache_and_persists_new_answers(monkeypatch):
    rdap.store_cached(
        {"203.0.113.10": {"rdap_owner_name": "ACME", "rdap_type": None, "maximum_cidrs": ["203.0.113.0/24"]}}
    )
    calls = []

    def fake_lookup(ip):
        calls.append(ip)
        return {"rdap_owner_name": "Other", "rdap_type": None, "maximum_cidrs": ["198.51.100.0/24"]}

    monkeypatch.setattr(rdap, "lookup", fake_lookup)
    progress = []
    out = ing._rdap_lookups(
        ["203.0.113.10", "203.0.113.77", "198.51.100.7"],
        workers=2,
        on_progress=lambda d, t, ip: progress.append(t),
    )
    # the cached IP and its sibling (same assigned block) never hit the network
    assert calls == ["198.51.100.7"]
    assert (
        out["203.0.113.10"]["rdap_owner_name"] == "ACME" and out["203.0.113.77"]["rdap_owner_name"] == "ACME"
    )
    assert out["198.51.100.7"]["rdap_owner_name"] == "Other"
    # progress counts only the IPs not found on disk by exact match (the sibling resolves via the
    # cached range without a network call, but still counts as processed)
    assert progress and progress[-1] == 2
    # the new answer is now on disk for the next run
    assert "198.51.100.7" in rdap.load_cached()


def test_rdap_lookups_all_cached_makes_no_calls(monkeypatch):
    rdap.store_cached({"9.9.9.9": {"rdap_owner_name": "Quad9", "rdap_type": None, "maximum_cidrs": None}})
    monkeypatch.setattr(rdap, "lookup", lambda ip: (_ for _ in ()).throw(AssertionError("network call")))
    out = ing._rdap_lookups(["9.9.9.9"], workers=4)
    assert out == {"9.9.9.9": {"rdap_owner_name": "Quad9", "rdap_type": None, "maximum_cidrs": None}}


def test_feeds_list_reports_real_row_counts():
    rdap.store_cached(
        {
            "1.1.1.1": {"rdap_owner_name": "A", "rdap_type": None, "maximum_cidrs": None},
            "2.2.2.2": {"rdap_owner_name": "B", "rdap_type": None, "maximum_cidrs": None},
        }
    )
    rows = {name: n for name, n, _age in cache.status_rows()}
    assert rows["rdap_owners"] == "2"
