"""Unit tests for feed line-parsing + shared helpers (no network — feed loaders are monkeypatched
at the HTTP layer)."""

from __future__ import annotations

from datetime import datetime, timezone

from dbx_nwp_helper.feeds import domains, http, threat, util

NOW = datetime.now(timezone.utc)


def test_http_get_returns_none_on_malformed_json(monkeypatch):
    """A non-JSON body (e.g. a proxy error page) must degrade to None, not raise."""

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def read(self):
            return b"<html>not json</html>"

    monkeypatch.setattr(http, "urlopen", lambda *a, **k: _Resp())
    monkeypatch.setattr(http.time, "sleep", lambda _s: None)  # don't wait through the backoff
    assert http.http_get("https://x.test/feed.json", as_json=True) is None
    # text mode still returns the body unchanged
    assert http.http_get("https://x.test/feed.txt") == "<html>not json</html>"


def test_valid_cidr_normalises_and_filters_version():
    assert util.valid_cidr("10.0.0.5/8") == "10.0.0.0/8"
    assert util.valid_cidr("1.2.3.4") == "1.2.3.4/32"
    assert util.valid_cidr("not-an-ip") is None
    assert util.valid_cidr("2001:db8::/32", want_version=4) is None
    assert util.valid_cidr("2001:db8::/32", want_version=6) == "2001:db8::/32"


def test_dedupe_preserves_order_on_keys():
    rows = [("a", 1), ("a", 2), ("b", 1)]
    assert util.dedupe(rows, (0,)) == [("a", 1), ("b", 1)]
    assert util.dedupe(rows, (0, 1)) == rows


def _patch_http(monkeypatch, text):
    monkeypatch.setattr(threat, "http_get", lambda url, as_json=False: text)


def test_spamhaus_parses_jsonl(monkeypatch):
    text = "\n".join(['{"cidr":"1.2.3.0/24"}', "garbage", '{"cidr":"bad"}'])
    _patch_http(monkeypatch, text)
    rows = threat._feed_spamhaus_drop(NOW)
    cidrs = {r[0] for r in rows}
    assert "1.2.3.0/24" in cidrs
    assert all(r[1] == "spamhaus_drop" and r[3] == 1 for r in rows)


def test_ipsum_min_lists_and_confidence(monkeypatch):
    # count 2 (<3) dropped; 3 -> conf 2; 6 -> conf 1.
    text = "1.1.1.1\t2\n2.2.2.2\t3\n3.3.3.3\t6\n# comment\n"
    _patch_http(monkeypatch, text)
    rows = {r[0]: r for r in threat._feed_ipsum(NOW)}
    assert "1.1.1.1/32" not in rows
    assert rows["2.2.2.2/32"][3] == 2
    assert rows["3.3.3.3/32"][3] == 1


def test_dshield_tab_format(monkeypatch):
    text = "1.2.3.0\t1.2.3.255\t24\tsomething\n# header\nbad line\n"
    _patch_http(monkeypatch, text)
    rows = threat._feed_dshield(NOW)
    assert rows and rows[0][0] == "1.2.3.0/24"
    assert rows[0][2] == "attacker_subnet"


def test_tor_exit_v4_and_comments(monkeypatch):
    text = "9.9.9.9\n# note\n\n8.8.8.8\n"
    _patch_http(monkeypatch, text)
    cidrs = {r[0] for r in threat._feed_tor_exit(NOW)}
    assert cidrs == {"9.9.9.9/32", "8.8.8.8/32"}


def test_firehol_and_cins_skip_comments(monkeypatch):
    _patch_http(monkeypatch, "# h\n5.5.5.0/24\nbad\n")
    assert {r[0] for r in threat._feed_firehol_level1(NOW)} == {"5.5.5.0/24"}
    _patch_http(monkeypatch, "# h\n6.6.6.6\n")
    assert {r[0] for r in threat._feed_cins_ci_army(NOW)} == {"6.6.6.6/32"}


def test_load_threat_intel_dedupes_across_feeds(monkeypatch):
    # firehol + cins both yield the same cidr under different feeds -> both kept (dedupe on cidr+feed).
    monkeypatch.setattr(
        threat, "http_get", lambda url, as_json=False: ("1.2.3.0/24" if "firehol" in url else "1.2.3.0")
    )
    df = threat.load_threat_intel(["firehol_level1", "cins_ci_army"])
    # firehol -> 1.2.3.0/24 ; cins -> 1.2.3.0/32 : different cidr strings, both present
    assert set(df["source_feed"]) == {"firehol_level1", "cins_ci_army"}


def test_all_loaders_registered():
    from dbx_nwp_helper.config import THREAT_FEEDS

    assert set(THREAT_FEEDS) == set(threat.THREAT_FEED_LOADERS)


def test_c2intel_ips_parses_csv(monkeypatch):
    _patch_http(monkeypatch, "#ip,ioc\n1.1.1.1,Cobalt Strike C2\n\nbad-not-ip\n2.2.2.2,x\n")
    cidrs = {r[0] for r in threat._feed_c2intel_ips(NOW)}
    assert cidrs == {"1.1.1.1/32", "2.2.2.2/32"}  # header + junk line skipped


def test_tor_exit_falls_back_to_danme_when_primary_unreachable(monkeypatch):
    from dbx_nwp_helper.feeds import cache

    # Primary (torproject) unreachable → fall back to dan.me.uk; the marker is touched BEFORE the fetch.
    monkeypatch.setattr(threat, "http_get", lambda url, **k: "7.7.7.7\n" if "dan.me.uk" in url else None)
    monkeypatch.setattr(cache, "too_soon", lambda *a, **k: False)
    touched = []
    monkeypatch.setattr(cache, "touch", lambda name: touched.append(name))
    cidrs = {r[0] for r in threat._feed_tor_exit(NOW)}
    assert cidrs == {"7.7.7.7/32"}
    assert touched == ["tor_danme"]


def test_tor_exit_fallback_skipped_when_rate_limited(monkeypatch):
    from dbx_nwp_helper.feeds import cache

    monkeypatch.setattr(threat, "http_get", lambda url, **k: None)  # primary unreachable
    monkeypatch.setattr(cache, "too_soon", lambda *a, **k: True)  # dan.me.uk fetched <30 min ago
    assert threat._feed_tor_exit(NOW) == []  # skipped rather than risk a ban


def test_load_block_domains_c2intel_keyless_and_abusech_gated(monkeypatch):
    def fake_get(url, as_json=False, headers=None):
        return "#domain,ioc\nevil.example.com,CS\n5.5.5.5,ip-literal\n" if "C2IntelFeeds" in url else None

    monkeypatch.setattr(domains, "http_get", fake_get)
    notes = []
    df = domains.load_block_domains(["c2intel", "threatfox"], auth_key=None, note=notes.append)
    assert set(df["domain"]) == {"evil.example.com"}  # IP literal dropped; threatfox skipped (no key)
    assert any("Auth-Key" in n for n in notes)


def test_load_block_domains_threatfox_api_with_key(monkeypatch):
    seen = {}

    def fake_post(url, body, headers=None):
        seen["headers"] = headers
        seen["body"] = body
        return {
            "query_status": "ok",
            "data": [
                {"ioc_type": "domain", "ioc": "bad.example.com"},
                {"ioc_type": "url", "ioc": "http://evil.test/path"},
                {"ioc_type": "ip:port", "ioc": "1.2.3.4:443"},  # dropped (not a domain)
            ],
        }

    monkeypatch.setattr(domains, "http_post_json", fake_post)
    df = domains.load_block_domains(["threatfox"], auth_key="KEY")
    assert set(df["domain"]) == {"bad.example.com", "evil.test"}  # domain + url-host; ip:port dropped
    assert seen["headers"]["Auth-Key"] == "KEY"
    assert seen["body"]["query"] == "get_iocs"


def test_load_block_domains_urlhaus_api_with_key(monkeypatch):
    def fake_get(url, as_json=False, headers=None):
        assert headers["Auth-Key"] == "KEY"
        return {"query_status": "ok", "urls": [{"url": "http://1.2.3.4/x"}, {"url": "https://mal.test/a"}]}

    monkeypatch.setattr(domains, "http_get", fake_get)
    df = domains.load_block_domains(["urlhaus"], auth_key="KEY")
    assert set(df["domain"]) == {"mal.test"}  # IP-host url dropped, domain-host kept


def test_load_allowlist_domains_misp_and_tranco(monkeypatch):
    monkeypatch.setattr(
        domains,
        "http_get",
        lambda url, as_json=False, headers=None: {"list": ["cloudflare.com", "Example.COM."]},
    )
    monkeypatch.setattr(
        domains, "http_get_zip_member", lambda url, suffix=".csv": "1,google.com\n2,bad-no-dot,\n"
    )
    df = domains.load_allowlist_domains(["cloudflare-top1k", "tranco"])
    got = set(df["domain"])
    assert {"cloudflare.com", "example.com", "google.com"} <= got  # MISP + normalised + Tranco


# ---------------------------------------------------------------- cloud-provider range parsing
def test_load_cloud_ranges_parses_all_providers(monkeypatch):
    from dbx_nwp_helper.feeds import cloud

    aws = {
        "prefixes": [{"ip_prefix": "3.0.0.0/24", "service": "EC2", "region": "us-east-1"}],
        "ipv6_prefixes": [{"ipv6_prefix": "2600:1f00::/40", "service": "EC2", "region": "us-east-1"}],
    }
    gcp = {"prefixes": [{"ipv4Prefix": "8.34.0.0/16", "service": "Google Cloud", "scope": "us-central1"}]}
    oci = {"regions": [{"region": "us-ashburn-1", "cidrs": [{"cidr": "129.213.0.0/16", "tags": ["OCI"]}]}]}
    # Microsoft download page HTML; the loader scrapes it for the dated ServiceTags JSON URL.
    azure_conf = "x https://download.microsoft.com/download/a/b/ServiceTags_Public_20260101.json y"
    azure_json = {
        "values": [
            {
                "properties": {
                    "systemService": "Storage",
                    "region": "eastus",
                    "addressPrefixes": ["20.0.0.0/16"],
                }
            }
        ]
    }

    def fake_get(url, as_json=False):
        if "ip-ranges.amazonaws.com" in url:
            return aws
        if "gstatic.com" in url:
            return gcp
        if "oracle.com" in url:
            return oci
        if "details.aspx" in url:  # the download page (fetched as text)
            return azure_conf
        if "ServiceTags_Public" in url:
            return azure_json
        return None

    monkeypatch.setattr(cloud, "http_get", fake_get)
    df = cloud.load_cloud_ranges()
    assert list(df.columns) == cloud.CLOUD_COLUMNS
    assert {"aws", "gcp", "oracle", "azure"} <= set(df["provider"])
    cidrs = set(df["cidr"])
    assert {"3.0.0.0/24", "2600:1f00::/40", "8.34.0.0/16", "129.213.0.0/16", "20.0.0.0/16"} <= cidrs


def test_load_cloud_ranges_warns_when_all_feeds_unavailable(monkeypatch, capsys):
    from dbx_nwp_helper.feeds import cloud

    monkeypatch.setattr(cloud, "http_get", lambda url, as_json=False: None)
    df = cloud.load_cloud_ranges()
    assert df.empty and list(df.columns) == cloud.CLOUD_COLUMNS
    assert "azure" in capsys.readouterr().out.lower()  # explicit warning that Azure was skipped


# ------------------------------------------------------------------ partner-platform range parsing
def test_load_partner_ranges_powerbi_dynamic_plus_curated(monkeypatch):
    from dbx_nwp_helper.feeds import cloud, partners

    azure_conf = "x https://download.microsoft.com/download/a/b/ServiceTags_Public_20260101.json y"
    azure_json = {
        "values": [
            {"name": "PowerBI", "properties": {"region": "", "addressPrefixes": ["13.73.248.0/22"]}},
            {
                "name": "PowerBI.WestEurope",
                "properties": {"region": "westeurope", "addressPrefixes": ["51.144.0.0/16"]},
            },
            # a non-Power-BI tag must be ignored by the partner feed
            {"name": "Storage", "properties": {"region": "eastus", "addressPrefixes": ["20.0.0.0/16"]}},
        ]
    }

    def fake_get(url, as_json=False):
        if "details.aspx" in url:
            return azure_conf
        if "ServiceTags_Public" in url:
            return azure_json
        return None

    monkeypatch.setattr(cloud, "http_get", fake_get)
    df = partners.load_partner_ranges()
    assert list(df.columns) == partners.PARTNER_COLUMNS
    powerbi = set(df[df["partner"] == "Power BI"]["cidr"])
    assert powerbi == {"13.73.248.0/22", "51.144.0.0/16"}  # global + regional PowerBI tags only
    assert "20.0.0.0/16" not in set(df["cidr"])  # Storage tag excluded
    # dbt is curated in-repo and present regardless of the Azure fetch; bare IPs normalised to /32
    dbt = set(df[df["partner"] == "dbt platform"]["cidr"])
    assert "52.45.144.63/32" in dbt and "34.33.2.0/26" in dbt
    # Tableau Cloud is likewise curated in-repo (Hyperforce pods), present regardless of the fetch
    tableau = set(df[df["partner"] == "Tableau Cloud"]["cidr"])
    assert "155.226.128.0/21" in tableau and "141.163.192.0/23" in tableau


def test_load_partner_ranges_curated_survive_powerbi_feed_failure(monkeypatch):
    from dbx_nwp_helper.feeds import cloud, partners

    monkeypatch.setattr(cloud, "http_get", lambda url, as_json=False: None)  # Azure feed down
    df = partners.load_partner_ranges()
    assert df[df["partner"] == "Power BI"].empty  # no Power BI ranges this run
    assert not df[df["partner"] == "dbt platform"].empty  # curated dbt ranges still present
    assert not df[df["partner"] == "Tableau Cloud"].empty  # curated Tableau ranges still present


# ------------------------------------------------------------------ Databricks range parsing
def test_load_databricks_ranges_parses_prefixes(monkeypatch):
    from dbx_nwp_helper.feeds import databricks as dbx

    data = {
        "prefixes": [
            {
                "platform": "aws",
                "region": "us-east-1",
                "type": "inbound",
                "ipv4Prefixes": ["3.4.5.0/24"],
                "ipv6Prefixes": ["2600:1f00::/40"],
            },
            {"platform": "gcp", "region": "us", "type": "outbound", "ipv4Prefixes": ["8.8.8.0/24"]},
        ]
    }
    monkeypatch.setattr(dbx, "http_get", lambda url, as_json=False: data)
    df = dbx.load_databricks_ranges()
    assert list(df.columns) == dbx.DATABRICKS_COLUMNS
    rows = {(r.cidr, r.direction) for r in df.itertuples()}
    assert ("3.4.5.0/24", "inbound") in rows
    assert ("2600:1f00::/40", "inbound") in rows  # ipv6 kept (no version filter)
    assert ("8.8.8.0/24", "outbound") in rows


def test_load_databricks_ranges_empty_when_feed_unavailable(monkeypatch, capsys):
    from dbx_nwp_helper.feeds import databricks as dbx

    monkeypatch.setattr(dbx, "http_get", lambda url, as_json=False: None)
    df = dbx.load_databricks_ranges()
    assert df.empty and list(df.columns) == dbx.DATABRICKS_COLUMNS
    assert "unavailable" in capsys.readouterr().out.lower()
