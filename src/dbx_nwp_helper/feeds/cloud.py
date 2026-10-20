"""Cloud-provider published IP ranges → a `cloud_provider_ranges` DataFrame.

Columns: cidr, provider, service, region, loaded_at. Official feeds only (Azure Service Tags is
resolved by scraping Microsoft's official download page for the current dated JSON).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

import pandas as pd

from .http import http_get
from .util import dedupe, valid_cidr

CLOUD_COLUMNS = ["cidr", "provider", "service", "region", "loaded_at"]


def fetch_azure_service_tags() -> dict | None:
    """The Azure 'IP Ranges and Service Tags – Public Cloud' JSON, or None if it couldn't be fetched.
    There's no stable direct URL — Microsoft publishes a weekly dated file — so scrape the official
    download page for the current `ServiceTags_Public_<date>.json` link and fetch the newest. Shared
    by the cloud-provider ranges and the partner-platform feed (Power BI lives in this same JSON)."""
    conf_page = http_get("https://www.microsoft.com/en-us/download/details.aspx?id=56519")
    if not conf_page:
        return None
    matches = re.findall(
        r"https://download\.microsoft\.com/download/[^\"']*ServiceTags_Public_\d+\.json", conf_page
    )
    if not matches:
        return None
    return http_get(sorted(set(matches))[-1], as_json=True)


def load_cloud_ranges() -> pd.DataFrame:
    now = datetime.now(timezone.utc)
    rows = []

    aws = http_get("https://ip-ranges.amazonaws.com/ip-ranges.json", as_json=True)
    if aws:
        for p in aws.get("prefixes", []):
            cidr = valid_cidr(p.get("ip_prefix", ""), want_version=4)
            if cidr:
                rows.append((cidr, "aws", p.get("service"), p.get("region"), now))
        for p in aws.get("ipv6_prefixes", []):
            cidr = valid_cidr(p.get("ipv6_prefix", ""), want_version=6)
            if cidr:
                rows.append((cidr, "aws", p.get("service"), p.get("region"), now))

    gcp = http_get("https://www.gstatic.com/ipranges/cloud.json", as_json=True)
    if gcp:
        for p in gcp.get("prefixes", []):
            cidr = valid_cidr(p.get("ipv4Prefix") or p.get("ipv6Prefix") or "")
            if cidr:
                rows.append((cidr, "gcp", p.get("service"), p.get("scope"), now))

    oci = http_get("https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json", as_json=True)
    if oci:
        for region in oci.get("regions", []):
            rname = region.get("region")
            for cidr_obj in region.get("cidrs", []):
                cidr = valid_cidr(cidr_obj.get("cidr", ""))
                if cidr:
                    rows.append((cidr, "oracle", ",".join(cidr_obj.get("tags", []) or []), rname, now))

    # Azure Service Tags — scrape Microsoft's official download page for the current dated JSON.
    azure_json = fetch_azure_service_tags()
    if azure_json:
        for v in azure_json.get("values", []):
            props = v.get("properties", {})
            for cidr_raw in props.get("addressPrefixes", []):
                cidr = valid_cidr(cidr_raw)
                if cidr:
                    rows.append((cidr, "azure", props.get("systemService"), props.get("region"), now))
    else:
        from ..console import banner

        banner("warn", "Azure Service Tags unavailable this run — continuing without them")

    rows = dedupe(rows, (0, 1))
    return pd.DataFrame(rows, columns=CLOUD_COLUMNS)
