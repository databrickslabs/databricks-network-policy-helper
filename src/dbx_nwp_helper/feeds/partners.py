"""Partner-platform published IP ranges → a `partner_ranges` DataFrame.

Columns: cidr, partner, region, source_url, loaded_at. These are the egress IPs that named SaaS
partner platforms connect to Databricks *from*. An observed inbound source IP that falls in one of
these ranges is labelled as that partner and recommended for allow-listing (the platform, not a
person, is reaching in).

Databricks itself now supports a **"Partner platforms" network source** for context-based ingress
(Beta; AWS + GCP; Power BI, Tableau Cloud, dbt platform), where Databricks manages the IP lists for
you. That source is **not exposed by the SDK** this tool writes with (console / Terraform only), so
matched partner IPs are emitted here as ordinary labelled CIDR allow-rules; the CLI additionally
advises enabling the console's Partner-platforms source as the cleaner, self-maintaining option.

Sourcing:
  * Power BI  — dynamic, from the Azure "IP Ranges and Service Tags" JSON (the `PowerBI` service
    tag), the same official feed the cloud-provider ranges use. No auth.
  * dbt       — curated in-repo snapshot of docs.getdbt.com (no machine-readable feed exists). Keep
    `_DBT_LAST_VERIFIED` current when refreshing from the source URL.
  * Tableau   — curated in-repo snapshot of help.tableau.com (Tableau Cloud Hyperforce pod egress
    ranges; no machine-readable feed, though the Salesforce-owned ip-ranges.json is a possible future
    source). Keep `_TABLEAU_LAST_VERIFIED` current when refreshing from the source URL.

Verify current licensing/terms before any customer-facing redistribution (as with the threat feeds).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pandas as pd

from . import cloud
from .util import dedupe, valid_cidr

PARTNER_COLUMNS = ["cidr", "partner", "region", "source_url", "loaded_at"]

# --- Power BI (dynamic — Azure Service Tags `PowerBI`) ---------------------------------------------
_POWERBI_SOURCE = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"


def _load_powerbi(now) -> list[tuple]:
    """Power BI ranges from the Azure Service Tags JSON — every service tag whose name is `PowerBI`
    or a regional `PowerBI.<region>` variant. Best-effort: an unavailable feed contributes nothing."""
    data = cloud.fetch_azure_service_tags()
    if not data:
        from ..console import banner

        banner("warn", "Azure Service Tags unavailable this run — Power BI partner ranges skipped")
        return []
    rows = []
    for v in data.get("values", []):
        name = v.get("name") or ""
        if name != "PowerBI" and not name.startswith("PowerBI."):
            continue
        props = v.get("properties", {})
        region = props.get("region") or None
        for cidr_raw in props.get("addressPrefixes", []):
            cidr = valid_cidr(cidr_raw)
            if cidr:
                rows.append((cidr, "Power BI", region, _POWERBI_SOURCE, now))
    return rows


# --- dbt platform (curated — docs.getdbt.com) ------------------------------------------------------
_DBT_SOURCE = "https://docs.getdbt.com/docs/cloud/about-cloud/access-regions-ip-addresses"
_DBT_LAST_VERIFIED = "2026-10-20"
# (cidr-or-bare-ip, region-label). Bare IPs are normalised to /32 by valid_cidr.
_DBT_RANGES = [
    # AWS — North America (us-east-1)
    ("52.45.144.63", "aws us-east-1"),
    ("54.81.134.249", "aws us-east-1"),
    ("52.22.161.231", "aws us-east-1"),
    ("52.3.77.232", "aws us-east-1"),
    ("3.214.191.130", "aws us-east-1"),
    ("34.233.79.135", "aws us-east-1"),
    # AWS — North America (us-west-2)
    ("32.185.64.51", "aws us-west-2"),
    ("34.217.173.137", "aws us-west-2"),
    ("52.37.223.167", "aws us-west-2"),
    # AWS — EMEA (eu-central-1, Frankfurt)
    ("3.123.45.39", "aws eu-central-1"),
    ("3.126.140.248", "aws eu-central-1"),
    ("3.72.153.148", "aws eu-central-1"),
    # AWS — APAC (ap-southeast-2, Sydney)
    ("52.65.89.235", "aws ap-southeast-2"),
    ("3.106.40.33", "aws ap-southeast-2"),
    ("13.239.155.206", "aws ap-southeast-2"),
    # AWS — Japan (ap-northeast-1, Tokyo)
    ("35.76.76.152", "aws ap-northeast-1"),
    ("54.238.211.79", "aws ap-northeast-1"),
    ("13.115.236.233", "aws ap-northeast-1"),
    # GCP
    ("34.33.2.0/26", "gcp us-central1"),
    ("34.39.41.0/26", "gcp europe-west2 (London)"),
    ("34.185.244.128/26", "gcp europe-west3 (Frankfurt)"),
    # Azure
    ("20.10.67.192/26", "azure East US 2"),
    ("20.13.190.192/26", "azure North Europe"),
    ("20.11.97.208/28", "azure Australia East"),
]


def _load_dbt(now) -> list[tuple]:
    rows = []
    for raw, region in _DBT_RANGES:
        cidr = valid_cidr(raw)
        if cidr:
            rows.append((cidr, "dbt platform", region, _DBT_SOURCE, now))
    return rows


# --- Tableau Cloud (curated — help.tableau.com Hyperforce pods) ------------------------------------
_TABLEAU_SOURCE = (
    "https://help.tableau.com/current/pro/desktop/en-us/"
    "publish_tableau_online_ip_authorization.htm"
)
_TABLEAU_LAST_VERIFIED = "2026-10-23"
# (cidr, region-label). Hyperforce pod egress ranges only — the page's pre-Hyperforce single IPs are
# listed there for *removal* from allowlists, so they're deliberately excluded.
_TABLEAU_RANGES: list[tuple[str, str]] = [
    # Asia Pacific
    ("141.163.192.0/23", "aws ap-southeast-2 (Australia)"),
    ("141.163.216.0/24", "aws ap-south-2 (India)"),
    ("141.163.212.0/24", "aws ap-southeast-3 (Indonesia)"),
    ("141.163.208.0/23", "aws ap-northeast-1 (Japan)"),
    ("141.163.196.0/23", "aws ap-southeast-1 (Singapore)"),
    ("141.163.200.0/23", "aws ap-northeast-2 (South Korea)"),
    # Canada
    ("155.226.152.0/23", "aws ca-central-1 (Canada)"),
    # Europe
    ("145.224.208.0/23", "aws eu-central-1 (Germany)"),
    ("145.224.198.0/24", "aws eu-central-2 (Switzerland)"),
    ("145.224.200.0/23", "aws eu-west-2 (UK)"),
    # United States
    ("155.226.128.0/21", "aws us-west-2 (US West)"),
    ("155.226.144.0/22", "aws us-east-1 (US East)"),
]


def _load_tableau(now) -> list[tuple]:
    rows = []
    for raw, region in _TABLEAU_RANGES:
        cidr = valid_cidr(raw)
        if cidr:
            rows.append((cidr, "Tableau Cloud", region, _TABLEAU_SOURCE, now))
    return rows


def load_partner_ranges() -> pd.DataFrame:
    now = datetime.now(timezone.utc)
    rows = _load_powerbi(now) + _load_dbt(now) + _load_tableau(now)
    rows = dedupe(rows, (0, 1))  # (cidr, partner) — a CIDR can be published by more than one partner
    return pd.DataFrame(rows, columns=PARTNER_COLUMNS)
