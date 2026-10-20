# Enrichment feeds

All feeds are **free, need no API key/registration, and are directly downloadable over HTTPS**.
They are selectable via the `--threat-feeds` option of `dbx-nwp-helper ingress` (all on by default),
and cached locally with a TTL (`dbx-nwp-helper feeds list` / `feeds refresh`). Verify current
licensing before any external/customer-facing distribution — terms can change.

## Threat-intelligence (`threat_intel_ips` table)

Columns: `cidr, source_feed, threat_type, confidence, source_url, loaded_at`.
`confidence` 1 = high (actively malicious / infrastructure), 2 = medium.

| Feed | source_feed | Represents | Grain | URL | License |
|---|---|---|---|---|---|
| Spamhaus DROP v4/v6 | `spamhaus_drop` | hijacked / botnet C2 ranges | CIDR | `www.spamhaus.org/drop/drop_v4.json` (+ `_v6`) | free, attribution |
| Tor exit list | `tor_exit` | anonymiser exit nodes (not inherently malicious) | IP→/32 | `check.torproject.org/torbulkexitlist` | public |
| FireHOL level1 | `firehol_level1` | conservative aggregation of trusted blocklists | CIDR | `raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset` | public-domain philosophy |
| IPsum | `ipsum` | 30+ feed aggregation | IP→/32 | `raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt` | Unlicense (public domain) |
| DShield (SANS ISC) | `dshield` | top attacking /24 subnets | /24 | `feeds.dshield.org/block.txt` | free/public |
| CINS CI Army | `cins_ci_army` | poorly-rated IPs, gap-filler | IP→/32 | `cinsscore.com/list/ci-badguys.txt` | free public use |

**IPsum confidence mapping:** IPsum lists each IP with the number of source blocklists it appears
on. The loader keeps only IPs seen on **≥3** lists (`IPSUM_MIN_LISTS`), tagging **≥5** as confidence
1 and 3–4 as confidence 2. This trims ~112k raw IPs to ~14k consensus entries.

### Held back (unconfirmed licensing — technically work, not enabled)
blocklist.de, Emerging Threats `compromised-ips.txt`, dataplane.org signals. All are free/ungated
and parse cleanly; they were left out pending explicit licensing confirmation. To add one: write a
`_feed_*` loader in `src/dbx_nwp_helper/feeds/threat.py`, register it in `THREAT_FEED_LOADERS`, and
add its key to `THREAT_FEEDS` in `src/dbx_nwp_helper/config.py`.

### Deliberately excluded (gated / unsuitable)
AbuseIPDB, GreyNoise, Cisco Talos, AlienVault OTX, VirusTotal, IPQualityScore (all API-key gated);
abuse.ch Feodo Tracker (deprecated); abuse.ch SSLBL (now needs registration).

## Cloud-provider ranges (`cloud_provider_ranges` table)

Columns: `cidr, provider, service, region, loaded_at`. An observed IP inside one of these is
cloud-hosted egress — context, and a signal not to allow-list a whole provider block wholesale.
All are the providers' **official** feeds:

| Provider | URL | Notes |
|---|---|---|
| AWS | `ip-ranges.amazonaws.com/ip-ranges.json` | stable |
| GCP | `www.gstatic.com/ipranges/cloud.json` | stable |
| Oracle | `docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json` | stable |
| Azure | scraped from `microsoft.com/.../details.aspx?id=56519` → dated `ServiceTags_Public_<date>.json` | Microsoft rotates the URL ~weekly; the CLI resolves the current one. **Do not** use third-party mirrors (e.g. femueller/cloud-ip-ranges). |

## Databricks-owned ranges (`databricks_ranges` table)

Columns: `cidr, platform, region, direction, loaded_at`. Databricks' own control-plane / serverless
/ storage IPs appear as source IPs in the audit log (the platform reaching into the workspace) — when
an **observed** source IP falls in one of these ranges its group is kept in the allow-list in its own
unscoped rule, and takes precedence over the cloud-provider flag (a Databricks IP is also an
AWS/Azure/GCP IP). Note this only allow-lists Databricks ranges actually seen in the audit traffic —
the tool does **not** inject the full published range set, so confirm the platform's own ranges are
covered before enforcing an ingress policy.

Source: the official machine-readable feed **`databricks.com/networking/v1/ip-ranges.json`** — one
JSON covering **AWS, Azure and GCP**, with `type` inbound/outbound per region. Verified to contain
the same control-plane CIDRs published per-region at the HTML docs
(`docs.databricks.com/.../resources/ip-domain-region`, and the Azure/GCP equivalents), so no HTML
scraping is needed. SCC-relay FQDNs (`tunnel.*`) are not in the feed but matter only for customer
egress allow-listing, not ingress source-IP analysis.

## Partner-platform ranges (`partner_ranges` table)

Columns: `cidr, partner, region, source_url, loaded_at`. The egress IPs that named SaaS partner
platforms connect to Databricks *from*. An observed inbound source IP inside one of these is labelled
as that partner and recommended for allow-listing (the platform, not a person, is reaching in).

| Partner | partner | Source | Notes |
|---|---|---|---|
| Power BI | `Power BI` | the Azure Service Tags JSON (`PowerBI` + `PowerBI.<region>` tags), via `microsoft.com/.../details.aspx?id=56519` | **dynamic** — reuses the same official feed as the cloud ranges; no auth |
| dbt platform | `dbt platform` | `docs.getdbt.com/docs/cloud/about-cloud/access-regions-ip-addresses` | **curated** in-repo (no machine feed); keep `_DBT_LAST_VERIFIED` current when refreshing |
| Tableau Cloud | `Tableau Cloud` | — | **deferred** — ships no ranges yet, pending a confirmed published-allowlist source; the loader slot is wired up |

Databricks' own managed **"Partner platforms"** context-based-ingress source (Beta; AWS + GCP; Power
BI / Tableau Cloud / dbt platform) maintains these lists for you and is the cleaner option. It is
**not exposed by the SDK** this tool writes with (console / Terraform only), so matched partner IPs
are emitted as ordinary labelled CIDR allow-rules and the CLI advises enabling the managed source.
Verify current licensing before any external redistribution of the curated lists.

## VPN / SASE ranges — intentionally not included
Enterprise SASE/SWG vendors (Zscaler, Palo Alto Prisma, Cisco Umbrella, Netskope) do **not** publish
ungated IP lists. Consumer VPNs don't publish official lists either. The only free/ungated options
are community aggregations (e.g. X4BNet) and Cloudflare's CDN ranges — judged too partial/unreliable
to be a meaningful signal for this use case, so no VPN signal is shipped.
