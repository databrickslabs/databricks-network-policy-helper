# Enrichment feeds

Almost all feeds are **free, need no API key/registration, and are directly downloadable over
HTTPS** — the one exception is the **abuse.ch** domain feeds (ThreatFox / URLhaus), which now need a
free opt-in Auth-Key (see below). Feeds are **selectable**: ingress IP feeds via `--threat-feeds`
and egress domain feeds via `--threat-feeds` on `egress` (both default to all keyless feeds), with a
checkbox in the guided wizard. All are cached locally with a TTL (`dbx-nwp-helper feeds list` /
`feeds refresh`). Verify current licensing before any external/customer-facing distribution — terms
can change.

## Threat-intelligence (`threat_intel_ips` table)

Columns: `cidr, source_feed, threat_type, confidence, source_url, loaded_at`.
`confidence` 1 = high (actively malicious / infrastructure), 2 = medium.

| Feed | source_feed | Represents | Grain | URL | License |
|---|---|---|---|---|---|
| Spamhaus DROP v4/v6 | `spamhaus_drop` | hijacked / botnet C2 ranges | CIDR | `www.spamhaus.org/drop/drop_v4.json` (+ `_v6`) | free, attribution |
| Tor exit list | `tor_exit` | anonymiser exit nodes (not inherently malicious) | IP→/32 | `check.torproject.org/torbulkexitlist`, fallback `dan.me.uk/torlist/?exit` | public |
| FireHOL level1 | `firehol_level1` | conservative aggregation of trusted blocklists | CIDR | `raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset` | public-domain philosophy |
| IPsum | `ipsum` | 30+ feed aggregation | IP→/32 | `raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt` | Unlicense (public domain) |
| DShield (SANS ISC) | `dshield` | top attacking /24 subnets | /24 | `feeds.dshield.org/block.txt` | free/public |
| CINS CI Army | `cins_ci_army` | poorly-rated IPs, gap-filler | IP→/32 | `cinsscore.com/list/ci-badguys.txt` | free public use |
| C2IntelFeeds | `c2intel` | validated C2 IPs (drb-ra; 30-day window, VPN files excluded) | IP→/32 | `raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv` | CC-BY-4.0 (attribution) |

**IPsum confidence mapping:** IPsum lists each IP with the number of source blocklists it appears
on. The loader keeps only IPs seen on **≥3** lists (`IPSUM_MIN_LISTS`), tagging **≥5** as confidence
1 and 3–4 as confidence 2. This trims ~112k raw IPs to ~14k consensus entries.

**`tor_exit` reachability:** `check.torproject.org` is frequently blocked on corporate/cloud egress
networks (and the Tor Project rate-limits datacenter IPs), surfacing as
`⚠️ feed fetch failed … Connection reset by peer`. The URL is still current — the feed just can't be
reached from those networks. When it's unreachable the loader falls back to the **dan.me.uk** Tor
exit list (`dan.me.uk/torlist/?exit`). dan.me.uk **bans clients that fetch more than once per 30
min**, so a marker guards the fallback (even under `--refresh-feeds`) — if it was fetched too
recently it's skipped for that run rather than risking a ban.

### Held back (unconfirmed licensing — technically work, not enabled)
blocklist.de, Emerging Threats `compromised-ips.txt`, dataplane.org signals. All are free/ungated
and parse cleanly; they were left out pending explicit licensing confirmation. **blocklist.de** has
since been recommended by the security team on *detection* grounds, but its terms are free for
**non-commercial** use (commercial use needs permission) — it stays held back until that licensing
call is made (a detection endorsement is not a licensing clearance). To add one: write a `_feed_*`
loader in `src/dbx_nwp_helper/feeds/threat.py`, register it in `THREAT_FEED_LOADERS`, and add its key
to `THREAT_FEEDS` in `src/dbx_nwp_helper/config.py`.

### Deliberately excluded (gated / unsuitable)
AbuseIPDB, GreyNoise, Cisco Talos, AlienVault OTX, VirusTotal, IPQualityScore (all API-key gated);
abuse.ch Feodo Tracker (deprecated); abuse.ch SSLBL (now needs registration).

## Egress domain block feeds (`egress --block-threat-domains`)

Selected via `--threat-feeds` on `egress` (default `c2intel`). Known-bad **domains** blocked as
egress destinations.

| Feed | key | Represents | Auth | URL |
|---|---|---|---|---|
| C2IntelFeeds | `c2intel` | validated C2 domains (drb-ra, 30-day) | none | `raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s-30day.csv` |
| abuse.ch ThreatFox | `threatfox` | botnet C2 domain IOCs | **Auth-Key** | `threatfox.abuse.ch/export/csv/recent/` |
| abuse.ch URLhaus | `urlhaus` | malware-distribution URL hosts | **Auth-Key** | `urlhaus.abuse.ch/downloads/csv_recent/` |

**abuse.ch Auth-Key.** As of 2024/25 abuse.ch retired its keyless bulk downloads (the old
`/downloads/hostfile/` now returns `410 Gone`) and requires a **free** Auth-Key. Sign up at
**https://auth.abuse.ch/**, then pass the key via `--abuse-ch-auth-key` or the
`DBX_NWP_ABUSE_CH_AUTH_KEY` env var; the tool sends it as the `Auth-Key` HTTP header. Without a key,
`threatfox`/`urlhaus` are **skipped with a note** and only the keyless feeds (`c2intel`) load.

## Domain allowlist / popularity (flag-only — `--domain-allowlist`)

Before enforcing a domain block list, the tool cross-checks block-candidates against popularity /
allowlist sources and **flags** any overlap for review. It **never auto-unblocks** — popularity is
**not** proof a domain is benign (these lists can and do contain real C2). Off with
`--no-domain-allowlist`; sources selected via `--domain-allowlist-feeds`.

| Source | key(s) | Notes | URL |
|---|---|---|---|
| MISP warninglists | `cloudflare-top1k`, `cisco_top1000`, `majestic_million`, … | popular-domain lists; `list.json` per list | `raw.githubusercontent.com/MISP/misp-warninglists/main/lists/<name>/list.json` |
| Tranco | `tranco` | research top-sites list (capped to the top 100k) | `tranco-list.eu/top-1m.csv.zip` |

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
| Tableau Cloud | `Tableau Cloud` | `help.tableau.com/current/pro/desktop/en-us/publish_tableau_online_ip_authorization.htm` | **curated** in-repo (Tableau Cloud Hyperforce pod ranges; no machine feed); keep `_TABLEAU_LAST_VERIFIED` current when refreshing |

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
