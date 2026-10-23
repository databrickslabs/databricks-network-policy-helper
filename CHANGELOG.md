# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). For a CLI, the
"public API" governed by SemVer is the command and flag surface: a breaking change to it bumps
the **major** version, a backward-compatible addition bumps the **minor**, and a fix bumps the
**patch**.

The version is derived from the git tag by `hatch-vcs`, so a release is cut by tagging the
commit `vX.Y.Z` — see the "Versioning & releases" section of the README.

## [Unreleased]

## [0.5.0] - 2026-10-23

### Fixed

- **Back-end PrivateLink endpoints are now included in a migrated restricted private policy (AWS /
  GCP).** When a workspace's front-end PrivateLink is endpoint-scoped, the generated `private_access`
  block is `RESTRICTED_ACCESS` — which gates **all** private ingress, not just the front-end.
  Previously the block was built from the Private Access Settings (front-end) alone, so the
  workspace's back-end data-plane endpoints (SCC relay + REST) — which live in the network
  configuration, not the PAS — were left out, and the restricted policy blocked the data plane
  (notebook commands failing "against the workspace's ingress policy"). The ingress run now reads
  those back-end endpoints from the workspace's network config (`network.vpc_endpoints`: AWS VPC
  endpoints / GCP PSC) and adds them as a distinct allow rule alongside the front-end endpoints,
  deduped. A workspace with no back-end PrivateLink migrates unchanged, with a note that none was
  detected.

### Added

- **Tableau Cloud partner-platform ranges are now shipped** (previously deferred pending a confirmed
  source). Observed inbound IPs in Tableau Cloud's published Hyperforce pod egress ranges are
  labelled and recommended for allow-listing, matching the existing Power BI / dbt platform
  behaviour. Curated in-repo from the Tableau Cloud IP authorization doc (`help.tableau.com`).

### Changed

- The policy-limit **truncation gate now offers a way back**. On interactive `ingress` runs, when
  rules/CIDRs are auto-capped to fit account network-policy limits, declining the "continue?" prompt
  no longer only aborts — it lets you return to the allow-rule selection (with the full rule set
  restored so you can deselect rules to get under the limit) or abort. `--yes` / scripted runs are
  unchanged.
- Documented that the `tor_exit` threat feed (`check.torproject.org`) is often unreachable from
  corporate/cloud networks — the "connection reset by peer" warning is a network block, not a
  dead/moved feed, and is safe to ignore or deselect.

## [0.4.0] - 2026-10-21

### Added

- **Front-end PrivateLink is now handled, not refused.** `ingress` no longer aborts on a PrivateLink
  workspace. Public and private access are migrated independently. On **AWS/GCP**, a **non-allow-all**
  Private Access Settings (PAS) — specific registered endpoints — is migrated into the policy's
  `private_access` block (endpoint ids mapped across as-is); an allow-all PAS needs no migration (CBI
  already defaults to allowing all registered endpoints). On **Azure**, front-end PrivateLink is not
  migrated at all (the `databricks_ui_api` endpoints are default-allowed and additive, and the
  public-access flag isn't being retired) — Azure simply migrates IP ACLs into public access.
- **Existing CBI ingress is reused/retained per dimension.** Public, private and cross-workspace
  access are independent: each is either built/migrated or **carried forward** from the workspace's
  currently-assigned CBI policy (deep-copied, restrictive blocks only). Public is built net-new from
  observed traffic + IP ACLs (an existing restrictive public block is preserved only when this run
  has nothing of its own to build); private is migrated from a non-allow-all PAS or carried forward
  (an allow-all PAS never loosens a stricter existing private block); **cross-workspace is always
  carried forward verbatim** (this tool doesn't build cross-workspace rules). Aligns the existing-
  policy handling with the `databricks-migrate-ip-acls` sibling tool.
- **Partner-platform IP detection.** Observed inbound IPs are matched against published partner
  ranges — **Power BI** (dynamic, from the Azure Service Tags `PowerBI` tag) and **dbt platform**
  (curated) — labelled as that partner and recommended for allow-listing. The CLI also points you at
  Databricks' managed "Partner platforms" ingress source (Beta; AWS + GCP) as a cleaner, self-
  updating alternative to pinning the CIDRs. (Tableau Cloud is wired up but ships no ranges yet,
  pending a confirmed source.) `feeds list` / `refresh` include the new `partner_ranges` feed.
- **`system.access.inbound_network` as an allow-list candidate source.** `ingress` now folds the
  public IPs a *dry-run* CBI policy would have denied (`access_type=DRY_RUN_DENIAL`) into the
  candidate set — the inbound clients your log-only allow-list doesn't cover yet. Enforced denials
  (`DROP`) continue to feed the recently-denied view. Best-effort; `--no-include-inbound-network`
  opts out.

### Changed

- **Per-dimension create-and-assign conflict gate.** The preflight now aborts only when a dimension
  this run **migrates** collides with a **restrictive** existing CBI block in that same dimension:
  migrating public (observed traffic / IP ACLs) over a restrictive public block, or migrating a
  non-allow-all PAS over a restrictive private block. (It aborts on any restrictive block — enforced
  or dry-run.) So legacy IP ACLs plus an existing CBI private-access block no longer aborts — the
  ACLs move to public and the private block is carried across. The egress opposite-direction guard on
  a new-id rebind is unchanged.
- **Minimum `databricks-sdk` is now 0.152.0** (for the `private_access` / `cross_workspace_access`
  CBI dataclasses).

## [0.3.0] - 2026-09-30

### Changed

- **A more visual companion guide.** `dbx-nwp-helper guide` gains navigation and visualisation
  enhancements: a reading-progress bar and scroll-spy table of contents that track where you are, a
  "you are here" step rail that lights up each stage as you move through the ingress / egress
  walkthroughs, inline **flow diagrams** (hand-authored, theme-aware SVG) summarising each command's
  decision path, and subtle reveal-on-scroll polish. All additive and self-contained — the guide
  stays a single offline file, respects `prefers-reduced-motion`, and still renders every section in
  the `--pdf` / print path.

## [0.2.0] - 2026-09-29

### Added

- **Interactive companion guide.** `dbx-nwp-helper guide` opens a self-contained, offline HTML
  companion (packaged with the tool): step-by-step **ingress and egress walkthroughs** that mirror
  the tool's actual flow, a collapsible **CLI options** reference (a readable version of `--help`),
  and "learn more" expanders (including what RDAP is and to treat it as a signal, not a source of
  truth). A one-line hint at the start of a run points new users to it. `--print-path` prints the
  file path instead of opening a browser, and `--pdf <path>` renders the whole guide to a PDF with
  every section expanded (via a headless Chrome / Chromium / Edge, with an on-page "Save as PDF"
  button as a fallback).
- **CBI-policy denials in the "recently denied" view.** Ingress now also reads
  `system.access.inbound_network` (when the table is available), so recently-blocked inbound
  requests are flagged whether they were denied by an IP access list (403) *or* a CBI network
  policy — merged into one view by source IP. Degrades gracefully when the table is absent.
- **Automatic IP access list detection.** When a workspace has enabled IP access lists, `ingress`
  detects them, shows their actual IP entries, and (interactively) offers a pre-checked checkbox to
  pick exactly which entries to migrate into the CBI policy (alongside the enriched observed-traffic
  rules). Scripted / `--yes` runs migrate them all.

### Changed

- **Rule selection is on by default.** The `--select-rules` checkbox now runs by default in
  interactive runs; pass `--no-select-rules` to keep everything. Scripted / `--yes` runs are
  unaffected (the selector is skipped, as before). The egress selector runs as two distinct prompts
  — one for internet FQDNs, one for storage destinations (S3 / GCS / Azure) — so each kind is
  curated separately.
- **Simpler rule labels.** Generated rules no longer carry a `(dry-run)` / `(enforced)` suffix, and
  migrated IP-ACL rules no longer carry a `migrated-acl-` prefix — labels are now verbatim.
- **Clearer account-auth errors.** When account-admin credentials can't be resolved, the CLI now
  explains that account auth is separate from the workspace `--profile` and how to set it up,
  instead of surfacing the raw SDK "cannot configure default credentials" message.

### Removed

- **`--ip-acl-handling`.** Replaced by the automatic detect-and-prompt flow above; observed-traffic
  rules are always included, and the standalone ACL-only (`migrate`) mode is gone. Use the prompt
  (or `--yes` to migrate non-interactively) to include existing IP access lists.

## [0.1.0] - 2026-09-18

First release. `dbx-nwp-helper` turns real observed traffic in the Databricks system
tables into proposed **account network policies**, with a dry-run-first, review-gated apply path.

### Added

- **Ingress (CBI).** `dbx-nwp-helper ingress` proposes and optionally applies a context-based
  ingress allow-list from `system.access.audit` source IPs — enriched with open threat-intel,
  cloud-provider and Databricks-owned IP ranges plus RDAP ownership, with minimal / optimal /
  maximum CIDR framings and optional scoping by destination (Apps / Lakebase) and identity.
- **Egress (SEG).** `dbx-nwp-helper egress` proposes and optionally applies a serverless egress
  allow-list from `system.access.outbound_network` destinations (S3 / GCS / Azure storage and
  internet FQDNs), with optional threat-intel domain blocking (abuse.ch ThreatFox).
- **Guided wizard.** `dbx-nwp-helper guided` walks through building either policy interactively.
- **Feed cache management.** `dbx-nwp-helper feeds list` / `refresh` / `clear` for the local
  threat-intel / cloud-range feed cache (free, key-less, HTTPS, TTL-cached).
- **Safety model.** Nothing is written without `--create-policy`; `dry_run` is the default mode;
  the target workspace is confirmed before any action; interactive step-through and review gates
  guard every stage (bypass with `--yes`); and pre-checks abort rather than clobber an existing
  PrivateLink / enforced policy or drop the opposite direction's enforced block.
- **Export.** `--export <path>` writes the proposed `AccountNetworkPolicy` as REST-ready JSON and
  a best-effort Terraform `.tf`, working in propose-only mode.
- **`--version`.** All commands expose the tool version via `dbx-nwp-helper --version`.

[Unreleased]: https://github.com/andyweaves/databricks-network-policy-helper/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/andyweaves/databricks-network-policy-helper/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/andyweaves/databricks-network-policy-helper/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/andyweaves/databricks-network-policy-helper/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/andyweaves/databricks-network-policy-helper/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/andyweaves/databricks-network-policy-helper/releases/tag/v0.1.0
