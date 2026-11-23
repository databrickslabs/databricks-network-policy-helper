# Findings catalog

Each finding is tagged with its defense-in-depth layer (Avoid · Expire · Scope · **Limit** · Detect ·
Respond · Posture, see `credential-theft-layers.md`). Unmarked rows are *Limit*.

Each check is implemented in `scripts/cbi_posture.py::evaluate()`. Severity is a default. Raise or
lower it based on the customer's context (e.g. a sandbox workspace with no data).

| ID | Severity | Check | Evidence source | Why it matters | Fix (propose-only first) |
|---|---|---|---|---|---|
| CBI-001 | high (medium if IP ACL state unknown) | Effective policy's public access is not restrictive **and** there is no enabled ALLOW IP access list | assigned/default policy, workspace IP ACLs, `traffic_by_ip_class` | Anyone with valid credentials (or a leaked PAT) can connect from anywhere | `dbx-nwp-helper ingress` |
| CBI-002 | medium | Enabled ALLOW IP ACLs, CBI public open | IP ACLs | Legacy control is IP-only (no identity / request-type context) and per-workspace. Databricks recommends CBI as the single engine | `dbx-nwp-helper ingress` (auto-detects ACLs) or `dbx-migrate-ip-acls` |
| CBI-003 | medium | Restrictive public rules live in `ingress_dry_run` only | policy, `dry_run_would_block` | Logs but blocks nothing. Count shows the gap before enforcement | re-run helper with `add_to_existing`, then enforce |
| CBI-004 | high: any IP (`all_ip_ranges`, or all public IPs `except` a few) reaches all workspace APIs for every identity · high: /0–/8 CIDRs · medium: /9–/15 CIDRs · medium: named identities reach all APIs from any IP | Allow rules that barely restrict API callers | policy (rule source, destination, authentication), IP ACLs | A stolen token works from anywhere. `workspace_api` with no scopes is treated as all APIs and called out | narrow the source; keep 'anywhere' for the UI only (B1), API families (B2) or time-boxed identities (B4) |
| CBI-005 | low | IP ACLs still enabled with an enforced CBI public block (workspace or account) | IP ACLs + policy | AND-combined: two lists to keep in sync, harder troubleshooting | `--disable-existing-ip-acls` **after** validation and with approval |
| CBI-006 | info | No explicit assignment; `default-policy` governs | workspace network option | Editing default-policy affects every new workspace. Databricks advises named policies | create a named policy |
| CBI-007 | medium | Workspace has a PAS but CBI `private_access` allows all registered endpoints | PAS + policy | Any endpoint registered to the account (incl. other BUs' VPCs/VNets) may reach the workspace | helper recreates the PAS posture (AWS/GCP) |
| CBI-008 | info | PrivateLink workspace with PAS public access enabled while public ingress < L2 | PAS | Hybrid exposure, so check it's intended | restrict public via CBI or block public in PAS |
| CBI-009 | high if account-level public traffic seen, else medium | `account-policy` public access not restrictive | account policy, `account_level_public_access` | Account console/APIs (and account Genie One) reachable from anywhere | derive IPs with `--include-account-level`; set `account-policy` in the console (Beta) |
| CBI-010 | medium | ≥ 80 % of 50 rules or 2,000 CIDRs | policy | Next change may be rejected by the API | `--consolidate-rules`, Partner platforms |
| CBI-011 | medium | `system.access.inbound_network` query failed | SQL | No visibility of dry-run gaps or enforced blocks | enable `access` schema, grant SELECT |
| CBI-012 | high (enforced) / medium | Enforced denials in the lookback | `enforced_denials` | Either an attack being stopped or a legitimate client being broken. Triage | add legit sources; `--deny-denied-ips` for hostile |
| CBI-013 | medium | Principals seen from ≥ 10 distinct public /24s | `principal_network_spread` | Roaming users / rotating SaaS IPs can't be pinned by CIDR | identity rules, VPN/egress gateway, Partner platforms |
| CBI-014 | info | BI/SaaS user agents on public IPs | `client_families_on_public_ips` | Managed Partner platforms source is simpler than hand-kept CIDRs | console → policy → Ingress → Partner platforms |
| CBI-015 | info | IPv6 public traffic | `traffic_by_ip_class` | CBI public rules are IPv4-only | identify clients before enforcing |
| CBI-016 | info | Pricing tier not ENTERPRISE | account workspaces API | CBI needs Enterprise tier | plan tier change |
| CBI-017 | low | Egress not restricted | policy egress | Ingress-only posture; data exfiltration path stays open | `dbx-nwp-helper egress` |
| CBI-018 | medium | Policy / account config unreadable | API errors | Assessment incomplete (UNKNOWN, not "fine") | re-run with account admin |
| CBI-019 | info | Cross-workspace access not restricted (L2+) | policy | Other workspaces can reach this one over serverless | cross-workspace allow-list (Beta) |
| CBI-020 | high on L0/L1, else medium · *Expire* | PATs with no expiry | `token-management list` | A leaked never-expiring token works until someone notices. With open ingress it works from anywhere too | revoke via Token report; replace with OAuth / short-lived |
| CBI-021 | medium · *Expire* | `maxTokenLifetimeDays` unset or > 90 | workspace-conf | New tokens can be long-lived. The limit doesn't shorten existing ones | set a short maximum (evaluate 1–7 days) |
| CBI-022 | medium · *Avoid* | `users` group has CAN_USE on tokens | token permissions | Every user can mint a bearer credential that skips SSO/MFA on use | OAuth U2M for people, WIF/M2M for automation; grant PAT use to an exception group |
| CBI-022 (info) | info · *Avoid* | Token permissions never customised (the permissions API returns `ResourceDoesNotExist`) | token permissions | The default applies, and the API doesn't say who that includes | Check Settings → Advanced → Personal Access Tokens → Permission settings; restrict to an exception group |
| CBI-023 | low · *Scope* | PATs with empty `scopes` (= all APIs) | `token-management list` | A token made for one job carries all its owner's API authority | scoped PATs, auto-scoping (preview) |
| CBI-024 | info · *Expire* | PATs unused 90+ days | `last_used_day` | Risk without value | revoke |
| CBI-025 | medium · *Detect* | Verbose audit logging disabled in the window | `audit_visibility` | Visibility gap: later conclusions are incomplete | re-enable, treat the gap as unknown |
| CBI-026 | info · *Limit* | Suggested CBI pattern for workspaces still open | `public_browser_vs_api`, client families, tier | No VPN needed: B1 browser-only, B2 API scopes, B3 partner source, B4 time-boxed; or credential and blast-radius layers when CBI isn't available | pilot the pattern in dry-run |
| CBI-027 | info · *Limit* | Allow rule with no IP source in the API response | policy | Usually a console-only source (Partner platforms, app integrations). The report can't judge who it admits | review in the account console |
| CBI-028 | low · *Limit* | Specific API scopes (or read-only variants) allowed from any IP | policy | Pattern B2. Fine if intended; the scopes are reachable with any stolen token that carries them | owner per scope; short token lifetimes |
| CBI-029 | info · *Limit* | Every IP allowed to the UI / Apps / Lakebase only | policy | Pattern B1 recognised: browser from anywhere, APIs restricted | pair with SSO + MFA |

## Maturity

Assigned per workspace before findings are applied, then L3 → **L4 Hardened** if the workspace has no
critical/high/medium findings.

```
PAS public access disabled                        → L3 Private-only
restrictive public block in ingress (enforced)    → L3 Enforced
restrictive public block in ingress_dry_run       → L2 Observing
enabled ALLOW IP access list                      → L1 Legacy perimeter
IP ACLs not collected                             → "CBI open, IP ACL unchecked" (L0 or L1)
otherwise                                         → L0 Open
```

"Restrictive" means `RESTRICTED_ACCESS` or any allow/deny rules, the same test
`dbx-nwp-helper` uses (`core/acl.py::_block_restrictive`).

**Open in effect.** A block that is restrictive on paper but has an allow rule letting any IP reach all
workspace APIs for every identity (CBI-004 high) doesn't count as restricting. It scores as if the public
block were open (L0, or L1 with IP access lists), and the reason names the rule.

## Known limits of the diagnostic

- The audit log records the client IP Databricks saw. Behind NAT or a proxy, that's the egress IP,
  which is exactly what CBI matches.
- `IpAccessDenied` only covers IP ACL blocks. CBI blocks are in `system.access.inbound_network`.
- The collector does not inject published Databricks / partner ranges. Use the helper's feed
  enrichment for that.
- Threat-intel matching of source IPs is done by the helper (`--block-threat-ips`), not here.
- The PAT inventory is per workspace (needs workspace admin on each `--workspace-profile`). The
  account console token report is the cross-workspace view.
- Client families come from user-agent strings, which can be spoofed. Treat them as a planning signal,
  not evidence.
