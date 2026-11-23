# `posture` checks

Each check is implemented in `src/dbx_nwp_helper/core/posture.py::evaluate()`. Severity is a default:
raise or lower it for the workspace's context (a sandbox with no data is not a production workspace).
The ids are stable, so findings can be tracked across runs (`findings.csv`).

| ID | Severity | Check | Evidence | Why it matters | Next step (propose-only first) |
|---|---|---|---|---|---|
| CBI-001 | high (medium if IP ACL state unknown) | Effective policy's public access isn't restrictive **and** there's no enabled ALLOW IP access list | assigned/default policy, IP ACLs, `traffic_by_ip_class` | Anyone with valid credentials (or a leaked PAT) connects from anywhere | `ingress` |
| CBI-002 | medium | Enabled ALLOW IP access lists, CBI public open | IP ACLs | Legacy control is IP-only (no identity / request type) and per workspace | `ingress` (auto-detects ACLs) or `dbx-migrate-ip-acls` |
| CBI-003 | medium | Restrictive public rules live in `ingress_dry_run` only | policy, `inbound_policy_outcomes` | Logs but blocks nothing; the count is the gap to close before enforcing | `ingress --policy-action add_to_existing`, then enforce |
| CBI-004 | high: any IP reaches all workspace APIs for all users and/or service principals · high: /0–/8 · medium: /9–/15 · medium: named identities reach all APIs from any IP | Allow rules that barely restrict API callers | policy (source, destination, authentication), IP ACLs | A stolen token works from anywhere. `workspace_api` with no scopes is treated as all APIs | narrow the source; keep "anywhere" for the UI (B1), API families (B2) or time-boxed identities (B4) |
| CBI-005 | low | IP access lists still enabled with an enforced CBI public block (workspace or account) | IP ACLs + policy | AND-combined: two lists to keep in sync | `--disable-existing-ip-acls` **after** validation and approval |
| CBI-006 | info | No explicit assignment; `default-policy` governs | workspace network option | Editing default-policy affects every new workspace | create a named policy |
| CBI-007 | medium | Workspace has a PAS but CBI `private_access` allows all registered endpoints | PAS + policy | Any endpoint registered to the account (other teams' VPCs/VNets) may reach the workspace | `ingress` recreates the PAS posture (AWS/GCP) |
| CBI-008 | info | PrivateLink workspace with PAS public access enabled while public ingress < L2 | PAS | Hybrid exposure: check it's intended | restrict public via CBI, or block public in the PAS |
| CBI-009 | high if account-level public traffic seen, else medium | `account-policy` public access not restrictive | account policy, `account_level_public_access` | Account console / APIs (and account Genie One) reachable from anywhere | `ingress --include-account-level` for candidate IPs; set `account-policy` in the console (Beta) |
| CBI-010 | medium | ≥ 80 % of the rule or CIDR cap | policy | The next change may be rejected by the API | `--consolidate-rules`, Partner platforms |
| CBI-011 | medium | `system.access.inbound_network` unreadable | SQL | No visibility of dry-run gaps or enforced blocks | enable the `access` schema, grant SELECT |
| CBI-012 | high (enforced) / medium | Enforced denials in the lookback | `inbound_policy_outcomes` | An attack being stopped, or a legitimate client being broken: triage | add legit sources; `--deny-denied-ips` for hostile ones |
| CBI-013 | medium | Principals seen from ≥ 10 distinct public /24s | `principal_network_spread` | Roaming users / rotating SaaS IPs can't be pinned by CIDR | identity rules, VPN/egress gateway, Partner platforms |
| CBI-014 | info | BI/SaaS user agents on public IPs | `client_families_on_public_ips` | The managed Partner platforms source is simpler than hand-kept CIDRs | console → policy → Ingress → Partner platforms |
| CBI-015 | info | IPv6 public traffic | `traffic_by_ip_class` | CBI public rules are IPv4-only | identify those clients before enforcing |
| CBI-016 | info | Pricing tier not ENTERPRISE | account workspaces API | CBI needs Enterprise | plan the tier change |
| CBI-017 | low | Egress not restricted | policy egress | Ingress-only posture; the exfiltration path stays open | `egress` |
| CBI-018 | medium | Policy / account config unreadable | API errors | Assessment incomplete: UNKNOWN, not "fine" | re-run with an account admin |
| CBI-019 | info | Cross-workspace access not restricted (L2+) | policy | Other workspaces can reach this one over serverless | cross-workspace allow-list (Beta) |
| CBI-020 | high on L0/L1, else medium | PATs with no expiry | token inventory | A leaked never-expiring token works until someone notices; with open ingress it works from anywhere too | revoke (`tokens-to-revoke.csv`); OAuth or short-lived tokens |
| CBI-021 | medium | `maxTokenLifetimeDays` unset or > 90 | workspace-conf | New tokens can be long-lived; the limit doesn't shorten existing ones | set a short maximum after compatibility testing |
| CBI-022 | medium | `users` group has CAN_USE on tokens (info: permissions never customised) | token permissions | Every user can mint a bearer credential that skips SSO/MFA on use | OAuth U2M for people, M2M / workload identity federation for automation; PAT use for an exception group |
| CBI-023 | low | PATs with empty `scopes` (= all APIs) | token inventory | A token made for one job carries all its owner's API authority | scoped PATs, auto-scoping (preview) |
| CBI-024 | info | PATs unused 90+ days | `last_used_day` | Risk without value | revoke (`tokens-to-revoke.csv`) |
| CBI-025 | medium | Verbose audit logging disabled in the window | `audit_visibility` | Visibility gap: later conclusions are incomplete | re-enable; treat the gap as unknown |
| CBI-026 | info | Suggested rollout pattern, while public access is still open | `public_browser_vs_api`, client families, tier | No VPN needed: B1–B4 (see `../../ingress-helper/references/rollout-patterns.md`) | pilot the pattern in dry-run |
| CBI-027 | info | Allow rule with no IP source in the API response | policy | Usually a console-only source (Partner platforms, app integrations) | review in the account console |
| CBI-028 | low | Specific API scopes (or read-only variants) allowed from any IP | policy | Pattern B2. Fine if intended | an owner per scope; short token lifetimes |
| CBI-029 | info | Every IP allowed to the UI / Apps / Lakebase only | policy | Pattern B1 recognised | pair with SSO + MFA |

CBI-020 to CBI-024 are the personal access token checks (`core/tokens.py`). They read the `--profile`
workspace only (workspace admin), and their urgency follows that workspace's ingress level.

## `tokens-to-revoke.csv`

One row per token worth reviewing (never expires, expires beyond the lifetime threshold, unused 90+
days, or no scopes), with its owner, dates, scopes, the reasons, and the
`databricks token-management delete <token_id>` command an owner would run. Token values are never
read (the API doesn't return them). **Nothing is revoked**: an owner decides each row, and a token used
by production automation needs its replacement in place first.

## Maturity

Assigned per workspace before findings, then L3 → **L4 Hardened** if the workspace has no
critical/high/medium findings.

```
PAS public access disabled                        → L3 Private-only
restrictive public block in ingress (enforced)    → L3 Enforced
restrictive public block in ingress_dry_run       → L2 Observing
enabled ALLOW IP access list                      → L1 Legacy perimeter
IP access lists not read for this workspace       → "CBI open, IP ACL unchecked" (L0 or L1)
otherwise                                         → L0 Open
```

The active block and "restrictive" are the same tests `ingress` uses when it inherits a policy's mode
(`core/acl._active_ingress`, `_block_restrictive`). **Open in effect:** a block that's restrictive on
paper but has an allow rule letting any IP reach all APIs for all users and/or service principals
(only *selected* identities narrow a rule; CBI-004 high)
doesn't count; it scores as if the public block were open.

## Known limits

- IP access lists and tokens are read per workspace, so only the `--profile` workspace has them; others
  score "IP ACL unchecked" and have no token findings until assessed with their own profile. The
  account console's Security → Token report is the cross-workspace token view.
- The audit log records the client IP Databricks saw. Behind NAT or a proxy that's the egress IP, which
  is exactly what CBI matches.
- `IpAccessDenied` covers IP ACL blocks only; CBI blocks are in `system.access.inbound_network`.
- Client families come from user-agent strings, which can be spoofed: a planning signal, not evidence.
- Threat-intel matching and published Databricks / partner ranges are `ingress`'s enrichment, not
  part of the posture score.
