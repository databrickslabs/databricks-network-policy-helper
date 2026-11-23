# CBI security posture report

_Generated 2026-11-18 06:00:00 by cbi-posture v0.3.0. Lookback 30 days. Read-only assessment; nothing was changed._

## Summary

**high**: 6 · **medium**: 9 · **low**: 6 · **info**: 12

## Maturity by workspace

| Workspace | Name | Policy | Mode | Level | Why |
|---|---|---|---|---|---|
| 1001 | sandbox-dev | default-policy | open | L0 Open | No restrictive CBI public block and no enabled allow IP access list |
| 1002 | analytics-prod | default-policy | open | L1 Legacy perimeter | IP access lists only; no restrictive CBI public block |
| 1003 | finance-prod | finance | dry_run | L2 Observing | `finance` restricts public access in dry-run only (log-only) |
| 1004 | ml-prod | ml | enforce | L3 Enforced | `ml` enforces a restricted public allow-list |

Levels: **L0 Open** → **L1 Legacy perimeter** (IP ACLs) → **L2 Observing** (CBI dry-run) → **L3 Enforced** (CBI enforced, or private-only) → **L4 Hardened** (L3 with no high/medium findings).

## Defense-in-depth coverage

CBI is the **Limit** layer: it decides *where* a valid credential works. A stolen token is worth less when it also expires soon (Expire), can call little (Scope), and its misuse is noticed (Detect).

| Layer | High | Medium | Low/Info |
|---|---|---|---|
| Avoid | 0 | 1 | 0 |
| Expire | 2 | 3 | 4 |
| Scope | 0 | 0 | 3 |
| Limit | 3 | 4 | 11 |
| Detect | 0 | 1 | 0 |
| Respond | 1 | 0 | 0 |

Checks for layers this tool cannot see (SSO/MFA, OAuth adoption, catalog bindings, UC secrets, admin counts) are covered by Governance Hub security posture and the Security Analysis Tool.

## Findings

### [HIGH] CBI-001: Public ingress is unrestricted  ·  workspace `1001`  ·  Limit

Governed by `default-policy` with public access FULL_ACCESS; no enabled allow IP access list. 412 distinct public IPs / 88 principals seen.

**Recommendation:** Generate an allow-list from observed traffic, apply it in DRY-RUN, review `dry_run_would_block`, then enforce.

```bash
uv run dbx-nwp-helper ingress --profile dev --lookback-days 90
```

Docs: https://docs.databricks.com/aws/en/security/network/front-end/context-based-ingress

### [HIGH] CBI-004: Overly broad allow CIDRs  ·  workspace `1002`  ·  Limit

/0–/8: ['52.0.0.0/8']; /9–/15: []

**Recommendation:** Broad ranges often cover a whole cloud provider or ISP. Re-frame from observed traffic (`--policy-framing minimal|optimal`) and keep only owned ranges.

```bash
uv run dbx-nwp-helper ingress --profile analytics --lookback-days 90 --policy-framing optimal --enable-rdap
```

Docs: https://docs.databricks.com/aws/en/security/network/front-end/context-based-ingress

### [HIGH] CBI-009: Account console / account APIs reachable from any public IP  ·  workspace `account`  ·  Limit

`account-policy` public access is FULL_ACCESS; 2 distinct public IPs reached account-level endpoints in the lookback.

**Recommendation:** Account-level CBI (Beta) protects the account console, account APIs and account-level Genie One. Derive the admin source IPs with the helper (propose-only; it reads workspace_id=0 rows but does not write `account-policy`), then configure `account-policy` in dry-run in the account console (Security → Networking → account level policies).

```bash
uv run dbx-nwp-helper ingress --profile dev --lookback-days 90 --include-account-level --export .   # candidate IPs only; apply to account-policy in the console
```

Docs: https://docs.databricks.com/aws/en/security/network/front-end/manage-ingress-account

### [HIGH] CBI-012: Requests are being blocked by an enforced CBI policy  ·  workspace `1004`  ·  Respond

57 denied requests across 1 day/rule buckets in the lookback.

**Recommendation:** Triage with `enforced_denials`; legitimate sources go back into the allow-list (`--deny-denied-ips` is the opposite: turning them into explicit deny rules).

```bash
uv run dbx-nwp-helper ingress --profile ml --lookback-days 90
```

Docs: https://docs.databricks.com/aws/en/security/network/front-end/context-based-ingress

### [HIGH] CBI-020: PATs that never expire  ·  workspace `1001`  ·  Expire

1 of 2 tokens have no expiry (owners: etl-owner@example.com). Public ingress is open, so each one is single-factor access from anywhere.

**Recommendation:** Replace with OAuth or short-lived tokens and revoke these explicitly (account console → Security → Token report covers every workspace). A new lifetime maximum does not shorten existing tokens.

```bash
databricks token-management list --profile dev -o json
```

Docs: https://docs.databricks.com/aws/en/admin/access-control/tokens

### [HIGH] CBI-020: PATs that never expire  ·  workspace `1002`  ·  Expire

1 of 2 tokens have no expiry (owners: etl-owner@example.com). Public ingress is open, so each one is single-factor access from anywhere.

**Recommendation:** Replace with OAuth or short-lived tokens and revoke these explicitly (account console → Security → Token report covers every workspace). A new lifetime maximum does not shorten existing tokens.

```bash
databricks token-management list --profile analytics -o json
```

Docs: https://docs.databricks.com/aws/en/admin/access-control/tokens

### [MEDIUM] CBI-002: Only legacy IP access lists protect this workspace  ·  workspace `1002`  ·  Limit

1 enabled ALLOW list(s), 2 entries; CBI public access is open.

**Recommendation:** Migrate to CBI (Databricks recommends CBI as the single policy engine). The helper auto-detects the IP ACLs and folds them in with observed traffic; for a verbatim migration use dbx-migrate-ip-acls (https://github.com/databrickslabs/migrate-ip-acls).

```bash
uv run dbx-nwp-helper ingress --profile analytics --lookback-days 90
```

Docs: https://docs.databricks.com/aws/en/security/network/front-end/migrate-to-context-based-ingress

### [MEDIUM] CBI-003: CBI policy is dry-run only (not blocking)  ·  workspace `1003`  ·  Limit

`finance` restricts public access in log-only mode. 1 source/identity/rule combinations would be blocked if enforced.

**Recommendation:** Close the gap: re-run the helper (it folds dry-run denials into the candidate set by default), re-apply in dry-run, and switch to enforce once `dry_run_would_block` is clean.

```bash
uv run dbx-nwp-helper ingress --profile finance --lookback-days 90 --policy-action add_to_existing --existing-policy-id finance
```

Docs: https://docs.databricks.com/aws/en/security/network/front-end/manage-ingress-workspace

### [MEDIUM] CBI-007: Front-end private access allows ALL registered endpoints  ·  workspace `1003`  ·  Limit

PAS `pas-fin` (level ACCOUNT); CBI private_access is ALLOW_ALL_REGISTERED_ENDPOINTS (default). Any endpoint registered to the account can reach this workspace if the PAS allows it.

**Recommendation:** Restrict private_access to the workspace's own endpoints (the helper recreates the PAS posture in a private_access block on AWS/GCP).

```bash
uv run dbx-nwp-helper ingress --profile finance --lookback-days 90
```

Docs: https://docs.databricks.com/aws/en/security/network/front-end/front-end-private-connect#private-access

### [MEDIUM] CBI-013: Principals connect from many public networks  ·  workspace `account`  ·  Limit

2 principals from >= 10 distinct public /24s (1 service principals). Top: 6f1c2a9e-0000-4000-8000-000000000001 (57), alex@example.com (14)

**Recommendation:** CIDR allow-lists will not hold for these. Use identity-scoped rules (all service principals / selected identities) or a VPN/egress gateway for users.

```bash
uv run dbx-nwp-helper ingress --profile dev --lookback-days 90 --scoping-mode ip_and_identity
```

Docs: https://docs.databricks.com/aws/en/security/network/front-end/context-based-ingress

### [MEDIUM] CBI-020: PATs that never expire  ·  workspace `1003`  ·  Expire

1 of 2 tokens have no expiry (owners: etl-owner@example.com). CBI limits where they work, but not for how long.

**Recommendation:** Replace with OAuth or short-lived tokens and revoke these explicitly (account console → Security → Token report covers every workspace). A new lifetime maximum does not shorten existing tokens.

```bash
databricks token-management list --profile finance -o json
```

Docs: https://docs.databricks.com/aws/en/admin/access-control/tokens

### [MEDIUM] CBI-021: No short maximum lifetime for new PATs  ·  workspace `1001`  ·  Expire

maxTokenLifetimeDays = unset (flag above 90).

**Recommendation:** Set a maximum lifetime your integrations can sustain (one or seven days is a useful starting point to evaluate). Existing tokens keep their expiry, so revoke old ones explicitly.

```bash
databricks workspace-conf set-status --profile dev --json '{"maxTokenLifetimeDays":"7"}'   # after compatibility testing
```

Docs: https://docs.databricks.com/aws/en/admin/access-control/tokens

### [MEDIUM] CBI-021: No short maximum lifetime for new PATs  ·  workspace `1002`  ·  Expire

maxTokenLifetimeDays = unset (flag above 90).

**Recommendation:** Set a maximum lifetime your integrations can sustain (one or seven days is a useful starting point to evaluate). Existing tokens keep their expiry, so revoke old ones explicitly.

```bash
databricks workspace-conf set-status --profile analytics --json '{"maxTokenLifetimeDays":"7"}'   # after compatibility testing
```

Docs: https://docs.databricks.com/aws/en/admin/access-control/tokens

### [MEDIUM] CBI-022: Every user may create and use PATs  ·  workspace `1001`  ·  Avoid

The `users` group has CAN_USE on tokens.

**Recommendation:** Move people to OAuth U2M (browser sign-in) and automation to workload identity federation or OAuth M2M; then grant PAT use only to an approved exception group or specific service principals.

Docs: https://docs.databricks.com/aws/en/security/auth/api-access-permissions

### [MEDIUM] CBI-025: Verbose audit logging was turned off in the lookback window  ·  workspace `1002`  ·  Detect

Last disabled at 2026-10-30 14:02:11. Notebook/command-level events after that point may be missing, so traffic-based conclusions have a gap.

**Recommendation:** Confirm who changed it and why, turn it back on, and treat the gap as unknown rather than clean.

Docs: https://docs.databricks.com/aws/en/admin/account-settings/verbose-logs

### [LOW] CBI-017: Serverless egress is unrestricted  ·  workspace `1001`  ·  Limit

Ingress-only posture: serverless workloads can reach any destination.

**Recommendation:** Pair CBI with serverless egress control (the helper's `egress` command).

```bash
uv run dbx-nwp-helper egress --profile dev --lookback-days 90
```

Docs: https://docs.databricks.com/aws/en/security/network/serverless-network-security/network-policies

### [LOW] CBI-017: Serverless egress is unrestricted  ·  workspace `1002`  ·  Limit

Ingress-only posture: serverless workloads can reach any destination.

**Recommendation:** Pair CBI with serverless egress control (the helper's `egress` command).

```bash
uv run dbx-nwp-helper egress --profile analytics --lookback-days 90
```

Docs: https://docs.databricks.com/aws/en/security/network/serverless-network-security/network-policies

### [LOW] CBI-017: Serverless egress is unrestricted  ·  workspace `1003`  ·  Limit

Ingress-only posture: serverless workloads can reach any destination.

**Recommendation:** Pair CBI with serverless egress control (the helper's `egress` command).

```bash
uv run dbx-nwp-helper egress --profile finance --lookback-days 90
```

Docs: https://docs.databricks.com/aws/en/security/network/serverless-network-security/network-policies

### [LOW] CBI-023: PATs without API scopes  ·  workspace `1001`  ·  Scope

1 of 2 tokens can call every API family (an empty scope list means all APIs, not none).

**Recommendation:** Scope each token to the API families its job needs, or enable PAT auto-scoping (preview) so long-lived tokens are narrowed to what they actually use after 30 days. Exercise rare and failover paths during the observation window.

Docs: https://docs.databricks.com/aws/en/dev-tools/auth/pat

### [LOW] CBI-023: PATs without API scopes  ·  workspace `1002`  ·  Scope

1 of 2 tokens can call every API family (an empty scope list means all APIs, not none).

**Recommendation:** Scope each token to the API families its job needs, or enable PAT auto-scoping (preview) so long-lived tokens are narrowed to what they actually use after 30 days. Exercise rare and failover paths during the observation window.

Docs: https://docs.databricks.com/aws/en/dev-tools/auth/pat

### [LOW] CBI-023: PATs without API scopes  ·  workspace `1003`  ·  Scope

1 of 2 tokens can call every API family (an empty scope list means all APIs, not none).

**Recommendation:** Scope each token to the API families its job needs, or enable PAT auto-scoping (preview) so long-lived tokens are narrowed to what they actually use after 30 days. Exercise rare and failover paths during the observation window.

Docs: https://docs.databricks.com/aws/en/dev-tools/auth/pat

### [INFO] CBI-006: Workspace relies on the account default policy  ·  workspace `1001`  ·  Limit

No explicit network-policy assignment; `default-policy` governs this workspace.

**Recommendation:** Databricks advises against editing default-policy ingress. Create a named policy and attach it to specific workspaces.

Docs: https://docs.databricks.com/aws/en/security/network/front-end/manage-ingress-workspace

### [INFO] CBI-006: Workspace relies on the account default policy  ·  workspace `1002`  ·  Limit

No explicit network-policy assignment; `default-policy` governs this workspace.

**Recommendation:** Databricks advises against editing default-policy ingress. Create a named policy and attach it to specific workspaces.

Docs: https://docs.databricks.com/aws/en/security/network/front-end/manage-ingress-workspace

### [INFO] CBI-014: SaaS / BI partner clients detected on public IPs  ·  workspace `account`  ·  Limit

Client families: Power BI, Tableau.

**Recommendation:** Prefer the managed Partner platforms source (Databricks keeps these IP lists current) over hand-maintained CIDRs.

Docs: https://docs.databricks.com/aws/en/security/network/front-end/partner-platforms

### [INFO] CBI-015: IPv6 client traffic observed  ·  workspace `1001`  ·  Limit

9 distinct IPv6 sources. CBI public rules are IPv4-only.

**Recommendation:** Identify these clients before enforcing (they cannot be allow-listed by CIDR).

Docs: https://docs.databricks.com/aws/en/security/network/front-end/context-based-ingress

### [INFO] CBI-019: Cross-workspace (serverless) ingress not restricted  ·  workspace `1003`  ·  Limit

cross_workspace_access is unset (compatibility mode).

**Recommendation:** If other workspaces should not reach this one over serverless, add a cross-workspace allow-list (Beta).

Docs: https://docs.databricks.com/aws/en/security/network/front-end/cross-workspace-access

### [INFO] CBI-019: Cross-workspace (serverless) ingress not restricted  ·  workspace `1004`  ·  Limit

cross_workspace_access is unset (compatibility mode).

**Recommendation:** If other workspaces should not reach this one over serverless, add a cross-workspace allow-list (Beta).

Docs: https://docs.databricks.com/aws/en/security/network/front-end/cross-workspace-access

### [INFO] CBI-024: Unused PATs  ·  workspace `1001`  ·  Expire

1 tokens not used in 90+ days.

**Recommendation:** Revoke them; unused credentials carry risk and no value.

Docs: https://docs.databricks.com/aws/en/admin/access-control/tokens

### [INFO] CBI-024: Unused PATs  ·  workspace `1002`  ·  Expire

1 tokens not used in 90+ days.

**Recommendation:** Revoke them; unused credentials carry risk and no value.

Docs: https://docs.databricks.com/aws/en/admin/access-control/tokens

### [INFO] CBI-024: Unused PATs  ·  workspace `1003`  ·  Expire

1 tokens not used in 90+ days.

**Recommendation:** Revoke them; unused credentials carry risk and no value.

Docs: https://docs.databricks.com/aws/en/admin/access-control/tokens

### [INFO] CBI-024: Unused PATs  ·  workspace `1004`  ·  Expire

1 tokens not used in 90+ days.

**Recommendation:** Revoke them; unused credentials carry risk and no value.

Docs: https://docs.databricks.com/aws/en/admin/access-control/tokens

### [INFO] CBI-026: Suggested CBI rollout pattern  ·  workspace `1001`  ·  Limit

**Browser yes, remote APIs no**: only 7 identities use programmatic clients from public IPs (88.0% of public traffic is browser). Allow Workspace UI · all users · all public IPs, plus API rules for the named service principals/identities only

**Recommendation:** (1) **Narrow partner exceptions**: allow the Partner platforms source for the hosted BI tools seen, instead of opening API access to the internet. (2) Pilot on one workspace in dry-run over a full business cycle before enforcing; use time-boxed selected-identity rules for occasional production access.

```bash
uv run dbx-nwp-helper ingress --profile dev --lookback-days 90
```

Docs: https://docs.databricks.com/aws/en/security/network/front-end/manage-ingress-workspace

### [INFO] CBI-026: Suggested CBI rollout pattern  ·  workspace `1002`  ·  Limit

**Allow only the API families you need**: 140 identities call APIs from public IPs. Use API allow rules with `IN <scopes>` (e.g. `sql`) rather than a general public API rule

**Recommendation:** (1) **Narrow partner exceptions**: allow the Partner platforms source for the hosted BI tools seen, instead of opening API access to the internet. (2) Pilot on one workspace in dry-run over a full business cycle before enforcing; use time-boxed selected-identity rules for occasional production access.

```bash
uv run dbx-nwp-helper ingress --profile analytics --lookback-days 90
```

Docs: https://docs.databricks.com/aws/en/security/network/front-end/manage-ingress-workspace

## Next steps

All remediation runs through **databricks-network-policy-helper** (https://github.com/databrickslabs/databricks-network-policy-helper). Every command above is propose-only (writes nothing). Add `--create-policy` (dry-run by default) only after reviewing the preview, and `--policy-mode enforce` only after dry-run denials are clean.
