# Security posture report: ingress (CBI) and personal access tokens

_Generated 2026-11-18 06:00:00 by `dbx-nwp-helper posture`. Lookback 30 days. Read-only assessment: no policy, assignment or setting was changed._

_Commands for a workspace other than the one the run used say `<profile-for-workspace-<id>>`: substitute that workspace's own profile._

## Summary

**high**: 5 · **medium**: 7 · **low**: 4 · **info**: 9

## Maturity by workspace

| Workspace | Name | Policy | Mode | Level | Why |
|---|---|---|---|---|---|
| 1001 | sandbox-dev | default-policy | open | L0 Open | No restrictive CBI public block and no enabled ALLOW IP access list |
| 1002 | analytics-prod | default-policy | open | L1 Legacy perimeter | IP access lists only; no restrictive CBI public block |
| 1003 | finance-prod | finance | dry_run | L2 Observing | `finance` restricts public access in dry-run only (log-only) |
| 1004 | ml-prod | ml | enforce | L3 Enforced | `ml` enforces a restricted public allow-list |

Levels: **L0 Open** → **L1 Legacy perimeter** (IP access lists) → **L2 Observing** (CBI dry-run) → **L3 Enforced** (CBI enforced, or private-only) → **L4 Hardened** (L3 with no high/medium findings).

## Findings

### [HIGH] CBI-001: Public ingress is unrestricted  ·  workspace `1001`

Governed by `default-policy` with public access FULL_ACCESS; no enabled ALLOW IP access list. 412 distinct public IPs / 88 principals seen.

**Recommendation:** Build an allow-list from observed traffic, apply it in DRY-RUN, close the dry-run gap, then enforce.

```bash
dbx-nwp-helper ingress --profile dev --lookback-days 90
```

Docs: https://docs.databricks.com/aws/en/security/network/front-end/context-based-ingress

### [HIGH] CBI-004: Overly broad allow CIDRs  ·  workspace `1002`

/0–/8: ['52.0.0.0/8']; /9–/15: []

**Recommendation:** Broad ranges often cover a whole cloud provider or ISP. Re-frame from observed traffic and keep only owned ranges.

```bash
dbx-nwp-helper ingress --profile analytics --lookback-days 90 --policy-framing optimal --enable-rdap
```

Docs: https://docs.databricks.com/aws/en/security/network/front-end/context-based-ingress

### [HIGH] CBI-009: Account console / account APIs reachable from any public IP  ·  workspace `account`

`account-policy` public access is FULL_ACCESS; 2 distinct public IPs reached account-level endpoints in the lookback.

**Recommendation:** Account-level CBI (Beta) protects the account console, account APIs and account-level Genie One. Derive the admin source IPs with `ingress --include-account-level` (propose-only; it doesn't write `account-policy`), then set `account-policy` in dry-run in the account console.

```bash
dbx-nwp-helper ingress --profile dev --lookback-days 90 --include-account-level --export .   # candidate IPs only; apply to account-policy in the console
```

Docs: https://docs.databricks.com/aws/en/security/network/front-end/manage-ingress-account

### [HIGH] CBI-012: Requests are being blocked by an enforced CBI policy  ·  workspace `1004`

57 denied requests from 1 source IP(s) in the lookback.

**Recommendation:** Triage: an attack being stopped, or a legitimate client being broken. Legitimate sources go back into the allow-list; `--deny-denied-ips` turns hostile ones into explicit deny rules.

```bash
dbx-nwp-helper ingress --profile ml --lookback-days 90
```

Docs: https://docs.databricks.com/aws/en/security/network/front-end/context-based-ingress

### [HIGH] CBI-020: PATs that never expire  ·  workspace `1002`

1 of 3 tokens have no expiry (owners: etl-owner@example.com). Public ingress is open, so each one is single-factor access from anywhere.

**Recommendation:** Replace with OAuth or short-lived tokens and revoke these (see `tokens-to-revoke.csv`; the account console's Security → Token report covers every workspace). A new lifetime maximum doesn't shorten existing tokens.

```bash
databricks token-management list --profile analytics -o json
```

Docs: https://docs.databricks.com/aws/en/admin/access-control/tokens

### [MEDIUM] CBI-002: Only legacy IP access lists protect this workspace  ·  workspace `1002`

1 enabled ALLOW list(s), 2 entries; CBI public access is open.

**Recommendation:** Migrate to CBI (Databricks recommends CBI as the single policy engine). `ingress` auto-detects the IP access lists and folds them in; for a verbatim migration use dbx-migrate-ip-acls (https://github.com/databrickslabs/migrate-ip-acls).

```bash
dbx-nwp-helper ingress --profile analytics --lookback-days 90
```

Docs: https://docs.databricks.com/aws/en/security/network/front-end/migrate-to-context-based-ingress

### [MEDIUM] CBI-003: CBI policy is dry-run only (not blocking)  ·  workspace `1003`

`finance` restricts public access in log-only mode. 1 source/identity/rule combinations would be blocked if enforced.

**Recommendation:** Close the gap: re-run `ingress` (it folds dry-run denials into the candidates by default), re-apply in dry-run, and enforce once the dry-run denials are clean.

```bash
dbx-nwp-helper ingress --profile finance --lookback-days 90 --policy-action add_to_existing --existing-policy-id finance
```

Docs: https://docs.databricks.com/aws/en/security/network/front-end/manage-ingress-workspace

### [MEDIUM] CBI-007: Front-end private access allows ALL registered endpoints  ·  workspace `1003`

PAS `pas-fin` (level ACCOUNT); CBI private_access is ALLOW_ALL_REGISTERED_ENDPOINTS (default).

**Recommendation:** Restrict private_access to this workspace's own endpoints: `ingress` recreates the PAS posture in a private_access block on AWS/GCP.

```bash
dbx-nwp-helper ingress --profile finance --lookback-days 90
```

Docs: https://docs.databricks.com/aws/en/security/network/front-end/front-end-private-connect#private-access

### [MEDIUM] CBI-013: Principals connect from many public networks  ·  workspace `account`

2 principals from >= 10 distinct public /24s (1 service principals). Top: 6f1c2a9e-0000-4000-8000-000000000001 (57), alex@example.com (14)

**Recommendation:** CIDR allow-lists won't hold for these. Use identity-scoped rules (all service principals / selected identities), the Partner platforms source, or a VPN/egress gateway for users.

```bash
dbx-nwp-helper ingress --profile dev --lookback-days 90 --scoping-mode ip_and_identity
```

Docs: https://docs.databricks.com/aws/en/security/network/front-end/context-based-ingress

### [MEDIUM] CBI-021: No short maximum lifetime for new PATs  ·  workspace `1002`

maxTokenLifetimeDays = unset (flagged above 90).

**Recommendation:** Set a maximum lifetime your integrations can sustain (one or seven days is a useful start to evaluate). Existing tokens keep their expiry, so revoke old ones explicitly.

```bash
databricks workspace-conf set-status --profile analytics --json '{"maxTokenLifetimeDays":"7"}'   # a setting change: only after explicit approval
```

Docs: https://docs.databricks.com/aws/en/admin/access-control/tokens

### [MEDIUM] CBI-022: Every user may create and use PATs  ·  workspace `1002`

The `users` group has CAN_USE on tokens.

**Recommendation:** Move people to OAuth U2M (browser sign-in) and automation to OAuth M2M or workload identity federation; then grant PAT use only to an approved exception group or specific service principals.

Docs: https://docs.databricks.com/aws/en/security/auth/api-access-permissions

### [MEDIUM] CBI-025: Verbose audit logging was turned off in the lookback window  ·  workspace `1002`

Last disabled at 2026-10-30 14:02:11. Events after that may be missing, so traffic-based conclusions have a gap.

**Recommendation:** Confirm who changed it and why, turn it back on, and treat the gap as unknown, not clean.

Docs: https://docs.databricks.com/aws/en/admin/account-settings/verbose-logs

### [LOW] CBI-017: Serverless egress is unrestricted  ·  workspace `1001`

Ingress-only posture: serverless workloads can reach any destination.

**Recommendation:** Pair CBI with serverless egress control.

```bash
dbx-nwp-helper egress --profile dev --lookback-days 90
```

Docs: https://docs.databricks.com/aws/en/security/network/serverless-network-security/network-policies

### [LOW] CBI-017: Serverless egress is unrestricted  ·  workspace `1002`

Ingress-only posture: serverless workloads can reach any destination.

**Recommendation:** Pair CBI with serverless egress control.

```bash
dbx-nwp-helper egress --profile analytics --lookback-days 90
```

Docs: https://docs.databricks.com/aws/en/security/network/serverless-network-security/network-policies

### [LOW] CBI-017: Serverless egress is unrestricted  ·  workspace `1003`

Ingress-only posture: serverless workloads can reach any destination.

**Recommendation:** Pair CBI with serverless egress control.

```bash
dbx-nwp-helper egress --profile finance --lookback-days 90
```

Docs: https://docs.databricks.com/aws/en/security/network/serverless-network-security/network-policies

### [LOW] CBI-023: PATs without API scopes  ·  workspace `1002`

1 of 3 tokens can call every API family (an empty scope list means all APIs, not none).

**Recommendation:** Scope each token to the API families its job needs, or enable PAT auto-scoping (preview).

Docs: https://docs.databricks.com/aws/en/dev-tools/auth/pat

### [INFO] CBI-006: Workspace relies on the account default policy  ·  workspace `1001`

No explicit network-policy assignment; `default-policy` governs this workspace.

**Recommendation:** Databricks advises against editing default-policy ingress. Create a named policy and assign it.

Docs: https://docs.databricks.com/aws/en/security/network/front-end/manage-ingress-workspace

### [INFO] CBI-006: Workspace relies on the account default policy  ·  workspace `1002`

No explicit network-policy assignment; `default-policy` governs this workspace.

**Recommendation:** Databricks advises against editing default-policy ingress. Create a named policy and assign it.

Docs: https://docs.databricks.com/aws/en/security/network/front-end/manage-ingress-workspace

### [INFO] CBI-014: SaaS / BI partner clients seen on public IPs  ·  workspace `account`

Client families: Power BI, Tableau.

**Recommendation:** Prefer the managed Partner platforms source (Databricks keeps those IP lists current) over hand-kept CIDRs; `ingress` labels observed partner ranges too.

Docs: https://docs.databricks.com/aws/en/security/network/front-end/partner-platforms

### [INFO] CBI-015: IPv6 client traffic observed  ·  workspace `1001`

9 distinct IPv6 sources. CBI public rules are IPv4-only.

**Recommendation:** Identify these clients before enforcing (they can't be allow-listed by CIDR).

Docs: https://docs.databricks.com/aws/en/security/network/front-end/context-based-ingress

### [INFO] CBI-019: Cross-workspace (serverless) ingress not restricted  ·  workspace `1003`

cross_workspace_access is unset (compatibility mode).

**Recommendation:** If other workspaces shouldn't reach this one over serverless, add a cross-workspace allow-list (Beta).

Docs: https://docs.databricks.com/aws/en/security/network/front-end/cross-workspace-access

### [INFO] CBI-019: Cross-workspace (serverless) ingress not restricted  ·  workspace `1004`

cross_workspace_access is unset (compatibility mode).

**Recommendation:** If other workspaces shouldn't reach this one over serverless, add a cross-workspace allow-list (Beta).

Docs: https://docs.databricks.com/aws/en/security/network/front-end/cross-workspace-access

### [INFO] CBI-024: Unused PATs  ·  workspace `1002`

1 tokens not used in 90+ days.

**Recommendation:** Revoke them (`tokens-to-revoke.csv`); unused credentials carry risk and no value.

Docs: https://docs.databricks.com/aws/en/admin/access-control/tokens

### [INFO] CBI-026: Suggested CBI rollout pattern  ·  workspace `1001`

**Browser yes, remote APIs no**: only 7 identities use programmatic clients from public IPs (88.0% of public traffic is browser). Allow Workspace UI · all users · all public IPs, plus API rules for the named identities only

**Recommendation:** (1) **Narrow partner exceptions**: use the Partner platforms source for the hosted BI tools seen, instead of opening API access to the internet. (2) Pilot on one workspace in dry-run over a full business cycle before enforcing; use time-boxed selected-identity rules for occasional production access.

```bash
dbx-nwp-helper ingress --profile dev --lookback-days 90
```

Docs: https://docs.databricks.com/aws/en/security/network/front-end/manage-ingress-workspace

### [INFO] CBI-026: Suggested CBI rollout pattern  ·  workspace `1002`

**Allow only the API families you need**: 140 identities call APIs from public IPs. Use API allow rules with `IN <scopes>` (e.g. `sql`) rather than a general API rule

**Recommendation:** (1) **Narrow partner exceptions**: use the Partner platforms source for the hosted BI tools seen, instead of opening API access to the internet. (2) Pilot on one workspace in dry-run over a full business cycle before enforcing; use time-boxed selected-identity rules for occasional production access.

```bash
dbx-nwp-helper ingress --profile analytics --lookback-days 90
```

Docs: https://docs.databricks.com/aws/en/security/network/front-end/manage-ingress-workspace

## Next steps

Every command above is propose-only (writes nothing). Add `--create-policy` (dry-run by default) only after reviewing the preview, and `--policy-mode enforce` only once dry-run denials are clean. `ingress --review-pack <dir>` turns a proposal into a test plan and review sheet for the owners. `tokens-to-revoke.csv` lists the tokens worth revoking, with the command an owner would run; nothing was revoked.
