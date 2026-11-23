---
name: posture-helper
description: Assess a Databricks account's security posture with the dbx-nwp-helper CLI's read-only `posture` command — where each workspace stands on Context-Based Ingress (CBI), scored L0 Open to L4 Hardened, and which personal access tokens (PATs) should be revoked. Use when the user asks "what does my security posture look like", "how exposed are my workspaces", "are we ready for CBI", "what would break if we enforce", "which tokens should we revoke", wants a CBI readiness or maturity report, or suspects a leaked PAT or OAuth secret. Reads network policies, assignments, Private Access Settings, IP access lists, the PAT inventory and token settings, and system.access audit / inbound_network traffic (direct, a one-scan staged rollup, or an incrementally persisted rollup for large accounts); writes report.md, findings.csv, maturity.csv, tokens-to-revoke.csv and posture.json; and hands every ingress fix to `dbx-nwp-helper ingress` as a propose-only command. Never changes a policy, setting or token.
---

# Security posture (`posture`)

Answer *"where do we stand, and what do we do next?"* before anyone writes a policy: each workspace's
ingress (CBI) posture, and the personal access tokens worth revoking. A stolen token is dangerous when
it **still works** (no expiry), **can do a lot** (no scopes) and **works from anywhere** (open
ingress); `posture` checks all three. Fixes go to `dbx-nwp-helper ingress` (the `ingress-helper`
skill) and to the token owners; this command only reads.

## Setup

Same as the other commands: `uv sync`, then `uv run dbx-nwp-helper posture …`. Pass a **workspace**
`--profile` and an **account admin** via `--account-id` (+ `--account-profile` if needed; see
`docs/account-admin-setup.md`) — the network policies, assignments and Private Access Settings are
account-level reads. The token checks need workspace admin on the `--profile` workspace.

```bash
uv run dbx-nwp-helper posture --profile <workspace-profile> --account-id <id> \
  [--account-profile <account-admin>] [--workspace-id <id> ...] [--lookback-days 90] [--out posture]
```

## Safety — read first

- **Read-only.** `list`/`get` calls and `SELECT` queries; no policy, assignment, setting or token is
  changed. Like `ingress`, it reuses or creates the small `dbx-nwp-helper` SQL warehouse unless
  `--warehouse-http-path` (or `--skip-traffic`) is passed. `--stage-schema` / `--uc-schema` write only
  the rollup table named there, and only when the user asks for them.
- **Every `next_step` is a suggestion.** Present it and let the user run it. Commands that write
  (`--create-policy`, a token setting) are marked *only after explicit approval*. Enforce mode can lock
  users (and admins) out.
- **`tokens-to-revoke.csv` never revokes.** It lists each token's owner, reasons and the
  `databricks token-management delete` command; an owner decides, and production automation needs a
  replacement credential first. Token values are never read (the API doesn't return them); never ask a
  user to paste one.
- **Don't over-claim.** When a check couldn't run it says UNKNOWN (CBI-018, "IP ACL unchecked",
  "Collection gaps"). An empty result is "no matching events in this window", not proof.
- **Observed traffic is not trust** — the audit log can contain an attacker.
- IPs, emails and principal names in the output are customer-confidential.

## Traffic checks on large accounts — pick one

The audit checks read one **rollup** of `system.access.audit` (events grouped by day, workspace,
source IP, principal, client family and outcome). The rollup is the same however it's built, so the
results don't depend on the choice; only the cost does.

| Option | Audit scans | Use when |
|---|---|---|
| *(default)* direct | one per check (8), run `--parallel 4` at a time | small/medium accounts, no schema to write to |
| `--stage-schema catalog.schema` | **one**, into a temporary table dropped at the end | a large account, a one-off assessment |
| `--uc-schema catalog.schema` | one the first time; later runs read only the newest days (`dbx_nwp_posture_daily`, kept incrementally like `dbx_nwp_ingress_daily`) | large accounts assessed repeatedly; `--refresh-persisted` rebuilds |
| `--skip-traffic` | none | no warehouse at all: configuration-only scoring |

`--workspace-id` (repeatable) narrows both the account reads and the traffic checks. `--skip-tokens`
skips the token checks.

## Ingress maturity

Each workspace's level comes from its effective network policy (assigned, or `default-policy`), its
Private Access Settings and — for the `--profile` workspace — its IP access lists. Other workspaces
score "IP ACL unchecked" until assessed with their own profile.

| Level | Meaning | Typical next move |
|---|---|---|
| **L0 Open** | No restrictive CBI public block and no enabled ALLOW IP access list | `ingress` propose-only |
| **L1 Legacy perimeter** | IP access lists only | `ingress` (folds the ACLs in) or `dbx-migrate-ip-acls` verbatim |
| **L2 Observing** | CBI restricts public access in **dry-run** | close the dry-run gap, then enforce |
| **L3 Enforced** | Public allow-list enforced, or the PAS blocks public access | fix the remaining medium/high findings |
| **L4 Hardened** | L3 with no high/medium findings | watch enforced denials; add `egress` |

"Restrictive" and the active block are the same tests `ingress` uses for mode inheritance; a block
that lets any IP call all workspace APIs as anyone is **open in effect** and scores as open. Checks,
severities and limits: `references/posture-checks.md`; CBI concepts to explain them:
`../ingress-helper/references/cbi-reference.md`; the no-VPN patterns CBI-026 suggests:
`../ingress-helper/references/rollout-patterns.md`.

Explaining a result: open with evidence coverage (the audit window and any verbose-audit gap,
CBI-025), then the maturity table, then findings highest-severity first, each as *what we saw → why it
matters → what to do next*.
- High principal spread or SaaS client families → CIDR rules alone won't hold: identity-scoped rules
  and the managed **Partner platforms** source.
- `workspace_id = '0'` rows are **account-level** (console / account APIs), governed by the Beta
  `account-policy`; a workspace policy doesn't cover them.
- Classic compute without PrivateLink, and serverless calls to the same workspace, aren't affected by
  public source rules; don't flag their traffic as at-risk.

## Tokens

CBI-020 to CBI-024 (see `references/posture-checks.md`): never-expiring PATs (high when the workspace's
public ingress is open: single-factor access from anywhere), no short maximum lifetime, PATs open to
every user, unscoped tokens and unused tokens. Lead with never-expiring tokens on an L0/L1 workspace —
credentials that work forever, from anywhere. A new lifetime maximum doesn't shorten existing tokens,
so the fix is revoke + replace (OAuth U2M for people, OAuth M2M / workload identity federation for
automation). Tokens are read for the `--profile` workspace; the account console's **Security → Token
report** covers every workspace.

## Genie agent (`genie-setup`)

For questions in plain English ("which tokens should we revoke?", "what would break if we enforced?"),
build a Genie agent over the posture tables:

```bash
uv run dbx-nwp-helper posture --profile <ws> --account-id <id> --uc-schema security.posture   # once, then on a schedule
uv run dbx-nwp-helper genie-setup --profile <ws> --uc-schema security.posture [--warehouse-http-path …] [--title …]
```

`posture --uc-schema` appends each run to `dbx_nwp_posture_workspaces`, `dbx_nwp_posture_findings` and
`dbx_nwp_posture_tokens` (and keeps the `dbx_nwp_posture_daily` rollup), so answers stay current and
trends work. `genie-setup` **writes**: it creates or replaces the `*_latest` views and
`dbx_nwp_inbound_events` in that schema, and creates the agent (or updates the one with the same
title). Ask before running it; it refuses non-interactive runs without `--yes`, and `--print-only
<file>` writes the agent definition and changes nothing. It also picks up the `ingress` / `egress`
tables when they were persisted to the same schema. It never shares the agent: share it (CAN RUN) by
hand, and grant viewers SELECT on the schema, because Genie runs queries as the person asking. The
agent answers questions; it doesn't change policies or revoke tokens.

## References

- `references/posture-checks.md` — every check, the maturity rules, `tokens-to-revoke.csv`, known limits.
- `../ingress-helper/references/cbi-reference.md` — CBI concepts, interactions and limits.
- `../ingress-helper/references/rollout-patterns.md` — the no-VPN patterns CBI-026 suggests.
- `../ingress-helper/references/incident-mode.md` — a suspected credential leak: contain first.
- `../ingress-helper/references/manual-checks.md` — the same reads with the Databricks CLI.
- `docs/examples/posture/report.md` — sample output on a synthetic 4-workspace account.
- `src/dbx_nwp_helper/genie/` — the agent's instructions, trusted queries and sample questions.
