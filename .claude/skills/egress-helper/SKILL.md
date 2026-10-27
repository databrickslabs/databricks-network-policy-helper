---
name: egress-helper
description: Propose and apply a Databricks serverless egress (SEG) network-policy allow-list from observed outbound traffic in system.access.outbound_network, using the dbx-nwp-helper CLI. Use when the user wants to build/suggest an egress policy, allow-list outbound destinations, control serverless egress, turn dry-run egress denials into an allow-list, or block known-bad domains. Runs `dbx-nwp-helper egress` (or the guided wizard), which classifies observed destinations into storage (S3/GCS/Azure) and internet FQDNs, shows what it would allow for review, and can create the egress policy (dry-run or enforce) and optionally block threat-intel domains.
---

# Egress Policy Helper (serverless egress / SEG)

Builds a Databricks **account network policy egress** allow-list from observed outbound traffic. The
engine is the **`dbx-nwp-helper`** CLI (this repo): `dbx-nwp-helper egress` or the guided wizard.

For **ingress** (source-IP allow-lists) use `ingress-helper`. To end up with a combined ingress +
egress policy, run one direction with `--policy-action create_new`, then the other with
`--policy-action add_to_existing --existing-policy-id <id>` pointed at the policy the first created.

## Setup

`uv sync`, then `uv run dbx-nwp-helper egress …`. Auth is the SDK's unified auth (`--profile` or
`DATABRICKS_*`); the CLI queries the system tables through a SQL warehouse (`--warehouse-http-path`,
else it reuses/creates a serverless `dbx-nwp-helper` warehouse). Creating/assigning a policy needs an
**account admin** — pass `--account-id` with account-admin credentials (see
`docs/account-admin-setup.md`).

## The dry-run-observe loop (important)

`system.access.outbound_network` records only **denied** egress — including **`DRY_RUN_DENIAL`**
(would-be-denials under a dry-run policy). So the workflow is:
1. Stand up an egress policy in **dry_run** (RESTRICTED_ACCESS, log-only) — blocks nothing.
2. Let it observe; the table logs every destination that *would* be denied = your egress footprint.
3. Run `dbx-nwp-helper egress` to turn those destinations into a real allow-list.

If the table is empty, no egress policy is logging yet — start with step 1.

## What it does

1. Reads `outbound_network` over `--lookback-days` (optional `--source-type-filter`).
2. Classifies each destination by host shape:
   - **S3** `<bucket>.s3.<region>.amazonaws.com` → storage rule (bucket + region from the host).
   - **GCS** `[<bucket>.]storage.googleapis.com` → storage rule.
   - **Azure** `<account>.<blob|dfs|file>.core.windows.net` → storage rule (account + service).
   - Bare `s3.<region>.amazonaws.com` (no bucket) → **skipped** (too broad to be a useful rule).
   - Everything else → **internet FQDN** allow rule.
3. Optional cloud-owner lookup on internet FQDNs (`--enable-rdap`, on by default) — resolve the IP
   (audit-log `rdata` first, else DNS) and match it **offline** against the AWS/GCP/Azure/Databricks
   published ranges. Shows `resolved_ip` + `hosting_owner` (the cloud, "non-cloud / unknown", or
   `DNS_RESOLUTION_FAILED` — DNS is resolved locally on the CLI host, so this is a local
   resolution failure, not the workspace's egress control). Context only.
4. **Review tables** (internet + per-cloud storage) — confirm before creating. In interactive runs
   a pre-checked selector (on by default; `--no-select-rules` to skip, or `--yes` non-interactively)
   lets you curate destinations before the policy is built, as **two separate prompts** — one for
   internet FQDNs, one for storage destinations (S3 / GCS / Azure).
5. Optional **threat-intel domain blocking** (`--block-threat-domains`: off / matched_only / all) →
   `blocked_internet_destinations` (FQDN-only, enforced in any mode, takes precedence over allows).
   When not `off`, an interactive run then asks which feeds to use (`c2intel` keyless default;
   abuse.ch `threatfox`/`urlhaus` when an Auth-Key is entered or `DBX_NWP_ABUSE_CH_AUTH_KEY` is set)
   and whether to flag popularity-allowlisted candidates; headless / `--yes` runs use the keyless
   feeds plus the abuse.ch feeds when the key env var is set. `matched_only` is the sensible default
   given the 100-FQDN cap (over which the block set is risk-prioritised: traffic-matched and
   higher-severity feeds kept, popularity-allowlisted dropped first).

   > **What actually stops data exfiltration** (e.g. a LiteLLM-style credential/data leak to an
   > attacker server) is the RESTRICTED_ACCESS allow-list itself: with egress enforced, traffic to
   > any destination *not* on the allow-list is blocked, including the attacker's. The threat-intel
   > domain block list is a **secondary** layer. Don't rely on the block feed as the primary defence.
6. Gated create: `--create-policy` writes the egress block; `--policy-action` chooses a new policy
   or an existing one; `--auto-assign` binds the workspace. An interactive review gate confirms
   before any write. By default the CLI also **steps through** each section — pausing after the
   analysis results and after the preview to ask whether to continue (*no* aborts cleanly). **`--yes`
   runs non-interactively**, skipping the step-through pauses and every review/write gate.

## Options

- `--lookback-days`, `--min-events`, `--source-type-filter`
- `--enable-rdap` / `--no-enable-rdap`
- `--policy-name` (prompted if omitted, blank = the profile name; the policy id for single-policy
  scopes, the prefix → `<name>-ws-<id>` for per_workspace), `--policy-mode`
  (**dry_run** default / enforce), `--policy-scope` (**current_workspace** default / per_workspace /
  all_workspaces), `--block-threat-domains` (feeds / Auth-Key / allowlist prompted interactively when
  not `off`; `DBX_NWP_ABUSE_CH_AUTH_KEY` for headless abuse.ch feeds)
- `--select-rules` / `--no-select-rules` — interactively curate which observed destinations to
  allow-list (on by default in interactive runs, as two prompts: FQDNs then storage; skipped with
  `--yes`)
- `--export <path>` — write the proposed `AccountNetworkPolicy` JSON (egress block + a `FULL_ACCESS`
  ingress default) for curl / the REST API, **and** a sibling best-effort Terraform `.tf`
  (`databricks_account_network_policy` — review before `terraform apply`); a directory writes
  `<policy-id>.json` + `<policy-id>.tf` inside it. Single-policy scopes only; works in propose-only mode.
- `--account-id` (+ account-admin creds) — required to create/assign.
- `--create-policy` (gate), `--policy-action` (`create_new` / `add_to_existing`),
  `--existing-policy-id`, `--auto-assign`. `add_to_existing` updates only the egress block of the
  supplied policy id (leaving its ingress intact) and needs a single-policy scope
  (`current_workspace` or `all_workspaces`, not `per_workspace`); a brand-new egress-only policy gets
  a permissive `FULL_ACCESS` ingress default.

## Pre-checks (create + assign only)

Mirroring the ingress helper, when the run will create **and** assign a single policy the CLI first
inspects the workspace's currently-assigned policy and **aborts** rather than silently clobbering it:
if that policy already has an **enforced** restrictive egress (replacing it isn't supported yet); a
restrictive *dry-run* egress only warns (assigning replaces it). It also guards the **opposite
direction** — if creating the policy under a **new** id would rebind the workspace and drop an
existing restrictive **ingress** (the new egress policy carries a `FULL_ACCESS` ingress default), it
aborts on an enforced ingress (warns on a dry-run one); use `add_to_existing` to keep it. Updating
the same id in place preserves the other direction. An allow-all (`FULL_ACCESS`) assigned policy — or
none — is fine. Skipped for `per_workspace` and `add_to_existing`.

## Limits & safety

Egress policy limits: 100 internet destinations, 100 storage destinations per policy (the CLI warns
+ caps). Nothing is written unless `--create-policy`. `--policy-mode dry_run` (default) is log-only;
`enforce` blocks egress not on the allow-list — validate in dry_run first.

## Notes

- The egress block replaces only the policy's `egress`; `ingress` / `ingress_dry_run` are untouched.
- Storage destinations and the CBI egress schema are documented at `docs/cbi-sdk-schema.md`.
- Also runnable via `dbx-nwp-helper guided` (interactive Q&A).
- New to the tool? `dbx-nwp-helper guide` opens a self-contained, offline companion guide
  (step-by-step walkthroughs + a readable CLI-options reference); `--print-path` prints its path and `--pdf <path>` renders it to a PDF (all sections expanded).
