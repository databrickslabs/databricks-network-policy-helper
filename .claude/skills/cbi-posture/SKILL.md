---
name: cbi-posture
description: Diagnose a Databricks customer's Context-Based Ingress (CBI) posture, meaning the account network policies that decide who can reach a workspace or the account console by identity, source IP or private endpoint, and request type. Use when asked "how exposed is my workspace", "are we ready for CBI", to assess or score ingress, network policy or IP access list posture, "what would break if we enforce", to review a dry-run policy, for a CBI readiness or maturity report, or for a starter or sample CBI policy, including after a leaked PAT or OAuth secret. Runs a read-only collector (network policies, private access, IP access lists, PAT settings, SQL over system.access audit and inbound_network), scores each workspace L0 Open to L4 Hardened, maps findings to the credential-theft defense layers, suggests a rollout pattern, and hands fixes to dbx-nwp-helper (propose-only first). On request ("set up the CBI Genie agent"), creates a CBI Security Posture Genie agent over the same data.
---

# CBI security-posture diagnostic

Assess *where a customer stands* on context-based ingress before anyone writes a policy, then route
them to the right next step. This skill **diagnoses**. Building and applying policies is delegated to
the `dbx-nwp-helper` CLI in this repo
([databricks-network-policy-helper](https://github.com/databrickslabs/databricks-network-policy-helper))
and its `ingress-helper` / `egress-helper` skills.

```
diagnose (this skill, read-only) ──► propose (dbx-nwp-helper, no --create-policy) ──► dry-run ──► enforce
```

**Why it matters.** Most credential breaches involve no platform bug. A valid token is stolen
elsewhere and replayed. A stolen credential is dangerous when it **still works**, **can do a lot**,
and **works from anywhere**. CBI removes "from anywhere": without it, a stolen PAT is single-factor
access to everything its owner can reach. Frame findings this way. CBI is the *Limit* layer of
seven (Avoid · Expire · Scope · **Limit** · Detect · Respond · Posture), and the report shows coverage
per layer. See `references/credential-theft-layers.md`.

**Suspected compromise?** If the customer mentions a leaked token or suspicious activity, stop the posture flow and follow
`references/incident-mode.md`: contain first, deploy known-good CBI rules, and investigate with the
Workspace Detection App.

## Where are you running?

Pick the path that matches your environment before Step 2.

- **Genie Code in the account console.** You can't run scripts or SQL here. Explain CBI and the
  maturity levels, and answer account questions with the tools you have. To run the assessment, send
  the user to Genie Code **in a workspace** that has this skill. In that workspace, they ask
  "assess our CBI posture". Don't print terminal commands.
- **Genie Code in a workspace** (or any notebook). Use the notebook
  `notebooks/run_cbi_posture.py` in this skill folder. It runs the collector inside the notebook, uses
  the notebook's own credentials, and runs the SQL on the notebook's compute unless `warehouse_id` is
  set. Account-level checks need the `account_secret` widget, which points to an account-admin service
  principal's OAuth credentials. It can be a Unity Catalog secret `catalog.schema.name`, holding JSON
  `{"account_id", "client_id", "client_secret"}` or just the secret plus the `account_id` and
  `account_client_id` widgets. It can also be a UC schema with secrets `account-id`, `client-id` and
  `client-secret`, or a workspace secret scope with those keys. UC secrets need `READ SECRET` and
  serverless environment 4+ (or DBR 17.3+). Without credentials, the run is workspace-only and the
  report says why. For quick questions,
  run the files in `sql/` in the SQL editor instead. Don't suggest `uv`, `databricks auth login` or
  `~/.databrickscfg` here. The network-policy helper is a terminal tool, so building a sample policy's
  `--export` is an account-team step from a terminal (Step 4b).
- **Terminal (Claude Code).** Follow Step 2 as written, with CLI profiles.

## Hard rules

1. **Read-only.** Never call create/update/delete APIs, never run `dbx-nwp-helper` with
   `--create-policy`, `--auto-assign` or `--disable-existing-ip-acls`, and never create a SQL warehouse
   on the customer's behalf. The writes this skill can do all go to a schema the customer names, and
   each needs a yes first: `--uc-schema` (appends two snapshot tables), `cbi_genie_setup.py` (views + Genie
   agent), and `--stage-schema` (warehouse runs only: a temporary table holding the audit rollup, dropped at
   the end). Notebook runs don't need `--stage-schema`: they cache the audit rollup in the session. If the
   run log says the DataFrame cache is unavailable on serverless, suggest environment version 5 or later.
2. **Every `next_step` is a suggestion for the customer.** Present it, explain it, and let them run it.
   Remind them that enforce mode can lock users (and admins) out.
3. **Don't over-claim.** System tables cover only what they log, and the account APIs need account
   admin. When a check couldn't run, the finding says UNKNOWN. Say so plainly and don't fill gaps with
   guesses.
4. Treat IPs, emails and principal names in outputs as **customer-confidential**. Don't paste them
   anywhere outside the session. Token metadata is collected (IDs, owners, expiry, scopes); token
   values never are, because the API doesn't return them. Never ask a customer to paste a token.
5. **Observed traffic is not trust.** The audit log can contain the attacker, and dry-run denials are
   candidates rather than evidence. Every proposed source needs an owner who vouches for it.

## Step 1: Scope (ask only what you can't infer)

- **Cloud** (AWS / Azure / GCP). This sets the accounts host and whether PrivateLink migration applies.
- **Credentials available:**
  - workspace profile(s) in `~/.databrickscfg` → IP access lists + system-table SQL
  - account-admin profile (or `--account-id`) → policies, assignments, PAS, account IP ACLs
- **A SQL warehouse id** they're happy to use (`databricks warehouses list`). If none exists, the
  SQL checks are skipped. Offer the `.sql` files to run in their own SQL editor instead.
- **Which workspaces.** Ask: **one** (default: the workspace they're in, or their profile's),
  **several** (a list of ids), or **all** (`--workspace-ids all`). All is slow on large accounts:
  roughly an hour for a few hundred workspaces at 90 days. Suggest one or several unless they need an
  account-wide view. Account-level events are always included.
- **Lookback** (default **90 days**, the window Databricks recommends for a first helper draft, so
  monthly and quarterly clients show up).
- **Is there a recent run?** Before running, look for `report.md` in the output folder (notebook
  default `/Workspace/Users/<me>/cbi-posture-out`). If it covers what they asked about, answer from it,
  and say when it was generated and which scope it covers (both are in its header). A re-run reuses
  traffic results under 24 hours old for the same scope and lookback and re-reads the configuration,
  so it's quick. Use `--refresh` (notebook: `refresh = yes`) only when they need fresh traffic, e.g.
  to check a policy they've just put in dry-run. A cached all-workspaces run is never reused for a
  narrower scope.
- **Tier and cloud.** Workspace CBI requires the **Enterprise** tier. It's also available in AWS
  GovCloud and AWS GovCloud DoD (GA as of 2026-11-04). Check the docs for other tiers. Below
  Enterprise, the report steers to the credential and blast-radius layers instead.
- **Workspace-admin rights** on the profiles, for IP ACLs and the PAT inventory
  (`token-management list`, `maxTokenLifetimeDays`, who may use tokens).

## Step 2: Collect and score

The scripts need Python 3.10+ and `databricks-sdk` (≥ 0.152). From this skill directory:

```bash
uv run --with databricks-sdk python scripts/cbi_posture.py \
  --workspace-profile <ws-profile> [--workspace-profile <ws2> ...] \
  --account-profile <account-admin-profile> [--account-id <id>] [--account-host https://accounts.azuredatabricks.net] \
  --warehouse-id <warehouse-id> --lookback-days 90 --out cbi-posture-out
```

Outputs `cbi-posture-out/report.md` (read this first), `posture.json` (raw snapshot) and
`findings.csv`. To re-score without API calls, use `--from-json cbi-posture-out/posture.json`.

**In a notebook** (Genie Code in a workspace): open `notebooks/run_cbi_posture.py`, set the widgets
and run all. Or call the collector in-process, which inherits the notebook's credentials:

```python
import sys; sys.path.insert(0, "<path to this skill>/scripts")
import cbi_posture
cbi_posture.main(["--lookback-days", "90", "--out", "/Workspace/Users/<me>/cbi-posture-out",
                  "--account-secret", "<catalog.schema.secret>"], spark=spark)   # omit for workspace-only
```

Run it in the notebook's Python process, not with `%sh` or `!python`. A subprocess doesn't inherit
the notebook's credentials.

**Degraded modes (still useful):**
- *No account admin*: workspace IP ACLs + traffic SQL only. Policy checks are UNKNOWN, and the report
  says so.
- *No Python*: run the read-only CLI calls in `references/manual-checks.md` and the SQL in `sql/`, then
  apply `references/findings.md` by hand.
- *SQL editor only*: run `sql/01…13_*.sql` (set `:lookback_days`). These are the same queries the
  collector uses.

If `system.access.inbound_network` fails, run `DESCRIBE TABLE system.access.inbound_network`. The
outcome column has been documented as both `policy_outcome` and `access_type`, with values
`DENY`/`DENIED`/`DROP` and `DENY_DRY_RUN`/`DRY_RUN_DENIAL`. The SQL normalises these values, and the
collector swaps the column name automatically.

## Step 3: Explain the result

Open with **evidence coverage**: `audit_visibility` shows the window and any verbose-audit gap
(CBI-025). Then lead with the **maturity table**, the **defense-in-depth coverage** table, and the
findings, highest severity first. Never-expiring PATs on an L0/L1 workspace (CBI-020 high) are the
headline risk: credentials that work forever, from anywhere. For each finding, cover
*what we saw → why it matters → what to do next*. The checks and their reasoning are in
`references/findings.md`, and the CBI concepts you'll need to explain are in
`references/cbi-reference.md`.

| Level | Meaning | Typical next move |
|---|---|---|
| **L0 Open** | Public ingress unrestricted: no restrictive CBI public block and no enabled allow IP ACL | Propose an allow-list from observed traffic |
| **L1 Legacy perimeter** | IP access lists only | Migrate the ACLs into CBI (helper auto-detects them; or `dbx-migrate-ip-acls` verbatim) |
| **L2 Observing** | CBI restricts public access in **dry-run** | Close the `dry_run_would_block` gap, then enforce |
| **L3 Enforced** | CBI enforces a public allow-list, or the PAS blocks public access (private-only) | Fix the remaining medium/high findings |
| **L4 Hardened** | L3 with no high/medium findings | Keep watching `enforced_denials`; add egress control |

Interpretation tips:
- `traffic_by_ip_class.public_pct` low + PrivateLink present → most users already come in privately,
  so focus on the private dimension (CBI-007).
- High `principal_network_spread` or BI/SaaS `client_families` → IP rules alone won't hold. Steer to
  identity-scoped rules and the managed **Partner platforms** source (Power BI, Tableau Cloud, dbt,
  ChatGPT, Claude; Genie for Slack/Teams by OAuth client).
- Workspace IP ACLs and CBI combine with **AND**. During migration both must allow a request.
- Classic compute without PrivateLink, and serverless calls to the same workspace, aren't affected by
  public source rules. Don't flag their traffic as at-risk.
- `workspace_id = '0'` rows are **account-level** (console / account APIs), governed by the Beta
  `account-policy`. A workspace policy doesn't cover them.
- **No VPN is not a blocker.** Use CBI-026's suggested pattern on a narrow slice first: one workspace,
  production service principals, or admin API calls. Pick from **B1 browser yes / APIs no** (few
  `programmatic_principals` in `public_browser_vs_api`), **B2 allow only the API families you need**
  (`IN sql`…), **B3 Partner platforms** for hosted BI, and **B4 time-boxed access**. Broad ISP ranges are
  not a VPN, and one broad allow rule undoes the rest.
- An empty result is "no matching events in this window", not proof. Compute and serverless traffic
  can show platform IPs, so don't treat every IP as a user endpoint.
- For layers this tool can't see (SSO/MFA, OAuth adoption, catalog bindings, UC secrets, admin count,
  notebook secrets), point to **Governance Hub → Security** and the **Security Analysis Tool**.

## Step 4: Hand off to the network-policy helper

Each finding carries the exact **propose-only** command. Run it from the repo root after `uv sync`; if
you copied this skill on its own, install the helper once:

```bash
git clone https://github.com/databrickslabs/databricks-network-policy-helper && cd databricks-network-policy-helper && uv sync
```

| Finding | Hand-off |
|---|---|
| CBI-001 Open / CBI-004 broad CIDRs | `uv run dbx-nwp-helper ingress --profile <p> --lookback-days 90` (add `--policy-framing optimal --enable-rdap` to re-frame) |
| CBI-002 Legacy IP ACLs | Same command; it auto-detects IP ACLs and offers to fold them in. Verbatim-only migration: `dbx-migrate-ip-acls` |
| CBI-003 Dry-run gap | `… ingress --policy-action add_to_existing --existing-policy-id <id>` (dry-run denials are folded in by default) |
| CBI-007 Private allow-all | `… ingress` (AWS/GCP recreate the PAS posture in `private_access`) |
| CBI-009 Account console open | `… ingress --include-account-level --export .` to derive admin IPs (propose-only). The helper doesn't write `account-policy`, so configure that in the account console (Beta) |
| CBI-010 Near limits | `… ingress --consolidate-rules` |
| CBI-013 / 014 Roaming / SaaS | `… ingress --scoping-mode ip_and_identity` + Partner platforms in the console |
| CBI-020–024 PATs | Token report → revoke never-expiring/unused tokens; `maxTokenLifetimeDays`; restrict token permissions; scopes / auto-scoping; move people to OAuth U2M and automation to workload identity federation |
| CBI-026 Pattern | Configure the suggested pattern on a dry-run pilot policy; use the helper's draft for the source lists |
| CBI-017 Egress open | `uv run dbx-nwp-helper egress --profile <p> --lookback-days 90` |

From there, follow the helper's own `ingress-helper` / `egress-helper` skill. The rollout is:
**propose → review the JSON/Terraform (`--export .`) → `--create-policy` (dry-run) → watch
`dry_run_would_block` → `--policy-mode enforce` only with explicit customer sign-off**.

## Step 4b (optional): Sample policy to test with the customer

When an account team wants something concrete to hand over ("a sample policy they can try"), build
a **dry-run sample policy** from the customer's own audit logs. Everything runs in the customer's account,
by the customer or with them on a call. Nothing is applied.

1. Run the collector **with `--warehouse-id`** so `posture.json` contains `source_ips_by_workspace`
   (`sql/13`), the per-workspace traffic profile the review sheet is built from.
2. Have the helper write a proposal without applying it, one per workspace:
   ```bash
   uv run dbx-nwp-helper ingress --profile <p> --lookback-days 90 \
     --warehouse-http-path <http-path> --policy-name <name> --export policy-in/
   ```
   Pass `--warehouse-http-path`; without it the helper creates its own serverless warehouse.
3. Build the sample policy:
   ```bash
   uv run --with databricks-sdk python scripts/cbi_sample_policy.py \
     --posture cbi-posture-out/posture.json --export <workspace-id>=policy-in/<name>.json \
     --warehouse-http-path <http-path> --out cbi-sample-policy
   ```

Each `cbi-sample-policy/<workspace-id>-<policy>/` folder holds:
- `README.md`: the proposal at a glance, warnings, the test plan, exit criteria, rollback and sign-off.
- `review-sheet.csv`: every proposed rule and range, with the traffic it covers, flags, and
  keep/drop + owner columns.
- `uncovered-sources.csv`: observed sources enforcement would block, with suggested handling.
- `monitor.sql`: the daily dry-run check.
- `policy.json`: the helper's export, unchanged.

`cbi_sample_policy.py` is pure: it reads files and writes files, with no API calls.

How to present it:
- **It's a starting point, not a Databricks recommendation.** It mirrors 90 days of the customer's
  traffic, which can include sources they don't want. Every kept row needs a customer owner.
- **Apply through the helper, never by posting `policy.json`.** The helper keeps existing egress,
  checks the assigned policy and fails closed. A hand-applied new policy carries a FULL_ACCESS
  egress default. The sample policy's README has the exact `--create-policy --policy-mode dry_run` command
  for the customer's admin to run.
- **Read the warnings first.** The most important is an export in **enforce** mode: the helper
  inherits enforce when the workspace already enforces CBI, so that "test" would be live.
- Exit criteria and the move to `--policy-mode enforce` are the customer's decision. Don't run
  either on their behalf.

## Step 5 (optional): Genie agent

So security teams can ask questions in plain English, offer to create the "CBI Security Posture"
Genie agent. It needs a schema (`catalog.schema`) the user can write to. **This writes** views and a
Genie agent, so confirm the schema and get a yes first.

1. If no snapshot exists in that schema yet, run the collector with `--uc-schema <schema>` (notebook:
   `uc_schema` widget). A recent run with the same scope reuses its SQL results, so this is quick.
2. Run `scripts/cbi_genie_setup.py --schema <schema>` (add `--warehouse-id` if the user named one). In a
   notebook, call `cbi_genie_setup.main([...], spark=spark)`, or set the notebook's
   `create_genie_agent` widget to `yes`. Re-running updates the same agent.
3. Give the user the printed link. Tell them sharing is theirs to do (CAN RUN, plus SELECT on the views).

Details and the manual fallback: [`genie/README.md`](genie/README.md). Suggest a weekly job on
the notebook to track maturity over time.

## Files

- `scripts/cbi_posture.py` — collector, evaluator and report (read-only except opt-in `--uc-schema` / `--stage-schema`; caches an audit rollup in notebook sessions)
- `scripts/cbi_sample_policy.py` — turns a helper `--export` into a dry-run sample policy (pure; no API calls)
- `scripts/cbi_genie_setup.py` — creates the Genie views and agent (writes; ask first)
- `scripts/cbi_sql.py` — single source of all diagnostic SQL (`--emit sql/` regenerates the files)
- `sql/*.sql` — read-only queries, parameter `:lookback_days`
- `references/findings.md` — every check: logic, severity, why, fix
- `references/cbi-reference.md` — CBI concepts, limits, interactions (from Databricks docs)
- `references/credential-theft-layers.md` — why CBI matters, the seven layers, the no-VPN patterns, rollout order, acceptance tests
- `references/incident-mode.md` — containment-first flow when a compromise is suspected
- `references/manual-checks.md` — read-only CLI equivalents of the collector
- `references/sources.md` — links (docs, repos)
