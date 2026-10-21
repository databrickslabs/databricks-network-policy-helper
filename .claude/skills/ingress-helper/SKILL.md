---
name: ingress-helper
description: Suggest and optionally apply Databricks Context-Based Ingress (CBI) network-policy allow-lists from real audit-log traffic, using the dbx-nwp-helper CLI. Use when the user wants to build/suggest a context-based ingress policy, tighten inbound network access, allow-list source IPs, analyse who connects to a workspace and from where, or turn system.access.audit logs into a CBI / account network-policy proposal. Runs `dbx-nwp-helper ingress` (or the guided wizard), which analyses public source IPs carrying successful traffic, enriches them with open threat-intelligence and cloud-provider ranges plus RDAP ownership, proposes minimal/optimal/maximum CIDR framings optionally scoped by destination (Apps/Lakebase) and identity (users/SPs), and can write the result into a network policy's dry-run (log-only) or enforced ingress block via the Databricks SDK.
---

# Context-Based Ingress (CBI) Helper

Turn real `system.access.audit` traffic into a proposed **Context-Based Ingress (CBI)** allow-list
for a Databricks **account network policy**, with threat-intel + cloud-range enrichment, optional
destination/identity scoping, and a safe dry-run-first apply path.

The engine is the **`dbx-nwp-helper`** CLI (this repo). This skill helps run it with sensible
parameters and review/apply a policy responsibly.

For **egress** (outbound allow-lists) use `egress-helper`. To end up with a combined ingress + egress
policy, run one direction with `--policy-action create_new`, then the other with
`--policy-action add_to_existing --existing-policy-id <id>` pointed at the policy the first created.

## When to use

The user wants to: suggest/build a CBI or ingress allow-list; see which public IPs / identities
connect to a workspace and from where; tighten inbound network access from observed traffic; or
trial an ingress policy in dry-run before enforcing.

## Setup

The CLI is a uv project. From a checkout: `uv sync`, then run via `uv run dbx-nwp-helper …` (or
`uv tool install .` to expose `dbx-nwp-helper` on PATH).

- **Auth** is the Databricks SDK's unified auth — pass `--profile <name>` (a `~/.databrickscfg`
  profile) or set `DATABRICKS_*` env vars. Analysis needs only workspace read on
  `system.access.audit`. **Applying a policy, or identity scoping, needs an account admin** — pass
  `--account-id` and have account-admin credentials resolvable (recommended: an account-admin
  service principal via OAuth M2M in the same profile). See `docs/account-admin-setup.md`.
- **SQL warehouse**: the CLI queries the system tables through a SQL warehouse. Pass
  `--warehouse-http-path` to use a specific one; otherwise it reuses (or creates) a small serverless
  warehouse named `dbx-nwp-helper`.
- **New to the tool?** `dbx-nwp-helper guide` opens a self-contained, offline companion guide
  (step-by-step walkthroughs + a readable CLI-options reference); `--print-path` prints its path and `--pdf <path>` renders it to a PDF (all sections expanded).

## Safety model — read first

- The default `--policy-mode` is **`dry_run`** — writes the log-only `ingress_dry_run` block and
  **blocks nothing**. Always propose and validate here first.
- **`enforce` mode writes the enforced `ingress` block and CAN lock users (and the operator) out**
  if the allow-list is incomplete. Keep `--policy-mode dry_run` until the logs look right.
- Nothing is written unless **`--create-policy`** is passed, and an interactive review gate
  confirms before any write (bypass only with `--yes` for scripting). Show the JSON preview first.
- By default the CLI **steps through** each section — pausing after the analysis results and after
  the proposed-policy preview to ask whether to continue (answering *no* aborts cleanly). **`--yes`
  runs non-interactively**, skipping the step-through pauses *and* every review/write gate.
- The CBI policy schema is **IPv4-only**; IPv6 is analysed but never put in a policy.
- Never pass `--create-policy` (let alone `--policy-mode enforce`) on the user's behalf without
  explicit, current confirmation of the mode and the exact CIDRs.

## Workflow

1. **Propose-only first** (no `--create-policy`):
   ```bash
   uv run dbx-nwp-helper ingress --profile <profile> --lookback-days 30
   ```
   This runs the analysis, prints the candidate IPs, ranked CIDR suggestions, the ⚠️ threat-match
   table, and the JSON policy preview — writing nothing.
2. **Review** the proposal with the user: framing, scoping, mode, and the exact CIDRs. In interactive
   runs a pre-checked **rule selector** (on by default; `--no-select-rules` to skip, or `--yes` for
   non-interactive) lets you drop specific owner-groups before the policy is built.
3. **Apply (gated)** — only with explicit go-ahead, add `--create-policy` (defaults to `dry_run`)
   and, when ready, `--policy-mode enforce`. Add `--auto-assign` to bind the workspace(s).
4. Or run **`uv run dbx-nwp-helper guided --profile <profile>`** for a structured Q&A wizard that
   walks the user through the same choices interactively.

## CIDR framings (`--policy-framing`)

- `minimal` (default) — one `/32` per observed IP (tightest).
- `optimal` — collapse adjacent addresses.
- `maximum` — the full RDAP-assigned range (needs `--enable-rdap`).

## Scoping modes (`--scoping-mode`)

- `ip_only` (default) — one rule: these CIDRs, all destinations, all identities.
- `ip_and_destination` — scope groups whose traffic maps cleanly to Apps or Lakebase.
- `ip_and_identity` — scope to the specific users/SPs seen (resolves emails→numeric ids via account
  SCIM; account admin required). Groups are **not** supported — only users and service principals.
- `ip_identity_and_destination` — both.

> **CBI API limit on per-identity rules.** The API rejects an `authentication` block on
> Apps / Lakebase / all-destinations rules (they allow all users + service principals) — the only
> destination shapes this tool emits. So identity scoping today does **not** pin a rule to the
> selected principals; its real effect is to **exclude** CIDR groups whose principals couldn't be
> resolved (narrowing the allow-list to identifiable traffic). The CLI **warns** when identity
> scoping is requested so this isn't a surprise.

## Policy scope (`--policy-scope`) & limits

- `current_workspace` (default) — one policy built from **this** workspace's traffic, named `<name>`,
  bound to this workspace on `--auto-assign`.
- `per_workspace` — a tailored policy per workspace seen, named `<name>-ws-<id>` (the name is the
  prefix here).
- `all_workspaces` — a single policy built from **all** workspaces' traffic, named `<name>`.

Audit `workspace_id = 0` is account-level, excluded unless `--include-account-level`.

`<name>` is the policy name: the CLI **prompts** for it (blank = the profile name, falling back to
the workspace id), or takes `--policy-name` non-interactively. With `--policy-action add_to_existing`
the id comes from `--existing-policy-id` instead, so `--policy-name` isn't used there. The name is
normalised to an id-safe slug (lowercased, non-alphanumerics → `-`, length-capped) and the CLI prints
the resulting id.

`--export <path>` writes the proposed network policy as a curl / REST-ready `AccountNetworkPolicy`
JSON (ingress block + a `FULL_ACCESS` egress default) **and** a sibling best-effort Terraform `.tf`
(`databricks_account_network_policy` — review before `terraform apply`); a directory writes
`<policy-id>.json` + `<policy-id>.tf` inside it. Single-policy scopes only (refused for
`per_workspace`); works in propose-only mode too.

Before any analysis or write, the CLI shows the **target workspace** (profile / URL / id) and asks
you to confirm it — so a mis-set `--profile` can't act on the wrong workspace (skip with `--yes`).

**Pre-checks (create + assign only).** When the run will create **and** assign a single policy, the
CLI guards public and private **independently**, aborting only when a dimension it **migrates**
collides with a **restrictive** existing CBI block in that same dimension (enforced OR dry-run):
- **public** — abort if migrating public (observed traffic / IP access lists) and the assigned policy
  has a restrictive public_access;
- **private** — abort if migrating a *non-allow-all* PAS and the assigned policy has a restrictive
  private_access.

An allow-all policy (e.g. the account's `default-policy`) is fine. It also guards the **egress**
direction: creating under a **new** id that would rebind the workspace and drop an existing restrictive
egress aborts on an enforced egress (warns on a dry-run one) — use `add_to_existing` to keep it.
Skipped for `per_workspace` and `add_to_existing`.

**Existing CBI ingress is reused per dimension.** Public, private and cross-workspace access are
independent — each is built/migrated or **carried forward** from the workspace's assigned CBI policy
(deep-copied, restrictive blocks only):
- **public** — built net-new from observed traffic + IP ACLs; an existing restrictive public block is
  preserved only when this run has nothing of its own to build.
- **private** — on **AWS/GCP** a **non-allow-all** PAS (specific registered endpoints) is migrated
  into `private_access` (ids mapped across as-is; an allow-all PAS needs nothing and never loosens a
  stricter existing block). On **Azure** front-end PrivateLink is **not** migrated (`databricks_ui_api`
  endpoints are default-allowed; the public-access flag isn't retired). An existing CBI private block
  is carried forward on all clouds.
- **cross-workspace** — never built; any existing block is carried forward verbatim.

Reading the PAS / assigned policy needs account-admin auth, so this is a no-op on a propose-only run
without one. (Mirrors the `databricks-migrate-ip-acls` sibling's existing-policy handling.)

`add_to_existing` updates only the ingress block and **leaves an existing egress as-is**; a brand-new
policy gets a permissive `FULL_ACCESS` egress default (and, symmetrically, the egress helper leaves
an existing ingress alone and defaults a missing one) — so composing ingress + egress never clobbers
the other direction.

Applying: **`--create-policy`** is the master switch; **`--policy-action`** chooses `create_new`
(a fresh policy named as above) or `add_to_existing` (update `--existing-policy-id`, replacing
only its ingress block and leaving egress intact — needs a single-policy scope, i.e.
`current_workspace` or `all_workspaces`, not `per_workspace`);
**`--auto-assign`** binds the workspace(s). `add_to_existing` is how you layer ingress onto a policy
the egress helper already created (and vice-versa) for a combined policy.

The CLI knows the Databricks network-policy limits and **warns + auto-caps** to keep proposals
valid: **50 ingress rules, 2000 CIDR blocks, 100 identities per policy; 1000 policies per account.**

## Existing IP access lists & denied requests

Existing IP access lists are **auto-detected** (there is no `--ip-acl-handling` flag). When the
workspace has enabled lists, the CLI shows their **actual IP entries** and — interactively — offers a
pre-checked **checkbox** to pick exactly which entries to fold into the CBI policy, kept **alongside**
the traffic-derived rules. Non-interactive / `--yes` runs migrate them all. Observed-traffic rules are
always included.

The CLI also surfaces requests **recently blocked inbound** — both IP-access-list 403s
(`system.access.audit`) and **enforced** CBI network-policy denials (`system.access.inbound_network`
`access_type=DROP`, when that table is available/non-empty; it degrades cleanly if not). Pass
`--deny-denied-ips` to turn those source IPs into explicit deny rules (labelled `deny-recently-denied`).

**Dry-run CBI denials as allow-list candidates.** When `system.access.inbound_network` is available,
the public IPs a *dry-run* CBI policy would have blocked (`access_type=DRY_RUN_DENIAL`) are folded
into the candidate set — the inbound clients your log-only allow-list doesn't yet cover. So you can
stand up a restricted dry-run ingress policy, let it observe, and complete the allow-list from what it
would have denied. On by default (best-effort); `--no-include-inbound-network` opts out.

**Partner platforms.** Observed inbound IPs matching a known partner-platform range (**Power BI**,
**dbt platform**; Tableau Cloud pending a confirmed source) are labelled as that partner and
recommended for allow-listing — kept as labelled CIDR allow rules. The CLI also flags Databricks'
managed **"Partner platforms"** ingress source (Beta; AWS + GCP), which maintains these IP lists for
you and is the cleaner option; it's console/Terraform-only (the SDK can't set it yet), so enable it on
the account console Previews page and add the source on the policy's Ingress tab.

Once the CBI policy replaces the old IP access list, pass `--disable-existing-ip-acls` (off by
default) to turn the workspace's IP access lists off (`enableIpAccessLists=false`) so both controls
don't apply at once. It only runs **after** the policy is created and assigned, and the CLI refuses
the flag unless the run also does both (`--create-policy` **and** `--auto-assign`) — so it can't
leave the workspace with no ingress control. The lists are preserved, so it's reversible.

## Flagged groups & threat-intel deny rules

Threat-intel and cloud-provider-owned groups are **always excluded** from proposed allow rules.
Threat matches still appear in the ⚠️ threat-match table for investigation. **Databricks-owned** IPs
are the exception and take **precedence**: an observed Databricks-owned group is always kept in the
allow-list (in its own unscoped rule, and never dropped even when a threat feed also matches). Note
this only covers Databricks ranges **seen in your audit traffic** — the tool does not inject the full
published range set, so confirm the platform's own ranges are covered before enforcing.

`--threat-deny-rules` adds **deny rules** from the threat-intel table: `off`, `matched_only` (only
threat CIDRs that matched observed traffic), or `all` (whole feeds). Over the cap it prioritises
(confidence-1, attacker_subnet first) rather than skipping. If a policy would have deny rules but no
allow rules, a catch-all allow is added so non-denied traffic is still permitted.

## Feeds

Enrichment feeds are cached locally with a TTL. `dbx-nwp-helper feeds list` shows the cache;
`feeds refresh` forces a re-download; the analysis commands accept `--refresh-feeds`. Feeds include
threat-intel, cloud-provider and Databricks ranges, and **partner-platform ranges** (`partner_ranges`
— Power BI dynamic via the Azure Service Tags `PowerBI` tag, dbt platform curated; Tableau Cloud
pending a source).

## References

- `docs/threat-intel-feeds.md` — the enrichment feeds, what each represents, licensing.
- `docs/cbi-sdk-schema.md` — the verified `AccountNetworkPolicy` SDK object model.
- `docs/account-admin-setup.md` — account-admin SP + credential setup.
