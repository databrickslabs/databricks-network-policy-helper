# CBI posture diagnostic (`cbi-posture` skill + Genie agent)

A read-only way for Databricks customers to answer *"where do we stand on context-based ingress, and
what do we do next?"* It's framed around credential theft: a stolen token is
dangerous when it still works, can do a lot, and **works from anywhere**, and CBI removes the last of these.

| Piece | For | What it does |
|---|---|---|
| [`.claude/skills/cbi-posture/`](../.claude/skills/cbi-posture/SKILL.md) | Claude Code / Claude with skills | Collects policies, assignments, PAS, IP ACLs and system-table traffic. Adds the PAT inventory, scores each workspace **L0 Open → L4 Hardened**, maps 26 checks to the seven credential-theft defense layers, suggests a no-VPN CBI pattern, and hands remediation to `dbx-nwp-helper`. Includes an incident mode and a **sample policy** for account teams |
| [`.claude/skills/cbi-posture/genie/`](../.claude/skills/cbi-posture/genie/README.md) | Databricks Genie | Curated views, instructions and trusted SQL, created as a Genie agent in one step (`cbi_genie_setup.py` or the notebook's `create_genie_agent` widget), so security teams can ask the same questions in plain English |

It sits in front of `dbx-nwp-helper`: this skill *diagnoses*, and the `ingress-helper` /
`egress-helper` skills *propose and apply*. Every remediation it suggests is a propose-only
`dbx-nwp-helper` command. It's self-contained (stdlib + `databricks-sdk`, no package import), so the
`.claude/skills/cbi-posture/` folder can also be copied on its own.

## Quick start

```bash
cd .claude/skills/cbi-posture
uv run --with databricks-sdk python scripts/cbi_posture.py \
  --workspace-profile <ws> --account-profile <account-admin> --warehouse-id <wh> --lookback-days 90 --out out
open out/report.md
```

**Inside Databricks** (Genie Code in a workspace, or any notebook): open
`.claude/skills/cbi-posture/notebooks/run_cbi_posture.py` and run it. It uses the notebook's own
credentials and compute; account checks are optional via a secret scope (see the notebook header).

Or ask Claude: *"assess our CBI posture"*. See [`examples/sample-report/report.md`](../.claude/skills/cbi-posture/examples/sample-report/report.md)
for the output on a synthetic 4-workspace account.

## Sample policy (for account teams)

To give a customer a concrete policy to **test**, build it from their own audit logs. Run the helper
with `--export` (it applies nothing), then build the sample policy:

```bash
uv run --with databricks-sdk python scripts/cbi_sample_policy.py \
  --posture out/posture.json --export <workspace-id>=policy-in/<policy>.json --out cbi-sample-policy
```

You get a README with the test plan, exit criteria and rollback, a review sheet (each rule, the
traffic it covers, keep/drop + owner), the observed sources enforcement would block, and a daily
dry-run check. The customer's admin applies it in **dry-run** through the helper. See
[`examples/sample-policy/`](../.claude/skills/cbi-posture/examples/sample-policy/) for the synthetic example, and Step 4b in [`SKILL.md`](../.claude/skills/cbi-posture/SKILL.md).

## Safety

The collector makes only `list`/`get` calls and `SELECT` queries. Its one default-off write is the
`--uc-schema` snapshot for Genie; `cbi_genie_setup.py` creates views and a Genie agent.

In a notebook, the collector reads `system.access.audit` once into a cached rollup (events counted
per date, workspace, principal, source IP and client family) and runs the audit queries over it (serverless: environment version 5+, DataFrame caching is in Public Preview). The
cache is private to the session and released at the end of the run; `--no-cache` turns it off. On a
SQL warehouse there's no session cache, so each query scans the audit log, unless you opt in to
`--stage-schema catalog.schema`, which keeps the rollup in a temporary table there (it holds identities
and source IPs, and is dropped when the run ends). Queries run four at a time (`--parallel N`; 1 runs them one after another), and the inbound-network queries start while the rollup is being built. It never creates warehouses or touches policies. The sample policy
script only reads and writes local files.

## Development

```bash
uv run pytest tests/cbi_posture                           # offline tests (evaluator, sample policy, Genie setup)
uv run --with pyspark==3.5.3 pytest tests/cbi_posture     # + runs the audit queries in local Spark (needs Java)
# Regenerate the .sql files and Genie views after changing cbi_sql.py:
python .claude/skills/cbi-posture/scripts/cbi_sql.py --emit .claude/skills/cbi-posture/sql \
  --emit-genie .claude/skills/cbi-posture/genie/views.sql
```
