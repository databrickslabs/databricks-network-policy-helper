# Genie agent: CBI Security Posture

Lets admins and security teams ask questions like *"what would break if we enforced?"* in plain
English, over the same data the `cbi-posture` Claude skill uses.

## Setup

You need a schema you own (e.g. `security.cbi_posture`) with `CREATE TABLE` / `CREATE VIEW`, and
`SELECT` on `system.access.audit` (and `system.access.inbound_network` if enabled). A metastore admin
may have to grant these and enable the `access` system schema.

**In a notebook** (simplest): open `.claude/skills/cbi-posture/notebooks/run_cbi_posture`, set
`uc_schema` to your schema and `create_genie_agent` to `yes`, and run all. It writes the posture
snapshot, creates the views and creates the agent, then prints the agent's link.

**With Genie Code**: ask *"set up the CBI Genie agent in security.cbi_posture"*. The skill asks before
it writes anything.

**From a terminal**:
```bash
uv run --with databricks-sdk python .claude/skills/cbi-posture/scripts/cbi_posture.py \
  --workspace-profile <ws> --account-profile <acct> --warehouse-id <wh> --uc-schema security.cbi_posture
uv run --with databricks-sdk python .claude/skills/cbi-posture/scripts/cbi_genie_setup.py \
  --workspace-profile <ws> --schema security.cbi_posture [--warehouse-id <wh>]
```

`cbi_genie_setup.py` creates the four views in the schema, builds the agent from
[`instructions.md`](instructions.md), [`trusted_queries.sql`](trusted_queries.sql) and the sample
questions below, and creates the agent, or updates the one with the same title (`--title`, default
"CBI Security Posture"). It uses an existing serverless/Pro warehouse unless you pass `--warehouse-id`,
and it never creates warehouses. `--print-only agent.json` writes the payload and changes nothing.

**What's left to do by hand: share the agent** with the security team (CAN RUN). Genie runs queries as
the person asking, so they also need SELECT on the views. Re-run the collector on a schedule (a weekly
job on the notebook) to track maturity; the agent always reads the latest snapshot.

<details><summary>Manual setup (if the API isn't available)</summary>

1. Run the collector with `--uc-schema` (above).
2. Replace `<catalog>.<schema>` in [`views.sql`](views.sql) and run it in the SQL editor.
3. In *Genie*, create a new agent on a serverless/Pro warehouse with the tables `cbi_posture_latest`,
   `cbi_findings_latest`, `cbi_posture_workspaces`, `cbi_audit_access` and `cbi_inbound_events`.
4. Paste [`instructions.md`](instructions.md) (below the line) into *General instructions*, and add
   each block of [`trusted_queries.sql`](trusted_queries.sql) as an example SQL query, with its `-- Q:`
   line as the question and `lookback_days` as an integer parameter (default 30).

</details>

## Sample questions

- What is our CBI maturity by workspace?
- Which workspaces are still open to the internet?
- What are the high-severity findings and what should we do first?
- How much traffic to workspace 1234 comes from public IPs?
- Which public IPs would an allow-list need to cover for workspace 1234?
- Which service principals connect from more than 10 networks?
- Do we have Power BI or Tableau traffic over the public internet?
- What would break if we enforced our dry-run policy?
- What did our enforced policy block yesterday, and which rule blocked it?
- Who logs into the account console from outside the corporate network?
- How has our maturity changed since last month?
- How exposed are we to stolen personal access tokens?
- Could we allow browser access from anywhere but restrict APIs? Who would that affect?
- Which identities showed up from a new IP address yesterday?
- Which defense-in-depth layers have the most open findings?

## Notes

- The views use a rolling 90-day window to keep Genie queries fast. To change it, regenerate them
  with `scripts/cbi_sql.py --emit-genie`.
- This agent covers **posture**. For **incident investigation**, use the Genie Agent from the
  [Databricks Workspace Detection App](https://github.com/databricks-solutions/cybersec-workspace-detection-app),
  which ships vetted detections such as `detect_verbose_audit_logging_disabled` and `detect_secrets_discovery`.
- The snapshot schema gained `layer` and PAT columns in v0.2. If you created the tables with v0.1, drop
  them before the next `--uc-schema` run, or `ALTER TABLE … ADD COLUMNS`.
- Genie answers questions; it doesn't change policies. For changes, use the Claude skill and the
  network-policy helper (propose-only → dry-run → enforce).
