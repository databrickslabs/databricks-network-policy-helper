# Databricks notebook source
# MAGIC %md
# MAGIC # CBI posture diagnostic (read-only)
# MAGIC
# MAGIC Assesses this account's context-based ingress (CBI) posture and writes `report.md`, `posture.json`
# MAGIC and `findings.csv` to a workspace folder. It makes only read calls and `SELECT` queries; the one
# MAGIC optional write is the Genie snapshot tables (`uc_schema`).
# MAGIC
# MAGIC **Speed:** it reads `system.access.audit` once into a cached rollup (events counted per date, workspace,
# MAGIC principal, source IP and client) and runs the queries over that, instead of scanning the audit log for
# MAGIC each query. On serverless this needs **environment version 5 or
# MAGIC later** (Environment panel, right side). The DataFrame cache is a Public Preview and isn't available on
# MAGIC GovCloud or with the compliance security profile; there the run falls back to one scan per query and
# MAGIC says so. The cache lives only in this session and is released when the run ends.
# MAGIC Queries run four at a time either way, and the log shows how long each step took.
# MAGIC
# MAGIC **Scope** (`scope`): `this workspace` (default), `selected workspaces` (fill in `workspace_ids`,
# MAGIC comma-separated), or `all workspaces` (every workspace in the account; slow on large accounts).
# MAGIC Account-level events (console / account APIs) are always included.
# MAGIC
# MAGIC **Reuse**: traffic results from a run in the last `reuse_hours` (default 24) with the same scope and
# MAGIC lookback are reused, and the configuration is re-read. Set `refresh` to `yes` to re-run the queries.
# MAGIC
# MAGIC | Widget | Leave blank to… |
# MAGIC |---|---|
# MAGIC | `warehouse_id` | run the SQL on this notebook's compute |
# MAGIC | `account_secret` | skip account-level checks (policies, assignments, PrivateLink). Otherwise where an **account-admin service principal**'s OAuth credentials are: a UC secret `catalog.schema.name` (JSON `{"account_id", "client_id", "client_secret"}`, or just the secret plus the two widgets below), a UC schema `catalog.schema` with secrets `account-id`, `client-id`, `client-secret`, or a workspace secret scope with those keys |
# MAGIC | `account_id` / `account_client_id` | read them from `account_secret` (needed when a UC secret holds only the OAuth secret) |
# MAGIC | `account_host` | derive the accounts host from this workspace's URL (AWS, AWS GovCloud, AWS GovCloud DoD, Azure, Azure Government, Azure China, GCP). Set it for any other environment |
# MAGIC | `uc_schema` | skip the Genie snapshot tables |
# MAGIC | `create_genie_agent` | `no` skips it. `yes` (needs `uc_schema`) creates the views in that schema and creates or updates the "CBI Security Posture" Genie agent, on `warehouse_id` or an existing serverless/Pro warehouse. Not shared with anyone |
# MAGIC | `sample_policy_workspace_id` / `sample_policy_export_path` | skip the sample policy. Otherwise the workspace id and the path of a `dbx-nwp-helper --export` JSON |
# MAGIC
# MAGIC Needs `SELECT` on `system.access.audit` (and `system.access.inbound_network` if enabled). Workspace
# MAGIC admin adds the IP access list and token checks.

# COMMAND ----------

# MAGIC %pip install -q "databricks-sdk>=0.152"

# COMMAND ----------

dbutils.library.restartPython()

# COMMAND ----------

me = spark.sql("SELECT current_user()").first()[0]
dbutils.widgets.text("lookback_days", "90")
dbutils.widgets.dropdown("scope", "this workspace", ["this workspace", "selected workspaces", "all workspaces"])
dbutils.widgets.text("workspace_ids", "")
dbutils.widgets.text("reuse_hours", "24")
dbutils.widgets.dropdown("refresh", "no", ["no", "yes"])
dbutils.widgets.text("warehouse_id", "")
dbutils.widgets.text("account_secret", "")
dbutils.widgets.text("account_id", "")
dbutils.widgets.text("account_client_id", "")
dbutils.widgets.text("account_host", "")
dbutils.widgets.text("out_dir", f"/Workspace/Users/{me}/cbi-posture-out")
dbutils.widgets.text("uc_schema", "")
dbutils.widgets.dropdown("create_genie_agent", "no", ["no", "yes"])
dbutils.widgets.text("sample_policy_workspace_id", "")
dbutils.widgets.text("sample_policy_export_path", "")

# COMMAND ----------

import os
import sys


def _scripts_dir() -> str:
    candidates = [os.path.join(os.getcwd(), "..", "scripts")]
    try:
        nb = dbutils.notebook.entry_point.getDbutils().notebook().getContext().notebookPath().get()
        candidates.append("/Workspace" + os.path.dirname(os.path.dirname(nb)) + "/scripts")
    except Exception:  # noqa: BLE001
        pass
    for c in candidates:
        if os.path.exists(os.path.join(c, "cbi_posture.py")):
            return os.path.abspath(c)
    raise FileNotFoundError(f"cbi_posture.py not found next to this notebook (looked in {candidates})")


SCRIPTS = _scripts_dir()
sys.path.insert(0, SCRIPTS)
import cbi_posture  # noqa: E402

w = dbutils.widgets.get
args = ["--lookback-days", w("lookback_days"), "--out", w("out_dir"), "--reuse-sql-hours", w("reuse_hours") or "0"]
if w("scope") == "all workspaces":
    args += ["--workspace-ids", "all"]
elif w("scope") == "selected workspaces":
    if not w("workspace_ids").strip():
        raise ValueError("scope = selected workspaces: fill in workspace_ids (comma-separated)")
    args += ["--workspace-ids", w("workspace_ids").replace(" ", "")]
if w("refresh") == "yes":
    args.append("--refresh")
for flag, key in (("--warehouse-id", "warehouse_id"), ("--account-secret", "account_secret"),
                  ("--account-id", "account_id"), ("--account-client-id", "account_client_id"),
                  ("--account-host", "account_host"),
                  ("--uc-schema", "uc_schema")):
    if w(key).strip():
        args += [flag, w(key).strip()]
print("cbi_posture", " ".join(args))
_ = cbi_posture.main(args, spark=spark)

# COMMAND ----------

# MAGIC %md ## Report

# COMMAND ----------

report = os.path.join(w("out_dir"), "report.md")
print(open(report).read())

# COMMAND ----------

# MAGIC %md ## Optional: Genie agent
# MAGIC Set `create_genie_agent` to `yes` (with `uc_schema`). Re-running updates the same agent.

# COMMAND ----------

if w("create_genie_agent") == "yes":
    if not w("uc_schema").strip():
        raise ValueError("create_genie_agent = yes needs uc_schema (the schema the snapshot was written to)")
    import cbi_genie_setup

    g = ["--schema", w("uc_schema").strip()]
    if w("warehouse_id").strip():
        g += ["--warehouse-id", w("warehouse_id").strip()]
    cbi_genie_setup.main(g, spark=spark)
else:
    print("No Genie agent requested (create_genie_agent = no).")

# COMMAND ----------

# MAGIC %md ## Optional: sample policy
# MAGIC Build the helper export first (`dbx-nwp-helper ingress ... --export <dir>`; it applies nothing), then set
# MAGIC `sample_policy_workspace_id` and `sample_policy_export_path`. The sample policy is written next to the report, under `sample-policy/`.

# COMMAND ----------

if w("sample_policy_workspace_id").strip() and w("sample_policy_export_path").strip():
    import cbi_sample_policy

    cbi_sample_policy.main(["--posture", os.path.join(w("out_dir"), "posture.json"),
                             "--export", f"{w('sample_policy_workspace_id').strip()}={w('sample_policy_export_path').strip()}",
                             "--out", os.path.join(w("out_dir"), "sample-policy")])
else:
    print("No sample policy requested (sample_policy_workspace_id / sample_policy_export_path blank).")
