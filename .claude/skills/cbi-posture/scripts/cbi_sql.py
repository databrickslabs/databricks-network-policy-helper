"""Read-only diagnostic SQL for a CBI (context-based ingress) security-posture review.

Single source of truth for every query the skill runs. `python cbi_sql.py --emit <dir>` writes each
query to `<dir>/NN_<name>.sql` (the copies checked in under `sql/` and reused as Genie trusted
queries) so the files and the collector can never drift.

Design rules (mirrors databricks-network-policy-helper/src/dbx_nwp_helper/queries.py):
  * SELECT-only. Nothing here writes, so it is safe to hand to a customer or to Genie.
  * Portable IP parsing (regex + integer bounds). The DBSQL INET built-ins (ip_cidr_contains, ...)
    are a non-public preview and raise INET_FUNCTIONS_NOT_ENABLED on most warehouses.
  * One named parameter, `:lookback_days` (INT). It works with the Statement Execution API,
    the SQL editor, and Genie trusted queries alike.
  * `system.access.audit.workspace_id` / `system.access.inbound_network.workspace_id` are STRING,
    and the tables are account-wide across every workspace that shares the metastore. Queries group
    by workspace rather than assuming a single one.
  * `system.access.inbound_network` outcome values differ between doc pages and releases
    (DENY / DENIED / DROP for enforced, DENY_DRY_RUN / DRY_RUN_DENIAL for dry-run), and some docs
    call the column `access_type` instead of `policy_outcome`. Every inbound query normalises the
    value through OUTCOME_CLASS; the collector swaps the column name if DESCRIBE shows otherwise.
"""

from __future__ import annotations

import argparse
import ipaddress
from pathlib import Path

# RFC1918 + loopback + link-local + CGNAT + TEST-NETs + benchmarking + 0/8. Never valid CBI sources.
NON_PUBLIC_V4 = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
]


def _non_public_predicate(col: str = "ip_long") -> str:
    parts = []
    for cidr in NON_PUBLIC_V4:
        n = ipaddress.ip_network(cidr)
        parts.append(f"{col} BETWEEN {int(n.network_address)} AND {int(n.broadcast_address)} /* {cidr} */")
    return "\n           OR ".join(parts)


# Shared audit CTE: one row per audit event with source IP, its class, and the principal type.
# ip_class ∈ public_v4 | private_v4 | ipv6 | other
AUDIT_CTE = """audit_raw AS (
  SELECT
    event_date,
    CAST(workspace_id AS STRING)                                         AS workspace_id,
    service_name,
    action_name,
    COALESCE(NULLIF(trim(user_identity.email), ''), NULLIF(trim(user_identity.subject_name), ''), 'UNKNOWN') AS principal,
    trim(source_ip_address)                                              AS source_ip,
    user_agent,
    response.status_code                                                 AS status_code
  FROM system.access.audit
  WHERE event_date >= date_sub(current_date(), :lookback_days)
    AND __AUDIT_SCOPE__
    AND source_ip_address IS NOT NULL
    AND trim(source_ip_address) <> ''
),
audit_parsed AS (
  SELECT *,
    CASE WHEN source_ip RLIKE '^[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}$' THEN
        CAST(split(source_ip, '[.]')[0] AS BIGINT) * 16777216
      + CAST(split(source_ip, '[.]')[1] AS BIGINT) * 65536
      + CAST(split(source_ip, '[.]')[2] AS BIGINT) * 256
      + CAST(split(source_ip, '[.]')[3] AS BIGINT)
    END AS ip_long
  FROM audit_raw
),
audit AS (
  SELECT *,
    CASE
      WHEN ip_long IS NOT NULL AND (
           __NON_PUBLIC__
      ) THEN 'private_v4'
      WHEN ip_long IS NOT NULL THEN 'public_v4'
      WHEN source_ip LIKE '%:%' THEN 'ipv6'
      ELSE 'other'
    END AS ip_class,
    CASE WHEN ip_long IS NOT NULL
         THEN concat_ws('.', split(source_ip, '[.]')[0], split(source_ip, '[.]')[1],
                        split(source_ip, '[.]')[2], '0') || '/24'
    END AS network_24,
    CASE
      WHEN principal RLIKE '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        THEN 'service_principal'
      WHEN principal LIKE '%@%' THEN 'user'
      WHEN principal = 'UNKNOWN' THEN 'unknown'
      ELSE 'other'
    END AS principal_type,
    (status_code IS NULL OR status_code < 400) AS succeeded
  FROM audit_parsed
)""".replace("__NON_PUBLIC__", _non_public_predicate())

# Workspace scope. Unscoped, every query reads the whole account's audit log: slow on large accounts, and
# the account-wide LIMITs can crowd out the workspaces being assessed. The collector replaces these markers
# with the assessed workspace ids plus '0' (account-level events); the emitted .sql files say how to.
AUDIT_SCOPE_MARK = "TRUE /* cbi:workspace-scope (all workspaces). To scope: workspace_id IN ('<id>', '0') */"
INBOUND_SCOPE_MARK = "TRUE /* cbi:workspace-scope (all workspaces). To scope: CAST(workspace_id AS STRING) IN ('<id>', '0') */"
AUDIT_CTE = AUDIT_CTE.replace("__AUDIT_SCOPE__", AUDIT_SCOPE_MARK)


def scope(stmt: str, workspace_ids) -> str:
    """Restrict a query to the given workspace ids (+ '0', account level). None/empty = whole account."""
    ids = sorted({str(i).strip() for i in (workspace_ids or []) if str(i).strip()})
    if not ids:
        return stmt
    bad = [i for i in ids if not i.isdigit()]
    if bad:
        raise ValueError(f"workspace ids must be numeric: {bad}")
    lst = ", ".join(f"'{i}'" for i in ids + (["0"] if "0" not in ids else []))
    return (stmt.replace(AUDIT_SCOPE_MARK, f"workspace_id IN ({lst})")
                .replace(INBOUND_SCOPE_MARK, f"CAST(workspace_id AS STRING) IN ({lst})"))


# Normalise the inbound_network outcome to DENIED / DRY_RUN_DENIAL / <raw>.
OUTCOME_CLASS = """CASE
      WHEN upper(policy_outcome) LIKE '%DRY%RUN%' THEN 'DRY_RUN_DENIAL'
      WHEN upper(policy_outcome) IN ('DENY', 'DENIED', 'DROP') THEN 'DENIED'
      ELSE upper(policy_outcome)
    END"""

INBOUND_CTE = f"""inbound AS (
  SELECT
    CAST(workspace_id AS STRING) AS workspace_id,
    event_time,
    request_path,
    source.ip                    AS source_ip,
    authenticated_as,
    rule_label,
    {OUTCOME_CLASS} AS outcome
  FROM system.access.inbound_network
  WHERE event_time >= date_sub(current_date(), :lookback_days)
    AND __INBOUND_SCOPE__
)""".replace("__INBOUND_SCOPE__", INBOUND_SCOPE_MARK)

# User-agent families that usually mean a SaaS / BI client with rotating egress IPs. These are
# better served by identity-based rules or the managed "Partner platforms" source than by CIDRs.
CLIENT_FAMILY = """CASE
      WHEN user_agent ILIKE '%powerbi%' OR user_agent ILIKE '%power bi%' OR user_agent ILIKE '%PBI%' THEN 'Power BI'
      WHEN user_agent ILIKE '%tableau%'                                   THEN 'Tableau'
      WHEN user_agent ILIKE '%dbt%'                                       THEN 'dbt'
      WHEN user_agent ILIKE '%fivetran%'                                  THEN 'Fivetran'
      WHEN user_agent ILIKE '%looker%'                                    THEN 'Looker'
      WHEN user_agent ILIKE '%chatgpt%' OR user_agent ILIKE '%openai%'    THEN 'ChatGPT'
      WHEN user_agent ILIKE '%claude%' OR user_agent ILIKE '%anthropic%'  THEN 'Claude'
      WHEN user_agent ILIKE '%terraform%'                                 THEN 'Terraform'
      WHEN user_agent ILIKE '%databricks-cli%' OR user_agent ILIKE '%cli/%' THEN 'Databricks CLI'
      WHEN user_agent ILIKE '%databricks-sdk%'                            THEN 'Databricks SDK'
      WHEN user_agent ILIKE '%jdbc%' OR user_agent ILIKE '%odbc%' OR user_agent ILIKE '%SimbaSpark%' THEN 'JDBC/ODBC'
      WHEN user_agent ILIKE '%mozilla%'                                   THEN 'Browser'
      WHEN user_agent IS NULL OR user_agent = ''                          THEN 'Unknown'
      ELSE 'Other'
    END"""


# name -> (description, sql). Order matters: it is the numbering of the emitted files.
QUERIES: dict[str, tuple[str, str]] = {
    "traffic_by_ip_class": (
        "Per workspace: how much audited traffic arrives from public IPv4, private IPv4 and IPv6, "
        "and how many distinct public sources / principals there are. workspace_id '0' = account level.",
        f"""WITH {AUDIT_CTE}
SELECT
  workspace_id,
  COUNT(*)                                                                    AS events,
  SUM(CASE WHEN ip_class = 'public_v4'  THEN 1 ELSE 0 END)                    AS public_v4_events,
  SUM(CASE WHEN ip_class = 'private_v4' THEN 1 ELSE 0 END)                    AS private_v4_events,
  SUM(CASE WHEN ip_class = 'ipv6'       THEN 1 ELSE 0 END)                    AS ipv6_events,
  COUNT(DISTINCT CASE WHEN ip_class = 'public_v4' THEN source_ip END)         AS distinct_public_ips,
  COUNT(DISTINCT CASE WHEN ip_class = 'public_v4' THEN network_24 END)        AS distinct_public_24s,
  COUNT(DISTINCT CASE WHEN ip_class = 'ipv6' THEN source_ip END)              AS distinct_ipv6_ips,
  COUNT(DISTINCT CASE WHEN ip_class = 'public_v4' THEN principal END)         AS public_principals,
  ROUND(100.0 * SUM(CASE WHEN ip_class = 'public_v4' THEN 1 ELSE 0 END) / COUNT(*), 1) AS public_pct
FROM audit
GROUP BY workspace_id
ORDER BY public_v4_events DESC""",
    ),
    "top_public_source_ips": (
        "The public IPv4 sources carrying successful traffic, the candidates a CBI allow-list must cover.",
        f"""WITH {AUDIT_CTE}
SELECT
  source_ip,
  network_24,
  COUNT(*)                                     AS events,
  COUNT(DISTINCT principal)                    AS principals,
  COUNT(DISTINCT workspace_id)                 AS workspaces,
  COUNT(DISTINCT event_date)                   AS active_days,
  MIN(event_date)                              AS first_seen,
  MAX(event_date)                              AS last_seen,
  slice(sort_array(collect_set(service_name)), 1, 8) AS services,
  slice(sort_array(collect_set(principal)), 1, 5)    AS sample_principals
FROM audit
WHERE ip_class = 'public_v4' AND succeeded
GROUP BY source_ip, network_24
ORDER BY events DESC
LIMIT 500""",
    ),
    "principal_network_spread": (
        "Principals connecting from many public networks. High spread usually means remote users "
        "without a VPN or SaaS clients with rotating IPs. Both are hard to pin with CIDRs and are "
        "candidates for identity-based rules or partner-platform sources.",
        f"""WITH {AUDIT_CTE}
SELECT
  principal,
  principal_type,
  COUNT(DISTINCT source_ip)    AS distinct_public_ips,
  COUNT(DISTINCT network_24)   AS distinct_public_24s,
  COUNT(DISTINCT workspace_id) AS workspaces,
  COUNT(*)                     AS events,
  MAX(event_date)              AS last_seen
FROM audit
WHERE ip_class = 'public_v4' AND succeeded
GROUP BY principal, principal_type
HAVING COUNT(DISTINCT network_24) >= 2
ORDER BY distinct_public_24s DESC, events DESC
LIMIT 200""",
    ),
    "client_families_on_public_ips": (
        "Which client tools (BI, SaaS, CLI, browser, JDBC/ODBC) reach Databricks over public IPs, "
        "used to decide between CIDR rules, identity rules and the managed Partner platforms source.",
        f"""WITH {AUDIT_CTE}
SELECT
  workspace_id,
  {CLIENT_FAMILY} AS client_family,
  COUNT(*)                   AS events,
  COUNT(DISTINCT source_ip)  AS distinct_public_ips,
  COUNT(DISTINCT network_24) AS distinct_public_24s,
  COUNT(DISTINCT principal)  AS principals
FROM audit
WHERE ip_class = 'public_v4' AND succeeded
GROUP BY ALL
ORDER BY events DESC
LIMIT 500""",
    ),
    "ip_access_list_denials": (
        "Requests the legacy IP access lists blocked (audit action IpAccessDenied), per workspace and source IP.",
        f"""WITH {AUDIT_CTE}
SELECT
  workspace_id,
  source_ip,
  ip_class,
  COUNT(*)                                        AS denied_events,
  COUNT(DISTINCT principal)                       AS principals,
  slice(sort_array(collect_set(principal)), 1, 5) AS sample_principals,
  MIN(event_date)                                 AS first_denied,
  MAX(event_date)                                 AS last_denied
FROM audit
WHERE action_name = 'IpAccessDenied'
GROUP BY workspace_id, source_ip, ip_class
ORDER BY denied_events DESC
LIMIT 500""",
    ),
    "account_level_public_access": (
        "Public sources reaching the account console / account APIs (workspace_id = '0'), the surface "
        "an account-level CBI policy (Beta, `account-policy`) protects.",
        f"""WITH {AUDIT_CTE}
SELECT
  source_ip,
  COUNT(*)                                        AS events,
  COUNT(DISTINCT principal)                       AS principals,
  slice(sort_array(collect_set(principal)), 1, 5) AS sample_principals,
  slice(sort_array(collect_set(action_name)), 1, 8) AS sample_actions,
  MAX(event_date)                                 AS last_seen
FROM audit
WHERE workspace_id = '0' AND ip_class = 'public_v4' AND succeeded
GROUP BY source_ip
ORDER BY events DESC
LIMIT 200""",
    ),
    "inbound_policy_outcomes": (
        "CBI policy evaluation outcomes per workspace from system.access.inbound_network: enforced "
        "denials and dry-run would-be denials.",
        f"""WITH {INBOUND_CTE}
SELECT
  workspace_id,
  outcome,
  COUNT(*)                         AS events,
  COUNT(DISTINCT source_ip)        AS distinct_source_ips,
  COUNT(DISTINCT authenticated_as) AS identities,
  COUNT(DISTINCT rule_label)       AS rules,
  MIN(event_time)                  AS first_seen,
  MAX(event_time)                  AS last_seen
FROM inbound
GROUP BY workspace_id, outcome
ORDER BY workspace_id, events DESC""",
    ),
    "dry_run_would_block": (
        "What a dry-run CBI policy WOULD block if enforced today: the gap to close before enforcing.",
        f"""WITH {INBOUND_CTE}
SELECT
  workspace_id,
  rule_label,
  source_ip,
  authenticated_as,
  COUNT(*)                                          AS events,
  slice(sort_array(collect_set(request_path)), 1, 5) AS sample_paths,
  MAX(event_time)                                   AS last_seen
FROM inbound
WHERE outcome = 'DRY_RUN_DENIAL'
GROUP BY ALL
ORDER BY events DESC
LIMIT 500""",
    ),
    "enforced_denials": (
        "Requests an ENFORCED CBI policy blocked. A spike right after a change usually means a "
        "legitimate client was missed.",
        f"""WITH {INBOUND_CTE}
SELECT
  workspace_id,
  CAST(event_time AS DATE)         AS day,
  rule_label,
  COUNT(*)                         AS denied_events,
  COUNT(DISTINCT source_ip)        AS distinct_source_ips,
  COUNT(DISTINCT authenticated_as) AS identities,
  slice(sort_array(collect_set(source_ip)), 1, 10) AS sample_source_ips
FROM inbound
WHERE outcome = 'DENIED'
GROUP BY ALL
ORDER BY day DESC, denied_events DESC
LIMIT 500""",
    ),
    "public_browser_vs_api": (
        "Per workspace: public traffic from browsers vs programmatic clients (CLI, SDK, JDBC/ODBC, BI, "
        "scripts), and how many identities use programmatic access from public IPs. A small number of "
        "programmatic identities makes the 'browser yes, remote APIs no' CBI pattern feasible.",
        f"""WITH {AUDIT_CTE},
labelled AS (
  SELECT *, {CLIENT_FAMILY} AS client_family FROM audit
  WHERE ip_class = 'public_v4' AND succeeded AND workspace_id <> '0'
)
SELECT
  workspace_id,
  COUNT(*)                                                                         AS public_events,
  SUM(CASE WHEN client_family = 'Browser' THEN 1 ELSE 0 END)                       AS browser_events,
  SUM(CASE WHEN client_family <> 'Browser' THEN 1 ELSE 0 END)                      AS programmatic_events,
  COUNT(DISTINCT CASE WHEN client_family <> 'Browser' THEN principal END)          AS programmatic_principals,
  COUNT(DISTINCT CASE WHEN client_family <> 'Browser' AND principal_type = 'user' THEN principal END)
                                                                                   AS programmatic_users,
  COUNT(DISTINCT CASE WHEN client_family <> 'Browser' AND principal_type = 'service_principal' THEN principal END)
                                                                                   AS programmatic_service_principals,
  COUNT(DISTINCT CASE WHEN client_family <> 'Browser' THEN source_ip END)          AS programmatic_public_ips,
  ROUND(100.0 * SUM(CASE WHEN client_family = 'Browser' THEN 1 ELSE 0 END) / COUNT(*), 1) AS browser_pct
FROM labelled
GROUP BY workspace_id
ORDER BY public_events DESC""",
    ),
    "audit_visibility": (
        "Evidence coverage per workspace: the audit window actually available, and whether verbose audit "
        "logging was switched off (a visibility gap for every conclusion after that point). An empty "
        "result means no matching events in this window, not proof that nothing happened.",
        f"""SELECT
  CAST(workspace_id AS STRING)  AS workspace_id,
  MIN(event_date)               AS first_event_date,
  MAX(event_date)               AS last_event_date,
  COUNT(DISTINCT event_date)    AS days_with_events,
  COUNT(*)                      AS events,
  SUM(CASE WHEN action_name = 'workspaceConfEdit'
            AND request_params['workspaceConfKeys'] = 'enableVerboseAuditLogs'
            AND lower(request_params['workspaceConfValues']) = 'false' THEN 1 ELSE 0 END) AS verbose_audit_disabled_events,
  MAX(CASE WHEN action_name = 'workspaceConfEdit'
            AND request_params['workspaceConfKeys'] = 'enableVerboseAuditLogs'
            AND lower(request_params['workspaceConfValues']) = 'false' THEN event_time END)   AS last_verbose_audit_disabled
FROM system.access.audit
WHERE event_date >= date_sub(current_date(), :lookback_days)
  AND {AUDIT_SCOPE_MARK}
GROUP BY CAST(workspace_id AS STRING)
ORDER BY workspace_id""",
    ),
    "new_source_identity_combinations": (
        "Triage signal (not a detector): identities seen in the last day from a public IP they did not use "
        "in the rest of the lookback window. A new IP alone is weak evidence for roaming users; look "
        "for it combined with sensitive actions. Adapted from the 'new source and identity' starter query.",
        f"""WITH {AUDIT_CTE},
public_events AS (
  SELECT event_date, workspace_id, principal, principal_type, source_ip, service_name, action_name
  FROM audit
  WHERE ip_class = 'public_v4' AND principal <> 'UNKNOWN'
),
known AS (
  SELECT DISTINCT principal, source_ip FROM public_events
  WHERE event_date < date_sub(current_date(), 1)
)
SELECT
  r.workspace_id,
  r.principal,
  r.principal_type,
  r.source_ip,
  COUNT(*)                                            AS events,
  slice(sort_array(collect_set(r.action_name)), 1, 10) AS sample_actions,
  MAX(r.event_date)                                   AS last_seen
FROM public_events r
LEFT ANTI JOIN known k ON r.principal = k.principal AND r.source_ip = k.source_ip
WHERE r.event_date >= date_sub(current_date(), 1)
GROUP BY r.workspace_id, r.principal, r.principal_type, r.source_ip
ORDER BY events DESC
LIMIT 500""",
    ),
    "source_ips_by_workspace": (
        "Per-workspace profile of every public IPv4 source carrying successful traffic: volume, identities, "
        "clients and first/last seen. Feeds the sample-policy review sheet (which source each proposed rule "
        "covers, and which observed sources no rule covers).",
        f"""WITH {AUDIT_CTE}
SELECT
  workspace_id,
  source_ip,
  COUNT(*)                                                  AS events,
  COUNT(DISTINCT principal)                                 AS principals,
  COUNT(DISTINCT CASE WHEN principal_type = 'user' THEN principal END)              AS users,
  COUNT(DISTINCT CASE WHEN principal_type = 'service_principal' THEN principal END) AS service_principals,
  COUNT(DISTINCT event_date)                                AS active_days,
  MIN(event_date)                                           AS first_seen,
  MAX(event_date)                                           AS last_seen,
  slice(sort_array(collect_set({CLIENT_FAMILY.strip()})), 1, 6) AS client_families,
  slice(sort_array(collect_set(principal)), 1, 5)           AS sample_principals
FROM audit
WHERE ip_class = 'public_v4' AND succeeded
GROUP BY workspace_id, source_ip
ORDER BY workspace_id, events DESC
LIMIT 20000""",
    ),
}


# ------------------------------------------------------------------------------------------ rollup
# Single-pass mode for large accounts. The collector reads system.access.audit ONCE into a rollup: events
# grouped by date, workspace, service, principal, source IP, client family and outcome, with a count. IP
# parsing and client classification run on the grouped rows, not on every event, and the audit queries
# below run over the rollup (SUM(events) where the direct queries COUNT(*)). action_name is kept only where
# a query uses it (IpAccessDenied, account-level events, the last day), which keeps the rollup small.
#   * notebook compute: the rollup is a cached DataFrame (serverless DataFrame cache, environment 5+).
#   * --stage-schema: the rollup is a temporary table in a schema the customer names, dropped at the end.
# The direct QUERIES above stay the single source for the .sql files, warehouses and Genie; tests check that
# both forms return the same rows.
AUDIT_SOURCE = "FROM system.access.audit"
ROLLUP_REF = "__CBI_ROLLUP__"
DF_SOURCE = "cbi_rollup"  # spark.sql(..., cbi_rollup=<DataFrame>) placeholder name
VERBOSE_OFF = """action_name = 'workspaceConfEdit'
             AND request_params['workspaceConfKeys'] = 'enableVerboseAuditLogs'
             AND lower(request_params['workspaceConfValues']) = 'false'"""


def rollup_select(lookback_days: int, workspace_ids=None) -> str:
    """SELECT the audit rollup the rollup queries run over: one scan of system.access.audit."""
    days = int(lookback_days)
    grouped = f"""audit_raw AS (
  SELECT
    event_date,
    CAST(workspace_id AS STRING) AS workspace_id,
    service_name,
    CASE WHEN action_name = 'IpAccessDenied' OR CAST(workspace_id AS STRING) = '0'
              OR event_date >= date_sub(current_date(), 1) THEN action_name END AS action_name,
    COALESCE(NULLIF(trim(user_identity.email), ''), NULLIF(trim(user_identity.subject_name), ''), 'UNKNOWN') AS principal,
    NULLIF(trim(source_ip_address), '') AS source_ip,
    user_agent,
    response.status_code AS status_code,
    COUNT(*) AS events,
    SUM(CASE WHEN {VERBOSE_OFF} THEN 1 ELSE 0 END) AS verbose_off_events,
    MAX(CASE WHEN {VERBOSE_OFF} THEN event_time END) AS last_verbose_off
  FROM system.access.audit
  WHERE event_date >= date_sub(current_date(), {days})
    AND {AUDIT_SCOPE_MARK}
  GROUP BY 1, 2, 3, 4, 5, 6, 7, 8
),
"""
    classify = AUDIT_CTE[AUDIT_CTE.index("audit_parsed AS ("):]  # same IP parsing / principal typing
    stmt = f"""WITH {grouped}{classify}
SELECT
  event_date, workspace_id, service_name, action_name, principal, principal_type,
  source_ip, ip_class, network_24,
  {CLIENT_FAMILY} AS client_family,
  succeeded,
  SUM(events)             AS events,
  SUM(verbose_off_events) AS verbose_off_events,
  MAX(last_verbose_off)   AS last_verbose_off
FROM audit
GROUP BY ALL"""
    return scope(stmt, workspace_ids)


def stage_statement(table: str, lookback_days: int, workspace_ids=None) -> str:
    """CREATE TABLE … AS the audit rollup (explicit --stage-schema only)."""
    return (f"CREATE OR REPLACE TABLE {table}\n"
            "COMMENT 'Temporary rollup of system.access.audit for one cbi-posture run (dropped when the run ends). "
            "Contains identities and source IPs.'\nAS " + rollup_select(lookback_days, workspace_ids))


def reads_audit(stmt: str) -> bool:
    return AUDIT_SOURCE in stmt


def over_rollup(name: str, ref: str) -> str:
    """A rollup query reading `ref`: a table name, or '{cbi_rollup}' for spark.sql(..., cbi_rollup=df)."""
    stmt = ROLLUP_QUERIES[name]
    if ref.startswith("{"):  # spark.sql formats DataFrame kwargs with str.format
        stmt = stmt.replace("{", "{{").replace("}", "}}")
    return stmt.replace(ROLLUP_REF, ref)


_R_AUDIT = f"audit AS (SELECT * FROM {ROLLUP_REF} WHERE source_ip IS NOT NULL)"

ROLLUP_QUERIES: dict[str, str] = {
    "traffic_by_ip_class": f"""WITH {_R_AUDIT}
SELECT
  workspace_id,
  SUM(events)                                                                 AS events,
  SUM(CASE WHEN ip_class = 'public_v4'  THEN events ELSE 0 END)               AS public_v4_events,
  SUM(CASE WHEN ip_class = 'private_v4' THEN events ELSE 0 END)               AS private_v4_events,
  SUM(CASE WHEN ip_class = 'ipv6'       THEN events ELSE 0 END)               AS ipv6_events,
  COUNT(DISTINCT CASE WHEN ip_class = 'public_v4' THEN source_ip END)         AS distinct_public_ips,
  COUNT(DISTINCT CASE WHEN ip_class = 'public_v4' THEN network_24 END)        AS distinct_public_24s,
  COUNT(DISTINCT CASE WHEN ip_class = 'ipv6' THEN source_ip END)              AS distinct_ipv6_ips,
  COUNT(DISTINCT CASE WHEN ip_class = 'public_v4' THEN principal END)         AS public_principals,
  ROUND(100.0 * SUM(CASE WHEN ip_class = 'public_v4' THEN events ELSE 0 END) / SUM(events), 1) AS public_pct
FROM audit
GROUP BY workspace_id
ORDER BY public_v4_events DESC""",
    "top_public_source_ips": f"""WITH {_R_AUDIT}
SELECT
  source_ip,
  network_24,
  SUM(events)                                  AS events,
  COUNT(DISTINCT principal)                    AS principals,
  COUNT(DISTINCT workspace_id)                 AS workspaces,
  COUNT(DISTINCT event_date)                   AS active_days,
  MIN(event_date)                              AS first_seen,
  MAX(event_date)                              AS last_seen,
  slice(sort_array(collect_set(service_name)), 1, 8) AS services,
  slice(sort_array(collect_set(principal)), 1, 5)    AS sample_principals
FROM audit
WHERE ip_class = 'public_v4' AND succeeded
GROUP BY source_ip, network_24
ORDER BY events DESC
LIMIT 500""",
    "principal_network_spread": f"""WITH {_R_AUDIT}
SELECT
  principal,
  principal_type,
  COUNT(DISTINCT source_ip)    AS distinct_public_ips,
  COUNT(DISTINCT network_24)   AS distinct_public_24s,
  COUNT(DISTINCT workspace_id) AS workspaces,
  SUM(events)                  AS events,
  MAX(event_date)              AS last_seen
FROM audit
WHERE ip_class = 'public_v4' AND succeeded
GROUP BY principal, principal_type
HAVING COUNT(DISTINCT network_24) >= 2
ORDER BY distinct_public_24s DESC, events DESC
LIMIT 200""",
    "client_families_on_public_ips": f"""WITH {_R_AUDIT}
SELECT
  workspace_id,
  client_family,
  SUM(events)                AS events,
  COUNT(DISTINCT source_ip)  AS distinct_public_ips,
  COUNT(DISTINCT network_24) AS distinct_public_24s,
  COUNT(DISTINCT principal)  AS principals
FROM audit
WHERE ip_class = 'public_v4' AND succeeded
GROUP BY workspace_id, client_family
ORDER BY events DESC
LIMIT 500""",
    "ip_access_list_denials": f"""WITH {_R_AUDIT}
SELECT
  workspace_id,
  source_ip,
  ip_class,
  SUM(events)                                     AS denied_events,
  COUNT(DISTINCT principal)                       AS principals,
  slice(sort_array(collect_set(principal)), 1, 5) AS sample_principals,
  MIN(event_date)                                 AS first_denied,
  MAX(event_date)                                 AS last_denied
FROM audit
WHERE action_name = 'IpAccessDenied'
GROUP BY workspace_id, source_ip, ip_class
ORDER BY denied_events DESC
LIMIT 500""",
    "account_level_public_access": f"""WITH {_R_AUDIT}
SELECT
  source_ip,
  SUM(events)                                     AS events,
  COUNT(DISTINCT principal)                       AS principals,
  slice(sort_array(collect_set(principal)), 1, 5) AS sample_principals,
  slice(sort_array(collect_set(action_name)), 1, 8) AS sample_actions,
  MAX(event_date)                                 AS last_seen
FROM audit
WHERE workspace_id = '0' AND ip_class = 'public_v4' AND succeeded
GROUP BY source_ip
ORDER BY events DESC
LIMIT 200""",
    "public_browser_vs_api": f"""WITH {_R_AUDIT},
labelled AS (
  SELECT * FROM audit
  WHERE ip_class = 'public_v4' AND succeeded AND workspace_id <> '0'
)
SELECT
  workspace_id,
  SUM(events)                                                                      AS public_events,
  SUM(CASE WHEN client_family = 'Browser' THEN events ELSE 0 END)                  AS browser_events,
  SUM(CASE WHEN client_family <> 'Browser' THEN events ELSE 0 END)                 AS programmatic_events,
  COUNT(DISTINCT CASE WHEN client_family <> 'Browser' THEN principal END)          AS programmatic_principals,
  COUNT(DISTINCT CASE WHEN client_family <> 'Browser' AND principal_type = 'user' THEN principal END)
                                                                                   AS programmatic_users,
  COUNT(DISTINCT CASE WHEN client_family <> 'Browser' AND principal_type = 'service_principal' THEN principal END)
                                                                                   AS programmatic_service_principals,
  COUNT(DISTINCT CASE WHEN client_family <> 'Browser' THEN source_ip END)          AS programmatic_public_ips,
  ROUND(100.0 * SUM(CASE WHEN client_family = 'Browser' THEN events ELSE 0 END) / SUM(events), 1) AS browser_pct
FROM labelled
GROUP BY workspace_id
ORDER BY public_events DESC""",
    "audit_visibility": f"""SELECT
  workspace_id,
  MIN(event_date)               AS first_event_date,
  MAX(event_date)               AS last_event_date,
  COUNT(DISTINCT event_date)    AS days_with_events,
  SUM(events)                   AS events,
  SUM(verbose_off_events)       AS verbose_audit_disabled_events,
  MAX(last_verbose_off)         AS last_verbose_audit_disabled
FROM {ROLLUP_REF}
GROUP BY workspace_id
ORDER BY workspace_id""",
    "new_source_identity_combinations": f"""WITH {_R_AUDIT},
public_events AS (
  SELECT event_date, workspace_id, principal, principal_type, source_ip, service_name, action_name, events
  FROM audit
  WHERE ip_class = 'public_v4' AND principal <> 'UNKNOWN'
),
known AS (
  SELECT DISTINCT principal, source_ip FROM public_events
  WHERE event_date < date_sub(current_date(), 1)
)
SELECT
  r.workspace_id,
  r.principal,
  r.principal_type,
  r.source_ip,
  SUM(r.events)                                       AS events,
  slice(sort_array(collect_set(r.action_name)), 1, 10) AS sample_actions,
  MAX(r.event_date)                                   AS last_seen
FROM public_events r
LEFT ANTI JOIN known k ON r.principal = k.principal AND r.source_ip = k.source_ip
WHERE r.event_date >= date_sub(current_date(), 1)
GROUP BY r.workspace_id, r.principal, r.principal_type, r.source_ip
ORDER BY events DESC
LIMIT 500""",
    "source_ips_by_workspace": f"""WITH {_R_AUDIT}
SELECT
  workspace_id,
  source_ip,
  SUM(events)                                               AS events,
  COUNT(DISTINCT principal)                                 AS principals,
  COUNT(DISTINCT CASE WHEN principal_type = 'user' THEN principal END)              AS users,
  COUNT(DISTINCT CASE WHEN principal_type = 'service_principal' THEN principal END) AS service_principals,
  COUNT(DISTINCT event_date)                                AS active_days,
  MIN(event_date)                                           AS first_seen,
  MAX(event_date)                                           AS last_seen,
  slice(sort_array(collect_set(client_family)), 1, 6)       AS client_families,
  slice(sort_array(collect_set(principal)), 1, 5)           AS sample_principals
FROM audit
WHERE ip_class = 'public_v4' AND succeeded
GROUP BY workspace_id, source_ip
ORDER BY workspace_id, events DESC
LIMIT 20000""",
}
assert set(ROLLUP_QUERIES) == {n for n, (_d, q) in QUERIES.items() if reads_audit(q)}, "rollup/direct query drift"


def genie_views(schema: str = "<catalog>.<schema>", days: int = 90) -> str:
    """CREATE VIEW statements for the Genie agent: the same parsing/classification as the diagnostic
    queries, with a fixed rolling window (views can't take parameters). Run them yourself in a schema
    you own. They are the only DDL in this skill, and they only read system tables."""
    audit = AUDIT_CTE.replace(":lookback_days", str(days))
    inbound = INBOUND_CTE.replace(":lookback_days", str(days))
    return f"""-- Genie views for the CBI posture agent. Replace {schema} and run once (needs CREATE VIEW on the schema
-- and SELECT on system.access.audit / system.access.inbound_network). Rolling {days}-day window.
-- Generated by .claude/skills/cbi-posture/scripts/cbi_sql.py --emit-genie; edit there.

CREATE OR REPLACE VIEW {schema}.cbi_audit_access
COMMENT 'Audit events with source-IP class (public_v4/private_v4/ipv6/other), /24 network, principal type and client family. Last {days} days. workspace_id 0 = account level.'
AS WITH {audit}
SELECT event_date, workspace_id, service_name, action_name, principal, principal_type,
       source_ip, ip_class, network_24, user_agent,
       {CLIENT_FAMILY} AS client_family,
       status_code, succeeded
FROM audit;

CREATE OR REPLACE VIEW {schema}.cbi_inbound_events
COMMENT 'CBI policy evaluations from system.access.inbound_network. outcome = DENIED (enforced block) or DRY_RUN_DENIAL (would be blocked). Last {days} days.'
AS WITH {inbound}
SELECT * FROM inbound;

-- Requires the collector to have run with --uc-schema {schema} at least once.
CREATE OR REPLACE VIEW {schema}.cbi_posture_latest
COMMENT 'Most recent posture snapshot per workspace (maturity level, policy mode, IP ACL / PrivateLink / egress state).'
AS SELECT * FROM {schema}.cbi_posture_workspaces
QUALIFY row_number() OVER (PARTITION BY workspace_id ORDER BY run_ts DESC) = 1;

CREATE OR REPLACE VIEW {schema}.cbi_findings_latest
COMMENT 'Findings from the most recent posture run.'
AS SELECT * FROM {schema}.cbi_posture_findings
WHERE run_id = (SELECT max_by(run_id, run_ts) FROM {schema}.cbi_posture_findings);
"""


def emit(out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for i, (name, (desc, sql)) in enumerate(QUERIES.items(), start=1):
        p = out_dir / f"{i:02d}_{name}.sql"
        header = (
            f"-- {name}\n-- {desc}\n"
            "-- Read-only. Parameter :lookback_days (INT, e.g. 30). Generated by scripts/cbi_sql.py; edit there.\n"
        )
        p.write_text(header + sql.strip() + ";\n")
        written.append(p)
    return written


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--emit", type=Path, help="directory to write the diagnostic .sql files into")
    ap.add_argument("--emit-genie", type=Path, help="file to write the Genie CREATE VIEW statements into")
    a = ap.parse_args()
    if a.emit:
        for path in emit(a.emit):
            print(path)
    if a.emit_genie:
        a.emit_genie.write_text(genie_views())
        print(a.emit_genie)
