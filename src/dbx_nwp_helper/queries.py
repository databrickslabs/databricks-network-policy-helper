"""SQL against the Databricks system tables.

IP parsing/versioning/range-membership can use the DBSQL INET built-ins (`try_ip_host`,
`ip_version`, `ip_cidr_contains`, `try_ip_cidr`) — fast, but a **non-public preview**: a warehouse
without them raises `INET_FUNCTIONS_NOT_ENABLED` (`ip_cidr_contains is disabled or unsupported. INET
functions are not publicly available yet.`). So every builder here takes `use_inet`:

  * use_inet=True  → the native INET builtins (the fast path; used by default).
  * use_inet=False → a portable regex/`split`-based parse + integer range checks that runs on any
    warehouse (the fallback).

The caller probes support once (see `INET_PROBE`) and picks the mode. Either way `core/ingress.py`
re-parses every candidate with the stdlib `ipaddress` module, so the SQL only has to be good enough
to filter, version, and aggregate.

The notebook staged an `audit_recent` temp view and read it repeatedly; over a stateless SQL
connection we inline that as a CTE / base subquery instead, so each query is self-contained.
"""

from __future__ import annotations

import ipaddress

# A one-shot probe: succeeds where the INET builtins are enabled, else raises
# INET_FUNCTIONS_NOT_ENABLED. The caller runs this once to choose native vs portable mode.
INET_PROBE = "SELECT ip_cidr_contains('10.0.0.0/8', '10.0.0.1') AS ok"

# --------------------------------------------------------------------------- native IP expressions
_NORMALIZED_IP_NATIVE = "try_ip_host(source_ip_address)"
_IP_VERSION_NATIVE = "ip_version(try_ip_host(source_ip_address))"

# --------------------------------------------------------------------------- portable IP expressions
# A permissive IPv4 shape test — four dot-separated digit groups. It is deliberately loose (it does
# not bound octets to 0-255): audit logs carry canonical client IPs, and `core/ingress.py` re-parses
# every candidate with `ipaddress`, dropping anything malformed. `[0-9]`/`[.]` (not `\d`/`\.`) keeps
# the pattern brace-free.
_IPV4_RLIKE = "source_ip_address RLIKE '^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+$'"

# normalized_ip: canonical-ish host string, NULL when the value is neither IPv4 nor IPv6 — the
# portable stand-in for try_ip_host(source_ip_address).
_NORMALIZED_IP_PORTABLE = f"""CASE
        WHEN {_IPV4_RLIKE} THEN trim(source_ip_address)
        WHEN source_ip_address LIKE '%:%' THEN lower(trim(source_ip_address))
      END"""

# ip_version: 4 / 6 / NULL — the portable stand-in for ip_version(try_ip_host(...)).
_IP_VERSION_PORTABLE = f"""CASE
        WHEN {_IPV4_RLIKE} THEN 4
        WHEN source_ip_address LIKE '%:%' THEN 6
      END"""

# ipv4_long: the IPv4 address as a 32-bit integer (NULL for non-IPv4), so private/reserved ranges can
# be excluded with integer BETWEEN checks instead of ip_cidr_contains(). Portable mode only.
_IPV4_LONG_PORTABLE = f"""CASE WHEN {_IPV4_RLIKE} THEN
        CAST(split(source_ip_address, '[.]')[0] AS BIGINT) * 16777216
        + CAST(split(source_ip_address, '[.]')[1] AS BIGINT) * 65536
        + CAST(split(source_ip_address, '[.]')[2] AS BIGINT) * 256
        + CAST(split(source_ip_address, '[.]')[3] AS BIGINT)
      END"""


def _audit_projection(
    use_inet: bool, predicate: str, *, always_ipv4_long: bool = False, with_request_params: bool = False
) -> str:
    """The base audit projection with normalized_ip / ip_version derived either natively or portably,
    filtered by `predicate` (an event_date window). Portable mode additionally projects ipv4_long
    (used by the integer-bounds private-range check); `always_ipv4_long` projects it in native mode
    too (the persisted daily table stores it so reads never need the INET builtins).
    `with_request_params` adds request_params (the posture verbose-audit check reads it)."""
    if use_inet:
        normalized, version = _NORMALIZED_IP_NATIVE, _IP_VERSION_NATIVE
        ipv4_long_col = f"{_IPV4_LONG_PORTABLE} AS ipv4_long,\n      " if always_ipv4_long else ""
    else:
        normalized, version = _NORMALIZED_IP_PORTABLE, _IP_VERSION_PORTABLE
        ipv4_long_col = f"{_IPV4_LONG_PORTABLE} AS ipv4_long,\n      "
    return f"""
    SELECT
      event_date, event_time, workspace_id, audit_level, service_name, action_name,
      COALESCE(user_identity.email, user_identity.subject_name, 'UNKNOWN') AS principal,
      user_identity.email AS principal_email,
      user_identity.subject_name AS subject_name,
      source_ip_address,
      {normalized} AS normalized_ip,
      {version} AS ip_version,
      {ipv4_long_col}user_agent,
      response.status_code AS status_code,
      session_id, request_id{", request_params" if with_request_params else ""}
    FROM system.access.audit
    WHERE {predicate}
"""


def _audit_recent(lookback_days: int, use_inet: bool) -> str:
    """The base audit projection the notebook exposed as the `audit_recent` temp view, over the last
    `lookback_days` days."""
    return _audit_projection(use_inet, f"event_date >= current_date() - INTERVAL {lookback_days} DAYS")


def audit_row_count(lookback_days: int, use_inet: bool = True) -> str:
    return f"SELECT COUNT(*) AS n FROM ({_audit_recent(lookback_days, use_inet)})"


# Private / reserved IPv4 ranges excluded from ingress candidates: RFC 1918 (10/8, 172.16/12,
# 192.168/16), loopback (127/8), link-local (169.254/16), CGNAT (100.64/10), and the TEST-NET /
# benchmarking ranges (192.0.2/24, 198.18/15, 198.51.100/24, 203.0.113/24). Declarative — both the
# native (ip_cidr_contains) and portable (integer bounds) predicates are generated from this list.
_PRIVATE_V4_CIDRS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "192.0.2.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
]


def _not_private(use_inet: bool) -> str:
    """A predicate that is TRUE when normalized_ip is a public IPv4 (or not IPv4 at all). Native mode
    uses ip_cidr_contains() on each range; portable mode uses integer BETWEEN checks on ipv4_long
    (bounds computed here via `ipaddress`, so the SQL carries only literals)."""
    if use_inet:
        checks = [f"ip_cidr_contains('{cidr}', normalized_ip)" for cidr in _PRIVATE_V4_CIDRS]
    else:
        checks = []
        for cidr in _PRIVATE_V4_CIDRS:
            net = ipaddress.ip_network(cidr)
            checks.append(f"ipv4_long BETWEEN {int(net.network_address)} AND {int(net.broadcast_address)}")
    checks.append("normalized_ip = '0.0.0.0'")
    joined = "\n        OR ".join(checks)
    return f"NOT (\n      ip_version = 4 AND (\n        {joined}\n      ))"


def candidate_funnel(lookback_days: int, treat_null_status_as_success: bool, use_inet: bool = True) -> str:
    """A single-row diagnostic showing how many audit rows survive each successive filter the
    candidate query applies — so an empty candidate set can be explained (private IPs? all
    account-level? nothing successful?). Independent of the include_* toggles: it always reports
    each dimension so the user can see which toggle would help."""
    null_status_ok = "TRUE" if treat_null_status_as_success else "FALSE"
    not_private = _not_private(use_inet)
    return f"""
    WITH a AS ({_audit_recent(lookback_days, use_inet)})
    SELECT
      COUNT(*) AS total_rows,
      SUM(CASE WHEN normalized_ip IS NOT NULL THEN 1 ELSE 0 END) AS with_source_ip,
      SUM(CASE WHEN normalized_ip IS NOT NULL AND ip_version = 4 THEN 1 ELSE 0 END) AS ipv4,
      SUM(CASE WHEN normalized_ip IS NOT NULL AND ip_version = 6 THEN 1 ELSE 0 END) AS ipv6,
      SUM(CASE WHEN normalized_ip IS NOT NULL
               AND (status_code < 400 OR (status_code IS NULL AND {null_status_ok}))
               THEN 1 ELSE 0 END) AS successful,
      SUM(CASE WHEN normalized_ip IS NOT NULL AND CAST(workspace_id AS STRING) <> '0'
               THEN 1 ELSE 0 END) AS workspace_level,
      SUM(CASE WHEN normalized_ip IS NOT NULL AND CAST(workspace_id AS STRING) = '0'
               THEN 1 ELSE 0 END) AS account_level,
      SUM(CASE WHEN normalized_ip IS NOT NULL AND ip_version = 4 AND {not_private}
               THEN 1 ELSE 0 END) AS public_ipv4,
      COUNT(DISTINCT CASE WHEN normalized_ip IS NOT NULL AND ip_version = 4 AND {not_private}
               AND (status_code < 400 OR (status_code IS NULL AND {null_status_ok}))
               THEN normalized_ip END) AS distinct_public_ok,
      COUNT(DISTINCT CASE WHEN normalized_ip IS NOT NULL AND ip_version = 4 AND {not_private}
               AND (status_code < 400 OR (status_code IS NULL AND {null_status_ok}))
               AND CAST(workspace_id AS STRING) <> '0'
               THEN normalized_ip END) AS distinct_public_ok_ws
    FROM a
    """


def surface_summary(lookback_days: int, use_inet: bool = True) -> str:
    return f"""
    WITH audit_recent AS ({_audit_recent(lookback_days, use_inet)})
    SELECT service_name, action_name,
      COUNT(*) AS events,
      COUNT(DISTINCT principal) AS principals,
      COUNT(DISTINCT normalized_ip) AS distinct_ips,
      COUNT(DISTINCT session_id) AS sessions,
      MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
    FROM audit_recent
    GROUP BY ALL
    ORDER BY events DESC, principals DESC
    LIMIT 100
    """


def _network_expr(use_inet: bool) -> str:
    """Each source IP's network: its /24 (IPv4) or /48 (IPv6). Native uses
    try_ip_cidr(CONCAT(ip,'/24' | '/48')); portable approximates it (IPv4 /24 = ipv4_long DIV 256,
    IPv6 the leading three hextets). Coarse, but it only feeds diagnostic counts."""
    if use_inet:
        return """CASE
          WHEN ip_version = 4 THEN CAST(try_ip_cidr(CONCAT(normalized_ip, '/24')) AS STRING)
          WHEN ip_version = 6 THEN CAST(try_ip_cidr(CONCAT(normalized_ip, '/48')) AS STRING)
        END"""
    return """CASE
          WHEN ip_version = 4 THEN CONCAT('v4:', CAST(ipv4_long DIV 256 AS STRING))
          WHEN ip_version = 6 THEN CONCAT('v6:', substring_index(normalized_ip, ':', 3))
        END"""


def principal_network_diversity(lookback_days: int, use_inet: bool = True) -> str:
    # distinct_networks approximates each principal's spread across networks (see _network_expr).
    networks = _network_expr(use_inet)
    return f"""
    WITH audit_recent AS ({_audit_recent(lookback_days, use_inet)}),
    principal_networks AS (
      SELECT principal,
        COUNT(*) AS events,
        COUNT(DISTINCT normalized_ip) AS distinct_ips,
        COUNT(DISTINCT {networks}) AS distinct_networks,
        COUNT(DISTINCT user_agent) AS distinct_user_agents,
        COUNT(DISTINCT service_name) AS distinct_services,
        MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
      FROM audit_recent
      WHERE normalized_ip IS NOT NULL
      GROUP BY principal
    )
    SELECT * FROM principal_networks
    ORDER BY distinct_networks DESC, distinct_ips DESC, events DESC
    LIMIT 100
    """


def frequent_public_ips(
    lookback_days: int,
    min_events: int,
    include_ipv6: bool,
    treat_null_status_as_success: bool,
    include_account_level: bool,
    only_workspace_id: int | None = None,
    use_inet: bool = True,
) -> str:
    ipv6_predicate = "OR ip_version = 6" if include_ipv6 else ""
    # workspace_id is a STRING column in system.access.audit; comparing to the integer 0 matches no
    # rows (silently excluding all workspace-level traffic), so compare against the string '0'.
    if only_workspace_id is not None:
        # current_workspace scope: restrict to this workspace's traffic. (Overrides the account-level
        # toggle — an explicit workspace id is never account-level.)
        account_level_predicate = f"AND CAST(workspace_id AS STRING) = '{int(only_workspace_id)}'"
    elif include_account_level:
        account_level_predicate = ""
    else:
        account_level_predicate = "AND CAST(workspace_id AS STRING) <> '0'"
    null_status_ok = "TRUE" if treat_null_status_as_success else "FALSE"
    return f"""
    WITH audit_recent AS ({_audit_recent(lookback_days, use_inet)}),
    successful AS (
      SELECT workspace_id, principal, principal_email, subject_name,
        service_name, action_name,
        normalized_ip AS public_ip, ip_version, event_date, session_id
      FROM audit_recent
      WHERE normalized_ip IS NOT NULL
        AND (ip_version = 4 {ipv6_predicate})
        AND (status_code < 400 OR (status_code IS NULL AND {null_status_ok}))
        {account_level_predicate}
        AND {_not_private(use_inet)}
    )
    SELECT public_ip,
      ANY_VALUE(ip_version) AS ip_version,
      COUNT(*) AS events,
      COUNT(DISTINCT principal) AS principals,
      COUNT(DISTINCT service_name) AS services,
      COUNT(DISTINCT action_name) AS actions,
      COUNT(DISTINCT event_date) AS active_days,
      COUNT(DISTINCT session_id) AS sessions,
      MIN(event_date) AS first_active_date, MAX(event_date) AS last_active_date,
      sort_array(collect_set(principal)) AS principal_list,
      sort_array(collect_set(principal_email)) AS principal_emails,
      sort_array(collect_set(subject_name)) AS subject_names,
      sort_array(collect_set(service_name)) AS service_list,
      sort_array(collect_set(workspace_id)) AS workspace_ids
    FROM successful
    GROUP BY public_ip
    HAVING COUNT(*) >= {min_events}
    ORDER BY events DESC, principals DESC
    """


def _workspace_predicate(only_workspace_id: int | None) -> str:
    """`AND CAST(workspace_id AS STRING) = '<id>'` for current_workspace scope, else ''. workspace_id
    is a STRING column in both system.access.audit and system.access.inbound_network (the system
    tables are account-wide across every workspace sharing the metastore), so an unscoped query mixes
    other workspaces' traffic into this workspace's view."""
    if only_workspace_id is None:
        return ""
    return f"AND CAST(workspace_id AS STRING) = '{int(only_workspace_id)}'"


def denied_requests(lookback_days: int, use_inet: bool = True, only_workspace_id: int | None = None) -> str:
    """Source IPs recently denied in the audit log (IP-access-list 403s). Scoped to one workspace
    when `only_workspace_id` is given (current_workspace scope) — otherwise, because the audit table is
    account-wide, denials from every workspace in the metastore would show up here (and, with
    --deny-denied-ips, become deny rules in THIS workspace's policy)."""
    return f"""
    WITH audit_recent AS ({_audit_recent(lookback_days, use_inet)})
    SELECT normalized_ip AS source_ip,
      COUNT(*) AS denied_events,
      COUNT(DISTINCT principal) AS principals,
      sort_array(collect_set(principal)) AS principal_list,
      MIN(event_date) AS first_denied, MAX(event_date) AS last_denied
    FROM audit_recent
    WHERE (action_name = 'IpAccessDenied' OR status_code = 403)
      AND normalized_ip IS NOT NULL
      {_workspace_predicate(only_workspace_id)}
    GROUP BY normalized_ip
    ORDER BY denied_events DESC
    """


def inbound_network_denied(lookback_days: int, only_workspace_id: int | None = None) -> str:
    """Inbound requests **enforced-denied** by a CBI network policy (policy_outcome='DENIED'), from
    system.access.inbound_network (columns: account_id, workspace_id, event_id, request_path,
    source.ip, authenticated_as, event_time, policy_outcome ∈ {{DENIED, DRY_RUN_DENIAL, ALLOWED}},
    rule_label). The table exists only where network monitoring is enabled, so the caller runs this
    best-effort and degrades if it's absent/empty. Same output shape as `denied_requests` so the two
    union cleanly; scoped to one workspace when `only_workspace_id` is given.

    Only DENIED (real, enforced blocks) feeds the recently-denied view here; log-only
    DRY_RUN_DENIAL rows are not denials — they're IPs a *dry-run* policy WOULD block, so they feed
    the allow-list candidate set instead (see `candidate_ips_from_inbound_network`). ALLOWED rows are
    sampled and never used."""
    return f"""
    SELECT source.ip AS source_ip,
      COUNT(*) AS denied_events,
      COUNT(DISTINCT authenticated_as) AS principals,
      sort_array(collect_set(authenticated_as)) AS principal_list,
      MIN(CAST(event_time AS DATE)) AS first_denied, MAX(CAST(event_time AS DATE)) AS last_denied
    FROM system.access.inbound_network
    WHERE event_time >= current_date() - INTERVAL {lookback_days} DAYS
      AND policy_outcome = 'DENIED'
      AND source.ip IS NOT NULL
      {_workspace_predicate(only_workspace_id)}
    GROUP BY source.ip
    ORDER BY denied_events DESC
    """


def candidate_ips_from_inbound_network(
    lookback_days: int, min_events: int = 1, only_workspace_id: int | None = None
) -> str:
    """Public source IPs that a **dry-run** CBI ingress policy WOULD have denied
    (policy_outcome='DRY_RUN_DENIAL') in system.access.inbound_network — i.e. inbound clients the
    current (log-only) allow-list doesn't yet cover, and therefore good candidates to allow-list.
    Scoped to one workspace when `only_workspace_id` is given (another workspace's would-be-denied
    clients are not candidates for this one).

    Shaped to line up with `frequent_public_ips` (public_ip + events/principals/dates +
    principal_list) so the rows merge straight into the candidate set before enrichment. The table
    exists only where network monitoring is enabled, so the caller runs this best-effort and degrades
    if it's absent/empty. Private/reserved IPs are filtered out in Python after the query (CBI governs
    public ingress, so source.ip is normally public)."""
    return f"""
    SELECT source.ip AS public_ip,
      COUNT(*) AS events,
      COUNT(DISTINCT authenticated_as) AS principals,
      COUNT(DISTINCT CAST(event_time AS DATE)) AS active_days,
      sort_array(collect_set(authenticated_as)) AS principal_list,
      MIN(CAST(event_time AS DATE)) AS first_active_date,
      MAX(CAST(event_time AS DATE)) AS last_active_date
    FROM system.access.inbound_network
    WHERE event_time >= current_date() - INTERVAL {lookback_days} DAYS
      AND policy_outcome = 'DRY_RUN_DENIAL'
      AND source.ip IS NOT NULL
      {_workspace_predicate(only_workspace_id)}
    GROUP BY source.ip
    HAVING COUNT(*) >= {min_events}
    ORDER BY events DESC
    """


def observed_egress(
    lookback_days: int, min_events: int, source_type_filter: str, only_workspace_id: int | None = None
) -> str:
    # Escape single quotes so a value containing one can't break (or inject into) the query.
    src_filter = (
        f"AND network_source_type = '{source_type_filter.replace(chr(39), chr(39) * 2)}'"
        if source_type_filter
        else ""
    )
    ws_filter = (
        f"AND CAST(workspace_id AS STRING) = '{int(only_workspace_id)}'"
        if only_workspace_id is not None
        else ""
    )
    return f"""
    SELECT
      COALESCE(dns_event.domain_name, storage_event.hostname, destination) AS destination,
      destination_type,
      COUNT(*) AS events,
      COUNT(DISTINCT access_type) AS distinct_access_types,
      sort_array(collect_set(access_type)) AS access_types,
      sort_array(collect_set(network_source_type)) AS source_types,
      sort_array(collect_set(workspace_id)) AS workspace_ids,
      sort_array(array_distinct(flatten(collect_list(dns_event.rdata)))) AS resolved_ips,
      MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
    FROM system.access.outbound_network
    WHERE event_time >= current_date() - INTERVAL {lookback_days} DAYS
      {src_filter}
      {ws_filter}
      AND COALESCE(dns_event.domain_name, storage_event.hostname, destination) IS NOT NULL
    GROUP BY 1, 2
    HAVING COUNT(*) >= {min_events}
    ORDER BY events DESC
    """


# ------------------------------------------------------------------- persisted daily aggregate (UC)
# `--uc-schema` maintains a per-(event_date, workspace, source IP, outcome) aggregate of the audit log
# in a Unity Catalog table, so re-runs re-aggregate that (small) table instead of re-scanning
# system.access.audit. The daily rows are parameter-agnostic: run-time filters (lookback, min events,
# IPv6, null-status handling, workspace scope) are applied when reading them back, so one table serves
# any combination of flags. See core/persist.py for the sync (watermark) logic.

DAILY_OUTCOMES = ("success", "null_status", "denied")


def daily_table_ddl(table: str) -> str:
    return f"""
    CREATE TABLE IF NOT EXISTS {table} (
      event_date DATE COMMENT 'Audit event date (UTC)',
      workspace_id STRING COMMENT 'Workspace the request targeted (0 = account level)',
      public_ip STRING COMMENT 'Normalised source IP',
      ip_version INT,
      ipv4_long BIGINT COMMENT 'IPv4 as a 32-bit integer (NULL for IPv6) for private-range checks',
      outcome STRING COMMENT 'success (status<400) | null_status | denied (403 / IpAccessDenied)',
      events BIGINT,
      sessions BIGINT COMMENT 'Distinct session ids that day',
      principal_list ARRAY<STRING>,
      principal_emails ARRAY<STRING>,
      subject_names ARRAY<STRING>,
      service_list ARRAY<STRING>,
      action_list ARRAY<STRING>,
      loaded_at TIMESTAMP COMMENT 'When dbx-nwp-helper wrote this row'
    )
    USING DELTA
    COMMENT 'dbx-nwp-helper: per-day source-IP aggregate of system.access.audit (ingress analysis cache)'
    """


def daily_table_insert(table: str, start_date: str, end_date: str, use_inet: bool = True) -> str:
    """Aggregate audit rows with event_date in [start_date, end_date] (ISO dates, inclusive) into the
    daily table. Rows that are neither a success, a null-status, nor a denial (other 4xx/5xx) are not
    kept — none of the analysis views use them."""
    predicate = f"event_date BETWEEN DATE'{start_date}' AND DATE'{end_date}'"
    return f"""
    INSERT INTO {table}
    WITH audit_recent AS ({_audit_projection(use_inet, predicate, always_ipv4_long=True)}),
    classified AS (
      SELECT *,
        CASE
          WHEN action_name = 'IpAccessDenied' OR status_code = 403 THEN 'denied'
          WHEN status_code IS NULL THEN 'null_status'
          WHEN status_code < 400 THEN 'success'
        END AS outcome
      FROM audit_recent
      WHERE normalized_ip IS NOT NULL
    )
    SELECT event_date,
      CAST(workspace_id AS STRING) AS workspace_id,
      normalized_ip AS public_ip,
      ANY_VALUE(ip_version) AS ip_version,
      ANY_VALUE(ipv4_long) AS ipv4_long,
      outcome,
      COUNT(*) AS events,
      COUNT(DISTINCT session_id) AS sessions,
      sort_array(collect_set(principal)) AS principal_list,
      sort_array(collect_set(principal_email)) AS principal_emails,
      sort_array(collect_set(subject_name)) AS subject_names,
      sort_array(collect_set(service_name)) AS service_list,
      sort_array(collect_set(action_name)) AS action_list,
      current_timestamp() AS loaded_at
    FROM classified
    WHERE outcome IS NOT NULL
    GROUP BY event_date, CAST(workspace_id AS STRING), normalized_ip, outcome
    """


def daily_table_bounds(table: str) -> str:
    return f"SELECT MIN(event_date) AS lo, MAX(event_date) AS hi, COUNT(*) AS rows FROM {table}"


def daily_table_delete_from(table: str, start_date: str) -> str:
    return f"DELETE FROM {table} WHERE event_date >= DATE'{start_date}'"


def server_today() -> str:
    return "SELECT current_date() AS today"


def _flat_distinct(col: str) -> str:
    return f"sort_array(array_distinct(flatten(collect_list({col}))))"


def persisted_frequent_public_ips(
    table: str,
    lookback_days: int,
    min_events: int,
    include_ipv6: bool,
    treat_null_status_as_success: bool,
    include_account_level: bool,
    only_workspace_id: int | None = None,
) -> str:
    """`frequent_public_ips` re-aggregated from the persisted daily table — same output columns, so
    the enrichment pipeline is unchanged. Private IPv4 ranges are excluded via the stored ipv4_long
    (the portable check), so this never needs the INET builtins."""
    ipv6_predicate = "OR ip_version = 6" if include_ipv6 else ""
    outcomes = "'success', 'null_status'" if treat_null_status_as_success else "'success'"
    if only_workspace_id is not None:
        account_level_predicate = f"AND workspace_id = '{int(only_workspace_id)}'"
    elif include_account_level:
        account_level_predicate = ""
    else:
        account_level_predicate = "AND workspace_id <> '0'"
    return f"""
    WITH daily AS (
      SELECT * FROM {table}
      WHERE event_date >= current_date() - INTERVAL {lookback_days} DAYS
        AND outcome IN ({outcomes})
        AND (ip_version = 4 {ipv6_predicate})
        {account_level_predicate}
        AND {_not_private(False).replace("normalized_ip", "public_ip")}
    )
    SELECT public_ip,
      ANY_VALUE(ip_version) AS ip_version,
      SUM(events) AS events,
      size({_flat_distinct("principal_list")}) AS principals,
      size({_flat_distinct("service_list")}) AS services,
      size({_flat_distinct("action_list")}) AS actions,
      COUNT(DISTINCT event_date) AS active_days,
      SUM(sessions) AS sessions,
      MIN(event_date) AS first_active_date, MAX(event_date) AS last_active_date,
      {_flat_distinct("principal_list")} AS principal_list,
      {_flat_distinct("principal_emails")} AS principal_emails,
      {_flat_distinct("subject_names")} AS subject_names,
      {_flat_distinct("service_list")} AS service_list,
      sort_array(collect_set(workspace_id)) AS workspace_ids
    FROM daily
    GROUP BY public_ip
    HAVING SUM(events) >= {min_events}
    ORDER BY events DESC, principals DESC
    """


def persisted_denied_requests(table: str, lookback_days: int, only_workspace_id: int | None = None) -> str:
    """`denied_requests` re-aggregated from the persisted daily table (outcome = 'denied')."""
    ws = f"AND workspace_id = '{int(only_workspace_id)}'" if only_workspace_id is not None else ""
    return f"""
    SELECT public_ip AS source_ip,
      SUM(events) AS denied_events,
      size({_flat_distinct("principal_list")}) AS principals,
      {_flat_distinct("principal_list")} AS principal_list,
      MIN(event_date) AS first_denied, MAX(event_date) AS last_denied
    FROM {table}
    WHERE event_date >= current_date() - INTERVAL {lookback_days} DAYS
      AND outcome = 'denied'
      {ws}
    GROUP BY public_ip
    ORDER BY denied_events DESC
    """


def suggestions_table_ddl(table: str) -> str:
    return f"""
    CREATE TABLE IF NOT EXISTS {table} (
      run_id STRING COMMENT 'One id per dbx-nwp-helper ingress run',
      run_at TIMESTAMP,
      workspace_id STRING COMMENT 'Workspace the run analysed',
      policy_name STRING,
      policy_mode STRING,
      policy_framing STRING,
      policy_target STRING COMMENT '__ALL__ for single-policy scopes, else the per-workspace target',
      rule_label STRING,
      rdap_owner STRING,
      recommendation STRING,
      distinct_ips INT,
      total_events BIGINT,
      cidrs ARRAY<STRING>,
      status STRING COMMENT 'kept | consolidated | dropped | deselected | excluded_*',
      consolidated_into STRING COMMENT 'Label of the consolidated rule when status = consolidated',
      written BOOLEAN COMMENT 'Whether this run wrote the policy (--create-policy)'
    )
    USING DELTA
    COMMENT 'dbx-nwp-helper: proposed ingress rules per run'
    """


# ------------------------------------------------------------------ persisted egress daily aggregate
# `egress --uc-schema` keeps a per-(event_date, workspace, source type, destination, destination type,
# access type) aggregate of system.access.outbound_network, re-aggregated per run exactly like the
# ingress daily table (see core/persist.py). Run-time filters (lookback, min events, source-type
# filter, workspace scope) apply when reading it back.


def egress_daily_table_ddl(table: str) -> str:
    return f"""
    CREATE TABLE IF NOT EXISTS {table} (
      event_date DATE COMMENT 'Outbound event date (UTC)',
      workspace_id STRING COMMENT 'Workspace whose serverless workload made the request',
      network_source_type STRING COMMENT 'Serverless product (DBSQL, Apps, MLServing, …)',
      destination STRING COMMENT 'FQDN / storage hostname / IP (coalesced from the dns/storage events)',
      destination_type STRING COMMENT 'DNS | IP | STORAGE',
      access_type STRING,
      events BIGINT,
      resolved_ips ARRAY<STRING> COMMENT 'DNS answers seen that day',
      first_seen TIMESTAMP,
      last_seen TIMESTAMP,
      loaded_at TIMESTAMP COMMENT 'When dbx-nwp-helper wrote this row'
    )
    USING DELTA
    COMMENT 'dbx-nwp-helper: per-day destination aggregate of system.access.outbound_network'
    """


def egress_daily_table_insert(table: str, start_date: str, end_date: str) -> str:
    """Aggregate outbound_network rows with event_date in [start_date, end_date] (ISO, inclusive)."""
    return f"""
    INSERT INTO {table}
    SELECT CAST(event_time AS DATE) AS event_date,
      CAST(workspace_id AS STRING) AS workspace_id,
      network_source_type,
      COALESCE(dns_event.domain_name, storage_event.hostname, destination) AS destination,
      destination_type,
      access_type,
      COUNT(*) AS events,
      sort_array(array_distinct(flatten(collect_list(dns_event.rdata)))) AS resolved_ips,
      MIN(event_time) AS first_seen, MAX(event_time) AS last_seen,
      current_timestamp() AS loaded_at
    FROM system.access.outbound_network
    WHERE CAST(event_time AS DATE) BETWEEN DATE'{start_date}' AND DATE'{end_date}'
      AND COALESCE(dns_event.domain_name, storage_event.hostname, destination) IS NOT NULL
    GROUP BY 1, 2, 3, 4, 5, 6
    """


def persisted_observed_egress(
    table: str,
    lookback_days: int,
    min_events: int,
    source_type_filter: str,
    only_workspace_id: int | None = None,
) -> str:
    """`observed_egress` re-aggregated from the persisted egress daily table — same output columns."""
    src_filter = (
        f"AND network_source_type = '{source_type_filter.replace(chr(39), chr(39) * 2)}'"
        if source_type_filter
        else ""
    )
    ws_filter = f"AND workspace_id = '{int(only_workspace_id)}'" if only_workspace_id is not None else ""
    return f"""
    SELECT destination,
      destination_type,
      SUM(events) AS events,
      size(array_distinct(collect_list(access_type))) AS distinct_access_types,
      sort_array(array_distinct(collect_list(access_type))) AS access_types,
      sort_array(collect_set(network_source_type)) AS source_types,
      sort_array(collect_set(workspace_id)) AS workspace_ids,
      {_flat_distinct("resolved_ips")} AS resolved_ips,
      MIN(first_seen) AS first_seen, MAX(last_seen) AS last_seen
    FROM {table}
    WHERE event_date >= current_date() - INTERVAL {lookback_days} DAYS
      {src_filter}
      {ws_filter}
    GROUP BY destination, destination_type
    HAVING SUM(events) >= {min_events}
    ORDER BY events DESC
    """


def egress_suggestions_table_ddl(table: str) -> str:
    return f"""
    CREATE TABLE IF NOT EXISTS {table} (
      run_id STRING COMMENT 'One id per dbx-nwp-helper egress run',
      run_at TIMESTAMP,
      workspace_id STRING COMMENT 'Workspace the run analysed (blank for all_workspaces)',
      policy_name STRING,
      policy_mode STRING,
      policy_target STRING COMMENT '__ALL__ for single-policy scopes, else the per-workspace target',
      kind STRING COMMENT 'internet | s3 | gcs | azure | databricks_workspace | blocked_domain',
      destination STRING COMMENT 'FQDN, bucket, storage account, workspace id or domain',
      detail STRING COMMENT 'region / storage service / inferred-from hosts / owner',
      events BIGINT,
      status STRING COMMENT 'allowed | blocked | deselected | capped | excluded_* | unresolved_workspace',
      written BOOLEAN COMMENT 'Whether this run wrote the policy (--create-policy)'
    )
    USING DELTA
    COMMENT 'dbx-nwp-helper: proposed egress destinations per run'
    """


def metastore_workspace_ids() -> str:
    """Every workspace id the metastore knows (system.access.workspaces_latest — all workspaces in the
    account, including banned/deleted ones). Used to verify inferred cross-workspace destination ids
    without account-admin credentials; the caller treats a missing table as "no verification"."""
    return "SELECT DISTINCT CAST(workspace_id AS BIGINT) AS workspace_id FROM system.access.workspaces_latest"


# ---------------------------------------------------------------------------- posture (read-only)
# `posture` scores each workspace before anyone writes a policy (see core/posture.py). Its audit checks
# all read one rollup of system.access.audit: events grouped by day, workspace, source IP, principal,
# client family and outcome, with IP parsing and classification done once per group rather than per
# event. The rollup is the same SELECT however it's materialised, so results don't depend on the mode:
#
#   * direct (default): each check inlines the rollup as a CTE — one audit scan per check (fine for
#     small accounts; the checks run in parallel);
#   * --stage-schema: the rollup is built once into a temporary table, read by every check, then
#     dropped — one audit scan per run;
#   * --uc-schema: the rollup is persisted as `dbx_nwp_posture_daily` and kept up to date
#     incrementally (core/persist.sync_daily, like dbx_nwp_ingress_daily) — later runs read only the
#     newest days.
#
# "Public" uses the same audit projection and private-range filter as the ingress candidates. One
# difference: posture counts NULL-status rows as not failed (it describes who reaches a workspace, not
# which IPs to allow-list). Every query is SELECT-only.

CLIENT_FAMILY = """CASE
      WHEN user_agent ILIKE '%powerbi%' OR user_agent ILIKE '%power bi%' THEN 'Power BI'
      WHEN user_agent ILIKE '%tableau%' THEN 'Tableau'
      WHEN user_agent ILIKE '%dbt%' THEN 'dbt'
      WHEN user_agent ILIKE '%fivetran%' THEN 'Fivetran'
      WHEN user_agent ILIKE '%looker%' THEN 'Looker'
      WHEN user_agent ILIKE '%chatgpt%' OR user_agent ILIKE '%openai%' THEN 'ChatGPT'
      WHEN user_agent ILIKE '%claude%' OR user_agent ILIKE '%anthropic%' THEN 'Claude'
      WHEN user_agent ILIKE '%terraform%' THEN 'Terraform'
      WHEN user_agent ILIKE '%databricks-cli%' OR user_agent ILIKE '%cli/%' THEN 'Databricks CLI'
      WHEN user_agent ILIKE '%databricks-sdk%' THEN 'Databricks SDK'
      WHEN user_agent ILIKE '%jdbc%' OR user_agent ILIKE '%odbc%' OR user_agent ILIKE '%SimbaSpark%'
        THEN 'JDBC/ODBC'
      WHEN user_agent ILIKE '%mozilla%' THEN 'Browser'
      WHEN user_agent IS NULL OR user_agent = '' THEN 'Unknown'
      ELSE 'Other'
    END"""

# Hosted BI / SaaS families: better served by the managed Partner platforms source than by CIDRs.
SAAS_CLIENT_FAMILIES = ("ChatGPT", "Claude", "Fivetran", "Looker", "Power BI", "Tableau", "dbt")

# A service principal's audit identity is its application id (a UUID).
_SP_PRINCIPAL = (
    "principal RLIKE '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'"
)


def _workspaces_predicate(workspace_ids) -> str:
    """`AND CAST(workspace_id AS STRING) IN ('<id>', …, '0')` for the assessed workspaces plus account
    level ('0'), or '' for the whole account. Ids must be numeric (they're inlined as literals)."""
    ids = sorted({str(i).strip() for i in (workspace_ids or []) if str(i).strip()})
    if not ids:
        return ""
    bad = [i for i in ids if not i.isdigit()]
    if bad:
        raise ValueError(f"workspace ids must be numeric: {bad}")
    if "0" not in ids:
        ids.append("0")
    return "AND CAST(workspace_id AS STRING) IN (" + ", ".join(f"'{i}'" for i in ids) + ")"


def posture_rollup_select(predicate: str, use_inet: bool = True) -> str:
    """The posture rollup of system.access.audit rows matching `predicate`. `is_public`, `network` and
    `client_family` are computed here (natively or portably), so reads never need INET functions.
    Action names are kept only where a check needs them (IP-ACL denials, verbose-audit changes); every
    other action collapses into one group, which keeps the rollup small."""
    public = f"(ip_version = 4 AND {_not_private(use_inet)})"
    verbose_off = (
        "action_name = 'workspaceConfEdit' "
        "AND request_params['workspaceConfKeys'] = 'enableVerboseAuditLogs' "
        "AND lower(request_params['workspaceConfValues']) = 'false'"
    )
    return f"""
    SELECT event_date,
      CAST(workspace_id AS STRING) AS workspace_id,
      normalized_ip AS source_ip,
      ip_version,
      {public} AS is_public,
      {_network_expr(use_inet)} AS network,
      principal,
      {CLIENT_FAMILY} AS client_family,
      CASE
        WHEN action_name = 'IpAccessDenied' OR status_code = 403 THEN 'denied'
        WHEN status_code IS NULL THEN 'null_status'
        WHEN status_code < 400 THEN 'success'
        ELSE 'failed'
      END AS outcome,
      CASE
        WHEN action_name = 'IpAccessDenied' THEN 'IpAccessDenied'
        WHEN {verbose_off} THEN 'verbose_audit_disabled'
      END AS action,
      COUNT(*) AS events,
      MIN(event_time) AS first_time,
      MAX(event_time) AS last_time
    FROM ({_audit_projection(use_inet, predicate, with_request_params=True)})
    WHERE normalized_ip IS NOT NULL OR ({verbose_off})
    GROUP BY ALL
    """


def posture_daily_table_ddl(table: str) -> str:
    return f"""
    CREATE TABLE IF NOT EXISTS {table} (
      event_date DATE COMMENT 'Audit event date (UTC)',
      workspace_id STRING COMMENT 'Workspace the request targeted (0 = account level)',
      source_ip STRING COMMENT 'Normalised source IP',
      ip_version INT,
      is_public BOOLEAN COMMENT 'Public IPv4 (not private / reserved)',
      network STRING COMMENT 'The source /24 (IPv4) or /48 (IPv6)',
      principal STRING,
      client_family STRING COMMENT 'User-agent family (Browser, Power BI, JDBC/ODBC, …)',
      outcome STRING COMMENT 'success | null_status | denied | failed',
      action STRING COMMENT 'IpAccessDenied | verbose_audit_disabled | NULL (any other action)',
      events BIGINT,
      first_time TIMESTAMP,
      last_time TIMESTAMP,
      loaded_at TIMESTAMP COMMENT 'When dbx-nwp-helper wrote this row'
    )
    USING DELTA
    COMMENT 'dbx-nwp-helper: per-day rollup of system.access.audit for the posture checks'
    """


def posture_daily_table_insert(table: str, start_date: str, end_date: str, use_inet: bool = True) -> str:
    predicate = f"event_date BETWEEN DATE'{start_date}' AND DATE'{end_date}'"
    return f"""
    INSERT INTO {table}
    SELECT *, current_timestamp() AS loaded_at FROM ({posture_rollup_select(predicate, use_inet)})
    """


def posture_stage_table(table: str, lookback_days: int, use_inet: bool = True, workspace_ids=None) -> str:
    """--stage-schema: build this run's rollup once into a temporary table (dropped at the end)."""
    predicate = (
        f"event_date >= current_date() - INTERVAL {lookback_days} DAYS {_workspaces_predicate(workspace_ids)}"
    )
    return f"CREATE OR REPLACE TABLE {table} AS {posture_rollup_select(predicate, use_inet)}"


def _rollup_cte(lookback_days: int, workspace_ids, table: str | None, use_inet: bool) -> str:
    """`WITH r AS (…)`: the rollup for this run's window, read from `table` (staged or persisted) or
    inlined over system.access.audit (direct mode)."""
    ws = _workspaces_predicate(workspace_ids)
    window = f"event_date >= current_date() - INTERVAL {lookback_days} DAYS"
    if table:
        body = f"SELECT * FROM {table} WHERE {window} {ws}"
    else:
        body = posture_rollup_select(f"{window} {ws}", use_inet)
    ok = "SELECT * FROM r WHERE is_public AND outcome IN ('success', 'null_status')"
    return f"WITH r AS ({body}),\n    ok AS ({ok})"


def posture_queries_over_rollup(
    lookback_days: int, workspace_ids=None, table: str | None = None, use_inet: bool = True
) -> dict[str, str]:
    """name → SQL for every audit-based posture check, over the rollup (see _rollup_cte)."""
    w = _rollup_cte(lookback_days, workspace_ids, table, use_inet)
    sp = _SP_PRINCIPAL
    return {
        "account_level_public_access": f"""{w}
    SELECT source_ip, SUM(events) AS events, COUNT(DISTINCT principal) AS principals,
      MAX(event_date) AS last_seen
    FROM ok WHERE workspace_id = '0'
    GROUP BY source_ip ORDER BY events DESC""",
        "audit_visibility": f"""{w}
    SELECT workspace_id,
      MIN(event_date) AS first_event_date, MAX(event_date) AS last_event_date,
      COUNT(DISTINCT event_date) AS days_with_events,
      SUM(CASE WHEN action = 'verbose_audit_disabled' THEN events ELSE 0 END)
        AS verbose_audit_disabled_events,
      MAX(CASE WHEN action = 'verbose_audit_disabled' THEN last_time END) AS last_verbose_audit_disabled
    FROM r GROUP BY workspace_id ORDER BY workspace_id""",
        "client_families_on_public_ips": f"""{w}
    SELECT workspace_id, client_family, SUM(events) AS events,
      COUNT(DISTINCT source_ip) AS distinct_public_ips, COUNT(DISTINCT principal) AS principals
    FROM ok GROUP BY workspace_id, client_family ORDER BY events DESC LIMIT 500""",
        "new_source_identity_pairs": f"""{w},
    known AS (
      SELECT DISTINCT principal, source_ip FROM ok WHERE event_date < current_date() - INTERVAL 1 DAYS
    )
    SELECT o.workspace_id, o.principal, o.source_ip, SUM(o.events) AS events, MAX(o.last_time) AS last_seen
    FROM ok o
    LEFT ANTI JOIN known k ON o.principal = k.principal AND o.source_ip = k.source_ip
    WHERE o.event_date >= current_date() - INTERVAL 1 DAYS AND o.principal <> 'UNKNOWN'
    GROUP BY o.workspace_id, o.principal, o.source_ip ORDER BY events DESC LIMIT 500""",
        "principal_network_spread": f"""{w}
    SELECT principal,
      CASE WHEN {sp} THEN 'service_principal' WHEN principal LIKE '%@%' THEN 'user' ELSE 'other' END
        AS principal_type,
      COUNT(DISTINCT source_ip) AS distinct_public_ips,
      COUNT(DISTINCT network) AS distinct_public_24s,
      COUNT(DISTINCT workspace_id) AS workspaces,
      SUM(events) AS events, MAX(event_date) AS last_seen
    FROM ok WHERE principal <> 'UNKNOWN'
    GROUP BY principal HAVING COUNT(DISTINCT network) >= 2
    ORDER BY distinct_public_24s DESC, events DESC LIMIT 200""",
        "public_browser_vs_api": f"""{w}
    SELECT workspace_id, SUM(events) AS public_events,
      SUM(CASE WHEN client_family = 'Browser' THEN events ELSE 0 END) AS browser_events,
      COUNT(DISTINCT CASE WHEN client_family <> 'Browser' THEN principal END) AS programmatic_principals,
      COUNT(DISTINCT CASE WHEN client_family <> 'Browser' AND {sp} THEN principal END)
        AS programmatic_service_principals,
      ROUND(100.0 * SUM(CASE WHEN client_family = 'Browser' THEN events ELSE 0 END) / SUM(events), 1)
        AS browser_pct
    FROM ok WHERE workspace_id <> '0'
    GROUP BY workspace_id ORDER BY public_events DESC""",
        "traffic_by_ip_class": f"""{w}
    SELECT workspace_id, SUM(events) AS events,
      SUM(CASE WHEN is_public THEN events ELSE 0 END) AS public_v4_events,
      SUM(CASE WHEN ip_version = 4 AND NOT is_public THEN events ELSE 0 END) AS private_v4_events,
      SUM(CASE WHEN ip_version = 6 THEN events ELSE 0 END) AS ipv6_events,
      COUNT(DISTINCT CASE WHEN is_public THEN source_ip END) AS distinct_public_ips,
      COUNT(DISTINCT CASE WHEN is_public THEN network END) AS distinct_public_24s,
      COUNT(DISTINCT CASE WHEN ip_version = 6 THEN source_ip END) AS distinct_ipv6_ips,
      COUNT(DISTINCT CASE WHEN is_public THEN principal END) AS public_principals
    FROM r WHERE source_ip IS NOT NULL
    GROUP BY workspace_id ORDER BY public_v4_events DESC""",
    }


def posture_inbound_outcomes(lookback_days: int, workspace_ids=None) -> str:
    """CBI policy outcomes per workspace from system.access.inbound_network: events, sources,
    identities and distinct source/identity/rule combinations per raw policy_outcome. The caller
    classifies the outcome values (core/posture.outcome_class). Best-effort: the table exists only
    where network monitoring is on."""
    return f"""
    SELECT CAST(workspace_id AS STRING) AS workspace_id, policy_outcome,
      COUNT(*) AS events,
      COUNT(DISTINCT source.ip) AS distinct_source_ips,
      COUNT(DISTINCT authenticated_as) AS identities,
      COUNT(DISTINCT concat_ws('|', source.ip, authenticated_as, rule_label)) AS combinations,
      MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
    FROM system.access.inbound_network
    WHERE event_time >= current_date() - INTERVAL {lookback_days} DAYS
      {_workspaces_predicate(workspace_ids)}
    GROUP BY ALL
    ORDER BY workspace_id, events DESC
    """
