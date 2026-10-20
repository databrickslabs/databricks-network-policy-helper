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


def _audit_recent(lookback_days: int, use_inet: bool) -> str:
    """The base audit projection the notebook exposed as the `audit_recent` temp view, with
    normalized_ip / ip_version derived either natively or portably. Portable mode additionally
    projects ipv4_long (used by the integer-bounds private-range check)."""
    if use_inet:
        normalized, version, ipv4_long_col = _NORMALIZED_IP_NATIVE, _IP_VERSION_NATIVE, ""
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
      session_id, request_id
    FROM system.access.audit
    WHERE event_date >= current_date() - INTERVAL {lookback_days} DAYS
"""


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


def principal_network_diversity(lookback_days: int, use_inet: bool = True) -> str:
    # distinct_networks approximates each principal's spread across networks. Native uses
    # try_ip_cidr(CONCAT(ip,'/24' | '/48')); portable approximates it (IPv4 /24 = ipv4_long DIV 256,
    # IPv6 the leading three hextets). Coarse, but this is a diagnostic surface only.
    if use_inet:
        networks = """CASE
          WHEN ip_version = 4 THEN CAST(try_ip_cidr(CONCAT(normalized_ip, '/24')) AS STRING)
          WHEN ip_version = 6 THEN CAST(try_ip_cidr(CONCAT(normalized_ip, '/48')) AS STRING)
        END"""
    else:
        networks = """CASE
          WHEN ip_version = 4 THEN CONCAT('v4:', CAST(ipv4_long DIV 256 AS STRING))
          WHEN ip_version = 6 THEN CONCAT('v6:', substring_index(normalized_ip, ':', 3))
        END"""
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


def denied_requests(lookback_days: int, use_inet: bool = True) -> str:
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
    GROUP BY normalized_ip
    ORDER BY denied_events DESC
    """


def inbound_network_denied(lookback_days: int) -> str:
    """Inbound requests **enforced-denied** by a CBI network policy (access_type='DROP'), from
    system.access.inbound_network. That table records only denied inbound events and exists only
    where network monitoring is enabled, so the caller runs this best-effort and degrades if the
    table is absent/empty. Same output shape as `denied_requests` so the two union cleanly.

    Only DROP (real, enforced blocks) feeds the recently-denied view here; log-only
    DRY_RUN_DENIAL rows are not denials — they're IPs a *dry-run* policy WOULD block, so they feed
    the allow-list candidate set instead (see `candidate_ips_from_inbound_network`)."""
    return f"""
    SELECT source.ip AS source_ip,
      COUNT(*) AS denied_events,
      COUNT(DISTINCT authenticated_as) AS principals,
      sort_array(collect_set(authenticated_as)) AS principal_list,
      MIN(CAST(event_time AS DATE)) AS first_denied, MAX(CAST(event_time AS DATE)) AS last_denied
    FROM system.access.inbound_network
    WHERE event_time >= current_date() - INTERVAL {lookback_days} DAYS
      AND access_type = 'DROP'
      AND source.ip IS NOT NULL
    GROUP BY source.ip
    ORDER BY denied_events DESC
    """


def candidate_ips_from_inbound_network(lookback_days: int, min_events: int = 1) -> str:
    """Public source IPs that a **dry-run** CBI ingress policy WOULD have denied
    (access_type='DRY_RUN_DENIAL') in system.access.inbound_network — i.e. inbound clients the
    current (log-only) allow-list doesn't yet cover, and therefore good candidates to allow-list.

    Shaped to line up with `frequent_public_ips` (public_ip + events/principals/dates +
    principal_list) so the rows merge straight into the candidate set before enrichment. The table
    records only denied inbound events and exists only where network monitoring is enabled, so the
    caller runs this best-effort and degrades if it's absent/empty. Private/reserved IPs are filtered
    out in Python after the query (CBI governs public ingress, so source.ip is normally public)."""
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
      AND access_type = 'DRY_RUN_DENIAL'
      AND source.ip IS NOT NULL
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
