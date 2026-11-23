-- Trusted / example SQL for the dbx-nwp-helper security posture Genie agent (`genie-setup`).
-- Each block starts with `-- Q: <question>`. :lookback_days is a Genie parameter (INT, default 30).
-- Tables are referenced unqualified; Genie resolves them from the agent's data sources. A block is left
-- out of the agent when a table it reads isn't in the schema.

-- Q: What is our CBI maturity by workspace?
SELECT workspace_id, workspace_name, maturity_level, maturity_label, policy_mode, effective_policy_id,
       ip_acl_enabled, has_private_link, egress_restricted, maturity_reason, run_at
FROM dbx_nwp_posture_latest
ORDER BY maturity_level NULLS FIRST, workspace_id;

-- Q: What are the highest-priority findings and what should we do next?
SELECT severity, finding_id, workspace_id, title, recommendation, next_step, docs
FROM dbx_nwp_posture_findings_latest
ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
         finding_id, workspace_id;

-- Q: Which personal access tokens should we revoke, and who owns them?
SELECT workspace_id, owner, token_id, expires, last_used, scopes, reasons
FROM dbx_nwp_posture_tokens_latest
ORDER BY CASE WHEN reasons LIKE '%never expires%' THEN 0 WHEN reasons LIKE '%unused%' THEN 1 ELSE 2 END, owner;

-- Q: How exposed are we to stolen personal access tokens?
SELECT workspace_id, workspace_name, maturity_label, policy_mode,
       pats_total, pats_never_expire, pats_unscoped, max_token_lifetime_days, pats_all_users
FROM dbx_nwp_posture_latest
WHERE pats_checked
ORDER BY pats_never_expire DESC NULLS LAST, maturity_level NULLS FIRST;

-- Q: How has our maturity changed over time?
SELECT CAST(run_at AS DATE) AS run_date, workspace_id, maturity_level, maturity_label, policy_mode
FROM dbx_nwp_posture_workspaces
ORDER BY workspace_id, run_date;

-- Q: How much of our traffic comes from public IPs, per workspace?
SELECT workspace_id, SUM(events) AS events,
       ROUND(100.0 * SUM(CASE WHEN is_public THEN events ELSE 0 END) / SUM(events), 1) AS public_pct,
       COUNT(DISTINCT CASE WHEN is_public THEN source_ip END) AS distinct_public_ips,
       COUNT(DISTINCT CASE WHEN ip_version = 6 THEN source_ip END) AS distinct_ipv6_ips
FROM dbx_nwp_posture_daily
WHERE event_date >= date_sub(current_date(), :lookback_days) AND source_ip IS NOT NULL
GROUP BY workspace_id
ORDER BY events DESC;

-- Q: Which public IPs would an allow-list need to cover?
SELECT source_ip, network, SUM(events) AS events, COUNT(DISTINCT principal) AS principals,
       COUNT(DISTINCT workspace_id) AS workspaces, MAX(event_date) AS last_seen
FROM dbx_nwp_posture_daily
WHERE event_date >= date_sub(current_date(), :lookback_days)
  AND is_public AND outcome IN ('success', 'null_status') AND workspace_id <> '0'
GROUP BY source_ip, network
ORDER BY events DESC
LIMIT 100;

-- Q: Who connects from the most different networks?
SELECT principal, COUNT(DISTINCT network) AS distinct_public_networks,
       COUNT(DISTINCT source_ip) AS distinct_public_ips, SUM(events) AS events
FROM dbx_nwp_posture_daily
WHERE event_date >= date_sub(current_date(), :lookback_days)
  AND is_public AND outcome IN ('success', 'null_status') AND principal <> 'UNKNOWN'
GROUP BY principal
ORDER BY distinct_public_networks DESC
LIMIT 50;

-- Q: Which BI / SaaS tools connect over the public internet?
SELECT client_family, SUM(events) AS events, COUNT(DISTINCT source_ip) AS distinct_public_ips,
       COUNT(DISTINCT principal) AS principals
FROM dbx_nwp_posture_daily
WHERE event_date >= date_sub(current_date(), :lookback_days)
  AND is_public AND outcome IN ('success', 'null_status')
GROUP BY client_family
ORDER BY events DESC;

-- Q: Could we allow browser access from anywhere but restrict APIs? Who uses programmatic access from the internet?
SELECT workspace_id, principal, client_family, SUM(events) AS events,
       COUNT(DISTINCT source_ip) AS distinct_public_ips, MAX(event_date) AS last_seen
FROM dbx_nwp_posture_daily
WHERE event_date >= date_sub(current_date(), :lookback_days)
  AND is_public AND outcome IN ('success', 'null_status') AND workspace_id <> '0'
  AND client_family <> 'Browser'
GROUP BY ALL
ORDER BY workspace_id, events DESC;

-- Q: Who reaches the account console from the internet?
SELECT source_ip, principal, SUM(events) AS events, MAX(event_date) AS last_seen
FROM dbx_nwp_posture_daily
WHERE workspace_id = '0' AND is_public AND outcome IN ('success', 'null_status')
  AND event_date >= date_sub(current_date(), :lookback_days)
GROUP BY source_ip, principal
ORDER BY events DESC
LIMIT 100;

-- Q: Which identities showed up from a new public IP yesterday? (triage signal, not proof)
WITH pub AS (
  SELECT event_date, workspace_id, principal, source_ip, events
  FROM dbx_nwp_posture_daily
  WHERE event_date >= date_sub(current_date(), :lookback_days) AND is_public AND principal <> 'UNKNOWN'
),
known AS (SELECT DISTINCT principal, source_ip FROM pub WHERE event_date < date_sub(current_date(), 1))
SELECT r.workspace_id, r.principal, r.source_ip, SUM(r.events) AS events
FROM pub r LEFT ANTI JOIN known k ON r.principal = k.principal AND r.source_ip = k.source_ip
WHERE r.event_date >= date_sub(current_date(), 1)
GROUP BY ALL
ORDER BY events DESC
LIMIT 100;

-- Q: What would break if we enforced our dry-run policy?
SELECT workspace_id, rule_label, source_ip, authenticated_as, COUNT(*) AS events, MAX(event_time) AS last_seen
FROM dbx_nwp_inbound_events
WHERE outcome = 'DRY_RUN_DENIAL' AND event_date >= date_sub(current_date(), :lookback_days)
GROUP BY ALL
ORDER BY events DESC
LIMIT 100;

-- Q: What did our enforced policy block recently?
SELECT event_date AS day, workspace_id, rule_label, COUNT(*) AS denied_events,
       COUNT(DISTINCT source_ip) AS distinct_ips, COUNT(DISTINCT authenticated_as) AS identities
FROM dbx_nwp_inbound_events
WHERE outcome = 'DENIED' AND event_date >= date_sub(current_date(), :lookback_days)
GROUP BY ALL
ORDER BY day DESC, denied_events DESC;

-- Q: Which ingress rules did the latest ingress run propose, and what happened to them?
SELECT workspace_id, policy_name, rule_label, rdap_owner, distinct_ips, total_events, status, consolidated_into, run_at
FROM dbx_nwp_ingress_suggestions
QUALIFY dense_rank() OVER (PARTITION BY workspace_id ORDER BY run_at DESC) = 1
ORDER BY total_events DESC;

-- Q: Which destinations do our serverless workloads reach?
SELECT workspace_id, network_source_type, destination, destination_type, SUM(events) AS events,
       MAX(last_seen) AS last_seen
FROM dbx_nwp_egress_daily
WHERE event_date >= date_sub(current_date(), :lookback_days)
GROUP BY ALL
ORDER BY events DESC
LIMIT 100;
