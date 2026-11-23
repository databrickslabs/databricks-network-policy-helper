-- Trusted / example SQL for the "CBI Security Posture" Genie agent.
-- Add each block under Instructions → SQL queries, using the comment as the question.
-- :lookback_days is a Genie parameter (INT, default 30). Tables are referenced unqualified; Genie
-- resolves them from the agent's data sources.

-- Q: What is our CBI maturity by workspace?
SELECT workspace_id, workspace_name, maturity_level, maturity_label, policy_mode,
       effective_policy_id, ip_acl_enabled, has_private_link, egress_restricted, maturity_reason, run_ts
FROM cbi_posture_latest
ORDER BY maturity_level NULLS FIRST, workspace_id;

-- Q: What are the highest-priority findings and what should we do next?
SELECT severity, finding_id, workspace_id, title, recommendation, next_step, docs
FROM cbi_findings_latest
ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
         finding_id;

-- Q: How much of our traffic comes from public IPs, per workspace?
SELECT workspace_id,
       COUNT(*) AS events,
       ROUND(100.0 * AVG(CASE WHEN ip_class = 'public_v4' THEN 1 ELSE 0 END), 1) AS public_pct,
       COUNT(DISTINCT CASE WHEN ip_class = 'public_v4' THEN source_ip END) AS distinct_public_ips,
       COUNT(DISTINCT CASE WHEN ip_class = 'ipv6' THEN source_ip END) AS distinct_ipv6_ips
FROM cbi_audit_access
WHERE event_date >= date_sub(current_date(), :lookback_days)
GROUP BY workspace_id
ORDER BY events DESC;

-- Q: Which public IPs would an allow-list need to cover?
SELECT source_ip, network_24, COUNT(*) AS events, COUNT(DISTINCT principal) AS principals,
       COUNT(DISTINCT workspace_id) AS workspaces, MAX(event_date) AS last_seen
FROM cbi_audit_access
WHERE event_date >= date_sub(current_date(), :lookback_days)
  AND ip_class = 'public_v4' AND succeeded
GROUP BY source_ip, network_24
ORDER BY events DESC
LIMIT 100;

-- Q: Who connects from the most different networks?
SELECT principal, principal_type, COUNT(DISTINCT network_24) AS distinct_public_24s,
       COUNT(DISTINCT source_ip) AS distinct_public_ips, COUNT(*) AS events
FROM cbi_audit_access
WHERE event_date >= date_sub(current_date(), :lookback_days)
  AND ip_class = 'public_v4' AND succeeded
GROUP BY principal, principal_type
ORDER BY distinct_public_24s DESC
LIMIT 50;

-- Q: Which BI / SaaS tools connect over the public internet?
SELECT client_family, COUNT(*) AS events, COUNT(DISTINCT source_ip) AS distinct_public_ips,
       COUNT(DISTINCT principal) AS principals
FROM cbi_audit_access
WHERE event_date >= date_sub(current_date(), :lookback_days)
  AND ip_class = 'public_v4' AND succeeded
GROUP BY client_family
ORDER BY events DESC;

-- Q: What would break if we enforced our dry-run policy?
SELECT workspace_id, rule_label, source_ip, authenticated_as, COUNT(*) AS events, MAX(event_time) AS last_seen
FROM cbi_inbound_events
WHERE outcome = 'DRY_RUN_DENIAL' AND event_time >= date_sub(current_date(), :lookback_days)
GROUP BY ALL
ORDER BY events DESC
LIMIT 100;

-- Q: What did our enforced policy block recently?
SELECT CAST(event_time AS DATE) AS day, workspace_id, rule_label,
       COUNT(*) AS denied_events, COUNT(DISTINCT source_ip) AS distinct_ips,
       COUNT(DISTINCT authenticated_as) AS identities
FROM cbi_inbound_events
WHERE outcome = 'DENIED' AND event_time >= date_sub(current_date(), :lookback_days)
GROUP BY ALL
ORDER BY day DESC, denied_events DESC;

-- Q: Who reaches the account console from the internet?
SELECT source_ip, principal, COUNT(*) AS events, MAX(event_date) AS last_seen
FROM cbi_audit_access
WHERE workspace_id = '0' AND ip_class = 'public_v4' AND succeeded
  AND event_date >= date_sub(current_date(), :lookback_days)
GROUP BY source_ip, principal
ORDER BY events DESC
LIMIT 100;

-- Q: How has our maturity changed over time?
SELECT CAST(run_ts AS DATE) AS run_date, workspace_id, maturity_level, maturity_label, policy_mode
FROM cbi_posture_workspaces
ORDER BY workspace_id, run_date;

-- Q: Could we use a "browser yes, remote APIs no" policy? Who uses programmatic access from the internet?
SELECT workspace_id, principal, principal_type, client_family,
       COUNT(*) AS events, COUNT(DISTINCT source_ip) AS distinct_public_ips, MAX(event_date) AS last_seen
FROM cbi_audit_access
WHERE event_date >= date_sub(current_date(), :lookback_days)
  AND ip_class = 'public_v4' AND succeeded AND workspace_id <> '0'
  AND client_family <> 'Browser'
GROUP BY ALL
ORDER BY workspace_id, events DESC;

-- Q: Which identities showed up from a new public IP in the last day? (triage signal, not proof)
WITH pub AS (
  SELECT event_date, workspace_id, principal, principal_type, source_ip, action_name
  FROM cbi_audit_access
  WHERE event_date >= date_sub(current_date(), :lookback_days)
    AND ip_class = 'public_v4' AND principal <> 'UNKNOWN'
),
known AS (SELECT DISTINCT principal, source_ip FROM pub WHERE event_date < date_sub(current_date(), 1))
SELECT r.workspace_id, r.principal, r.principal_type, r.source_ip, COUNT(*) AS events,
       slice(sort_array(collect_set(r.action_name)), 1, 10) AS sample_actions
FROM pub r LEFT ANTI JOIN known k ON r.principal = k.principal AND r.source_ip = k.source_ip
WHERE r.event_date >= date_sub(current_date(), 1)
GROUP BY ALL
ORDER BY events DESC
LIMIT 100;

-- Q: How exposed are we to stolen personal access tokens?
SELECT workspace_id, workspace_name, maturity_label, policy_mode,
       pats_total, pats_never_expire, pats_unscoped, max_token_lifetime_days, pats_all_users
FROM cbi_posture_latest
ORDER BY pats_never_expire DESC NULLS LAST, maturity_level NULLS FIRST;

-- Q: Which defense-in-depth layers have the most open findings?
SELECT layer, severity, COUNT(*) AS findings
FROM cbi_findings_latest
GROUP BY layer, severity
ORDER BY layer, CASE severity WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END;
