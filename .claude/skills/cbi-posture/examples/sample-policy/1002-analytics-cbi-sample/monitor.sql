-- Daily dry-run check for workspace 1002: requests the sample policy WOULD block if enforced.
-- Read-only. Set :lookback_days to 1 for a daily check, or 7 for a weekly one.
-- If system.access.inbound_network names the outcome column access_type, replace policy_outcome.
-- What a dry-run CBI policy WOULD block if enforced today: the gap to close before enforcing.
SELECT * FROM (
WITH inbound AS (
  SELECT
    CAST(workspace_id AS STRING) AS workspace_id,
    event_time,
    request_path,
    source.ip                    AS source_ip,
    authenticated_as,
    rule_label,
    CASE
      WHEN upper(policy_outcome) LIKE '%DRY%RUN%' THEN 'DRY_RUN_DENIAL'
      WHEN upper(policy_outcome) IN ('DENY', 'DENIED', 'DROP') THEN 'DENIED'
      ELSE upper(policy_outcome)
    END AS outcome
  FROM system.access.inbound_network
  WHERE event_time >= date_sub(current_date(), :lookback_days)
    AND TRUE /* cbi:workspace-scope (all workspaces). To scope: CAST(workspace_id AS STRING) IN ('<id>', '0') */
)
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
LIMIT 500
) WHERE workspace_id = '1002';
