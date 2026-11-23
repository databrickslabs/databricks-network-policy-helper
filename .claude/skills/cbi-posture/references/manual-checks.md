# Manual, read-only checks (no Python)

Use these when the collector can't run. Every command is a `list` or `get`.

```bash
# --- account (account-admin profile; host = accounts.cloud.databricks.com | accounts.azuredatabricks.net | accounts.gcp.databricks.com)
databricks account network-policies list-network-policies-rpc -p <acct> -o json        # all policies (incl. default-policy, account-policy)
databricks account workspaces list -p <acct> -o json                                   # pricing_tier, private_access_settings_id (AWS/GCP)
databricks account workspace-network-configuration get-workspace-network-option-rpc <workspace-id> -p <acct> -o json   # assigned policy
databricks account network-policies get-network-policy-rpc <policy-id> -p <acct> -o json
databricks account private-access list -p <acct> -o json                               # PAS: level, allowed_vpc_endpoint_ids, public_access_enabled
databricks account ip-access-lists list -p <acct> -o json                              # account console IP ACLs

# --- workspace (workspace-admin profile)
databricks workspace-conf get-status enableIpAccessLists -p <ws> -o json
databricks ip-access-lists list -p <ws> -o json
databricks workspace-conf get-status maxTokenLifetimeDays,enableTokensConfig -p <ws> -o json
databricks token-management list -p <ws> -o json                                      # PAT metadata: expiry_time (-1 / 0 = never), last_used_day, scopes ([] = all APIs)
databricks permissions get authorization tokens -p <ws> -o json                        # does group 'users' have CAN_USE?
```

Account-wide PAT view: account console → **Security → Token report**.

Read a policy like this:
- `ingress.public_access.restriction_mode = RESTRICTED_ACCESS` (or any rules) → **enforced**
  restriction. The same under `ingress_dry_run` → **dry-run** only.
- `origin.all_ip_ranges: true` in an allow rule → effectively open for that rule.
- `private_access` missing or `ALLOW_ALL_REGISTERED_ENDPOINTS` → any registered endpoint.
- `egress.network_access.restriction_mode = FULL_ACCESS` → egress open.

Then run `sql/*.sql` in the SQL editor and apply `findings.md` by hand.
