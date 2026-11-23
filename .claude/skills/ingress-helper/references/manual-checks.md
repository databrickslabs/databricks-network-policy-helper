# Manual, read-only ingress checks (Databricks CLI)

For when `posture` can't run. Every command is a `list` or `get`.

```bash
# --- account (account-admin profile)
databricks account network-policies list-network-policies-rpc -p <acct> -o json        # all policies (incl. default-policy, account-policy)
databricks account workspaces list -p <acct> -o json                                   # pricing_tier, private_access_settings_id (AWS/GCP)
databricks account workspace-network-configuration get-workspace-network-option-rpc <workspace-id> -p <acct> -o json   # assigned policy
databricks account network-policies get-network-policy-rpc <policy-id> -p <acct> -o json
databricks account private-access list -p <acct> -o json                               # PAS: level, allowed_vpc_endpoint_ids, public_access_enabled
databricks account ip-access-lists list -p <acct> -o json                              # account console IP access lists

# --- workspace (workspace-admin profile)
databricks workspace-conf get-status enableIpAccessLists -p <ws> -o json
databricks ip-access-lists list -p <ws> -o json
```

Read a policy like this:
- `ingress.public_access.restriction_mode = RESTRICTED_ACCESS` (or any rules) → **enforced**
  restriction. The same under `ingress_dry_run` → **dry-run** only.
- `origin.all_ip_ranges: true` in an allow rule → open for that rule's destinations.
- `private_access` missing or `ALLOW_ALL_REGISTERED_ENDPOINTS` → any registered endpoint.
- `egress.network_access.restriction_mode = FULL_ACCESS` → egress open.

Then apply `../../posture-helper/references/posture-checks.md` by hand.
