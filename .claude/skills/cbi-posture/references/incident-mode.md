# Incident mode: when the customer suspects a credential is compromised

Posture diagnosis is for planning. If the customer reports a leaked token or suspicious activity,
**switch to containment** and don't make them wait for a 90-day traffic sample. The customer's
incident-response owner drives. This skill stays read-only and only supplies evidence and suggested
commands.

## First steps (contain in parallel with the investigation)

1. **Revoke exposed credentials.** Revoke PATs by token ID (token management) and rotate OAuth
   secrets for affected service principals.
2. **Deactivate compromised users / service principals** at the account level, which also blocks
   credentials you haven't found yet.
3. **Restrict ingress with CBI where possible.** Deploy **known-good** rules (corporate/VPN egress,
   named automation, a recovery admin path) in a new named policy rather than waiting for a traffic
   sample. Pair it with revocation, not instead of it.
4. **Preserve evidence**: audit logs, query history and affected table history.
5. **Stop suspicious jobs, queries and compute**, and look for new tokens, secrets or identities that
   could be used to come back.
6. **Rotate downstream secrets** the identity could read, at the system that issued them.

## Using this skill during an incident

- Run `sql/11_audit_visibility.sql` **first**. If verbose audit logging was disabled (CBI-025), later
  conclusions have a gap.
- `sql/12_new_source_identity_combinations.sql`, `03_principal_network_spread.sql` and
  `05_ip_access_list_denials.sql` are useful pivots.
- **A proposed allow-list built from observed traffic can include the attacker.** Treat observed
  sources as candidates and confirm each with its owner.
- An empty result means "no matching events in this table and window", not "it didn't happen".
- A workspace policy doesn't cover the **account console / account APIs**. That needs the
  account-level policy.

## Hand off for the investigation

- **Databricks Workspace Detection App** (open source, customer-operated):
  https://github.com/databricks-solutions/cybersec-workspace-detection-app. See its README for the
  detections and investigation notebooks it ships.
- Keep queries, parameters and saved results next to each conclusion. A model's narrative is not
  evidence.
