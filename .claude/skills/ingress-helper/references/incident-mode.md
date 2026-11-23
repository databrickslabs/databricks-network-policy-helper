# Incident mode: a credential may be compromised

Posture diagnosis is for planning. If a token is reported leaked or activity looks suspicious, **switch
to containment** and don't wait for a 90-day traffic sample. The customer's incident-response owner
drives; stay read-only and supply evidence and suggested commands.

## Contain (in parallel with the investigation)

1. **Revoke exposed credentials** and **deactivate compromised identities** at the account level. Network
   policy is not a substitute for revocation.
2. **Restrict ingress to known-good sources.** Put **known** rules (corporate / VPN egress, named
   automation, a recovery admin path) in a new named policy rather than one derived from recent
   traffic, which may contain the attacker. Build it with `ingress` and **untick every source an owner
   can't vouch for** in the rule selector.
3. **Preserve evidence** (audit logs, query history) before changing anything else.

## Use the tools

- `dbx-nwp-helper posture --lookback-days 7 --workspace-id <id>` first: check `audit_visibility`
  (a verbose-audit gap, CBI-025, means later conclusions are incomplete) and the
  `new_source_identity_pairs` section of `posture.json`: identities seen in the last day from a public
  IP they hadn't used before. A new IP alone is weak evidence for roaming users; it matters combined
  with sensitive actions or a known-leaked credential.
- `principal_network_spread` and the denied-requests view of `ingress` (IP ACL 403s and CBI denials)
  are useful pivots.
- An empty result means "no matching events in this table and window", not "it didn't happen".
- A workspace policy doesn't cover the **account console / account APIs**; that's the account-level
  policy (CBI-009).

## Hand off

- **Databricks Workspace Detection App** (open source, customer-operated):
  https://github.com/databricks-solutions/cybersec-workspace-detection-app
- Keep queries, parameters and saved results next to each conclusion. A model's narrative is not
  evidence.
