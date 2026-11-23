# CBI without a VPN: rollout patterns (CBI-026)

CBI itself doesn't need a VPN. What's hard is requiring a trusted network for *everyone at once*. Apply
CBI to a narrower slice first (one workspace, production service principals, admin API calls). The
patterns are alternatives; pick the ones that fit.

| Pattern | Suits | Stays open | Restricted | Evidence for it |
|---|---|---|---|---|
| **B1 Browser yes, remote APIs no** | Browser users working from home | Workspace UI, all users, all public IPs | Programmatic access, except named automation from approved sources | `public_browser_vs_api`: few `programmatic_principals` |
| **B2 Only the API families you need** | Teams needing some remote API/SQL | API rules with `IN <scopes>` (e.g. `sql`) | All other API families | many programmatic identities; JDBC/ODBC/SDK client families |
| **B3 Narrow partner exceptions** | Hosted Power BI / Tableau Cloud / dbt Cloud | The named Partner platforms source | Everyone else on the internet | SaaS client families on public IPs |
| **B4 Temporary access on request** | Occasional production support | Nothing by default | Everything until an approved window | an operational process; rules don't expire on their own |

`ingress` proposes IP-based rules. B1, B2 and B4 shape the destination / identity of those rules (or
are added in the account console); B3 is the console's managed Partner platforms source.

Rule behaviour to explain:
- Restricted mode blocks anything no allow rule permits, so **one broad allow rule undoes the rest**
  (CBI-004).
- Deny rules win. API-scope conditions belong in **allow** rules only.
- Changes take 10–15 minutes to propagate.
- Private, cross-workspace, Apps, Lakebase and **account-level** access are separate paths. A workspace
  policy doesn't cover them.
- A service-principal rule from all public IPs is an **identity exception, not a network boundary**.
- Partner IP ranges don't prove the request is *your* tenant, and don't cover desktop clients (e.g.
  Power BI Desktop).
- Broad residential/ISP ranges are not a VPN. Block lists only stop known sources.

## Rollout order

1. **Assess** with `posture`: owners, public clients, production identities, audit access and a
   recovery path.
2. **Propose** with `ingress` over 90 days of traffic; review with the owners (`--review-pack`).
3. **Apply the pattern that fits** in dry-run on the pilot slice; close the dry-run gap.
4. **Enforce**, then widen to the next slice. Separate high-impact workspaces with a stricter policy and
   egress control.
5. **Retest** after every material change.

## Acceptance tests after enforcement

Test both ways: something that should work, and something that should fail. A saved setting proves only
that it was saved.

- A normal user signs in and works from an approved network → succeeds.
- An unapproved identity calls the public API (B1) → fails after propagation.
- An excluded API family is called (B2) → fails, and the intended alternative works.
- The partner's real scheduled refresh runs (B3) → succeeds, and an unrelated public source is blocked.
- A temporary exception expires (B4) → access fails, and the cleanup is recorded.
- A request from an unapproved network (e.g. a phone hotspot) → blocked, and shows in
  `system.access.inbound_network` as `DENIED`.

Record identity, source, workspace, operation, time, result and policy version for each.
