# Why CBI matters: the stolen-credential threat model

Use this to explain **why** a finding matters, in customer language.

## The core argument

Almost no well-known credential breach involved a platform vulnerability. The credential was valid,
stolen somewhere else (an infected laptop, a public repo, a CI log, a third party), and replayed. A
stolen credential is dangerous when three things are true:

1. **It still works**: it hasn't expired or been revoked. → *Expire*
2. **It has useful permissions**: it can read data, run code, or fetch other secrets. → *Scope*, blast radius
3. **It works from anywhere**: Databricks accepts it from the attacker's network. → **CBI (Limit)**

MFA doesn't fix #3. A PAT created after one MFA prompt works on its own afterwards. Without CBI, a
stolen token is **single-factor access to everything its owner can reach**. With CBI, the theft must
also come with a network, identity and request type the customer approved. CBI doesn't stop abuse
from an already-allowed network, endpoint or workload, which is why the other layers still matter.

## Seven layers (map every finding to one)

| Layer | Objective | Databricks controls | Checked here |
|---|---|---|---|
| 1 Avoid | No long-lived credential to steal | SSO, MFA, OAuth U2M (people), OAuth M2M + workload identity federation (machines) | CBI-022 (PATs open to all users) |
| 2 Expire | Shorten the useful window | Max token lifetime, short defaults, inactivity revocation, token report | CBI-020, 021, 024 |
| 3 Scope | Limit what it can call | API scopes on PATs and OAuth secrets, PAT auto-scoping, UC managed secrets | CBI-023 |
| **4 Limit** | **Limit where / how it works** | **Context-based ingress**; legacy IP ACLs, front-end PrivateLink | CBI-001…010, 013–015, 019, 026 |
| 5 Detect | Notice exposure and misuse | Audit logs, Workspace Detection App, Databricks leak/abuse detection | CBI-011, 025, new-source query |
| 6 Respond | Close discovery → invalidation | Revoke, deactivate, rotate | CBI-012 |
| 7 Posture | Know the controls are on | Security Analysis Tool, Governance Hub security posture, SRA, token inventory | this skill, CBI-016, 018 |

For SSO/MFA, OAuth adoption, catalog bindings, UC secrets, admin counts, notebook-secret scanning and
egress, point to **Governance Hub → Security** and the **Security Analysis Tool**. This skill
focuses on the ingress layer and the credential facts that change how urgent it is.

## Where to start (the order Databricks recommends)

1. **Enable CBI.** Start from the network policy helper's draft over the **last 90 days** of audit
   logs. Review it rather than adopting it wholesale, and roll out in stages (dry-run first).
2. **Run a posture review.** Use this skill, Governance Hub security posture and SAT to see which
   layers are actually on.
3. **Inventory long-lived tokens.** Pull the account token report. Tokens issued before a lifetime
   policy are still perpetual.
4. **Turn on PAT auto-scoping** and adopt Unity Catalog managed secrets.

## CBI without a VPN: the four patterns (CBI-026)

CBI itself doesn't need a VPN. What's hard is requiring a trusted network for *everyone at once*.
Apply CBI to a narrower slice first. The patterns are alternatives; pick the ones that fit.

| Pattern | Suits | Stays open | Restricted | Evidence for it |
|---|---|---|---|---|
| **B1 Browser yes, remote APIs no** | Browser users working from home | Workspace UI, all users, all public IPs | Programmatic access, except named automation from approved sources | `public_browser_vs_api`: few `programmatic_principals` |
| **B2 Only the API families you need** | Teams needing some remote API/SQL | API rules with `IN <scopes>` (e.g. `sql`) | All other API families | many programmatic identities; `client_families` show JDBC/ODBC/SDK |
| **B3 Narrow partner exceptions** | Hosted Power BI / Tableau Cloud / dbt Cloud | The named Partner platforms source | Everyone else on the internet | `client_families_on_public_ips` shows SaaS |
| **B4 Temporary access on request** | Occasional production support | Nothing by default | Everything until an approved window | operational process; no built-in rule expiry |

Rule behaviour to explain:
- Restricted mode blocks anything no allow rule permits, so **one broad allow rule undoes the rest**
  (CBI-004).
- Deny rules win. API-scope conditions belong in **allow** rules only.
- Changes take 10–15 minutes to propagate.
- Private, cross-workspace, Apps, Lakebase and **account-level** access are separate paths. A workspace
  policy doesn't cover them.
- A service-principal rule from all public IPs is an **identity exception, not a network boundary**.
- Partner IP ranges don't prove the request is *your* tenant, so auth and permissions still matter.
  They also don't cover desktop clients (e.g. Power BI Desktop).
- Broad residential/ISP ranges are not a VPN. Block lists only stop known sources.

If CBI isn't available (tier), skip the B patterns and prioritise Avoid/Expire/Scope, blast radius
(catalog workspace bindings, least privilege + masking, UC secrets, fewer workspace admins, outbound
restrictions, notebook secret scanning) and Detect.

## Rollout order (no-VPN guide)

1. **Know what you have.** Name owners, inventory credentials, public clients, sensitive data and
   production identities, confirm audit access and a recovery path.
2. **Remove avoidable credentials:** OAuth for people, keyless automation, restrict and expire PATs.
3. **Narrow authority:** scopes, fewer admins and grants, lock down stored secrets.
4. **Apply the public-access pattern that fits** (B1–B3). Pilot; don't wait for a company VPN.
5. **Separate high-impact environments** (bind sensitive catalogs, stricter policy, egress control).
6. **Test, respond, maintain.** Run the acceptance tests and retest after every material change.

## Acceptance tests to recommend after enforcement

Test both ways: something that should work, and something that should fail. A saved setting proves
only that it was saved.

- A normal user signs in and does their work → succeeds.
- A retired PAT is presented → authentication fails.
- An unapproved identity calls the public API (B1) → fails after propagation.
- An excluded API family is called (B2) → fails, and the intended alternative works.
- The partner's real scheduled refresh runs (B3) → succeeds, and an unrelated public source is
  blocked.
- A temporary exception expires (B4) → access fails, and cleanup is recorded.
- A known test event flows through detection → time to visibility, alert and containment measured.

Record identity, source, workspace, operation, time, result and policy version for each.
