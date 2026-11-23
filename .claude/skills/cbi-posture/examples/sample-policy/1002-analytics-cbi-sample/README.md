# Sample CBI policy: analytics-prod (`1002`)

_Built 2026-11-18 06:00:00 from 30 days of this workspace's own audit logs, by cbi-posture v0.3.0. Nothing has been applied._

> **This is a starting point to test, not a recommendation.** It reflects the traffic seen in the window. Observed traffic can include sources you don't want, including an attacker, so the customer's owners confirm every source before anything is enforced. Test in dry-run (log-only) first.

## What's in this folder

- `policy.json`: the proposed policy as exported by `dbx-nwp-helper` (for reference; apply it through the helper).
- `review-sheet.csv`: one row per proposed rule and range, with the traffic it covers. Fill in **keep / drop** and an **owner**.
- `uncovered-sources.csv`: observed sources no rule covers. Enforcing would block these.
- `monitor.sql`: the daily dry-run check.

## The proposal at a glance

| Category | Rules | Ranges | Events covered | What to do |
|---|---|---|---|---|
| consolidated | 1 | 2 | 45 | Low-traffic owners folded together to stay under the 50-rule limit. |
| databricks | 1 | 1 | 1,500 | Databricks-owned range seen in your traffic (platform callbacks). |
| deny-recently-denied | 1 | 1 | 0 | Sources that were blocked recently (IP access list or enforced CBI). |
| ip-acl | 1 | 2 | 39,000 | Migrated from the workspace's existing IP access list. |
| observed | 2 | 3 | 2,903 | Derived from successful traffic in the lookback window. |
| partner | 1 | 1 | 4,200 | A partner platform (BI / transformation SaaS). |

- Mode in the export: **dry_run**.
- Coverage: the allow rules cover **94.4%** of 50,448 successful public-IPv4 events from 11 sources. **2 sources (2,800 events)** would be blocked if enforced.
- Rows flagged for a closer look: **3** (see the `flags` column).

### Suggested rollout pattern

**Allow only the API families you need**: 140 identities call APIs from public IPs. Use API allow rules with `IN <scopes>` (e.g. `sql`) rather than a general public API rule

(1) **Narrow partner exceptions**: allow the Partner platforms source for the hosted BI tools seen, instead of opening API access to the internet. (2) Pilot on one workspace in dry-run over a full business cycle before enforcing; use time-boxed selected-identity rules for occasional production access.

_The helper proposes IP-based rules only. Use the dry-run baseline from this sample policy first, then make the pattern's identity, API-scope or partner changes in the account console and re-test in dry-run._

## Read before testing

- Verbose audit logging was turned off during the window (CBI-025), so the traffic sample has a gap.

### Flagged rows

| Label | Range | Category | Events | Flags |
|---|---|---|---|---|
| corp | 52.0.0.0/8 | ip-acl | 0 | broad range /8 (16,777,216 addresses): confirm it isn't a whole cloud or ISP block; no successful traffic in the window: confirm still needed |
| Example-ISP | 203.0.113.77/32 | observed | 3 | seen on one day only |
| Consolidated-Observed-IPs | 192.0.2.20/32 | consolidated | 5 | low volume (5 events) |

### Largest uncovered sources

| Source | Events | Days | Clients | Identities | Suggested handling |
|---|---|---|---|---|---|
| 34.120.5.6 | 2500 | 60 | Tableau | analyst@example.com | partner client: use the managed Partner platforms source if it covers this partner, otherwise the vendor's published ranges |
| 81.2.69.142 | 300 | 20 | Databricks CLI | alex@example.com | one identity, recurring: likely a roaming user or a job host; confirm, then add the network or route it via an approved one |

## How to test it

1. **Review.** Fill in `review-sheet.csv` (keep / drop, owner) and `uncovered-sources.csv` (add / accept block). Every kept row needs an owner who recognises the source.
2. **Apply in dry-run, through the helper**, run by the customer's account admin. The helper re-reads current traffic and shows a rule selector: untick the rows marked *drop*. It also keeps existing egress and checks the assigned policy before writing.

   ```
   uv run dbx-nwp-helper ingress --profile analytics --lookback-days 30 --warehouse-http-path <sql-warehouse-http-path> --create-policy --policy-mode dry_run --policy-action create_new --policy-name analytics-cbi-sample --auto-assign
   ```

   Creates `analytics-cbi-sample` and assigns it to workspace 1002, replacing `default-policy`. The helper checks first and aborts if that would drop an enforced egress policy.
   Add partner platforms flagged in the sheet as the managed *Partner platforms* source on the policy's Ingress tab in the account console. The SDK can't set it yet.

3. **Watch for 28 days** (at least 14, and long enough to include a month-end). Run `monitor.sql` daily. Each row is a request the policy would block: add it if legitimate, or record why it should be blocked.
4. **Re-run the helper propose-only weekly** to fold in legitimate misses; dry-run denials are picked up automatically.
5. **Acceptance tests during dry-run:**
   - Browser sign-in from an approved network: no new would-block rows.
   - A scheduled job, a BI refresh and each named automation identity: no would-block rows.
   - A request from an unapproved network (e.g. a phone hotspot) **does** appear as a would-block row. This proves the policy is evaluating.

## Ready to enforce when

- It has run in dry-run for 28+ days, including a month-end.
- There have been no would-block events from sources marked *keep* for the last 7 days.
- Every kept rule has an owner, and every uncovered source has a decision.
- A recovery path is in place: at least one admin can reach the workspace from a confirmed source, and the account console is reachable (it's governed separately).
- The rollback below has been rehearsed.

Enforce by re-running the helper with `--policy-mode enforce`. The customer decides when; this sample policy never does.

## Rollback

Reassign the workspace to the policy it had before the test:

```
databricks account workspace-network-configuration update-workspace-network-option-rpc 1002 --network-policy-id default-policy -p <account-profile>
```

Allow time for the change to propagate before re-testing. IP access lists, if enabled, keep applying throughout the test.

## Not fixed by this policy

A network policy limits where a credential works. These findings for the same workspace need their own fixes:

- **CBI-020** (high, Expire): PATs that never expire.
- **CBI-021** (medium, Expire): No short maximum lifetime for new PATs.
- **CBI-025** (medium, Detect): Verbose audit logging was turned off in the lookback window.

## Sign-off

| Role | Name | Date | Decision |
|---|---|---|---|
| Workspace owner |  |  |  |
| Security |  |  |  |
| Account admin (applies) |  |  |  |
