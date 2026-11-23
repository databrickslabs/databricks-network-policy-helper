# Context-based ingress (CBI): what to know when explaining findings

Condensed from the Databricks docs (links at the end). Re-check the docs for anything marked Beta.

## What it is
An **account network policy** (one policy can govern many workspaces) whose ingress section decides
whether a request is allowed from **identity × source × request type**:

- **Identity:** all users and SPs · all users · all SPs · selected identities. Apps and Lakebase
  runtime support only "all users and service principals".
- **Source:**
  - *public*: all IPs · selected IPv4/CIDRs · **partner platforms** (Power BI, Tableau Cloud, dbt
    Cloud, ChatGPT, Claude by IP; Genie for Slack/Teams by OAuth client id)
  - *private*: all registered endpoints · selected endpoints
  - *cross-workspace* (Beta): selected source workspaces, or compatibility mode
- **Request type:** Workspace UI · API (all / IN scopes / NOT IN scopes; includes JDBC/ODBC SQL
  endpoints) · Apps runtime · Lakebase runtime · (account level) Account UI / Account API.

Evaluation: in restricted mode the default is **deny**, allow rules open paths, and **deny rules win**
over allow rules.

## Workspace vs account level
| | Workspace-level | Account-level (Beta) |
|---|---|---|
| Protects | workspaces | account console, account APIs, account Genie One |
| Default | `default-policy` for unassigned workspaces | fixed `account-policy`, auto-attached |
| Logs | `system.access.inbound_network` | same table, `workspace_id = 0` |

## Modes
- **Dry run:** violations are logged (`DRY_RUN_DENIAL` / `DENY_DRY_RUN`), nothing is blocked. Start here.
- **Enforced:** violations are blocked (`DENIED` / `DENY` / `DROP`).
- One mode per policy. In the API the rules live in `ingress` (enforced) **or** `ingress_dry_run`.
- Changes take **10–15 minutes** to propagate and may be inconsistent meanwhile.

## Interactions
- **Workspace IP access lists:** logical **AND** with CBI. Both must allow, so IP lists can only narrow.
- **Account IP access lists:** AND with the account-level policy.
- **PAS public-access toggle:** "Block public network access" means public ingress is blocked and CBI
  public rules are not evaluated.
- **Front-end PrivateLink:** both the PAS **and** CBI `private_access` must permit the endpoint. CBI
  defaults to all registered endpoints (up to 200).
- **Classic compute without PrivateLink** is auto-allowed regardless of public rules. With PrivateLink
  it must use PrivateLink.
- **Serverless → same workspace** isn't affected by public rules. Workspace-to-workspace serverless
  traffic is governed by cross-workspace access.
- **OpenSharing recipient IP lists** are separate and not governed by CBI.
- **Serverless egress control** lives in the same policy object (`egress`). CBI is the inbound half.

## Limits (per policy unless noted)
50 ingress rules · 2,000 CIDR blocks · 100 identities · 1,000 policies per account · 200 private
endpoints under the default rule. Public rules are **IPv4 only**.

## Requirements
Enterprise tier · account admin to manage policies · the `access` system schema enabled (plus SELECT
grants) to read `system.access.inbound_network`.

**Availability:** AWS commercial, Azure and GCP. AWS GovCloud and AWS GovCloud DoD were added on
2026-11-04 (GovCloud release notes). Serverless egress network policies have been GA in AWS GovCloud
since 2026-03-05; that release note doesn't mention DoD.

## Databricks best practices
Start in dry run · use identity-based rules for SaaS clients that rotate IPs · apply deny rules to
privileged service principals first · use clear, consistent policy names · don't edit
`default-policy` ingress; attach named policies · migrate IP access lists so CBI is the only engine.

## Docs (AWS paths; Azure/GCP have equivalents)
- Context-based ingress: https://docs.databricks.com/aws/en/security/network/front-end/context-based-ingress
- Manage workspace ingress policies: https://docs.databricks.com/aws/en/security/network/front-end/manage-ingress-workspace
- Manage account ingress policies (Beta): https://docs.databricks.com/aws/en/security/network/front-end/manage-ingress-account
- Migrate IP access lists to CBI: https://docs.databricks.com/aws/en/security/network/front-end/migrate-to-context-based-ingress
- Partner platforms: https://docs.databricks.com/aws/en/security/network/front-end/partner-platforms
- Cross-workspace access: https://docs.databricks.com/aws/en/security/network/front-end/cross-workspace-access
- Front-end private connectivity: https://docs.databricks.com/aws/en/security/network/front-end/front-end-private-connect
- Private access settings: https://docs.databricks.com/aws/en/security/network/classic/private-access-settings
- Network access system tables: https://docs.databricks.com/aws/en/admin/system-tables/network
- AWS GovCloud release notes 2026 (CBI in GovCloud + GovCloud DoD): https://docs.databricks.com/aws/en/release-notes/gov-cloud/2026
- Azure: https://learn.microsoft.com/azure/databricks/security/network/front-end/context-based-ingress
