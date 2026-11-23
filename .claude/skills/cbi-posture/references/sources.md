# Sources

## Tools folded into this skill
- databricks-network-policy-helper (`dbx-nwp-helper`): remediation engine for ingress + egress
  https://github.com/databrickslabs/databricks-network-policy-helper
  - its skills: `.claude/skills/ingress-helper/SKILL.md`, `.claude/skills/egress-helper/SKILL.md`
  - schema notes: `docs/cbi-sdk-schema.md`; privileges: `docs/account-admin-setup.md`
- databricks-migrate-ip-acls (`dbx-migrate-ip-acls`): verbatim IP ACL → CBI migration
  https://github.com/databrickslabs/migrate-ip-acls

## Related open-source / posture tools
- Databricks Workspace Detection App (detections, threat-model notebooks, Genie Agent):
  https://github.com/databricks-solutions/cybersec-workspace-detection-app
- Security Analysis Tool (SAT): https://github.com/databricks-industry-solutions/security-analysis-tool
- Security Reference Architecture (SRA): https://github.com/databricks/terraform-databricks-sra

## Databricks documentation (AWS paths; Azure/GCP have equivalents)
- Context-based ingress control: https://docs.databricks.com/aws/en/security/network/front-end/context-based-ingress
- Manage workspace ingress policies: https://docs.databricks.com/aws/en/security/network/front-end/manage-ingress-workspace
- Manage account ingress policies (Beta): https://docs.databricks.com/aws/en/security/network/front-end/manage-ingress-account
- Migrate IP access lists to CBI: https://docs.databricks.com/aws/en/security/network/front-end/migrate-to-context-based-ingress
- AWS GovCloud release notes 2026 (CBI available in GovCloud + GovCloud DoD, 2026-11-04): https://docs.databricks.com/aws/en/release-notes/gov-cloud/2026
- Partner platforms: https://docs.databricks.com/aws/en/security/network/front-end/partner-platforms
- Cross-workspace access: https://docs.databricks.com/aws/en/security/network/front-end/cross-workspace-access
- Front-end private connectivity: https://docs.databricks.com/aws/en/security/network/front-end/front-end-private-connect
- Private access settings: https://docs.databricks.com/aws/en/security/network/classic/private-access-settings
- Network access system tables: https://docs.databricks.com/aws/en/admin/system-tables/network
- Serverless egress control: https://docs.databricks.com/aws/en/security/network/serverless-network-security/network-policies
- Grant access to system tables: https://docs.databricks.com/aws/en/admin/system-tables/#grant-access
- Personal access token management / token report: https://docs.databricks.com/aws/en/admin/access-control/tokens
- OAuth U2M / M2M and workload identity federation: https://docs.databricks.com/aws/en/dev-tools/auth/
- Unity Catalog secrets: https://docs.databricks.com/aws/en/security/secrets/
- Audit log reference: https://docs.databricks.com/aws/en/admin/account-settings/audit-logs
- Azure: https://learn.microsoft.com/azure/databricks/security/network/front-end/context-based-ingress
