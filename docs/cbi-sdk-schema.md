# CBI network-policy SDK schema

Verified against `databricks-sdk` **0.152.0** by introspection (not from docs/memory). The project
pins `databricks-sdk>=0.152.0` in `pyproject.toml` because the `private_access` /
`cross_workspace_access` sub-blocks (and their dataclasses) don't exist in earlier versions — the
0.113.0 floor only carried the public-access allow/deny rules.

## Client & methods

- Client: **`AccountClient`** (account-level; not `WorkspaceClient`). Requires account admin.
- Service: `a.network_policies` → `NetworkPoliciesAPI` in `databricks.sdk.service.settings`.
- Methods (update is a **full replace**, not a patch):
  - `create_network_policy_rpc(network_policy: AccountNetworkPolicy)`
  - `get_network_policy_rpc(network_policy_id: str)`
  - `update_network_policy_rpc(network_policy_id: str, network_policy: AccountNetworkPolicy)`
  - `list_network_policies_rpc()`
  - `delete_network_policy_rpc(network_policy_id: str)`

## Object model

```
AccountNetworkPolicy
├── account_id: str
├── network_policy_id: str
├── ingress:         CustomerFacingIngressNetworkPolicy   # ENFORCED — blocks non-matching source IPs
├── ingress_dry_run: CustomerFacingIngressNetworkPolicy   # LOG-ONLY — records, never blocks
└── egress:          NetworkPolicyEgress                  # SEG; preserved verbatim on update

CustomerFacingIngressNetworkPolicy
├── public_access:          CustomerFacingIngressNetworkPolicyPublicAccess          # source-IP allow-list
├── private_access:         CustomerFacingIngressNetworkPolicyPrivateAccess         # front-end PrivateLink
└── cross_workspace_access: CustomerFacingIngressNetworkPolicyCrossWorkspaceAccess  # workspace→workspace

CustomerFacingIngressNetworkPolicyPrivateAccess          # front-end PrivateLink (the workspace PAS)
├── restriction_mode: {ALLOW_ALL_REGISTERED_ENDPOINTS | RESTRICTED_ACCESS}
├── allow_rules: [CustomerFacingIngressNetworkPolicyPrivateIngressRule]
└── deny_rules:  [...]
    PrivateRequestOrigin ├── all_registered_endpoints: bool   # any endpoint registered to the account
                         ├── endpoints: Endpoints(endpoint_ids: [str])   # specific registered endpoints
                         ├── all_private_access / azure_workspace_private_link: bool   # deny-rule only
    # AWS/GCP migration (core/policy.build_private_access_block): a non-allow-all PAS (level ENDPOINT)
    # -> RESTRICTED_ACCESS with endpoints=allowed_vpc_endpoint_ids (mapped across as-is; the PAS name
    # is kept as the rule label). An allow-all (ACCOUNT) PAS needs no migration (CBI defaults to
    # allowing all registered endpoints) and never loosens a stricter existing private block. Azure
    # does NOT migrate front-end PrivateLink. Public, private and cross-workspace are independent
    # dimensions: each is built/migrated or carried forward from the assigned policy's restrictive
    # blocks (acl.existing_cbi_ingress), composed via policy.assemble_ingress. Cross-workspace is
    # never built — always carried forward.

CustomerFacingIngressNetworkPolicyCrossWorkspaceAccess   # serverless workspace→workspace ingress
├── restriction_mode: {FULL_ACCESS | LEGACY_MODE | RESTRICTED_ACCESS}   # LEGACY_MODE = "compatibility"
├── allow_rules / deny_rules: [...CrossWorkspaceIngressRule]
    CrossWorkspaceRequestOrigin ├── all_source_workspaces: bool
                                └── selected_workspaces: WorkspaceIdList(workspace_ids: [int])
    # This tool leaves it unset (account default = compatibility) and preserves any existing block on
    # update — it doesn't build cross-workspace rules yet.

CustomerFacingIngressNetworkPolicyPublicAccess
├── restriction_mode: {FULL_ACCESS | RESTRICTED_ACCESS}   # helper always uses RESTRICTED_ACCESS
├── allow_rules: [CustomerFacingIngressNetworkPolicyPublicIngressRule]   # the suggested allow-list
└── deny_rules:  [CustomerFacingIngressNetworkPolicyPublicIngressRule]   # optional threat-intel deny rules
                                                                          # (same rule shape; origin CIDRs only)

PublicIngressRule
├── label: str
├── origin:         PublicRequestOrigin   # the IPs
├── destination:    RequestDestination    # optional — what they may reach
└── authentication: Authentication        # optional — who

PublicRequestOrigin
├── included_ip_ranges: IpRanges(ip_ranges: List[str])   # IPv4 CIDR only
├── excluded_ip_ranges: IpRanges
└── all_ip_ranges: bool

RequestDestination  (set exactly one shape)
├── all_destinations: bool
├── apps_runtime:     AppsRuntimeDestination(all_destinations=True)
├── lakebase_runtime: LakebaseRuntimeDestination(all_destinations=True)
├── workspace_ui / workspace_api / account_ui / account_api / account_databricks_one: ...

Authentication
├── identity_type: {IDENTITY_TYPE_ALL_USERS | IDENTITY_TYPE_ALL_SERVICE_PRINCIPALS | IDENTITY_TYPE_SELECTED_IDENTITIES}
└── identities: [AuthenticationIdentity]   # only with SELECTED_IDENTITIES

AuthenticationIdentity
├── principal_id: int                       # NUMERIC account principal id — NOT the email
└── principal_type: {PRINCIPAL_TYPE_USER | PRINCIPAL_TYPE_SERVICE_PRINCIPAL}
```

## Gotchas baked into the CLI

- **`included_ip_ranges` is an `IpRanges` object**, not a bare list — wrap: `IpRanges(ip_ranges=[...])`.
- **IPv4 only** — the schema comment says "We only support IPv4 ... CIDR notation for now". IPv6
  framings are dropped before building a policy (`core/ingress_rules.py`).
- **`principal_id` is `int`.** The audit log only has string emails/subject_names — there is no
  numeric id in `system.access.audit`. Identity scoping therefore resolves emails→ids via account
  SCIM (`AccountClient.users.list(filter='userName eq "..."')` /
  `service_principals.list(filter='applicationId eq "..."')`, taking `.id`).
- **No groups** — only USER and SERVICE_PRINCIPAL principal types exist.
- **`authentication` is rejected on Apps / Lakebase / `all_destinations` rules** — those destinations
  implicitly allow all users + service principals, so a `SELECTED_IDENTITIES` block returns
  `InvalidParameterValue` ("omit the authentication block"). These are the only destination shapes
  the CLI emits, so per-identity scoping can't be attached today; `build_ingress_rule` omits the
  block and the ingress engine warns (`core/policy.py`, `core/ingress_rules.py`).
- **Dry-run vs enforce are separate blocks**, not an enforcement flag: write `ingress_dry_run` to
  trial (log-only), `ingress` to enforce (blocking). Update replaces the whole policy, so the CLI
  reads the existing policy and re-sends the untouched blocks (`core/policy.py`).
- **Update is a full replace, so `build_ingress_block` only ever sets `public_access` (+ a mirrored
  `private_access` when migrating a PAS).** `apply_ingress` carries over the existing policy's
  `private_access` / `cross_workspace_access` sub-blocks (from either mode's block, so a mode switch
  doesn't drop them) unless the freshly built block set them — so an in-place update never clobbers a
  console-configured private-access or cross-workspace (compatibility) config.
- **No "Partner platforms" network source exists in the SDK.** `PublicRequestOrigin` is only
  `included_ip_ranges` / `excluded_ip_ranges` / `all_ip_ranges`. The console's managed "Partner
  platforms" source (Beta; AWS + GCP) is console/Terraform-only, so partner-platform IPs this tool
  recognises (Power BI / dbt) are emitted as ordinary labelled CIDR allow-rules, and the CLI advises
  the managed source as the cleaner alternative.
