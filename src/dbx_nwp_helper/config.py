"""Configuration dataclasses mirroring the notebook widget option sets.

Each command builds one of these from its CLI flags (or the guided wizard), and the core logic reads
only the dataclass — so the flag surface, the wizard, and the engine never drift apart. The literal
choice sets here are the single source of truth for both Typer's validation and questionary's menus.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --- Enumerated choice sets (shared by CLI flags + guided prompts) ---
THREAT_FEEDS = ["spamhaus_drop", "tor_exit", "firehol_level1", "ipsum", "dshield", "cins_ci_army"]
POLICY_FRAMINGS = ["minimal", "optimal", "maximum"]
SCOPING_MODES = ["ip_only", "ip_and_destination", "ip_and_identity", "ip_identity_and_destination"]
POLICY_SCOPES = ["current_workspace", "per_workspace", "all_workspaces"]
POLICY_MODES = ["dry_run", "enforce"]
THREAT_DENY_RULES = ["off", "matched_only", "all"]
POLICY_ACTIONS = ["create_new", "add_to_existing"]
BLOCK_THREAT_DOMAINS = ["off", "matched_only", "all"]
EGRESS_THREAT_FEEDS = ["threatfox"]

DEFAULT_ACCOUNT_HOST = "https://accounts.cloud.databricks.com"
DEFAULT_NAME_PREFIX = "dbx-nwp"

# Databricks account network-policy limits (warn + auto-cap so proposals stay valid).
MAX_INGRESS_RULES_PER_POLICY = 50
MAX_CIDRS_PER_POLICY = 2000
MAX_IDENTITIES_PER_POLICY = 100
MAX_POLICIES_PER_ACCOUNT = 1000
MAX_DENY_CIDRS = 5000
# Egress limits.
MAX_INTERNET_DESTINATIONS = 100
MAX_STORAGE_DESTINATIONS = 100
# Generated policy ids have an empirical ~30-char limit.
MAX_POLICY_ID_LEN = 30


@dataclass
class Connection:
    """How the CLI reaches the workspace + account. Auth itself is resolved by the SDK's unified
    auth (profile / env / OAuth); this only carries the selectors and the warehouse target."""

    profile: str | None = None
    warehouse_http_path: str | None = None
    # When no warehouse path is given, the CLI reuses/creates a serverless warehouse; store its name.
    warehouse_name: str = "dbx-nwp-helper"
    # Cluster ("t-shirt") size for that auto-created warehouse. Default X-Small; bump for large audit
    # logs. Ignored when --warehouse-http-path points at an existing warehouse.
    warehouse_size: str = "X-Small"
    account_id: str = ""
    account_host: str = DEFAULT_ACCOUNT_HOST
    # Whether --account-host was set explicitly. When False, the CLI derives the account host from the
    # workspace's environment (so a staging / GCP / Azure workspace reaches the matching account API
    # instead of the AWS prod default); an explicit host is always respected.
    account_host_explicit: bool = False
    # A workspace OAuth session can't call the account API, so the account client uses its own
    # profile when given. If unset, unified auth resolves account creds from env / matching profile.
    account_profile: str | None = None


@dataclass
class ApplyOptions:
    """The gated write path — shared shape across all three commands."""

    create_policy: bool = False
    policy_action: str = "create_new"  # create_new | add_to_existing
    existing_policy_id: str = ""
    auto_assign: bool = False
    reviewed: bool = False  # the review gate; --yes/--reviewed sets it non-interactively


@dataclass
class IngressConfig:
    # Analysis window & candidate selection
    lookback_days: int = 30
    min_events: int = 1
    treat_null_status_as_success: bool = False
    include_ipv6: bool = False
    include_account_level: bool = False
    # Also mine system.access.inbound_network for public IPs a dry-run CBI policy would have denied
    # (access_type=DRY_RUN_DENIAL) and fold them into the allow-list candidate set. Best-effort — the
    # table exists only where network monitoring is enabled; absent/empty degrades silently.
    include_inbound_network: bool = True
    # Enrichment
    threat_feeds: list[str] = field(default_factory=lambda: list(THREAT_FEEDS))
    enable_rdap: bool = True
    # How many RDAP owner lookups to run concurrently (they're network-bound and independent). 1 =
    # sequential. Higher is faster but hits RIR rate limits harder (lookups retry/back off on 429).
    rdap_workers: int = 16
    refresh_feeds: bool = False
    # Policy shape
    policy_framing: str = "minimal"
    scoping_mode: str = "ip_only"
    policy_scope: str = "current_workspace"
    policy_mode: str = "dry_run"
    threat_deny_rules: str = "off"
    # The policy name. Explicit (--policy-name) or, when left blank, the CLI resolves it to the
    # profile name (falling back to the workspace id). For single-policy scopes it's the policy id;
    # for per_workspace it's the prefix (-> <name>-ws-<id>). Slugified + length-capped.
    policy_name: str = ""
    # Optional path to write the proposed network-policy JSON (single-policy scopes only).
    export: str = ""
    # Whether to fold the workspace's enabled IP access lists into the CBI policy (alongside the
    # enriched observed-traffic rules). Detected automatically and confirmed interactively
    # (_reconcile_ip_acls); defaults to True so a --yes / non-interactive run migrates them.
    migrate_ip_acls: bool = True
    deny_denied_ips: bool = False
    # The CBI private_access SDK block to attach to the generated policy, or None. Populated by the
    # CLI (_reconcile_private_access) either by migrating a non-allow-all PAS (AWS/GCP — specific
    # registered endpoints) or by copying an existing policy's private_access forward (all clouds).
    # Azure never migrates PrivateLink (ui_api endpoints are default-allowed), so it only ever carries
    # an existing block forward. Held as the SDK object so preview/export/apply emit it verbatim.
    private_access: object | None = None
    # Interactively pick which proposed allow rules to keep (checkbox), before they're built. On by
    # default in interactive runs; skipped under --yes / non-interactive or with --no-select-rules.
    select_rules: bool = True
    # After creating AND assigning the policy, turn off the workspace's existing IP access lists
    # (the CBI policy replaces them). Gated by validate_disable_ip_acls so it can't leave the
    # workspace unprotected.
    disable_existing_ip_acls: bool = False
    apply: ApplyOptions = field(default_factory=ApplyOptions)

    @property
    def scope_destination(self) -> bool:
        return self.scoping_mode in ("ip_and_destination", "ip_identity_and_destination")

    @property
    def scope_identity(self) -> bool:
        return self.scoping_mode in ("ip_and_identity", "ip_identity_and_destination")

    @property
    def policy_mode_target(self) -> str:
        return {"dry_run": "ingress_dry_run", "enforce": "ingress"}[self.policy_mode]


@dataclass
class EgressConfig:
    lookback_days: int = 30
    min_events: int = 1
    source_type_filter: str = ""
    enable_rdap: bool = True
    refresh_feeds: bool = False
    # See IngressConfig.policy_name — same resolution (explicit / profile / workspace id).
    policy_name: str = ""
    export: str = ""  # optional path to write the proposed network-policy JSON (single-policy)
    policy_mode: str = "dry_run"
    policy_scope: str = "current_workspace"
    block_threat_domains: str = "off"
    threat_feed: str = "threatfox"
    # Interactively pick which observed destinations to allow-list (checkbox). On by default in
    # interactive runs; skipped under --yes / non-interactive or with --no-select-rules.
    select_rules: bool = True
    apply: ApplyOptions = field(default_factory=ApplyOptions)


def validate_apply(apply: ApplyOptions, policy_scope: str, other_direction: str) -> None:
    """Validate the add_to_existing invariants early with an actionable message (mirrors the
    notebooks' upfront checks). `other_direction` names the helper that created the target policy."""
    if not (apply.create_policy and apply.policy_action == "add_to_existing"):
        return
    if not apply.existing_policy_id:
        raise ValueError(
            "policy_action=add_to_existing requires --existing-policy-id "
            f"(e.g. the id the {other_direction} helper created). Set it and re-run."
        )
    if policy_scope == "per_workspace":
        raise ValueError(
            "policy_action=add_to_existing updates one supplied policy id, so it can't be used with "
            "--policy-scope per_workspace (which fans out to many policies). Use current_workspace "
            "or all_workspaces, or use create_new for per_workspace."
        )


def validate_policy_name(policy_name: str, policy_scope: str, policy_action: str) -> None:
    """--policy-name names the created policy: the id for a single-policy scope, or the prefix for
    per_workspace (-> <name>-ws-<id>). Reject it only with add_to_existing, where the target id comes
    from --existing-policy-id instead."""
    if not policy_name:
        return
    if policy_action == "add_to_existing":
        raise ValueError(
            "--policy-name is for creating a new policy; with policy_action=add_to_existing the "
            "target id comes from --existing-policy-id. Drop one of them."
        )


def validate_export(export: str, policy_scope: str) -> None:
    """--export writes a single policy body, so it can't be used with per_workspace (which builds one
    policy per workspace)."""
    if export and policy_scope == "per_workspace":
        raise ValueError(
            "--export writes a single network-policy body, so it can't be used with --policy-scope "
            "per_workspace (which builds one policy per workspace). Use current_workspace or "
            "all_workspaces."
        )


def validate_disable_ip_acls(disable: bool, create_policy: bool, auto_assign: bool) -> None:
    """--disable-existing-ip-acls turns OFF the workspace's IP access list enforcement, which is a
    live ingress control. Only permit it when the run will both *create* AND *assign* the
    replacement CBI policy — otherwise disabling the ACL could leave the workspace with no ingress
    protection at all."""
    if not disable:
        return
    if not (create_policy and auto_assign):
        raise ValueError(
            "--disable-existing-ip-acls turns off the workspace's IP access lists, so it may only be "
            "used when the run also creates AND assigns the replacement policy (otherwise the "
            "workspace could be left with no ingress protection). Re-run with --create-policy and "
            "--auto-assign, or drop --disable-existing-ip-acls."
        )
