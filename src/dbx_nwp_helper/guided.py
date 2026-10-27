"""The guided Q&A wizard.

`dbx-nwp-helper guided` — point it at a workspace (a profile, optionally a warehouse) and it walks the
user through building an ingress / egress policy with questionary prompts, using the same choice sets
as the flags (config.py) and the same run flow as the flag commands (cli._run_*). It always ends
propose-only by default; the user opts into a write and mode via prompts, then the shared review gate
confirms before anything is sent.

(The verbatim IP-ACL → CBI migration now has its own tool, `dbx-migrate-ip-acls`.)
"""

from __future__ import annotations

import os

import questionary

from . import console
from .config import (
    ABUSE_CH_FEEDS,
    BLOCK_THREAT_DOMAINS,
    DEFAULT_EGRESS_THREAT_FEEDS,
    DOMAIN_ALLOWLIST_FEEDS,
    EGRESS_THREAT_FEEDS,
    POLICY_FRAMINGS,
    POLICY_MODES,
    POLICY_SCOPES,
    SCOPING_MODES,
    THREAT_DENY_RULES,
    THREAT_FEEDS,
    ApplyOptions,
    Connection,
    EgressConfig,
    IngressConfig,
)

_STYLE = questionary.Style(
    [
        ("qmark", "fg:#FF3621 bold"),
        ("question", "bold"),
        ("answer", "fg:#00A972 bold"),
        ("pointer", "fg:#FF3621 bold"),
        ("highlighted", "fg:#FF3621 bold"),
    ]
)


def _select(message: str, choices: list[str], default: str | None = None) -> str:
    return questionary.select(message, choices=choices, default=default or choices[0], style=_STYLE).ask()


def _confirm(message: str, default: bool = False) -> bool:
    # auto_enter=False: a y/n keypress alone must NOT submit — the answer requires an explicit Enter.
    # Otherwise a single keystroke confirms instantly and a habitual follow-up Enter falls through to
    # the next prompt, accepting its default (e.g. selecting the wrong profile/workspace).
    return questionary.confirm(message, default=default, style=_STYLE, auto_enter=False).ask()


def _text(message: str, default: str = "") -> str:
    return (questionary.text(message, default=default, style=_STYLE).ask() or "").strip()


def _int(message: str, default: int) -> int:
    while True:
        raw = _text(message, str(default))
        try:
            return int(raw)
        except ValueError:
            console.banner("warn", "Enter a whole number.")


def run_wizard(conn: Connection) -> None:
    from .cli import _run_egress, _run_ingress

    console.title_panel(
        "dbx-nwp-helper — guided setup", "Answer a few questions; I'll analyse traffic and propose a policy."
    )

    direction = _select(
        "What would you like to build?",
        [
            "Ingress (CBI) — who may connect IN, by source IP",
            "Egress (SEG) — where workloads may connect OUT",
        ],
    )
    if direction is None:
        return

    # account_id is needed only if the user later opts to apply / identity-scope. Ask up front so the
    # apply step doesn't fail late, but allow blank for propose-only.
    if not conn.account_id:
        acct = _text("Databricks account_id (blank = propose-only, no apply/identity scoping)")
        conn.account_id = acct

    if direction.startswith("Ingress"):
        _run_ingress(_ingress_wizard(conn), conn, yes=False)
    else:
        _run_egress(_egress_wizard(conn), conn, yes=False)


def resolve_threat_ip_feeds(interactive: bool, engaged: bool) -> list[str]:
    """Resolve the threat-intel IP feeds for ingress — the interactive selection behind the single
    ``--block-threat-ips`` flag (the IP-side mirror of ``resolve_threat_domain_feeds``). These feeds
    both flag known-bad source IPs (always, keeping them out of the allow-list) and, when the flag is
    not ``off``, build CBI deny rules. A checkbox is offered only when the flag is engaged and the run
    is interactive; otherwise all feeds load — the safe default for the always-on flagging path and
    headless / ``--yes`` runs."""
    if not (interactive and engaged):
        return list(THREAT_FEEDS)
    return questionary.checkbox(
        "Select threat-intel feeds:",
        choices=[questionary.Choice(f, checked=True) for f in THREAT_FEEDS],
        style=_STYLE,
    ).ask() or list(THREAT_FEEDS)


def _ingress_wizard(conn: Connection) -> IngressConfig:
    console.rule("Ingress questions")
    lookback = _int("How many days of audit history to analyse?", 30)
    min_events = _int("Minimum successful events for an IP to be a candidate?", 1)
    framing = _select("CIDR framing?", POLICY_FRAMINGS, default="minimal")
    scoping = _select("Scoping mode?", SCOPING_MODES, default="ip_only")
    scope = _select("Policy scope?", POLICY_SCOPES, default="current_workspace")
    enable_rdap = framing == "maximum" or _confirm("Do RDAP owner lookups (external calls)?", True)
    threat_deny = _select(
        "Add threat-intel deny rules for known-bad source IPs?", THREAT_DENY_RULES, default="off"
    )
    feeds = resolve_threat_ip_feeds(interactive=True, engaged=threat_deny != "off")

    apply = _apply_wizard(conn, scope, other="egress")
    mode = _mode_wizard() if apply.create_policy else "dry_run"
    disable_acls = (
        apply.create_policy
        and apply.auto_assign
        and _confirm(
            "Disable the workspace's existing IP access lists after applying? "
            "(the new CBI policy replaces them)",
            False,
        )
    )
    # The policy name is prompted for centrally in the run flow (blank = profile name), so it isn't
    # asked here.
    return IngressConfig(
        lookback_days=lookback,
        min_events=min_events,
        threat_feeds=feeds,
        enable_rdap=enable_rdap,
        policy_framing=framing,
        scoping_mode=scoping,
        policy_scope=scope,
        policy_mode=mode,
        threat_deny_rules=threat_deny,
        disable_existing_ip_acls=disable_acls,
        apply=apply,
    )


def resolve_threat_domain_feeds(interactive: bool) -> tuple[list[str], str | None, bool]:
    """Resolve the domain block feeds, abuse.ch Auth-Key, and popularity-allowlist toggle for a
    ``--block-threat-domains`` run — the single interactive front door that replaces the old
    ``--threat-feeds`` / ``--abuse-ch-auth-key`` / ``--domain-allowlist`` flags.

    Interactive → a checkbox feed picker, then a key prompt only when a key-gated feed is selected.
    Non-interactive (``--yes`` / no TTY) → the keyless feeds, plus the abuse.ch feeds when
    ``DBX_NWP_ABUSE_CH_AUTH_KEY`` is set, with the allowlist review on. The key is always read from
    ``DBX_NWP_ABUSE_CH_AUTH_KEY`` (and offered as the prompt default interactively)."""
    env_key = os.environ.get("DBX_NWP_ABUSE_CH_AUTH_KEY") or None
    if not interactive:
        feeds = list(DEFAULT_EGRESS_THREAT_FEEDS)
        if env_key:
            feeds += [f for f in EGRESS_THREAT_FEEDS if f in ABUSE_CH_FEEDS]
        return feeds, env_key, True
    feeds = questionary.checkbox(
        "Select domain block feeds (threatfox/urlhaus need an abuse.ch Auth-Key):",
        choices=[
            questionary.Choice(f, checked=f in DEFAULT_EGRESS_THREAT_FEEDS) for f in EGRESS_THREAT_FEEDS
        ],
        style=_STYLE,
    ).ask() or list(DEFAULT_EGRESS_THREAT_FEEDS)
    auth_key = env_key
    if any(f in ABUSE_CH_FEEDS for f in feeds):
        auth_key = (
            _text(
                "abuse.ch Auth-Key (blank to skip those feeds; sign up at auth.abuse.ch)",
                default=env_key or "",
            )
            or None
        )
    allowlist = _confirm(
        "Flag block-candidates that are also on a popularity/allowlist (Tranco/MISP) for review?",
        True,
    )
    return feeds, auth_key, allowlist


def _egress_wizard(conn: Connection) -> EgressConfig:
    console.rule("Egress questions")
    lookback = _int("How many days of outbound_network history to analyse?", 30)
    min_events = _int("Minimum events per destination?", 1)
    src_filter = _text("network_source_type filter (blank = all)")
    scope = _select("Policy scope?", POLICY_SCOPES, default="current_workspace")
    enable_rdap = _confirm("Look up the cloud owner of internet FQDNs?", True)
    block = _select("Block known-bad domains from a threat feed?", BLOCK_THREAT_DOMAINS, default="off")
    feeds, auth_key, allowlist = list(DEFAULT_EGRESS_THREAT_FEEDS), None, True
    if block != "off":
        feeds, auth_key, allowlist = resolve_threat_domain_feeds(interactive=True)

    apply = _apply_wizard(conn, scope, other="ingress")
    mode = _mode_wizard() if apply.create_policy else "dry_run"
    # The policy name is prompted for centrally in the run flow (blank = profile name), so it isn't
    # asked here.
    return EgressConfig(
        lookback_days=lookback,
        min_events=min_events,
        source_type_filter=src_filter,
        enable_rdap=enable_rdap,
        policy_scope=scope,
        policy_mode=mode,
        block_threat_domains=block,
        threat_feeds=feeds,
        abuse_ch_auth_key=auth_key,
        domain_allowlist=allowlist,
        domain_allowlist_feeds=list(DOMAIN_ALLOWLIST_FEEDS),
        apply=apply,
    )


def _apply_wizard(conn: Connection, scope: str, other: str) -> ApplyOptions:
    if not conn.account_id:
        console.banner("info", "No account_id set — this will be a propose-only run.")
        return ApplyOptions(create_policy=False)
    if not _confirm("Create/apply the policy now (needs account admin)?", False):
        return ApplyOptions(create_policy=False)
    action = "create_new"
    existing_id = ""
    if _confirm(f"Add these rules to an EXISTING policy (e.g. one the {other} helper made)?", False):
        action = "add_to_existing"
        existing_id = _text("Existing policy id?")
        if scope == "per_workspace":
            console.banner(
                "warn", "add_to_existing can't be used with per_workspace scope — the " "run will flag this."
            )
    auto_assign = _confirm("Bind the workspace(s) to the policy?", False)
    return ApplyOptions(
        create_policy=True, policy_action=action, existing_policy_id=existing_id, auto_assign=auto_assign
    )


def _mode_wizard() -> str:
    mode = _select(
        "Policy mode? (dry_run is log-only and strongly recommended first)", POLICY_MODES, default="dry_run"
    )
    if mode == "enforce":
        console.banner("danger", "ENFORCE will block non-matching traffic once applied.")
        if not _confirm("Are you sure you want enforce (not dry_run)?", False):
            return "dry_run"
    return mode
