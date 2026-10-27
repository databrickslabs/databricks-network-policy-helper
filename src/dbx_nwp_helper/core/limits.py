"""Enforce Databricks account network-policy limits on ingress rule specs (warn + auto-cap).

Ported from the ingress notebook's `_enforce_limits`. Emits human-readable warnings via a callback so
the caller (CLI) controls presentation; returns the capped (allow, deny) spec lists.
"""

from __future__ import annotations

from collections.abc import Callable

from ..config import (
    MAX_CIDRS_PER_POLICY,
    MAX_IDENTITIES_PER_POLICY,
    MAX_INGRESS_RULES_PER_POLICY,
)

Warn = Callable[[str], None]


def _label_list(rules: list[dict], limit: int = 10) -> str:
    """Comma-joined rule labels, capped so a big drop doesn't produce a wall of text."""
    labels = [r.get("label", "?") for r in rules]
    if len(labels) > limit:
        return ", ".join(labels[:limit]) + f", …+{len(labels) - limit} more"
    return ", ".join(labels)


def enforce_limits(
    specs: list[dict], deny: list[dict], label: str, warn: Warn
) -> tuple[list[dict], list[dict]]:
    """Cap a target policy's rules to 50 ingress rules / 2000 CIDRs / 100 identities per policy."""
    # Identities per rule (100).
    for spec in specs:
        n = len(spec.get("identities") or [])
        if n > MAX_IDENTITIES_PER_POLICY:
            warn(
                f"[{label}] rule '{spec['label']}' has {n} identities > "
                f"{MAX_IDENTITIES_PER_POLICY} — using the first {MAX_IDENTITIES_PER_POLICY}."
            )
            spec["identities"] = spec["identities"][:MAX_IDENTITIES_PER_POLICY]

    # Ingress rules per policy (50): allow + deny combined. Allow rules are prioritised (so legitimate
    # traffic stays reachable); deny rules take whatever budget is left. When that pushes deny rules
    # (or trailing allow rules) out, say so explicitly and by name — a silent drop here would quietly
    # discard security rules the operator asked for (e.g. --block-threat-ips / --deny-denied-ips).
    all_rules = specs + list(deny)
    if len(all_rules) > MAX_INGRESS_RULES_PER_POLICY:
        kept_allow = specs[:MAX_INGRESS_RULES_PER_POLICY]
        kept_deny = deny[: max(MAX_INGRESS_RULES_PER_POLICY - len(kept_allow), 0)]
        dropped_allow = specs[len(kept_allow) :]
        dropped_deny = deny[len(kept_deny) :]
        parts = [
            f"[{label}] {len(all_rules)} rules (allow+deny) > {MAX_INGRESS_RULES_PER_POLICY} — kept "
            f"{len(kept_allow)} allow + {len(kept_deny)} deny (allow rules prioritised); dropped "
            f"{len(dropped_deny)} deny and {len(dropped_allow)} allow rule(s)."
        ]
        if dropped_deny:
            parts.append(
                f"DENY rules dropped — the threat-intel / denied-IP denies you requested will NOT be "
                f"in this policy: {_label_list(dropped_deny)}."
            )
        if dropped_allow:
            parts.append(f"Allow rules dropped: {_label_list(dropped_allow)}.")
        warn(" ".join(parts))
        specs, deny = kept_allow, kept_deny

    def _total_cidrs(rs):
        return sum(len(r["cidrs"]) for r in rs)

    allow_cidrs = _total_cidrs(specs)
    budget = MAX_CIDRS_PER_POLICY - allow_cidrs
    if budget < 0:
        # Allow CIDRs alone blow the budget: trim allow rules to fit, and drop deny rules entirely.
        # Say so by count and name — like the rule-count cap, this can silently zero requested denies.
        trimmed, used = [], 0
        for r in specs:
            room = MAX_CIDRS_PER_POLICY - used
            if room <= 0:
                break
            r = dict(r, cidrs=r["cidrs"][:room])
            trimmed.append(r)
            used += len(r["cidrs"])
        dropped_allow = specs[len(trimmed) :]
        parts = [
            f"[{label}] allow CIDRs ({allow_cidrs:,}) alone exceed the {MAX_CIDRS_PER_POLICY:,}-CIDR "
            f"policy limit — kept {used:,}, dropped {len(dropped_allow)} allow and all {len(deny)} "
            f"deny rule(s)."
        ]
        if deny:
            parts.append(
                f"DENY rules dropped — the threat-intel / denied-IP denies you requested will NOT be "
                f"in this policy: {_label_list(deny)}."
            )
        if dropped_allow:
            parts.append(f"Allow rules fully dropped: {_label_list(dropped_allow)}.")
        warn(" ".join(parts))
        specs, deny = trimmed, []
    else:
        deny_cidrs = _total_cidrs(deny)
        trimmed_deny, used = [], 0
        for r in deny:
            room = budget - used
            if room <= 0:
                break
            r = dict(r, cidrs=r["cidrs"][:room])
            trimmed_deny.append(r)
            used += len(r["cidrs"])
        if used < deny_cidrs:
            dropped_deny = deny[len(trimmed_deny) :]
            parts = [
                f"[{label}] deny CIDRs trimmed to fit the {MAX_CIDRS_PER_POLICY:,}-CIDR policy limit — "
                f"kept {used:,} of {deny_cidrs:,} deny CIDR(s)."
            ]
            if dropped_deny:
                parts.append(
                    f"Deny rules fully dropped (threat-intel / denied-IP denies NOT in the policy): "
                    f"{_label_list(dropped_deny)}."
                )
            warn(" ".join(parts))
        deny = trimmed_deny
    return specs, deny
