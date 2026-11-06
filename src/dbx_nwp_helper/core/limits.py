"""Enforce Databricks account network-policy limits on ingress rule specs (warn + auto-cap), and
consolidate low-traffic rules so a large environment fits the rule cap without losing its IPs.

Ported from the ingress notebook's `_enforce_limits`. Emits human-readable warnings via a callback so
the caller (CLI) controls presentation; returns the capped (allow, deny) spec lists. The optional
`summary` dict accumulates structured counts (rules / CIDRs dropped) for the CLI's truncation panel.

`consolidate` runs BEFORE `enforce_limits`: when a target has more allow rules than the cap allows,
the highest-traffic owner groups keep their own labelled rules and the remainder are folded into
one "Consolidated-Observed-IPs" rule per (destination, identity) shape. Rule count drops to the cap
while every CIDR is preserved — the CIDR cap is the only thing that can still drop IPs afterwards.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from collections.abc import Callable

from ..config import (
    CONSOLIDATED_RULE_LABEL,
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


def _bump(summary: dict | None, key: str, n: int) -> None:
    if summary is not None and n:
        summary[key] = summary.get(key, 0) + n


def _total_cidrs(rules: list[dict]) -> int:
    return sum(len(r.get("cidrs") or []) for r in rules)


# --------------------------------------------------------------------------------- consolidation
def _shape_key(spec: dict) -> tuple:
    """Rules may only be merged when they'd produce the same policy semantics: same destination and
    the same authentication (identity type + identities)."""
    ids = tuple(sorted((i["principal_id"], i["principal_type"]) for i in (spec.get("identities") or [])))
    return (spec.get("destination") or "all_destinations", spec.get("identity_type") or "ALL_USERS", ids)


def _rank(spec: dict) -> tuple:
    """Higher-traffic groups keep their own rule; sort descending by events, then distinct IPs."""
    return (-(spec.get("events") or 0), -(spec.get("distinct_ips") or len(spec.get("cidrs") or [])))


def _collapse(cidrs: list[str]) -> list[str]:
    """Merge adjacent/overlapping IPv4 CIDRs (lossless) so a consolidated rule carries as few entries
    as possible; anything unparsable is kept verbatim."""
    nets, other = [], []
    for c in cidrs:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            other.append(c)
    out = [str(n) for n in ipaddress.collapse_addresses(nets)]
    return out + [c for c in other if c not in out]


def consolidate(
    specs: list[dict],
    deny: list[dict],
    *,
    max_rules: int = MAX_INGRESS_RULES_PER_POLICY,
    label: str = CONSOLIDATED_RULE_LABEL,
) -> tuple[list[dict], dict]:
    """Fold low-traffic allow rules into consolidated rule(s) until allow + deny fits `max_rules`.

    Rules flagged `pinned` (Databricks-owned ranges, migrated IP access lists) are never folded.
    Deny rules are left untouched but their count is reserved so they aren't pushed out afterwards.
    Returns (new_specs, summary) where summary = {"folded": n_rules_folded, "consolidated": n_rules
    created, "kept_named": n_named_rules_kept, "cidrs": CIDRs carried by the consolidated rules,
    "collapsed": CIDR entries saved by merging adjacent ranges}. When nothing needs folding the
    specs are returned unchanged with all-zero counts."""
    empty = {"folded": 0, "consolidated": 0, "kept_named": len(specs), "cidrs": 0, "collapsed": 0}
    if len(specs) + len(deny) <= max_rules:
        return list(specs), empty

    pinned = [s for s in specs if s.get("pinned")]
    foldable = sorted((s for s in specs if not s.get("pinned")), key=_rank)
    budget = max(max_rules - len(deny) - len(pinned), 1)
    if not foldable:
        return list(specs), empty

    # Keep the top-k named rules and fold the rest; the number of consolidated rules depends on how
    # many distinct (destination, identity) shapes the folded set spans, so shrink k until it fits.
    k = min(len(foldable), budget - 1)
    while True:
        kept, folded = foldable[:k], foldable[k:]
        groups: dict[tuple, list[dict]] = defaultdict(list)
        for s in folded:
            groups[_shape_key(s)].append(s)
        if k + len(groups) <= budget or k == 0:
            break
        k -= 1

    merged: list[dict] = []
    raw_cidrs = 0
    multi = len(groups) > 1
    for n, (shape, members) in enumerate(sorted(groups.items(), key=lambda kv: str(kv[0])), 1):
        destination, identity_type, _ = shape
        cidrs = [c for m in members for c in (m.get("cidrs") or [])]
        raw_cidrs += len(cidrs)
        collapsed = _collapse(list(dict.fromkeys(cidrs)))
        rule_label = label
        if multi:
            suffix = destination if destination != "all_destinations" else f"{n}"
            rule_label = f"{label}-{suffix}"[:250]
        merged.append(
            {
                "label": rule_label,
                "cidrs": collapsed,
                "destination": destination,
                "identity_type": identity_type,
                "identities": list(members[0].get("identities") or []),
                "events": sum(m.get("events") or 0 for m in members),
                "distinct_ips": sum(m.get("distinct_ips") or 0 for m in members),
                "partner": False,
                "pinned": False,
                "consolidated_from": [m.get("label", "?") for m in members],
            }
        )

    new_specs = pinned + kept + merged
    summary = {
        "folded": len(folded),
        "consolidated": len(merged),
        "kept_named": len(pinned) + len(kept),
        "cidrs": _total_cidrs(merged),
        "collapsed": raw_cidrs - _total_cidrs(merged),
    }
    return new_specs, summary


# --------------------------------------------------------------------------------- hard caps
def enforce_limits(
    specs: list[dict],
    deny: list[dict],
    label: str,
    warn: Warn,
    *,
    max_rules: int = MAX_INGRESS_RULES_PER_POLICY,
    max_cidrs: int = MAX_CIDRS_PER_POLICY,
    summary: dict | None = None,
) -> tuple[list[dict], list[dict]]:
    """Cap a target policy's rules to `max_rules` ingress rules / `max_cidrs` CIDRs / 100 identities
    per rule (platform defaults 50 / 2000 / 100). `summary`, when given, accumulates
    rules_dropped / cidrs_dropped / identities_dropped counts for the truncation panel."""
    # Identities per rule (100).
    for spec in specs:
        n = len(spec.get("identities") or [])
        if n > MAX_IDENTITIES_PER_POLICY:
            warn(
                f"[{label}] rule '{spec['label']}' has {n} identities > "
                f"{MAX_IDENTITIES_PER_POLICY} — using the first {MAX_IDENTITIES_PER_POLICY}."
            )
            _bump(summary, "identities_dropped", n - MAX_IDENTITIES_PER_POLICY)
            spec["identities"] = spec["identities"][:MAX_IDENTITIES_PER_POLICY]

    # Ingress rules per policy: allow + deny combined. Allow rules are prioritised (so legitimate
    # traffic stays reachable); deny rules take whatever budget is left. When that pushes deny rules
    # (or trailing allow rules) out, say so explicitly and by name — a silent drop here would quietly
    # discard security rules the operator asked for (e.g. --block-threat-ips / --deny-denied-ips).
    all_rules = specs + list(deny)
    if len(all_rules) > max_rules:
        kept_allow = specs[:max_rules]
        kept_deny = deny[: max(max_rules - len(kept_allow), 0)]
        dropped_allow = specs[len(kept_allow) :]
        dropped_deny = deny[len(kept_deny) :]
        parts = [
            f"[{label}] {len(all_rules)} rules (allow+deny) > {max_rules} — kept "
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
        _bump(summary, "rules_dropped", len(dropped_allow) + len(dropped_deny))
        _bump(summary, "cidrs_dropped", _total_cidrs(dropped_allow) + _total_cidrs(dropped_deny))
        specs, deny = kept_allow, kept_deny

    allow_cidrs = _total_cidrs(specs)
    budget = max_cidrs - allow_cidrs
    if budget < 0:
        # Allow CIDRs alone blow the budget: trim allow rules to fit, and drop deny rules entirely.
        # Say so by count and name — like the rule-count cap, this can silently zero requested denies.
        trimmed, used = [], 0
        for r in specs:
            room = max_cidrs - used
            if room <= 0:
                break
            r = dict(r, cidrs=r["cidrs"][:room])
            trimmed.append(r)
            used += len(r["cidrs"])
        dropped_allow = specs[len(trimmed) :]
        parts = [
            f"[{label}] allow CIDRs ({allow_cidrs:,}) alone exceed the {max_cidrs:,}-CIDR "
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
        _bump(summary, "rules_dropped", len(dropped_allow) + len(deny))
        _bump(summary, "cidrs_dropped", (allow_cidrs - used) + _total_cidrs(deny))
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
                f"[{label}] deny CIDRs trimmed to fit the {max_cidrs:,}-CIDR policy limit — "
                f"kept {used:,} of {deny_cidrs:,} deny CIDR(s)."
            ]
            if dropped_deny:
                parts.append(
                    f"Deny rules fully dropped (threat-intel / denied-IP denies NOT in the policy): "
                    f"{_label_list(dropped_deny)}."
                )
            warn(" ".join(parts))
            _bump(summary, "rules_dropped", len(dropped_deny))
            _bump(summary, "cidrs_dropped", deny_cidrs - used)
        deny = trimmed_deny
    return specs, deny
