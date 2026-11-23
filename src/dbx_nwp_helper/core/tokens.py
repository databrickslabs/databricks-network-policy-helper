"""Personal access token (PAT) posture for `posture`: what a stolen token is worth.

CBI decides *where* a valid credential works; these checks cover how long it works (expiry, lifetime
policy, unused tokens), how much it can call (scopes) and who can mint one. Read-only: collect() lists
token metadata (the API never returns token values) and token settings; revocation_rows() only
*suggests* `databricks token-management delete` commands for an owner to review. Nothing here revokes.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

CRED_DOCS = "https://docs.databricks.com/aws/en/admin/access-control/tokens"
PAT_DOCS = "https://docs.databricks.com/aws/en/dev-tools/auth/pat"
PERMISSION_DOCS = "https://docs.databricks.com/aws/en/security/auth/api-access-permissions"
_KEEP = (
    "autoscope_state",
    "created_by_username",
    "creation_time",
    "expiry_time",
    "last_used_day",
    "owner_id",
    "scopes",
    "token_id",
)


@dataclass
class TokenThresholds:
    max_token_lifetime_days: int = 90  # a lifetime policy above this (or none) is flagged
    stale_token_days: int = 90


def _err(e: Exception) -> str:
    return f"{type(e).__name__}: {' '.join(str(e).split())[:300]}"


def collect(workspace_client) -> dict:
    """Token settings, the PAT inventory and who may use tokens (workspace admin). Metadata only."""
    out: dict = {}
    try:
        conf = (
            workspace_client.workspace_conf.get_status(keys="maxTokenLifetimeDays,enableTokensConfig") or {}
        )
        out["max_token_lifetime_days"] = conf.get("maxTokenLifetimeDays")
        out["tokens_enabled"] = str(conf.get("enableTokensConfig", "true")).lower() != "false"
    except Exception as e:  # noqa: BLE001 - recorded, shown under "Collection gaps"
        out["config_error"] = _err(e)
    try:
        out["tokens"] = [
            {k: v for k, v in t.as_dict().items() if k in _KEEP}
            for t in workspace_client.token_management.list()
        ]
    except Exception as e:  # noqa: BLE001
        out["tokens_error"] = _err(e)
    try:
        perms = workspace_client.permissions.get(
            request_object_type="authorization", request_object_id="tokens"
        )
        out["all_users_can_use"] = any(
            acl.group_name == "users"
            and any(
                str(getattr(p.permission_level, "value", p.permission_level)) == "CAN_USE"
                for p in (acl.all_permissions or [])
            )
            for acl in (perms.access_control_list or [])
        )
    except Exception as e:  # noqa: BLE001
        if type(e).__name__ in ("NotFound", "ResourceDoesNotExist"):
            # No token permissions object: never customised, so the (undocumented) default applies.
            out["permissions_customised"] = False
        else:
            out["permissions_error"] = _err(e)
    return out


def _date(ms) -> dt.date | None:
    try:
        ms = int(ms)
    except (TypeError, ValueError):
        return None
    if ms <= 0:
        return None
    return dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc).date()


def _reasons(t: dict, today: dt.date, th: TokenThresholds) -> list[str]:
    reasons = []
    expiry, used = _date(t.get("expiry_time")), _date(t.get("last_used_day"))
    if expiry is None:
        reasons.append("never expires")
    elif (expiry - today).days > th.max_token_lifetime_days:
        reasons.append(f"expires in {(expiry - today).days} days")
    if used is not None and (today - used).days > th.stale_token_days:
        reasons.append(f"unused for {(today - used).days} days")
    if not t.get("scopes"):
        reasons.append("no API scopes (all APIs)")
    return reasons


def summarise(tok: dict | None, today: dt.date, th: TokenThresholds) -> dict | None:
    if not tok or "tokens" not in tok:
        return None
    toks = tok["tokens"]
    never = [t for t in toks if _date(t.get("expiry_time")) is None]
    return {
        "never_expire": len(never),
        "never_expire_owners": sorted({t.get("created_by_username") or "?" for t in never})[:10],
        "stale": sum(1 for t in toks if any(r.startswith("unused") for r in _reasons(t, today, th))),
        "total": len(toks),
        "unscoped": sum(1 for t in toks if not t.get("scopes")),
    }


def revocation_rows(tok: dict | None, today: dt.date, profile: str | None, th: TokenThresholds) -> list[dict]:
    """One row per token worth reviewing (never expires, long-lived, unused or unscoped), with the
    command an owner would run to revoke it. Suggestions only: nothing is revoked."""
    rows = []
    for t in (tok or {}).get("tokens") or []:
        reasons = _reasons(t, today, th)
        if not reasons:
            continue
        expiry, used, created = (_date(t.get(k)) for k in ("expiry_time", "last_used_day", "creation_time"))
        rows.append(
            {
                "created": str(created or ""),
                "decision (revoke / keep)": "",
                "expires": str(expiry or "never"),
                "last_used": str(used or ""),
                "owner": t.get("created_by_username") or "",
                "reasons": "; ".join(reasons),
                "revoke_command": f"databricks token-management delete {t.get('token_id')} "
                f"-p {profile or '<workspace-admin-profile>'}",
                "scopes": ", ".join(t.get("scopes") or []) or "all APIs",
                "token_id": t.get("token_id") or "",
            }
        )
    # Never-expiring first, then unused, then the rest.
    return sorted(rows, key=lambda r: ("never expires" not in r["reasons"], "unused" not in r["reasons"]))


def evaluate(
    tok: dict | None, workspace_id: str, profile: str | None, open_public: bool, today: dt.date, th=None
):
    """Findings (CBI-020 to CBI-024) for one workspace's tokens. `open_public` raises the urgency: a
    never-expiring token on a workspace with open public ingress works forever, from anywhere."""
    from .posture import Finding

    th = th or TokenThresholds()
    F: list[Finding] = []
    tok = tok or {}
    prof = profile or f"<profile-for-workspace-{workspace_id}>"

    def add(fid, sev, title, detail, rec, next_step="", docs=CRED_DOCS):
        F.append(
            Finding(fid, sev, title, detail, rec, workspace_id=workspace_id, next_step=next_step, docs=docs)
        )

    if tok and tok.get("tokens_enabled") is not False:
        mtl = tok.get("max_token_lifetime_days")
        try:
            mtl_i = int(mtl) if mtl not in (None, "") else 0
        except ValueError:
            mtl_i = 0
        if "max_token_lifetime_days" in tok and (mtl_i <= 0 or mtl_i > th.max_token_lifetime_days):
            add(
                "CBI-021",
                "medium",
                "No short maximum lifetime for new PATs",
                f"maxTokenLifetimeDays = {mtl or 'unset'} (flagged above {th.max_token_lifetime_days}).",
                "Set a maximum lifetime your integrations can sustain (one or seven days is a useful "
                "start to evaluate). Existing tokens keep their expiry, so revoke old ones explicitly.",
                f"databricks workspace-conf set-status --profile {prof} "
                '--json \'{"maxTokenLifetimeDays":"7"}\'   # a setting change: only after explicit approval',
            )
        if tok.get("all_users_can_use"):
            add(
                "CBI-022",
                "medium",
                "Every user may create and use PATs",
                "The `users` group has CAN_USE on tokens.",
                "Move people to OAuth U2M (browser sign-in) and automation to OAuth M2M or workload identity "
                "federation; then grant PAT use only to an approved exception group or specific service "
                "principals.",
                docs=PERMISSION_DOCS,
            )
        elif tok.get("permissions_customised") is False:
            add(
                "CBI-022",
                "info",
                "PAT permissions were never customised",
                "No token permissions are set, so the default applies, and the API doesn't say who that "
                "includes.",
                "Check Settings → Advanced → Personal Access Tokens → Permission settings, and grant PAT use "
                "only to an approved exception group.",
                docs=PERMISSION_DOCS,
            )
    ts = summarise(tok, today, th)
    if ts and ts["never_expire"]:
        add(
            "CBI-020",
            "high" if open_public else "medium",
            "PATs that never expire",
            f"{ts['never_expire']} of {ts['total']} tokens have no expiry (owners: "
            f"{', '.join(ts['never_expire_owners'])}). "
            + (
                "Public ingress is open, so each one is single-factor access from anywhere."
                if open_public
                else "CBI limits where they work, but not for how long."
            ),
            "Replace with OAuth or short-lived tokens and revoke these (see `tokens-to-revoke.csv`; the "
            "account console's Security → Token report covers every workspace). A new lifetime maximum "
            "doesn't shorten existing tokens.",
            f"databricks token-management list --profile {prof} -o json",
        )
    if ts and ts["unscoped"]:
        add(
            "CBI-023",
            "low",
            "PATs without API scopes",
            f"{ts['unscoped']} of {ts['total']} tokens can call every API family (an empty scope list means "
            "all APIs, not none).",
            "Scope each token to the API families its job needs, or enable PAT auto-scoping (preview).",
            docs=PAT_DOCS,
        )
    if ts and ts["stale"]:
        add(
            "CBI-024",
            "info",
            "Unused PATs",
            f"{ts['stale']} tokens not used in {th.stale_token_days}+ days.",
            "Revoke them (`tokens-to-revoke.csv`); unused credentials carry risk and no value.",
        )
    return F
