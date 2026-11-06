"""Cross-workspace egress: map observed Databricks hostnames to workspace ids.

Serverless egress to another Databricks workspace (its REST API, Apps, AI gateway, model serving…)
can't be allow-listed as an internet destination — the egress API rejects every host on the
Databricks domains. It IS allowed through the policy's **cross-workspace** egress list
(`allowed_databricks_destinations`, a list of numeric workspace ids; the destination workspace's
ingress policy must also allow this workspace, see the Databricks cross-workspace access docs).

System tables only give us the hostname, so the id has to be inferred:

  * Databricks Apps     `<app-slug>-<workspace_id>.aws.databricksapps.com`
                        `<app-slug>-<workspace_id>.<n>.azure.databricksapps.com`     → trailing digits
  * AI gateway          `<workspace_id>.ai-gateway.cloud.databricks.com`              → leading digits
  * Azure workspace     `adb-<workspace_id>.<n>.azuredatabricks.net`
  * GCP workspace       `<workspace_id>.<n>.gcp.databricks.com`
  * AWS workspace       `<deployment_name>.cloud.databricks.com` — no id in the host; resolved via the
                        account API's workspace list (deployment_name → workspace_id), so only
                        workspaces in the SAME account resolve. Other accounts' workspaces stay
                        unresolved (their id can still be added by hand in the console).

Hosts that aren't workspaces at all (docs / www / community, Lakebase endpoints, dev proxies,
internal service hosts) are reported as unresolved with a reason so the operator knows why.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Workspace ids are 16-digit integers today; accept ≥ 10 digits so a shorter future/legacy id still
# matches while an app slug ending in a small number ("app-v2") does not.
_MIN_ID_DIGITS = 10

_APPS = re.compile(
    rf"^(?P<slug>[a-z0-9-]*?)-?(?P<id>\d{{{_MIN_ID_DIGITS},}})\.(?:[a-z0-9-]+\.)*databricksapps\.com$"
)
_AI_GATEWAY = re.compile(rf"^(?P<id>\d{{{_MIN_ID_DIGITS},}})\.ai-gateway\.(?:[a-z0-9-]+\.)*databricks\.com$")
_AZURE_WS = re.compile(rf"^adb-(?P<id>\d{{{_MIN_ID_DIGITS},}})\.\d+\.azuredatabricks\.net$")
_GCP_WS = re.compile(rf"^(?P<id>\d{{{_MIN_ID_DIGITS},}})\.\d+\.gcp\.databricks\.com$")
_AWS_WS = re.compile(r"^(?P<deployment>[a-z0-9-]+)\.(?:staging\.)?cloud\.databricks\.com$")
_LAKEBASE = re.compile(r"^ep-[a-z0-9-]+\.database\.[a-z0-9-]+\.cloud\.databricks\.com$")

# Well-known non-workspace hosts on the Databricks domains.
_PLATFORM_LABELS = {"www", "docs", "community", "accounts", "help", "kb", "status", "login"}


@dataclass
class XwsResolution:
    """Outcome of resolving the observed Databricks hosts for one run."""

    # {workspace_id -> {"hosts": [host, …], "events": int, "methods": {method, …},
    #                    "verified": True | False | None}}
    # verified: True = the id is a workspace this run can see (metastore workspace table, account
    # API, or a source workspace in the outbound log); False = none of those know it (another
    # account's workspace, or a host whose digits aren't a workspace id); None = no source to check.
    resolved: dict[int, dict] = field(default_factory=dict)
    # [(host, reason)] — Databricks hosts that can't become cross-workspace destinations.
    unresolved: list[tuple[str, str]] = field(default_factory=list)
    # Hosts whose traffic is same-workspace only (the calling workspace IS the destination, or it's
    # this workspace) — always allowed, nothing to add.
    own: list[str] = field(default_factory=list)
    # True when an account client was available for the deployment-name lookup.
    account_lookup: bool = False
    # True when a set of known workspace ids was available to verify against.
    verification: bool = False

    @property
    def workspace_ids(self) -> list[int]:
        return sorted(self.resolved)

    @property
    def verified_ids(self) -> list[int]:
        """Ids safe to include by default: verified, or unverifiable because nothing could check."""
        return sorted(w for w, i in self.resolved.items() if i.get("verified") is not False)


def workspace_id_from_host(host: str) -> tuple[int | None, str]:
    """(workspace_id, method) for a Databricks hostname when the id is encoded in the host itself,
    else (None, reason). `reason` for None is one of: 'aws-deployment-name' (needs the account
    lookup), 'lakebase-endpoint', 'platform-host', 'unknown-host-shape'."""
    h = (host or "").strip().rstrip(".").lower()
    for rx, method in (
        (_APPS, "apps-url"),
        (_AI_GATEWAY, "ai-gateway-url"),
        (_AZURE_WS, "azure-url"),
        (_GCP_WS, "gcp-url"),
    ):
        m = rx.match(h)
        if m:
            wid = int(m.group("id"))
            if wid == 0:
                return None, "unknown-host-shape"  # a placeholder/zero id is not a workspace
            return wid, method
    if _LAKEBASE.match(h):
        return None, "lakebase-endpoint"
    first = h.split(".")[0] if h else ""
    if h in ("databricks.com", "azuredatabricks.net") or first in _PLATFORM_LABELS:
        return None, "platform-host"
    if (
        ".dev.databricks.com" in h
        or ".staging.dbns.databricks.com" in h
        or h.endswith(".dbns.databricks.com")
    ):
        return None, "platform-host"
    if _AWS_WS.match(h):
        return None, "aws-deployment-name"
    return None, "unknown-host-shape"


def _deployment_map(account) -> dict[str, int]:
    """deployment_name → workspace_id for every workspace in the account (best-effort; {} on error)."""
    try:
        out = {}
        for ws in account.workspaces.list():
            dep = getattr(ws, "deployment_name", None)
            wid = getattr(ws, "workspace_id", None)
            if dep and wid:
                out[str(dep).lower()] = int(wid)
        return out
    except Exception:  # noqa: BLE001 - lookup is an enrichment, never a failure
        return {}


def resolve(
    hosts: dict[str, int],
    account=None,
    own_workspace_id=None,
    *,
    sources: dict[str, set[int]] | None = None,
    known_workspace_ids: set[int] | None = None,
) -> XwsResolution:
    """Resolve `{host: events}` of observed Databricks hostnames into cross-workspace destinations.

    `account` (an AccountClient, optional) enables the deployment-name lookup for AWS workspace URLs.
    `sources` maps host → the set of workspace ids whose workloads called it (from the outbound log):
    a host called ONLY by the workspace it belongs to is same-workspace traffic, not cross-workspace,
    and is reported under `own` instead of becoming a destination (an Apps URL carries its own
    workspace id, so under all_workspaces scope every workspace calling its own app would otherwise
    "resolve" to itself). This workspace's own id is never a destination either.
    `known_workspace_ids` (metastore workspace table ∪ account API ∪ observed source workspaces) lets
    each resolved id be marked verified / unverified; None = no verification possible."""
    res = XwsResolution()
    deployments: dict[str, int] | None = None
    own = int(own_workspace_id) if own_workspace_id is not None else None
    sources = sources or {}
    if known_workspace_ids is not None:
        res.verification = True
        known = {int(w) for w in known_workspace_ids}
        for srcs in sources.values():
            known.update(int(w) for w in srcs)
    else:
        known = None
    for host, events in sorted(hosts.items()):
        wid, how = workspace_id_from_host(host)
        if wid is None and how == "aws-deployment-name":
            if account is not None:
                if deployments is None:
                    deployments = _deployment_map(account)
                    res.account_lookup = True
                dep = host.lower().split(".")[0]
                if dep in deployments:
                    wid, how = deployments[dep], "account-workspace-list"
                else:
                    how = "aws-deployment-name-not-in-this-account"
            else:
                how = "aws-deployment-name-needs-account-lookup"
        if wid is None:
            res.unresolved.append((host, how))
            continue
        callers = {int(w) for w in sources.get(host, set())}
        if (own is not None and wid == own) or (callers and callers <= {wid}):
            res.own.append(host)  # this workspace, or only ever called by itself → same-workspace
            continue
        entry = res.resolved.setdefault(
            wid,
            {"hosts": [], "events": 0, "methods": set(), "verified": None if known is None else wid in known},
        )
        entry["hosts"].append(host)
        entry["events"] += int(events or 0)
        entry["methods"].add(how)
    return res


REASON_TEXT = {
    "lakebase-endpoint": (
        "Lakebase endpoint — not a workspace; reach it via its own connectivity, not egress rules"
    ),
    "platform-host": (
        "Databricks platform site/service — not a workspace, not an allow-listable internet destination"
    ),
    "aws-deployment-name-needs-account-lookup": (
        "AWS workspace URL — id needs the account API (account credentials not available)"
    ),
    "aws-deployment-name-not-in-this-account": (
        "AWS workspace URL not in this account — add its workspace id by hand if needed"
    ),
    "unknown-host-shape": "Databricks host of unknown shape — no workspace id could be inferred",
}
