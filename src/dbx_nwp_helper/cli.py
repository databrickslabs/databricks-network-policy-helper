"""dbx-nwp-helper — the Typer CLI.

Commands:
  ingress       Build/apply a context-based ingress (CBI) allow-list from audit-log source IPs.
  egress        Build/apply a serverless egress (SEG) allow-list from observed outbound traffic.
  guided        Interactive Q&A wizard — point it at a workspace and it walks you through a policy.
  feeds         Manage the local threat-intel / cloud-range feed cache.

The verbatim IP-ACL → CBI migration lives in its own tool now: `dbx-migrate-ip-acls`
(https://github.com/andyweaves/databricks-migrate-ip-acls).

Every notebook widget maps to a flag here; the guided command exposes the same choices as prompts.
Nothing is written unless --create-policy is set, and an interactive review gate (or --yes) guards
the write. Auth is the SDK's unified auth (a --profile, DATABRICKS_* env, or OAuth).
"""

from __future__ import annotations

from enum import Enum

import typer

from . import console, render
from .config import (
    DEFAULT_ACCOUNT_HOST,
    DEFAULT_NAME_PREFIX,
    MAX_POLICY_ID_LEN,
    ApplyOptions,
    Connection,
    EgressConfig,
    IngressConfig,
    validate_apply,
    validate_disable_ip_acls,
    validate_export,
    validate_policy_name,
)

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
    help="Build Databricks account network policies from real observed traffic.",
)
feeds_app = typer.Typer(no_args_is_help=True, help="Manage the local feed cache.")
app.add_typer(feeds_app, name="feeds")


def _version_callback(value: bool) -> None:
    if value:
        from . import __version__

        typer.echo(f"dbx-nwp-helper {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    ctx: typer.Context,
    version: bool = typer.Option(
        None,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """Runs before every command — tag SDK requests with the tool name (usage tracking, before any
    client is built) and make TLS verification use the OS trust store so corporate proxy CAs are
    honoured by the SDK, the SQL connector, and feed downloads alike."""
    import sys

    from . import tls, usage

    usage.tag()
    tls.enable()
    # A one-line discoverability nudge toward the companion guide, for interactive runs of the
    # policy-building commands (not `guide` itself, and never in scripted / piped output).
    if ctx.invoked_subcommand not in (None, "guide") and sys.stdout.isatty():
        console.console.print(
            "[muted]New here? Run [bold]dbx-nwp-helper guide[/bold] for a step-by-step "
            "walkthrough. 📖[/muted]"
        )


# --- Enums so Typer validates + shows choices (mirroring config.py) ---
class Framing(str, Enum):
    minimal = "minimal"
    optimal = "optimal"
    maximum = "maximum"  # noqa: E702


class Scoping(str, Enum):
    ip_only = "ip_only"
    ip_and_destination = "ip_and_destination"  # noqa: E702
    ip_and_identity = "ip_and_identity"
    ip_identity_and_destination = "ip_identity_and_destination"  # noqa: E702


class Scope(str, Enum):
    current_workspace = "current_workspace"  # noqa: E702
    per_workspace = "per_workspace"
    all_workspaces = "all_workspaces"  # noqa: E702


class Mode(str, Enum):
    dry_run = "dry_run"
    enforce = "enforce"  # noqa: E702


class ThreatDeny(str, Enum):
    off = "off"
    matched_only = "matched_only"
    all = "all"  # noqa: E702


class Action(str, Enum):
    create_new = "create_new"
    add_to_existing = "add_to_existing"  # noqa: E702


class WarehouseSize(str, Enum):
    """Serverless SQL warehouse cluster ("t-shirt") sizes, smallest → largest. Values are the exact
    strings the warehouses API accepts. Typer lists them as the --warehouse-size choices."""

    xxsmall = "2X-Small"
    xsmall = "X-Small"
    small = "Small"
    medium = "Medium"
    large = "Large"
    xlarge = "X-Large"  # noqa: E702
    xxlarge = "2X-Large"
    xxxlarge = "3X-Large"
    xxxxlarge = "4X-Large"  # noqa: E702


def _read_config_profiles() -> dict[str, dict[str, str]]:
    """Every profile in ~/.databrickscfg (or $DATABRICKS_CONFIG_FILE) as {name: {key: value}},
    including the DEFAULT section. Empty on a missing file or any read error."""
    import configparser
    import os

    path = os.path.expanduser(os.environ.get("DATABRICKS_CONFIG_FILE") or "~/.databrickscfg")
    if not os.path.exists(path):
        return {}
    cp = configparser.ConfigParser()
    try:
        cp.read(path)
    except configparser.Error:
        return {}
    out = {name: dict(cp[name]) for name in cp.sections()}
    # DEFAULT is a real, selectable profile in .databrickscfg; ConfigParser hides it in sections().
    if cp.defaults():
        out["DEFAULT"] = dict(cp.defaults())
    return out


def _available_profiles() -> list[str]:
    """Profile names configured in ~/.databrickscfg (or $DATABRICKS_CONFIG_FILE), DEFAULT first."""
    profiles = _read_config_profiles()
    names = [n for n in profiles if n != "DEFAULT"]
    if "DEFAULT" in profiles:
        names = ["DEFAULT", *names]
    return names


def _norm_host(host: str | None) -> str:
    """Bare, comparable host: scheme + trailing slash stripped, lower-cased."""
    if not host:
        return ""
    from urllib.parse import urlparse

    return urlparse(host if "://" in host else f"https://{host}").netloc.lower().rstrip("/")


def account_host_from_workspace_host(host: str | None) -> str | None:
    """Derive the account-console API host from a workspace host, so a workspace in a non-default
    environment (e.g. AWS staging, GCP) reaches the matching account API instead of the AWS prod
    default. None if it can't be derived.

    * Azure — one fixed account host (accounts.azuredatabricks.net).
    * AWS — `<deployment>.[staging.]cloud.databricks.com`; the single leading label is
      workspace-specific, so replace it with 'accounts'.
    * GCP — `<workspace-id>.<shard>.[staging.]gcp.databricks.com` has *two* workspace-specific leading
      labels (id + shard) that the account console drops entirely, so anchor on the shared base
      domain rather than stripping a fixed number of labels. Custom/vanity subdomains
      (acme.<base>) resolve to the same shared account console."""
    h = (host or "").strip().lower()
    h = h.split("://", 1)[-1]  # drop any scheme
    h = h.split("/", 1)[0]  # drop any path / trailing slash
    if not h:
        return None
    if "azuredatabricks.net" in h:
        return "https://accounts.azuredatabricks.net"
    if "gcp.databricks.com" in h:
        base = "staging.gcp.databricks.com" if ".staging.gcp.databricks.com" in h else "gcp.databricks.com"
        return f"https://accounts.{base}"
    if "cloud.databricks.com" in h:
        _first, _, rest = h.partition(".")
        if rest:
            return f"https://accounts.{rest}"
    return None


def _matching_account_profiles(account_host: str, account_id: str) -> list[str]:
    """Profiles in the Databricks config whose host is `account_host` AND whose account_id is
    `account_id`. Matching on BOTH is deliberate: an account_id alone is ambiguous — the same id
    appears under several profiles, and across environments — so pairing it with the account-console
    host disambiguates."""
    if not account_host or not account_id:
        return []
    target = _norm_host(account_host)
    return [
        name
        for name, cfg in _read_config_profiles().items()
        if _norm_host(cfg.get("host")) == target and (cfg.get("account_id") or "") == account_id
    ]


def _resolve_profile(profile: str | None) -> str | None:
    """Require an explicit profile choice rather than silently falling back to the first-configured
    one. If --profile is given, use it. If env-based auth is configured (DATABRICKS_HOST), allow it
    through. Otherwise prompt the user to pick from ~/.databrickscfg; error if none / non-interactive."""
    import os
    import sys

    if profile:
        return profile
    if os.environ.get("DATABRICKS_HOST"):
        return None  # explicit env auth — respect it

    profiles = _available_profiles()
    if not profiles:
        raise typer.BadParameter(
            "No --profile given and no profiles found in ~/.databrickscfg. Pass --profile <name> "
            "or run `databricks auth login` first."
        )
    if not sys.stdin.isatty():
        raise typer.BadParameter(
            "No --profile given (non-interactive). Pass --profile <name> explicitly — the CLI won't "
            f"guess. Available: {', '.join(profiles)}"
        )

    import questionary

    choice = questionary.select(
        "Which Databricks profile? (pass --profile to skip this prompt)", choices=profiles
    ).ask()
    if not choice:
        raise typer.Abort()
    return choice


# Shared connection options (used by every command that hits the workspace).
def _conn(
    profile,
    warehouse_http_path,
    account_id,
    account_host,
    account_profile=None,
    warehouse_size: str = "X-Small",
) -> Connection:
    profile = _resolve_profile(profile)
    return Connection(
        profile=profile,
        warehouse_http_path=warehouse_http_path,
        warehouse_size=warehouse_size,
        account_id=account_id or "",
        # None → not pinned: the CLI derives it from the workspace host (see _resolve_account_host).
        account_host=account_host or DEFAULT_ACCOUNT_HOST,
        account_host_explicit=account_host is not None,
        account_profile=account_profile,
    )


def _resolve_account_host(conn: Connection, wc) -> None:
    """When --account-host wasn't pinned, derive it from the workspace host so a workspace in a
    non-default environment (AWS staging / GCP / Azure) reaches the matching account API instead of
    the AWS prod default. An explicit --account-host is always respected. Mutates conn."""
    if conn.account_host_explicit:
        return
    ws_host = getattr(getattr(wc, "config", None), "host", None)
    derived = account_host_from_workspace_host(ws_host)
    if derived and derived != conn.account_host:
        console.banner(
            "info",
            f"Using account host '{derived}', matched to the workspace's environment. "
            "Pass --account-host to override.",
        )
        conn.account_host = derived


def _default_account_id_from_workspace(conn: Connection, wc) -> None:
    """When --account-id wasn't given, default it from the workspace profile's own account_id (a
    workspace .databrickscfg profile usually carries it), so the user needn't retype it — and can't
    fat-finger a different account's id. Mutates conn."""
    if conn.account_id:
        return
    ws_account_id = getattr(getattr(wc, "config", None), "account_id", None)
    if ws_account_id:
        conn.account_id = str(ws_account_id)
        console.banner(
            "info",
            f"Using account id '{conn.account_id}' from the workspace profile. Pass --account-id to "
            "override.",
        )


def _resolve_account_profile(conn: Connection) -> None:
    """When no --account-profile was given, find a config profile matching the account host +
    account_id and use it, so account calls authenticate as that account admin rather than whatever
    ambient credential unified auth would otherwise resolve (a frequent source of wrong-tenant /
    wrong-account failures). Mutates conn. No-op when --account-profile was passed or nothing
    matches; on multiple matches it uses the first and says so."""
    if conn.account_profile:
        return
    matches = _matching_account_profiles(conn.account_host, conn.account_id)
    if not matches:
        return  # nothing matched → fall through; the account-access probe explains any failure
    if len(matches) > 1:
        console.banner(
            "info",
            f"Multiple config profiles match account '{conn.account_id}' at {conn.account_host} "
            f"({', '.join(matches)}); using '{matches[0]}'. Pass --account-profile to choose.",
        )
    else:
        console.banner(
            "info",
            f"Using account profile '{matches[0]}', matched to account '{conn.account_id}' at "
            f"{conn.account_host}. Pass --account-profile to override.",
        )
    conn.account_profile = matches[0]


def _step(message: str) -> None:
    console.console.print(f"[muted]· {message}[/muted]")


def _ensure_account_id(conn: Connection, reason: str) -> None:
    """Ensure conn.account_id is set before account-level work begins, prompting for it up front
    rather than failing deep in the apply/SCIM step. `reason` explains why it's needed. Mutates conn.
    Prompts interactively; errors clearly when non-interactive."""
    import sys

    if conn.account_id:
        return
    msg = (
        f"{reason} needs a Databricks account_id (numeric). Find it in the Account console "
        "top-right user menu, or in the account-console URL after '/account/'."
    )
    if not sys.stdin.isatty():
        raise typer.BadParameter(f"{msg}\nPass --account-id <id> (non-interactive, so the CLI can't prompt).")
    import questionary

    console.banner("info", msg)
    entered = (questionary.text("Databricks account_id:").ask() or "").strip()
    if not entered:
        raise typer.Abort()
    conn.account_id = entered


def _is_expired_auth(msg: str) -> bool:
    """True if an SDK auth error looks like expired / invalid Databricks-CLI credentials that a
    `databricks auth login` would fix — as opposed to a mistyped profile or missing config."""
    m = msg.lower()
    return (
        "reauthenticate" in m
        or "refresh token" in m
        or "cannot get access token" in m
        or "databricks auth login" in m
    )


def _is_default_auth_failure(msg: str) -> bool:
    """True if an SDK client-construction error means unified auth found no credentials at all — as
    opposed to an expired token (`_is_expired_auth`) or a mistyped profile. It's what you get when
    nothing (no --account-profile, no matching config profile, no DATABRICKS_* env) resolves for the
    host, so the SDK reports `default auth: cannot configure default credentials`."""
    m = msg.lower()
    return "cannot configure default credentials" in m or "default auth:" in m


def _reauth_profile(msg: str, fallback: str | None) -> str | None:
    """The profile that actually needs re-authenticating. The SDK error spells out the fix as
    `databricks auth login --profile <name>`, so prefer that exact profile — account access is often
    a different, auto-discovered profile than the workspace one (matched by account host + id), and
    re-authing the profile we *asked* for wouldn't fix it. Falls back to the passed profile when the
    message doesn't name one."""
    import re

    m = re.search(r"auth login --profile (\S+)", msg)
    return m.group(1).rstrip(".").strip("'\"") if m else fallback


def _reauthenticate(profile: str) -> bool:
    """Offer to run `databricks auth login --profile <profile>` and return True if it succeeded (so
    the caller can retry building the client). Returns False — after printing the command to run —
    when non-interactive, when the user declines, when the databricks CLI isn't on PATH, or when the
    login doesn't complete."""
    import shutil
    import subprocess
    import sys

    cmd = f"databricks auth login --profile {profile}"
    console.banner(
        "warn", f"The credentials for profile '{profile}' have expired (or its refresh token is invalid)."
    )
    if not sys.stdin.isatty():
        console.banner("info", f"Re-authenticate, then re-run: {cmd}")
        return False
    if not typer.confirm(
        typer.style(f"Re-authenticate now? This runs `{cmd}` and opens a browser.", fg="yellow"), default=True
    ):
        console.banner("info", f"Re-authenticate when ready, then re-run: {cmd}")
        return False
    if shutil.which("databricks") is None:
        console.banner(
            "danger",
            "The `databricks` CLI isn't on your PATH — install it "
            "(https://docs.databricks.com/dev-tools/cli/install), then run: "
            f"{cmd}",
        )
        return False
    console.banner("info", f"Running `{cmd}` …")
    try:
        result = subprocess.run(["databricks", "auth", "login", "--profile", profile])
    except OSError as e:  # noqa: BLE001 - surface a clean message, don't crash
        console.banner("danger", f"Couldn't launch the databricks CLI: {e}. Run manually: {cmd}")
        return False
    if result.returncode != 0:
        console.banner(
            "danger",
            f"Re-authentication didn't complete (exit {result.returncode}). "
            f"Run it manually, then re-run: {cmd}",
        )
        return False
    console.banner("success", "Re-authenticated — continuing.")
    return True


def _client_or_exit(build, profile: str | None, flag: str, on_config_error=None):
    """Build a Databricks client, turning a config/auth ValueError into a clean CLI error. If the
    failure is expired CLI credentials and a profile is set, offer to re-authenticate and retry the
    build once; any other ValueError (or a declined/failed re-auth) exits cleanly.

    `on_config_error(e, profile, flag)` is the terminal handler for a non-reauthable ValueError; it
    defaults to `_profile_config_error`. The account path passes its own so a no-account-credentials
    failure gets account-admin guidance instead of the generic message."""
    on_config_error = on_config_error or _profile_config_error
    try:
        return build()
    except ValueError as e:
        # Re-auth the profile the SDK error actually names (which may differ from `profile` — e.g.
        # the account client resolves to a separate auto-discovered profile), not the one we assumed.
        reauth = _reauth_profile(str(e), profile) if _is_expired_auth(str(e)) else None
        if reauth and _reauthenticate(reauth):
            try:
                return build()
            except ValueError as e2:
                on_config_error(e2, profile, flag)
        on_config_error(e, profile, flag)


def _profile_config_error(e: Exception, profile: str | None, flag: str) -> None:
    """Turn an SDK client-construction ValueError (e.g. a mistyped profile that isn't in
    ~/.databrickscfg) into a clean, actionable message instead of a raw traceback. Always raises."""
    msg = str(e)
    if profile and "profile configured" in msg:
        available = ", ".join(_available_profiles()) or "(none found)"
        console.banner(
            "danger",
            f"{flag} '{profile}' isn't configured in your Databricks config "
            "(~/.databrickscfg or $DATABRICKS_CONFIG_FILE). Available profiles: "
            f"{available}. Fix the name or run `databricks auth login`.",
        )
    else:
        console.banner("danger", f"Couldn't initialise the Databricks client: {msg}")
    raise typer.Exit(code=1) from None


def _workspace_client_or_exit(conn: Connection):
    """Build the workspace client, converting a config/profile ValueError into a clean CLI error
    (and offering re-auth on expired credentials)."""
    from . import auth

    return _client_or_exit(lambda: auth.workspace_client(conn), conn.profile, "--profile")


def _account_client_or_exit(conn: Connection, workspace_id: int | None = None):
    """Build the account client, converting a config/profile ValueError into a clean CLI error
    (and offering re-auth on expired credentials). First auto-resolves a matching account profile
    from the config (so account calls don't fall back to an ambient, often wrong-tenant, credential).
    When `workspace_id` is given, probes the account API once so a bad account credential fails fast
    with an actionable message rather than surfacing later as a raw SDK traceback."""
    from . import auth

    _resolve_account_profile(conn)
    account = _client_or_exit(
        lambda: auth.account_client(conn),
        conn.account_profile or conn.profile,
        "--account-profile" if conn.account_profile else "--profile",
        on_config_error=lambda e, prof, flag: _account_build_error(e, conn, prof, flag),
    )
    if workspace_id is not None:
        account = _verify_account_access_or_exit(conn, account, workspace_id)
    return account


def _account_build_error(e: Exception, conn: Connection, profile: str | None, flag: str) -> None:
    """Terminal handler for a failed *account* client construction. When unified auth resolved no
    account credentials at all (the common case: no --account-profile and no matching config
    profile), explain that account auth is separate from the workspace --profile and how to set it
    up — rather than the generic 'couldn't initialise the client' message. Any other construction
    error defers to the standard profile/config handler. Always raises."""
    if not _is_default_auth_failure(str(e)):
        _profile_config_error(e, profile, flag)  # raises
        return
    login = (
        f"databricks auth login --host {conn.account_host} "
        f"--account-id {conn.account_id or '<account-id>'}"
    )
    console.banner(
        "danger",
        f"Couldn't authenticate to the Databricks account API at {conn.account_host} for account "
        f"'{conn.account_id or '(unset)'}'.\n"
        "  This operation is account-level and needs account-admin credentials, which are separate "
        "from your workspace --profile — a workspace login can't call the account API.\n"
        "  No --account-profile was given and no profile in your Databricks config matches this "
        "account's host + id, so unified auth found no account credentials at all.\n"
        f"  Fix: create an account-admin login — {login} — then re-run with --account-profile <name> "
        "(or set DATABRICKS_* account env vars). See docs/account-admin-setup.md.",
    )
    raise typer.Exit(code=1) from None


def _account_access_error(e: Exception, conn: Connection) -> None:
    """Clean, actionable exit when the account API rejects our credentials — wrong account, wrong
    Azure AD / Entra tenant, missing account-admin rights, or (with no --account-profile) no account
    creds resolved for the account host at all. Always raises."""
    if conn.account_profile:
        creds = f"the --account-profile '{conn.account_profile}' credentials"
    else:
        creds = (
            "the account credentials resolved by unified auth — no --account-profile was given and no "
            "profile in your Databricks config matches this account's host + id, so they came from "
            "$DATABRICKS_* / an auto-discovered profile / a cached cloud login, which may be for a "
            "different tenant or account"
        )
    detail = " ".join(str(e).split())[:300] or type(e).__name__
    console.banner(
        "danger",
        f"Couldn't access the Databricks account API at {conn.account_host} for account "
        f"'{conn.account_id}' using {creds}.\n"
        f"  The API rejected the request: {type(e).__name__}: {detail}\n"
        "  This usually means those credentials are for a different account, or (on Azure) a "
        "different Entra ID / AAD tenant than the account console, or lack account-admin rights.\n"
        "  Fix: pass --account-profile <name> for an account-admin login to THIS account "
        "(create one with `databricks auth login --host <account-console-url>`), then re-run.",
    )
    raise typer.Exit(code=1) from None


def _verify_account_access_or_exit(conn: Connection, account, workspace_id: int):
    """Probe the account API once (fetch this workspace via the account API) so a bad account
    credential fails fast with an actionable message instead of surfacing later as a raw SDK
    traceback. On expired creds, offers the same re-auth flow as client construction and retries once
    with a fresh client. Returns the (possibly rebuilt) account client."""
    from . import auth

    prof = conn.account_profile or conn.profile
    retried = False
    while True:
        try:
            account.workspaces.get(workspace_id=int(workspace_id))
            return account
        except Exception as e:  # noqa: BLE001 - any account-API failure becomes a clean exit
            msg = str(e)
            if not retried and _is_expired_auth(msg):
                reauth = _reauth_profile(msg, prof)
                if reauth and _reauthenticate(reauth):
                    account = auth.account_client(conn)  # rebuild with the refreshed credentials
                    retried = True
                    continue
            _account_access_error(e, conn)


def _looks_like_account_console(host: str | None) -> bool:
    """True if this host is a Databricks *account* console (accounts.*.databricks.com /
    accounts.azuredatabricks.net) rather than a workspace. Used to catch an --account-profile
    mistakenly passed as the workspace --profile before we call workspace-only APIs on it (those
    return non-JSON on an account host and would otherwise blow up as a raw JSONDecodeError)."""
    return _norm_host(host).startswith("accounts.")


def _confirm_workspace(conn: Connection, yes: bool):
    """Resolve the workspace client and surface exactly which workspace this run reads from and (on
    apply) modifies — profile, URL, id — then gate on Y/N so the target can't be mistaken. Always
    displays; the confirmation is skipped with --yes and is a no-op non-interactively (like
    _confirm_params). Returns the WorkspaceClient (reused by the caller)."""
    import sys

    wc = _workspace_client_or_exit(conn)
    try:
        host = (wc.config.host or "").rstrip("/") or "unknown"
    except Exception:  # noqa: BLE001 - display best-effort; real auth errors surface later in use
        host = "unknown"
    # A profile pointing at an account console isn't a workspace and would otherwise fail deep inside
    # get_workspace_id with a raw JSONDecodeError — catch it up front with an actionable message.
    if _looks_like_account_console(host):
        console.banner(
            "danger",
            f"The workspace profile resolves to a Databricks account console ({host}), not a "
            "workspace — it looks like an account profile was passed as --profile.\n"
            "  Pass a WORKSPACE profile as --profile (its host is an adb-* / dbc-* workspace URL), "
            "and put the account profile in --account-profile.",
        )
        raise typer.Exit(code=1)
    try:
        ws_id = wc.get_workspace_id()
    except Exception:  # noqa: BLE001
        ws_id = "unknown"
    console.workspace_panel(conn.profile or "env / OAuth", host, ws_id)
    if yes or not sys.stdin.isatty():
        return wc
    if not typer.confirm(
        typer.style("Is this the correct workspace to analyse / modify?", fg="yellow"), default=True
    ):
        console.banner("info", "Aborted — re-run with the intended --profile.")
        raise typer.Exit(code=0)
    return wc


def _resolve_policy_name(cfg, conn: Connection, wc, yes: bool) -> None:
    """Resolve the policy name once, centrally (all three commands). An explicit --policy-name is
    kept as-is; otherwise prompt for one (blank = the profile name, falling back to the workspace
    id). Skipped when the run adds to an existing policy (the id comes from --existing-policy-id).
    Mutates cfg.policy_name. For single-policy scopes the name is the policy id; for per_workspace
    it's the prefix (-> <name>-ws-<id>)."""
    import sys

    if cfg.policy_name:
        return
    if getattr(getattr(cfg, "apply", None), "policy_action", "create_new") == "add_to_existing":
        return
    try:
        ws_id = wc.get_workspace_id()
    except Exception:  # noqa: BLE001
        ws_id = None
    default = conn.profile or (str(ws_id) if ws_id is not None else DEFAULT_NAME_PREFIX)
    if yes or not sys.stdin.isatty():
        cfg.policy_name = default
        return
    import questionary

    entered = (
        questionary.text(f"Policy name for the new network policy? (blank = use '{default}')").ask() or ""
    ).strip()
    cfg.policy_name = entered or default


def _confirm_overwrite(dest, yes: bool) -> bool:
    """True if it's OK to write `dest`. A new file: always. An existing file: overwrite silently
    with --yes / non-interactively (for scripting), otherwise prompt (default No)."""
    import sys

    if not dest.exists():
        return True
    if yes or not sys.stdin.isatty():
        return True
    return typer.confirm(typer.style(f"'{dest}' already exists — overwrite?", fg="yellow"), default=False)


def _write_json_export(path: str, payload: dict, yes: bool = False) -> str | None:
    """Write `payload` as pretty JSON to `path`, and return the final path written (or None if an
    existing file was kept). If `path` is a directory (or ends with a separator), write
    `<network_policy_id>.json` inside it; create missing parent dirs; and turn write failures into a
    clean error instead of a traceback."""
    import json
    import os
    from pathlib import Path

    dest = Path(path).expanduser()
    if dest.is_dir() or path.endswith(("/", os.sep)):
        name = payload.get("network_policy_id") or "network-policy"
        dest = dest / f"{name}.json"
    if not _confirm_overwrite(dest, yes):
        console.banner("info", f"Kept existing '{dest}' — not overwritten.")
        return None
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        # Pin UTF-8 so a non-ASCII rule label writes identically on macOS and Windows (whose default
        # text encoding is cp1252, which would otherwise raise on such characters).
        with dest.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
    except OSError as e:
        console.banner("danger", f"Couldn't write --export to '{path}': {e}")
        raise typer.Exit(code=1) from None
    return str(dest)


def _write_tf_export(path: str, payload: dict, yes: bool = False) -> str | None:
    """Write a best-effort Terraform config for `payload` alongside the JSON, and return the path (or
    None if an existing file was kept). A directory writes `<network_policy_id>.tf` inside it; a file
    path takes a `.tf` suffix."""
    import os
    from pathlib import Path

    from .core import terraform

    dest = Path(path).expanduser()
    if dest.is_dir() or path.endswith(("/", os.sep)):
        name = payload.get("network_policy_id") or "network-policy"
        dest = dest / f"{name}.tf"
    else:
        dest = dest.with_suffix(".tf")
    if not _confirm_overwrite(dest, yes):
        console.banner("info", f"Kept existing '{dest}' — not overwritten.")
        return None
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(terraform.network_policy_hcl(payload), encoding="utf-8")
    except OSError as e:
        console.banner("danger", f"Couldn't write Terraform export to '{path}': {e}")
        raise typer.Exit(code=1) from None
    return str(dest)


def _export_policy(path: str, payload: dict, yes: bool = False) -> None:
    """Write the proposed policy as both JSON (curl / REST body) and best-effort Terraform. An
    existing file is only overwritten after confirmation (or with --yes)."""
    json_dest = _write_json_export(path, payload, yes)
    tf_dest = _write_tf_export(path, payload, yes)
    if json_dest and tf_dest:
        console.banner(
            "success", f"Wrote proposed network-policy JSON to {json_dest} and Terraform to {tf_dest}."
        )
    elif json_dest:
        console.banner("success", f"Wrote proposed network-policy JSON to {json_dest}.")
    elif tf_dest:
        console.banner("success", f"Wrote proposed network-policy Terraform to {tf_dest}.")


def _ingress_preflight(
    account, workspace_id, new_policy_id: str, yes: bool, existing, migrating_public: bool
):
    """ingress create-and-assign per-dimension conflict gate. Public and private access are
    independent, so each aborts only when a dimension this run **migrates** collides with a
    **restrictive** CBI block already live on the assigned policy for that SAME dimension
    (`existing_cbi_ingress` already filters to restrictive — enforced OR dry-run):

      * **public**  — abort if we're migrating public (observed traffic / IP access lists) and the
        assigned policy has a restrictive public_access;
      * **private** — abort if we're migrating a *non-allow-all* PAS and the assigned policy has a
        restrictive private_access.

    `existing` is (existing_public, existing_private, migrating_restrictive_private, assigned_id) from
    _reconcile_existing_ingress. Existing private-access and cross-workspace blocks are carried
    forward (not dropped), so only the egress opposite-direction guard remains on a new-id rebind.
    Called only when the run will create AND assign a single policy — never for per_workspace or
    add_to_existing."""
    from .core import acl as acl_core

    existing_public, existing_private, migrating_restrictive_private, assigned_id = existing
    if migrating_public and existing_public is not None:
        console.banner(
            "danger",
            f"This workspace's assigned CBI policy ('{assigned_id}') already has restrictive PUBLIC "
            "ingress rules, and this run migrates public access (observed traffic / IP access lists) "
            "over the top. Replacing an existing restrictive CBI public policy is NOT supported yet - "
            "aborting.",
        )
        raise typer.Exit(code=1)
    if migrating_restrictive_private and existing_private is not None:
        console.banner(
            "danger",
            f"This workspace's assigned CBI policy ('{assigned_id}') already has restrictive PRIVATE "
            "access rules, and this run migrates a non-allow-all front-end PrivateLink PAS over the "
            "top. Replacing an existing restrictive CBI private policy is NOT supported yet - aborting.",
        )
        raise typer.Exit(code=1)

    # Egress opposite-direction guard: a new policy id rebinds the workspace, dropping the assigned
    # policy's egress (the new policy carries a FULL_ACCESS egress default). Ingress blocks are built
    # or carried forward, so only egress needs guarding here.
    if new_policy_id and new_policy_id != assigned_id:
        _pid, pol = acl_core.assigned_policy(account, workspace_id)
        if pol is not None:
            _warn_or_abort_dropped_egress(acl_core, assigned_id, getattr(pol, "egress", None), "ingress")


def _warn_or_abort_dropped_egress(acl_core, pid, egress, this_direction: str) -> None:
    """Shared by both preflights: when create-and-assign of a NEW policy id would rebind the
    workspace away from an assigned policy that has a restrictive egress, abort if that egress is
    ENFORCED (real protection lost) or warn if it's DRY-RUN. `this_direction` is the command running
    ('ingress' / 'egress'), used only for the message."""
    if not acl_core.egress_restrictive(egress):
        return
    if acl_core.egress_enforced(egress):
        console.banner(
            "danger",
            f"The policy assigned to this workspace ('{pid}') has an ENFORCED restrictive "
            f"egress; creating a new {this_direction} policy would rebind the workspace "
            f"and drop it - aborting. Use --policy-action add_to_existing "
            f"--existing-policy-id {pid} to keep the egress and add {this_direction} to it.",
        )
        raise typer.Exit(code=1)
    console.banner(
        "warn",
        f"The policy assigned to this workspace ('{pid}') has a restrictive DRY-RUN egress "
        f"(not enforced) — creating a new {this_direction} policy will drop it.",
    )


def _egress_preflight(account, workspace_id, new_policy_id: str, yes: bool) -> None:
    """egress create-and-assign pre-check — the egress-direction mirror of _ingress_preflight.
    Aborts if the policy already assigned to the workspace has an ENFORCED restrictive egress
    (replacing it isn't supported yet); warns if it's a restrictive DRY-RUN egress (assigning
    replaces it). Also guards the opposite direction: assigning a *new* policy id drops the assigned
    policy's ingress (the new policy defaults to FULL_ACCESS ingress), so abort/warn on a restrictive
    ingress there. Allow-all (FULL_ACCESS) blocks — or no assigned policy — are fine. Called only when
    the run will create AND assign a single policy."""
    from .core import acl as acl_core

    pid, pol = acl_core.assigned_policy(account, workspace_id)
    if pol is None:
        return
    egr = getattr(pol, "egress", None)
    if acl_core.egress_restrictive(egr):
        if acl_core.egress_enforced(egr):
            console.banner(
                "danger",
                "This workspace already has an ENFORCED restrictive egress "
                f"policy ('{pid}'). Replacing it is NOT supported yet - "
                "aborting.",
            )
            raise typer.Exit(code=1)
        console.banner(
            "warn",
            f"The policy assigned to this workspace ('{pid}') has a restrictive "
            "DRY-RUN egress (not enforced) — assigning the new policy will replace "
            "it.",
        )
    # Opposite direction: a new policy id rebinds the workspace, dropping the assigned policy's
    # ingress (the new egress policy defaults to FULL_ACCESS ingress). Same-id updates preserve it.
    if new_policy_id and new_policy_id != pid:
        ing = getattr(pol, "ingress", None)
        dry = getattr(pol, "ingress_dry_run", None)

        def _ing_restrictive(blk):
            return acl_core.public_restrictive(blk) or acl_core.private_or_xws_restrictive(blk)

        if _ing_restrictive(ing):
            console.banner(
                "danger",
                f"The policy assigned to this workspace ('{pid}') has an ENFORCED "
                "restrictive ingress; creating a new egress policy would rebind the "
                "workspace and drop it - aborting. Use --policy-action add_to_existing "
                f"--existing-policy-id {pid} to keep the ingress and add egress to it.",
            )
            raise typer.Exit(code=1)
        if _ing_restrictive(dry):
            console.banner(
                "warn",
                f"The policy assigned to this workspace ('{pid}') has a "
                "restrictive DRY-RUN ingress (not enforced) — creating a new "
                "egress policy will drop it.",
            )


def _note_policy_name(policy_name: str) -> None:
    """Show the id the resolved policy name normalises to (so the user sees the real id when
    case/characters/length were adjusted). For per_workspace the name is a prefix, so callers skip
    this there."""
    if not policy_name:
        return
    from .core import policy

    normalized = policy.policy_name("", explicit=policy_name)
    if normalized != policy_name:
        console.banner(
            "info",
            f"Using policy id '{normalized}' (names are normalised: lowercased, "
            f"non-alphanumerics become '-', capped at {MAX_POLICY_ID_LEN} chars).",
        )


def _confirm_params(yes: bool) -> None:
    """After showing the config, ask the user to confirm before doing any work. --yes skips it, and
    it's a no-op non-interactively so scripted runs aren't blocked. Aborting exits cleanly (0)."""
    import sys

    if yes or not sys.stdin.isatty():
        return
    if not typer.confirm("Proceed with these parameters? (No to abort and adjust flags)", default=True):
        console.banner("info", "Aborted — adjust the flags and re-run (see --help).")
        raise typer.Exit(code=0)


def _has_rules(policies: dict) -> bool:
    """True if any policy target carries at least one allow or deny rule. Guards the apply path so an
    empty analysis (e.g. no candidate IPs) fails with a clear message instead of a KeyError."""
    return any(p.get("allow") or p.get("deny") for p in (policies or {}).values())


def _confirm_write(cfg_mode: str, yes: bool) -> bool:
    """The write gate. Returns True if the user has confirmed (or --yes given)."""
    if yes:
        return True
    console.mode_banner(cfg_mode)
    return typer.confirm(
        typer.style("Review the proposed rules above. Create/apply the policy now?", fg="yellow"),
        default=False,
    )


def _confirm_overwrite_policy(account, policy_id: str, direction: str, yes: bool) -> None:
    """Before writing the `direction` ('ingress'/'egress') block of a policy that ALREADY EXISTS,
    warn when that same direction already carries real rules this run would replace, and get a Y/N.
    The opposite direction is left untouched by apply_*, so it doesn't count — this fires only on
    genuine same-direction data loss (so composing a new direction onto a policy won't prompt). A
    missing policy, or an empty / permissive one (e.g. the account default policy), is silent.
    --yes / non-interactive proceeds after printing the warning; 'No' aborts cleanly (exit 0)."""
    from databricks.sdk.errors import NotFound

    from .core import acl as acl_core

    try:
        pol = account.network_policies.get_network_policy_rpc(network_policy_id=policy_id)
    except NotFound:
        return  # brand-new policy id — nothing to overwrite
    except Exception:  # noqa: BLE001 - best-effort; a read failure shouldn't block the write
        return
    content = acl_core.ingress_content(pol) if direction == "ingress" else acl_core.egress_content(pol)
    if not content:
        return  # empty / permissive in this direction — safe to write, no prompt
    console.banner(
        "warn",
        f"Policy '{policy_id}' already exists and its {direction} config will be REPLACED "
        f"(the opposite direction is left unchanged):\n  • " + "\n  • ".join(content),
    )
    if not _interactive(yes):
        return
    if not typer.confirm(
        typer.style(f"Overwrite the existing {direction} rules on '{policy_id}'?", fg="yellow"),
        default=False,
    ):
        console.banner("info", "Aborted — nothing written.")
        raise typer.Exit(code=0)


def _reconcile_existing_ingress(account, workspace_id, wc, cfg: IngressConfig, yes: bool):
    """Read the workspace's front-end PrivateLink (AWS/GCP PAS) and its existing assigned CBI policy,
    and decide — per independent dimension — what the generated policy carries alongside the net-new
    public allow-list built from traffic:

    * **private_access** — migrate a **non-allow-all** PAS (AWS/GCP, specific registered endpoints,
      mapped across as-is); else carry an existing CBI private_access forward. An allow-all (ACCOUNT)
      PAS needs no migration (CBI defaults to allow-all) and must NOT loosen an existing *restrictive*
      private block — the stricter existing rules win. Azure never migrates PrivateLink (its
      `databricks_ui_api` endpoints are default-allowed), so it only ever carries existing forward.
    * **cross_workspace_access** — never built; any existing block is carried forward verbatim.
    * **public_access** — built net-new from traffic/ACLs; an existing restrictive public is carried
      forward only when this run has nothing of its own to build (resolved in ingress_rules).

    Sets cfg.private_access / cfg.existing_public / cfg.existing_xws. Returns
    (existing_public, existing_private, migrating_restrictive_private, assigned_id) for the conflict
    gate. Needs an account client; a no-op (all None/False) without one."""
    from .core import acl as acl_core
    from .core import egress as eg
    from .core import policy as policy_core

    if account is None:
        return None, None, False, None  # can't read the PAS / assigned policy without account creds
    cloud = eg.workspace_cloud_from_host(getattr(getattr(wc, "config", None), "host", None))

    # Front-end PrivateLink plan (AWS/GCP only — Azure has no PAS to migrate).
    plan = None
    if cloud in ("aws", "gcp"):
        pas, status = acl_core.read_workspace_pas(account, workspace_id)
        if status == "error":
            console.banner(
                "warn",
                "Couldn't read the workspace's Private Access Settings (account read failed) — "
                "front-end PrivateLink won't be migrated. Verify it manually if this workspace uses it.",
            )
        elif status == "ok":
            plan = acl_core.plan_from_pas(pas)

    # Existing assigned CBI policy's (restrictive-only, deep-copied) ingress sub-blocks.
    assigned_id, existing_public, existing_private, existing_xws = acl_core.existing_cbi_ingress(
        account, workspace_id
    )

    # Resolve private_access: migrate the PAS, else carry existing forward (allow-all never loosens).
    if plan is not None:
        if plan.restriction_mode == "ALLOW_ALL_REGISTERED_ENDPOINTS" and acl_core.block_restrictive(
            existing_private
        ):
            cfg.private_access = existing_private
            console.banner(
                "info",
                "Front-end PrivateLink is account-level (all registered endpoints), but the workspace "
                "already has restrictive CBI private access — keeping the stricter existing private rules.",
            )
        else:
            # A RESTRICTED_ACCESS (endpoint-scoped) private block gates ALL private ingress, so the
            # workspace's back-end PrivateLink endpoints (data-plane relay + REST — in the network
            # config, not the PAS) must be allowed too, or the data plane is blocked. (ALLOW_ALL
            # already permits every registered endpoint, so there's nothing to add there.)
            if plan.restriction_mode == "RESTRICTED_ACCESS":
                plan.backend_endpoint_ids = acl_core.backend_private_endpoint_ids(account, workspace_id)
                if plan.backend_endpoint_ids:
                    console.banner(
                        "info",
                        f"Detected {len(plan.backend_endpoint_ids)} back-end PrivateLink endpoint(s) "
                        "(data-plane relay + REST) for this workspace — including them in the policy's "
                        "private_access so the restricted private rules don't block the data plane.",
                    )
                else:
                    console.banner(
                        "warn",
                        "No back-end PrivateLink endpoint detected for this workspace to migrate.",
                    )
            cfg.private_access = policy_core.build_private_access_block(
                plan.restriction_mode,
                plan.endpoint_ids,
                plan.label,
                backend_endpoint_ids=plan.backend_endpoint_ids,
            )
            console.banner(
                "info",
                f"Front-end PrivateLink detected (PAS '{plan.source_pas_id}') — recreating it in the "
                "policy's private_access block.",
            )
    elif existing_private is not None:
        cfg.private_access = existing_private
        console.banner(
            "info",
            "Carrying the workspace's existing CBI private_access block forward into the generated policy.",
        )

    cfg.existing_public = existing_public
    cfg.existing_xws = existing_xws
    if existing_xws is not None:
        console.banner(
            "info",
            "Carrying the workspace's existing cross-workspace access block forward (this tool "
            "doesn't build cross-workspace rules).",
        )

    migrating_restrictive_private = plan is not None and plan.restriction_mode == "RESTRICTED_ACCESS"
    return existing_public, existing_private, migrating_restrictive_private, assigned_id


def _note_partner_platforms(analysis) -> None:
    """When observed IPs fall in a known partner-platform (Power BI / dbt / Tableau) range, flag it:
    those groups are recommended for allow-listing, and Databricks' console/Terraform now offers a
    self-maintaining 'Partner platforms' network source (Beta; AWS + GCP) that's cleaner than pinning
    the raw CIDRs — but the SDK this tool writes with can't set it, so they go in as labelled CIDR
    allow-rules here."""
    partners = sorted({p for r in (analysis.suggestion_rows or []) for p in (r.get("partners") or [])})
    if not partners:
        return
    console.banner(
        "info",
        f"Observed inbound traffic from partner platform(s): {', '.join(partners)}. These are "
        "allow-listed as labelled CIDR rules. Databricks also offers a managed 'Partner platforms' "
        "ingress source (Beta, AWS + GCP — Power BI / Tableau Cloud / dbt platform) that maintains "
        "these IP lists for you; enable it on the account console Previews page and add the source "
        "on the policy's Ingress tab for a cleaner, self-updating alternative to pinning the CIDRs.",
    )


def _note_cross_workspace_compat(cfg: IngressConfig) -> None:
    """Flag the cross-workspace posture. This tool doesn't build cross-workspace rules; an existing
    block is carried forward verbatim (noted at reconcile time), and when there's none the policy is
    left in compatibility mode (the account default)."""
    if cfg.existing_xws is not None:
        return  # already noted that the existing cross-workspace block is carried forward
    console.banner(
        "info",
        "Cross-workspace access is left in compatibility mode (the account default) — this tool "
        "doesn't build cross-workspace ingress/egress rules yet.",
    )


def _checkpoint(yes: bool) -> None:
    """Step-through pause after a results/preview section: let the user review it and choose whether
    to continue. Aborts the run cleanly (exit 0) on 'n'. On by default; skipped with --yes and in
    non-interactive/scripted runs (so scripting and the guided flow are unaffected)."""
    import sys

    if yes or not sys.stdin.isatty():
        return
    if not typer.confirm(typer.style("Continue to the next step?", fg="yellow"), default=True):
        console.banner("info", "Stopped — nothing further was done.")
        raise typer.Exit(code=0)


def _interactive(yes: bool) -> bool:
    """True only when we can and should prompt — interactive TTY and not --yes/scripted."""
    import sys

    return not yes and sys.stdin.isatty()


def _confirm_truncation(truncations: list[str], yes: bool, *, allow_reselect: bool = False) -> bool:
    """Decision point when rules / CIDRs / destinations were auto-capped to fit policy limits. The
    per-item warnings already printed inline during build/preview; this forces the operator to
    acknowledge that some rules were dropped before continuing to export/apply. Skipped by --yes and
    non-interactively (scripted runs proceed → returns True). Returns True to continue. When
    `allow_reselect` is set, declining the prompt offers a second choice — go back to the selection
    step (returns False) or abort; without it (or if the user picks abort) the run stops cleanly
    (exit 0)."""
    if not truncations or not _interactive(yes):
        return True
    n = len(truncations)
    if typer.confirm(
        typer.style(
            f"⚠️  {n} truncation(s) were applied to fit policy limits (see warnings above). Continue?",
            fg="yellow",
        ),
        default=False,
    ):
        return True
    if allow_reselect:
        import questionary

        choice = questionary.select(
            "Some rules were trimmed to fit the policy limits. What next?",
            choices=[
                questionary.Choice(
                    title="Go back to the allow-rule selection (deselect rules to get under the limit)",
                    value="reselect",
                ),
                questionary.Choice(title="Abort — write nothing", value="abort"),
            ],
        ).ask()
        if choice == "reselect":
            return False
    console.banner("info", "Stopped — nothing further was done.")
    raise typer.Exit(code=0)


def _reconcile_ip_acls(analysis, cfg: IngressConfig, yes: bool) -> None:
    """Detect the workspace's IP access lists and decide which to fold into the CBI policy (alongside
    the enriched observed-traffic rules). Both **enabled and disabled** lists are shown with their
    status and actual IPs. Interactive runs get a checkbox — enabled entries pre-checked, disabled
    ones offered unchecked so you can consciously migrate a dormant list (checking one ACTIVATES rules
    that were off). --yes / non-interactive runs migrate all *enabled* lists (the safe default — the
    CBI policy replaces the ACL, so dropping it silently could lose coverage) and never auto-activate
    disabled ones. Prunes analysis.ip_acls to the selection and sets cfg.migrate_ip_acls. No-op when
    the workspace has no IP access list entries."""
    all_acls = list(analysis.ip_acls or [])
    enabled = [a for a in all_acls if a.get("enabled")]
    entries = [(a, ip) for a in all_acls for ip in a["ip_addresses"]]
    if not entries:
        cfg.migrate_ip_acls = False  # no lists with any IPs; keep the preview/echo honest
        return

    def _status(a):
        return "enabled" if a.get("enabled") else "disabled"

    # Show the full inventory — enabled AND disabled — with status + actual IPs.
    listing = "\n".join(
        f"    • {a['label']} ({a['list_type'] or '?'} · {_status(a)}): {', '.join(a['ip_addresses'])}"
        for a in all_acls
    )
    n_disabled = len(all_acls) - len(enabled)
    console.banner(
        "info",
        f"Detected {len(all_acls)} IP access list(s) — {len(enabled)} enabled, {n_disabled} disabled "
        f"({len(entries)} entr{'y' if len(entries) == 1 else 'ies'}) on this workspace:\n{listing}",
    )

    if not _interactive(yes):
        cfg.migrate_ip_acls = bool(enabled)
        console.banner(
            "info",
            "Non-interactive run — folding all ENABLED IP access list entries into the CBI policy "
            "(disabled lists are left dormant; use interactive mode to include one or pick a subset).",
        )
        return

    import questionary

    choices = [
        questionary.Choice(
            title=f"{ip}  [{a['label']} · {a['list_type'] or '?'} · {_status(a)}]",
            value=(id(a), ip),
            checked=bool(a.get("enabled")),  # enabled pre-checked; disabled offered unchecked
        )
        for a, ip in entries
    ]
    kept = _checkbox_keep(
        "Select IP access list entries to migrate (enabled pre-checked; checking a disabled one "
        "ACTIVATES it) — space=toggle, enter=confirm:",
        choices,
    )
    if kept is None:
        console.banner("info", "Selection cancelled — aborting, nothing written.")
        raise typer.Exit(code=0)
    kept_keys = set(kept)
    migrated, preserved, activated = [], [], []
    for a in all_acls:
        keep_ips = [ip for ip in a["ip_addresses"] if (id(a), ip) in kept_keys]
        if keep_ips:
            # Selected → migrate. Mark enabled so _acl_specs includes it even if the list was dormant
            # (the user explicitly opted to activate these previously-off rules).
            migrated.append({**a, "ip_addresses": keep_ips, "enabled": True})
            if not a.get("enabled"):
                activated.append(a["label"])
        elif not a.get("enabled"):
            preserved.append(a)  # unselected dormant list — kept in the analysis, not migrated
    analysis.ip_acls = migrated + preserved
    cfg.migrate_ip_acls = bool(migrated)
    if activated:
        console.banner(
            "warn",
            f"Migrating {len(activated)} previously-DISABLED IP access list(s) — these were not "
            f"enforced on the workspace and will become ACTIVE in the new policy: {', '.join(activated)}.",
        )
    if migrated:
        kept_n = sum(len(a["ip_addresses"]) for a in migrated)
        console.banner(
            "info", f"Including {kept_n} IP access list entr{'y' if kept_n == 1 else 'ies'} in the policy."
        )
    else:
        console.banner(
            "info",
            "No IP access list entries selected — the policy will be built from observed traffic only.",
        )


def _checkbox_keep(title: str, choices: list) -> list | None:
    """Show a pre-checked checkbox of `choices` (questionary.Choice with .value); return the list of
    kept values, or None if the user cancelled (Ctrl-C). All start checked so 'keep everything' is a
    single Enter."""
    import questionary

    return questionary.checkbox(title, choices=choices).ask()


def _select_ingress_rules(analysis, cfg: IngressConfig, yes: bool) -> None:
    """Let the user pick which proposed allow rules (owner groups) to keep, then filter the analysis
    in place so only the selected groups become rules. Threat-flagged groups aren't offered (they're
    never allow-listed). No-op under --yes / non-interactive / when --select-rules wasn't passed."""
    if not cfg.select_rules or not _interactive(yes):
        return
    import questionary

    framing_col = {"minimal": "minimal_cidrs", "optimal": "optimal_cidrs", "maximum": "maximum_cidrs"}[
        cfg.policy_framing
    ]
    # Only offer groups that would actually become allow rules (Databricks-owned always would;
    # otherwise a threat-feed match means it's excluded from the allow-list by design).
    eligible = [r for r in analysis.suggestion_rows if r["databricks_owned"] or not r["threat_feeds"]]
    if not eligible:
        return
    choices = []
    for r in eligible:
        cidrs = r.get(framing_col) or r.get("minimal_cidrs") or []
        shown = ", ".join(cidrs[:3]) + (f" +{len(cidrs) - 3} more" if len(cidrs) > 3 else "")
        target = "" if r["policy_target"] == "__ALL__" else f" [ws {r['policy_target']}]"
        title = f"{r['rdap_owner']}{target} — {r['recommendation']} — {shown}"
        choices.append(
            questionary.Choice(title=title, value=(r["policy_target"], r["rdap_owner"]), checked=True)
        )

    kept = _checkbox_keep("Select the ingress allow rules to include (space=toggle, enter=confirm):", choices)
    if kept is None:
        console.banner("info", "Selection cancelled — aborting, nothing written.")
        raise typer.Exit(code=0)
    kept_keys = set(kept)
    drop = {(r["policy_target"], r["rdap_owner"]) for r in eligible} - kept_keys
    if not drop:
        return
    df = analysis.suggestions
    analysis.suggestions = df[
        ~df.apply(lambda row: (row["policy_target"], row["rdap_owner"]) in drop, axis=1)
    ].reset_index(drop=True)
    analysis.suggestion_rows = [
        r for r in analysis.suggestion_rows if (r["policy_target"], r["rdap_owner"]) not in drop
    ]
    console.banner("info", f"Excluded {len(drop)} rule(s) from your selection; kept {len(kept_keys)}.")


def _egress_pick(title: str, entries: list) -> set:
    """Show one pre-checked checkbox for a list of (value, title) egress destinations and return the
    set of kept values. Cancelling (Ctrl-C) aborts the whole run, writing nothing."""
    import questionary

    choices = [questionary.Choice(title=t, value=v, checked=True) for v, t in entries]
    kept = _checkbox_keep(title, choices)
    if kept is None:
        console.banner("info", "Selection cancelled — aborting, nothing written.")
        raise typer.Exit(code=0)
    return set(kept)


def _select_egress_rules(analysis, cfg: EgressConfig, yes: bool) -> None:
    """Let the user pick which observed egress destinations to allow-list, then remove the deselected
    ones from every target. Runs as two distinct prompts — one for **internet FQDNs**, one for
    **storage destinations** (S3 / GCS / Azure) — so the two kinds are curated separately rather than
    in a single mixed list. No-op under --yes / non-interactive / when --select-rules wasn't passed."""
    if not cfg.select_rules or not _interactive(yes):
        return

    from .core import egress as eg

    def _ranked(kind):  # observed destinations of one kind, busiest first
        return sorted(eg.union(analysis.targets, kind).items(), key=lambda kv: -kv[1])

    fqdns = [
        (("internet", f), f"{f}  ({analysis.fqdn_owner.get(f) or 'owner unknown'}, {n} events)")
        for f, n in _ranked("internet")
    ]
    storage = (
        [(("s3", (b, r)), f"S3  {b} ({r}, {n} events)") for (b, r), n in _ranked("s3")]
        + [(("gcs", b), f"GCS  {b} ({n} events)") for b, n in _ranked("gcs")]
        + [(("azure", (a, s)), f"Azure  {a}.{s} ({n} events)") for (a, s), n in _ranked("azure")]
    )
    if not fqdns and not storage:
        return

    drop = set()
    if fqdns:
        kept = _egress_pick("Select the internet FQDNs to allow-list (space=toggle, enter=confirm):", fqdns)
        drop |= {value for value, _title in fqdns} - kept
    if storage:
        kept = _egress_pick(
            "Select the storage destinations to allow-list (space=toggle, enter=confirm):", storage
        )
        drop |= {value for value, _title in storage} - kept
    if not drop:
        return
    for t in analysis.targets.values():
        for kind, key in drop:
            t[kind].pop(key, None)
    console.banner("info", f"Excluded {len(drop)} destination(s) from your selection.")


def _maybe_disable_ip_acls(disable: bool, results: list[dict], workspace_client) -> None:
    """After a successful create+assign, optionally turn off the workspace's IP access lists. Only
    fires when at least one policy was actually assigned — if the apply errored and assigned nothing,
    we must NOT disable the ACLs (that would strip the workspace's protection). The create+assign
    flag combination itself is validated up front by validate_disable_ip_acls."""
    if not disable:
        return
    if not any(r.get("assigned") is not None for r in results):
        console.banner(
            "warn",
            "Skipped disabling IP access lists — no policy was assigned (the "
            "apply may have failed), so the workspace keeps its current "
            "protection.",
        )
        return
    from .core import acl as acl_core

    try:
        with console.status("Disabling workspace IP access lists…"):
            acl_core.disable_ip_access_lists(workspace_client, note=lambda m: console.banner("info", m))
    except Exception as e:  # noqa: BLE001 - the policy is already applied; cleanup failure shouldn't crash
        console.banner(
            "warn",
            f"Couldn't disable the workspace IP access lists automatically: {e}. The new "
            "policy is created and assigned (the workspace stays protected — both "
            "controls just apply for now); disable the IP access lists manually in Admin "
            "settings if you want them off.",
        )


@app.command()
def ingress(
    profile: str | None = typer.Option(None, help="Databricks CLI/config profile."),
    warehouse_http_path: str | None = typer.Option(
        None, help="SQL warehouse http_path. If omitted, a serverless warehouse is reused/created."
    ),
    warehouse_size: WarehouseSize = typer.Option(
        WarehouseSize.xsmall,
        help="Cluster size for the auto-created serverless warehouse (ignored with "
        "--warehouse-http-path). One of: 2X-Small, X-Small (default), Small, Medium, Large, "
        "X-Large, 2X-Large, 3X-Large, 4X-Large. Bump it if the analysis query is slow on a large "
        "audit log.",
    ),
    lookback_days: int = typer.Option(30, help="Days of system.access.audit history."),
    min_events: int = typer.Option(1, help="Min successful events per IP."),
    treat_null_status_as_success: bool = typer.Option(False, help="Count NULL status as success."),
    include_ipv6: bool = typer.Option(False, help="Analyse IPv6 (policy stays IPv4-only)."),
    include_account_level: bool = typer.Option(
        False,
        help="Include account-level (workspace_id=0) audit rows (default off; these are "
        "account console / SCIM traffic, not workspace-scoped).",
    ),
    include_inbound_network: bool = typer.Option(
        True,
        help="Also use system.access.inbound_network dry-run denials (access_type=DRY_RUN_DENIAL) as "
        "allow-list candidates — public inbound clients a log-only CBI policy would block but the "
        "allow-list doesn't yet cover. Best-effort; on by default, --no-include-inbound-network to skip.",
    ),
    enable_rdap: bool = typer.Option(True, help="RDAP owner lookup (needed for 'maximum')."),
    rdap_workers: int = typer.Option(
        16,
        help="Concurrent RDAP lookups (network-bound; the slow part of enrichment with many "
        "candidate IPs). 1 = sequential. Higher is faster but hits RIR rate limits harder.",
    ),
    refresh_feeds: bool = typer.Option(False, help="Force re-download of cached feeds."),
    policy_framing: Framing = typer.Option(Framing.minimal, help="CIDR framing."),
    scoping_mode: Scoping = typer.Option(Scoping.ip_only, help="Destination/identity scoping."),
    policy_scope: Scope = typer.Option(
        Scope.current_workspace,
        help="current_workspace (default): one policy for the profile's workspace; per_workspace: "
        "one per workspace seen; all_workspaces: a single policy from all workspaces' traffic.",
    ),
    policy_mode: Mode = typer.Option(Mode.dry_run, help="dry_run=log-only; enforce=blocking."),
    block_threat_ips: ThreatDeny = typer.Option(
        ThreatDeny.off,
        help="Deny known-bad source IPs: off/matched_only/all (builds CBI deny rules). When not 'off', "
        "an interactive run then asks which threat-intel feeds to use. Known-bad source IPs are always "
        "flagged and kept out of the allow-list regardless of this setting.",
    ),
    policy_name: str = typer.Option(
        "",
        help="Policy name. If omitted you'll be prompted (blank there = the profile name). The "
        "policy id for single-policy scopes; the prefix (→ <name>-ws-<id>) for "
        "per_workspace. Normalised: lowercased, non-alphanumerics → '-', length-capped.",
    ),
    deny_denied_ips: bool = typer.Option(False, help="Deny recently-denied (403) source IPs."),
    select_rules: bool = typer.Option(
        True,
        help="Interactively pick which proposed allow rules to include (a checkbox after the "
        "preview). On by default; use --no-select-rules to keep everything. Ignored with --yes / "
        "non-interactively.",
    ),
    export: str = typer.Option(
        "",
        help="Write the proposed network-policy JSON to this path (for curl / the REST API); a "
        "directory writes <policy-id>.json inside it. Single-policy scopes only. Works in "
        "propose-only mode too.",
    ),
    disable_existing_ip_acls: bool = typer.Option(
        False,
        help="After creating AND assigning the policy, disable this workspace's existing IP "
        "access lists (enableIpAccessLists=false). Requires --create-policy and "
        "--auto-assign.",
    ),
    account_id: str | None = typer.Option(None, help="Databricks account_id (apply/identity)."),
    account_host: str | None = typer.Option(
        None, help="Account host. When unset, derived from the workspace's environment."
    ),
    account_profile: str | None = typer.Option(
        None, help="Profile for account-level calls (apply/identity). Defaults to unified auth."
    ),
    create_policy: bool = typer.Option(False, help="Master switch: write the policy."),
    policy_action: Action = typer.Option(Action.create_new, help="Create new or add to existing."),
    existing_policy_id: str = typer.Option("", help="Target id for add_to_existing."),
    auto_assign: bool = typer.Option(False, help="Bind the workspace(s) to the policy."),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Non-interactive mode: skip all prompts — the step-through pauses between sections and "
        "the review/write gates. Use for scripted runs.",
    ),
):
    """Build (and optionally apply) a context-based ingress (CBI) allow-list."""
    from . import guided

    block = block_threat_ips.value
    # Feeds always load to flag known-bad source IPs (kept out of the allow-list); the interactive
    # picker is offered only when deny rules are engaged. Headless / --yes → all feeds.
    feeds = guided.resolve_threat_ip_feeds(_interactive(yes), block != "off")
    cfg = IngressConfig(
        lookback_days=lookback_days,
        min_events=min_events,
        treat_null_status_as_success=treat_null_status_as_success,
        include_ipv6=include_ipv6,
        include_account_level=include_account_level,
        include_inbound_network=include_inbound_network,
        threat_feeds=feeds,
        enable_rdap=enable_rdap,
        rdap_workers=rdap_workers,
        refresh_feeds=refresh_feeds,
        policy_framing=policy_framing.value,
        scoping_mode=scoping_mode.value,
        policy_scope=policy_scope.value,
        policy_mode=policy_mode.value,
        threat_deny_rules=block,
        policy_name=policy_name,
        export=export,
        deny_denied_ips=deny_denied_ips,
        select_rules=select_rules,
        disable_existing_ip_acls=disable_existing_ip_acls,
        apply=ApplyOptions(
            create_policy=create_policy,
            policy_action=policy_action.value,
            existing_policy_id=existing_policy_id,
            auto_assign=auto_assign,
        ),
    )
    conn = _conn(
        profile, warehouse_http_path, account_id, account_host, account_profile, warehouse_size.value
    )
    _run_ingress(cfg, conn, yes)


@app.command()
def egress(
    profile: str | None = typer.Option(None, help="Databricks CLI/config profile."),
    warehouse_http_path: str | None = typer.Option(
        None, help="SQL warehouse http_path. If omitted, a serverless warehouse is reused/created."
    ),
    warehouse_size: WarehouseSize = typer.Option(
        WarehouseSize.xsmall,
        help="Cluster size for the auto-created serverless warehouse (ignored with "
        "--warehouse-http-path). One of: 2X-Small, X-Small (default), Small, Medium, Large, "
        "X-Large, 2X-Large, 3X-Large, 4X-Large. Bump it if the analysis query is slow on a large "
        "audit log.",
    ),
    lookback_days: int = typer.Option(30, help="Days of outbound_network history."),
    min_events: int = typer.Option(1, help="Min events per destination."),
    source_type_filter: str = typer.Option("", help="network_source_type filter (blank=all)."),
    enable_rdap: bool = typer.Option(True, help="Cloud-owner lookup for internet FQDNs."),
    refresh_feeds: bool = typer.Option(False, help="Force re-download of cached feeds."),
    policy_scope: Scope = typer.Option(
        Scope.current_workspace,
        help="current_workspace (default): one policy for the profile's workspace; per_workspace: "
        "one per workspace seen; all_workspaces: a single policy from all workspaces' traffic.",
    ),
    policy_mode: Mode = typer.Option(Mode.dry_run, help="dry_run=log-only; enforce=blocking."),
    block_threat_domains: ThreatDeny = typer.Option(
        ThreatDeny.off,
        help="Block known-bad domains: off/matched_only/all. When not 'off', an interactive run then "
        "asks which threat feeds to use (c2intel keyless; threatfox/urlhaus need a free abuse.ch "
        "Auth-Key) and whether to flag popularity-allowlisted candidates. Non-interactive / --yes runs "
        "use the keyless feeds plus the abuse.ch feeds when DBX_NWP_ABUSE_CH_AUTH_KEY is set.",
    ),
    select_rules: bool = typer.Option(
        True,
        help="Interactively pick which observed destinations to allow-list (a checkbox after the "
        "analysis). On by default; use --no-select-rules to keep everything. Ignored with --yes / "
        "non-interactively.",
    ),
    policy_name: str = typer.Option(
        "",
        help="Policy name. If omitted you'll be prompted (blank there = the profile name). The "
        "policy id for single-policy scopes; the prefix (→ <name>-ws-<id>) for "
        "per_workspace. Normalised: lowercased, non-alphanumerics → '-', length-capped.",
    ),
    export: str = typer.Option(
        "",
        help="Write the proposed network-policy JSON to this path (for curl / the REST API); a "
        "directory writes <policy-id>.json inside it. Single-policy scopes only. Works in "
        "propose-only mode too.",
    ),
    account_id: str | None = typer.Option(None, help="Databricks account_id (apply)."),
    account_host: str | None = typer.Option(
        None, help="Account host. When unset, derived from the workspace's environment."
    ),
    account_profile: str | None = typer.Option(
        None, help="Profile for account-level calls (apply/identity). Defaults to unified auth."
    ),
    create_policy: bool = typer.Option(False, help="Master switch: write the policy."),
    policy_action: Action = typer.Option(Action.create_new, help="Create new or add to existing."),
    existing_policy_id: str = typer.Option("", help="Target id for add_to_existing."),
    auto_assign: bool = typer.Option(False, help="Bind the workspace(s) to the policy."),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Non-interactive mode: skip all prompts — the step-through pauses between sections and "
        "the review/write gates. Use for scripted runs.",
    ),
):
    """Build (and optionally apply) a serverless egress (SEG) allow-list."""
    from . import guided
    from .config import DEFAULT_EGRESS_THREAT_FEEDS

    block = block_threat_domains.value
    if block != "off":
        feeds, abuse_ch_auth_key, domain_allowlist = guided.resolve_threat_domain_feeds(_interactive(yes))
    else:
        feeds, abuse_ch_auth_key, domain_allowlist = list(DEFAULT_EGRESS_THREAT_FEEDS), None, True
    cfg = EgressConfig(
        lookback_days=lookback_days,
        min_events=min_events,
        source_type_filter=source_type_filter,
        enable_rdap=enable_rdap,
        refresh_feeds=refresh_feeds,
        policy_name=policy_name,
        export=export,
        policy_mode=policy_mode.value,
        policy_scope=policy_scope.value,
        block_threat_domains=block,
        threat_feeds=feeds,
        abuse_ch_auth_key=abuse_ch_auth_key,
        domain_allowlist=domain_allowlist,
        select_rules=select_rules,
        apply=ApplyOptions(
            create_policy=create_policy,
            policy_action=policy_action.value,
            existing_policy_id=existing_policy_id,
            auto_assign=auto_assign,
        ),
    )
    conn = _conn(
        profile, warehouse_http_path, account_id, account_host, account_profile, warehouse_size.value
    )
    _run_egress(cfg, conn, yes)


@app.command()
def guided(
    profile: str | None = typer.Option(None, help="Databricks CLI/config profile."),
    warehouse_http_path: str | None = typer.Option(
        None, help="SQL warehouse http_path. If omitted, a serverless warehouse is reused/created."
    ),
    warehouse_size: WarehouseSize = typer.Option(
        WarehouseSize.xsmall,
        help="Cluster size for the auto-created serverless warehouse (ignored with "
        "--warehouse-http-path). One of: 2X-Small, X-Small (default), Small, Medium, Large, "
        "X-Large, 2X-Large, 3X-Large, 4X-Large.",
    ),
    account_id: str | None = typer.Option(None, help="Databricks account_id (apply/identity)."),
    account_host: str | None = typer.Option(
        None, help="Account host. When unset, derived from the workspace's environment."
    ),
    account_profile: str | None = typer.Option(
        None, help="Profile for account-level calls (apply/identity). Defaults to unified auth."
    ),
):
    """Interactive Q&A wizard — walks you through building an ingress/egress policy."""
    from .guided import run_wizard

    conn = _conn(
        profile, warehouse_http_path, account_id, account_host, account_profile, warehouse_size.value
    )
    run_wizard(conn)


def _guide_path():
    """Filesystem path to the packaged interactive guide (shipped inside the package so it's present
    after `uv tool install`)."""
    from pathlib import Path

    return Path(__file__).parent / "guide" / "index.html"


def _find_chrome() -> str | None:
    """Path to a Chromium-family browser that can render a PDF headlessly (Chrome / Chromium / Edge),
    or None. Checks the usual PATH names plus the macOS app-bundle locations."""
    import shutil

    for name in (
        "google-chrome",
        "google-chrome-stable",
        "chromium",
        "chromium-browser",
        "chrome",
        "microsoft-edge",
        "msedge",
    ):
        found = shutil.which(name)
        if found:
            return found
    from pathlib import Path

    for app in (
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    ):
        if Path(app).exists():
            return app
    return None


def _guide_to_pdf(guide, out: str) -> None:
    """Render the guide to a PDF at `out` using a headless Chromium-family browser, with every section
    expanded (the guide auto-expands on the #print hash). Falls back to a clear message — and the
    on-page 'Save as PDF' button — when no such browser is found. Always returns or raises typer.Exit."""
    import os
    import subprocess
    from pathlib import Path

    # Accept either a file path or a directory. A directory (existing, or written with a trailing
    # slash) gets the default filename so we never try to "write" onto the directory itself.
    dest = Path(out).expanduser()
    if dest.is_dir() or out.endswith(("/", os.sep)):
        dest = dest / "dbx-nwp-helper-guide.pdf"
    out_abs = dest.resolve()
    chrome = _find_chrome()
    if chrome is None:
        console.banner(
            "danger",
            "Couldn't find a Chrome / Chromium / Edge browser to render the PDF.\n"
            "  Open the guide (`dbx-nwp-helper guide`) and use the on-page '⭳ PDF' button (or your "
            "browser's Save as PDF) — it expands every section first, so nothing is missing.",
        )
        raise typer.Exit(code=1)
    out_abs.parent.mkdir(parents=True, exist_ok=True)  # create the target dir if needed
    url = f"{guide.as_uri()}#print"
    cmd = [
        chrome,
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--no-pdf-header-footer",
        f"--print-to-pdf={out_abs}",
        url,
    ]
    with console.status(f"Rendering the guide to PDF via {Path(chrome).name}…"):
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=90)
        except (OSError, subprocess.TimeoutExpired) as e:  # noqa: BLE001 - surface a clean message
            console.banner("danger", f"Couldn't run the browser to render the PDF: {e}")
            raise typer.Exit(code=1) from None
    if result.returncode != 0 or not out_abs.is_file():
        detail = (result.stderr or b"").decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
        console.banner(
            "danger",
            f"The browser didn't produce a PDF (exit {result.returncode}). {detail[0]}\n"
            "  Try `dbx-nwp-helper guide` and use the on-page '⭳ PDF' button instead.",
        )
        raise typer.Exit(code=1)
    console.banner("success", f"Wrote the guide PDF (all sections expanded) to:\n  {out_abs}")


@app.command()
def guide(
    print_path: bool = typer.Option(
        False, "--print-path", help="Print the guide's file path instead of opening a browser."
    ),
    pdf: str = typer.Option(
        "",
        "--pdf",
        metavar="PATH",
        help="Render the guide to a PDF at PATH, with every section expanded (needs a headless "
        "Chrome / Chromium / Edge). PATH may be a file or a directory (a directory gets "
        "dbx-nwp-helper-guide.pdf). Falls back to the on-page 'Save as PDF' button if none is found.",
    ),
) -> None:
    """Open the interactive companion guide — a self-contained, offline page that walks through what
    the tool does, each step of a run, and links to read more. Use --pdf to render it to a file."""
    import webbrowser

    path = _guide_path()
    if not path.exists():
        console.banner("danger", f"Couldn't find the guide at {path}. Try reinstalling the package.")
        raise typer.Exit(code=1)
    if print_path:
        typer.echo(str(path))  # plain, unwrapped — safe to consume from a script
        return
    if pdf:
        _guide_to_pdf(path, pdf)
        return
    console.banner("info", f"Opening the interactive guide in your browser:\n  {path}")
    if not webbrowser.open(path.as_uri()):
        console.banner(
            "info", f"Couldn't launch a browser automatically — open this file yourself:\n  {path}"
        )


# --- feeds subcommands ---
@feeds_app.command("list")
def feeds_list():
    """Show the cached feed tables (name, rows, age)."""
    from .feeds import cache

    rows = cache.status_rows()
    if not rows:
        console.banner(
            "info",
            f"No cached feeds yet ({cache.cache_dir()}). Run an analysis or " "`feeds refresh` to populate.",
        )
        return
    import pandas as pd

    console.dataframe(
        pd.DataFrame(rows, columns=["feed", "rows", "age"]), f"Cached feeds ({cache.cache_dir()})"
    )


@feeds_app.command("refresh")
def feeds_refresh():
    """Force a re-download of all enrichment feeds into the cache."""
    from .config import THREAT_FEEDS as ALL_FEEDS
    from .feeds import loaders

    with console.status("Refreshing threat-intel feeds…"):
        loaders.threat_intel(list(ALL_FEEDS), refresh=True)
    with console.status("Refreshing cloud-provider ranges…"):
        loaders.cloud_ranges(refresh=True)
    with console.status("Refreshing Databricks ranges…"):
        loaders.databricks_ranges(refresh=True)
    with console.status("Refreshing partner-platform ranges…"):
        loaders.partner_ranges(refresh=True)
    console.banner("success", "Feed cache refreshed.")


@feeds_app.command("clear")
def feeds_clear():
    """Remove all cached feed files."""
    from .feeds import cache

    removed = cache.clear()
    console.banner("success", f"Removed {len(removed)} cached feed file(s).")


# --------------------------------------------------------------------------------- run helpers
# These are importable by the guided wizard too, so a wizard run and a flag run share one flow.

# Server-side signatures of a preview-gated SQL feature the warehouse doesn't have enabled. The
# queries no longer use the INET functions, but this keeps any such gate a clear message not a
# traceback (e.g. a future dependency, or an older/limited warehouse).
_UNSUPPORTED_SQL_SIGNATURES = ("INET_FUNCTIONS_NOT_ENABLED", "is disabled or unsupported")

# Signatures of a query that couldn't complete because the warehouse was too slow to respond or the
# connection dropped. The databricks-sql connector retries up to a max duration (default 900s) and
# then raises rather than hanging forever — good, but it surfaces as a raw traceback we should catch.
_SQL_UNAVAILABLE_SIGNATURES = (
    "Retry policy max retry duration",  # RequestError: retry budget exhausted
    "Error during request to server",  # the RequestError message prefix
    "Remote end closed connection",
    "Max retries exceeded",
    "Connection aborted",
    "Connection refused",
    "timed out",  # socket / read timeout
)


# A source system table the analysis reads doesn't exist — the `system.access` schema (or that
# specific table) isn't enabled/available in this workspace's metastore. An enablement issue, not a
# bug, so give clear guidance rather than a traceback.
_MISSING_TABLE_SIGNATURE = "TABLE_OR_VIEW_NOT_FOUND"

# Per-table guidance keyed by the system.access table name. outbound_network is the serverless-egress
# (SEG) monitoring table; audit is the audit log. Both live in the `access` system schema.
_SYSTEM_TABLE_GUIDANCE = {
    "outbound_network": (
        "`system.access.outbound_network` records serverless egress (SEG) network traffic and is "
        "what the egress command analyses. It's available only once the `access` system schema is "
        "enabled for the workspace's metastore AND serverless egress logging has produced data — "
        "stand up a dry-run egress network policy first so outbound traffic is logged, give it time "
        "to populate, then re-run."
    ),
    "audit": (
        "`system.access.audit` is the audit-log system table the ingress command analyses. Enable "
        "the `access` system schema for the workspace's metastore (an account / metastore admin), "
        "then re-run."
    ),
}


def _missing_table_message(msg: str) -> str:
    """Actionable message for a TABLE_OR_VIEW_NOT_FOUND on one of the source system tables — names the
    missing table (parsed from the error) and how to enable it. Falls back to generic guidance."""
    import re

    m = re.search(r"`system`\.`access`\.`([a-z_]+)`", msg)
    table = m.group(1) if m else None
    head = (
        f"The system table system.access.{table} isn't available in this workspace."
        if table
        else "A system.access system table isn't available in this workspace."
    )
    tail = _SYSTEM_TABLE_GUIDANCE.get(table) or (
        "Enable the `access` system schema for the workspace's metastore (an account / metastore "
        "admin) and confirm the table exists, then re-run."
    )
    return f"{head}\n\n{tail}\n\nNothing was written."


def _run_analysis(analyze_call):
    """Run an engine's analysis SQL, turning known SQL/warehouse failures into a clear, actionable
    message instead of a raw traceback. Unrecognised errors are re-raised unchanged."""
    try:
        return analyze_call()
    except Exception as e:  # noqa: BLE001 - narrowed by message signature below, else re-raised
        msg = str(e)
        if _MISSING_TABLE_SIGNATURE in msg:
            console.banner("danger", _missing_table_message(msg))
            raise typer.Exit(code=1) from None
        if any(sig in msg for sig in _UNSUPPORTED_SQL_SIGNATURES):
            console.banner(
                "danger",
                "The SQL warehouse rejected a function this tool needs — the workspace looks to be "
                "missing a required (preview) SQL capability:\n\n"
                f"    {msg.strip().splitlines()[0]}\n\n"
                "Try a different warehouse/workspace where the feature is enabled, or raise it with "
                "Databricks. Nothing was written.",
            )
            raise typer.Exit(code=1) from None
        if any(sig in msg for sig in _SQL_UNAVAILABLE_SIGNATURES):
            console.banner(
                "danger",
                "The analysis query didn't complete — the SQL warehouse was too slow to respond or "
                "the connection dropped (the client retried up to its timeout, then gave up rather "
                "than hang).\n"
                "  Try again once the warehouse is running/warmed up; lighten the query with a "
                "smaller --lookback-days or a higher --min-events; or point --warehouse-http-path at "
                "a larger warehouse. Nothing was written.",
            )
            raise typer.Exit(code=1) from None
        raise


def _run_ingress(cfg: IngressConfig, conn: Connection, yes: bool) -> None:
    from . import auth, sql
    from .core import ingress as ing
    from .core import ingress_rules as rules

    try:
        validate_apply(cfg.apply, cfg.policy_scope, other_direction="egress")
        validate_disable_ip_acls(cfg.disable_existing_ip_acls, cfg.apply.create_policy, cfg.apply.auto_assign)
        validate_policy_name(cfg.policy_name, cfg.policy_scope, cfg.apply.policy_action)
        validate_export(cfg.export, cfg.policy_scope)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from None

    console.title_panel(
        "Context-Based Ingress (CBI) Helper", "Propose a CBI allow-list from real audit-log source IPs."
    )
    wc = _confirm_workspace(conn, yes)
    # Point account-level calls at the account console matching the workspace's environment and pick
    # a matching account-admin profile + account_id, so a staging / GCP / Azure workspace doesn't
    # fall back to the AWS prod default or an ambient (wrong-tenant) credential.
    _resolve_account_host(conn, wc)
    _default_account_id_from_workspace(conn, wc)
    _resolve_policy_name(cfg, conn, wc, yes)
    render.ingress_decisions(cfg)
    if cfg.policy_scope != "per_workspace":
        _note_policy_name(cfg.policy_name)
    _confirm_params(yes)

    # Account-level work (apply, or identity scoping via SCIM) needs account-admin auth. Resolve it
    # ALL up front — account_id, a matching account-admin profile, and a built + verified account
    # client — right after params are confirmed and BEFORE the (potentially slow) analysis, feed
    # downloads, and RDAP lookups run. That way wrong-account / wrong-tenant / not-account-admin
    # credentials fail in seconds with a clear message, instead of after the whole analysis. The one
    # client is reused for both SCIM and the apply below.
    account = None
    this_ws = None
    if cfg.apply.create_policy or cfg.scope_identity:
        reason = "Creating a policy" if cfg.apply.create_policy else "Identity scoping (SCIM)"
        _ensure_account_id(conn, reason)
        _resolve_account_profile(conn)
        this_ws = auth.this_workspace_id(conn)
        account = _account_client_or_exit(conn, workspace_id=this_ws)

    http_path = sql.resolve_warehouse(conn)
    with sql.connection(conn, http_path) as sconn:
        analysis = _run_analysis(lambda: ing.analyze(cfg, sconn, wc, on_step=_step, status=console.status))

    render.ingress_analysis(analysis, cfg)
    _note_partner_platforms(analysis)
    _checkpoint(yes)
    # Auto-detect the workspace's IP access lists and confirm whether to migrate them into the policy.
    _reconcile_ip_acls(analysis, cfg, yes)
    # Read the workspace's front-end PrivateLink (AWS/GCP PAS) + existing assigned CBI policy, and
    # decide per dimension what the generated policy carries (migrate private from a PAS, carry
    # existing private/public/cross-workspace forward). Needs an account client → no-op without one.
    existing_ingress = _reconcile_existing_ingress(account, this_ws, wc, cfg, yes)
    # Optionally let the user cull the proposed allow rules before they're built (and before SCIM).
    # Snapshot the full observed-traffic suggestions first: if a policy-limit truncation makes the
    # user want to go back and re-pick, the selection screen can re-offer every rule (the picker
    # prunes the analysis in place) rather than only the already-narrowed subset.
    suggestions_full = analysis.suggestions.copy(deep=True)
    suggestion_rows_full = list(analysis.suggestion_rows)
    while True:
        _select_ingress_rules(analysis, cfg, yes)

        identity_resolution = None
        if cfg.scope_identity:
            with console.status("Resolving identities via account SCIM…"):
                identity_resolution = rules.resolve_identities(
                    analysis, account, note=lambda m: console.banner("info", m)
                )

        policies = rules.build_rules(
            analysis, cfg, identity_resolution, note=lambda m: console.banner("warn", m)
        )
        previews = rules.preview_blocks(policies, cfg, note=lambda m: console.banner("info", m))
        render.ingress_preview(previews, cfg, analysis)
        if previews:
            console.responsibility_warning("source IP addresses / CIDRs")
            _note_cross_workspace_compat(cfg)
        if _confirm_truncation(analysis.truncations, yes, allow_reselect=True):
            break
        # The user chose to go back: restore the full rule set and force the picker on for the retry.
        analysis.suggestions = suggestions_full.copy(deep=True)
        analysis.suggestion_rows = list(suggestion_rows_full)
        cfg.select_rules = True

    if cfg.export:
        if previews:
            payload = rules.export_payload(
                policies, cfg, conn.account_id or "", auth.this_workspace_id(conn), profile=conn.profile
            )
            _export_policy(cfg.export, payload, yes)
        else:
            console.banner("warn", "Nothing to export — the analysis produced no ingress rules.")

    if not cfg.apply.create_policy:
        console.banner("info", "Propose-only run (no --create-policy). Nothing was written.")
        return
    if not _has_rules(policies) and not (cfg.private_access or cfg.existing_public or cfg.existing_xws):
        console.banner(
            "danger",
            "Nothing to apply — the analysis produced no ingress rules, so no "
            "policy can be created. Review the candidate funnel above (try "
            "--lookback-days / --min-events / --include-account-level).",
        )
        raise typer.Exit(code=1)

    # account + this_ws were resolved and verified up front (the create-policy path guarantees it).
    # Pre-check the workspace we'd bind — but only when creating AND assigning a single new policy
    # (per_workspace fans out; add_to_existing targets a chosen policy on purpose).
    if (
        cfg.apply.auto_assign
        and cfg.apply.policy_action == "create_new"
        and cfg.policy_scope in ("current_workspace", "all_workspaces")
    ):
        new_id = rules._single_policy_id(cfg, conn.profile, this_ws)
        _ingress_preflight(
            account, this_ws, new_id, yes, existing=existing_ingress, migrating_public=_has_rules(policies)
        )

    # Guard against silently clobbering an existing policy's ingress rules — for every id apply()
    # would write (one for single-policy scopes, one per workspace target for per_workspace). Covers
    # create_new whose id happens to already exist and add_to_existing alike (apply_ingress replaces
    # the ingress block either way).
    for target_id in rules.planned_policy_ids(policies, cfg, conn.profile, this_ws):
        _confirm_overwrite_policy(account, target_id, "ingress", yes)

    if not _confirm_write(cfg.policy_mode, yes):
        console.banner("info", "Aborted — nothing written.")
        return

    with console.status("Applying policy…"):
        results = rules.apply(
            policies,
            cfg,
            account,
            conn.account_id,
            this_ws,
            profile=conn.profile,
            note=lambda m: console.banner("info", m),
        )
    render.apply_results(results, conn.account_host, conn.account_id)
    _maybe_disable_ip_acls(cfg.disable_existing_ip_acls, results, wc)


def _run_egress(cfg: EgressConfig, conn: Connection, yes: bool) -> None:
    from . import auth, sql
    from .core import egress as eg

    try:
        validate_apply(cfg.apply, cfg.policy_scope, other_direction="ingress")
        validate_policy_name(cfg.policy_name, cfg.policy_scope, cfg.apply.policy_action)
        validate_export(cfg.export, cfg.policy_scope)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from None

    console.title_panel(
        "Egress Policy Helper (serverless egress / SEG)",
        "Propose an egress allow-list from observed outbound traffic.",
    )
    wc = _confirm_workspace(conn, yes)
    # Point account-level calls at the account console matching the workspace's environment and pick
    # a matching account-admin profile + account_id (see _run_ingress).
    _resolve_account_host(conn, wc)
    _default_account_id_from_workspace(conn, wc)
    _resolve_policy_name(cfg, conn, wc, yes)
    render.egress_decisions(cfg)
    if cfg.policy_scope != "per_workspace":
        _note_policy_name(cfg.policy_name)
    _confirm_params(yes)

    # Resolve account-admin auth ALL up front when we'll create a policy — account_id, a matching
    # account-admin profile, and a built + verified account client — BEFORE the (potentially slow)
    # analysis runs, so wrong-account / wrong-tenant / not-account-admin credentials fail in seconds
    # with a clear message rather than after the whole analysis. Reused for the preflight + apply.
    account = None
    if cfg.apply.create_policy:
        _ensure_account_id(conn, "Creating a policy")
        _resolve_account_profile(conn)

    # current_workspace scope needs this workspace's id to both filter analysis and name the policy.
    this_ws = auth.this_workspace_id(conn) if cfg.policy_scope == "current_workspace" else None

    # The workspace we'd probe/bind is always "this" workspace, independent of the analysis scope.
    apply_ws = None
    if cfg.apply.create_policy:
        apply_ws = this_ws if this_ws is not None else auth.this_workspace_id(conn)
        account = _account_client_or_exit(conn, workspace_id=apply_ws)

    # The workspace's cloud gates which storage-destination type the egress policy can carry (the API
    # rejects cross-cloud storage, e.g. Azure storage on an AWS workspace) — derive it from the host.
    ws_cloud = eg.workspace_cloud_from_host(getattr(getattr(wc, "config", None), "host", None))

    http_path = sql.resolve_warehouse(conn)
    with sql.connection(conn, http_path) as sconn:
        analysis = _run_analysis(
            lambda: eg.analyze(
                cfg,
                sconn,
                on_step=_step,
                this_workspace_id=this_ws,
                workspace_cloud=ws_cloud,
                status=console.status,
            )
        )

    render.egress_analysis(analysis)
    _checkpoint(yes)
    # Optionally let the user cull the observed destinations before the policy is built/previewed.
    _select_egress_rules(analysis, cfg, yes)
    previews = eg.preview_blocks(analysis, cfg, note=lambda m: console.banner("warn", m))
    render.egress_preview(previews, cfg)
    if previews:
        console.responsibility_warning("FQDNs and storage destinations")
    _confirm_truncation(analysis.truncations, yes)

    if cfg.export:
        if previews:
            # this_ws is set for current_workspace (the only scope whose name uses it); None otherwise.
            payload = eg.export_payload(analysis, cfg, conn.account_id or "", this_ws, profile=conn.profile)
            _export_policy(cfg.export, payload, yes)
        else:
            console.banner("warn", "Nothing to export — no egress destinations were classified.")

    if not cfg.apply.create_policy:
        console.banner("info", "Propose-only run (no --create-policy). Nothing was written.")
        return
    if not previews:
        console.banner(
            "danger",
            "Nothing to apply — no egress destinations were classified, so no "
            "policy can be created. Confirm outbound_network has data for this "
            "window (stand up a dry_run egress policy first to populate it).",
        )
        raise typer.Exit(code=1)

    # account + apply_ws were resolved and verified up front (the create-policy path guarantees it).
    # Pre-check the workspace we'd bind — but only when creating AND assigning a single new policy
    # (per_workspace fans out; add_to_existing targets a chosen policy on purpose).
    if (
        cfg.apply.auto_assign
        and cfg.apply.policy_action == "create_new"
        and cfg.policy_scope in ("current_workspace", "all_workspaces")
    ):
        new_id = eg._single_policy_id(cfg, conn.profile, apply_ws)
        _egress_preflight(account, apply_ws, new_id, yes)

    # Guard against silently clobbering an existing policy's egress rules — for every id apply()
    # would write (one for single-policy scopes, one per workspace target for per_workspace). Covers
    # create_new whose id happens to already exist and add_to_existing alike (apply_egress replaces
    # the egress block either way). `previews` keys are the targets that actually get a policy.
    for target_id in eg.planned_policy_ids(previews, cfg, conn.profile, apply_ws):
        _confirm_overwrite_policy(account, target_id, "egress", yes)

    if not _confirm_write(cfg.policy_mode, yes):
        console.banner("info", "Aborted — nothing written.")
        return

    with console.status("Applying egress policy…"):
        results = eg.apply(
            analysis,
            cfg,
            account,
            conn.account_id,
            apply_ws,
            profile=conn.profile,
            note=lambda m: console.banner("info", m),
        )
    render.apply_results(results, conn.account_host, conn.account_id)


if __name__ == "__main__":
    app()
