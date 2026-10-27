"""Tests for the apply-time empty guards — a run that produces no rules must fail with a clear
message and a non-zero exit, not crash with a KeyError."""

from __future__ import annotations

import types

import pandas as pd
import pytest
from typer.testing import CliRunner

from dbx_nwp_helper import cli
from dbx_nwp_helper.core.ingress import IngressAnalysis

runner = CliRunner()


def _plain(text: str) -> str:
    """Strip ANSI escape codes so substring assertions hold regardless of whether the runtime emitted
    colour. GitHub Actions forces colour on, and Rich styles option tokens as separate coloured spans
    (`--policy-name` -> `-` `-policy` `-name`), which otherwise splits substrings with escape
    sequences; a local non-TTY run emits no colour, so the same assertion passes there but not in CI."""
    import re

    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def test_resolve_profile_passthrough():
    assert cli._resolve_profile("myprofile") == "myprofile"


def test_resolve_profile_respects_env_auth(monkeypatch):
    monkeypatch.setenv("DATABRICKS_HOST", "https://x.cloud.databricks.com")
    assert cli._resolve_profile(None) is None


def test_resolve_profile_none_and_no_profiles_errors(monkeypatch):
    import typer

    monkeypatch.delenv("DATABRICKS_HOST", raising=False)
    monkeypatch.setattr(cli, "_available_profiles", lambda: [])
    with pytest.raises(typer.BadParameter):
        cli._resolve_profile(None)


def test_resolve_profile_none_noninteractive_errors(monkeypatch):
    import typer

    monkeypatch.delenv("DATABRICKS_HOST", raising=False)
    monkeypatch.setattr(cli, "_available_profiles", lambda: ["a", "b"])
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    with pytest.raises(typer.BadParameter):
        cli._resolve_profile(None)


def test_confirm_params_yes_skips(monkeypatch):
    # --yes must not prompt and must not raise.
    called = {"n": 0}
    monkeypatch.setattr("typer.confirm", lambda *a, **k: called.__setitem__("n", called["n"] + 1))
    cli._confirm_params(yes=True)
    assert called["n"] == 0


def test_confirm_params_noninteractive_skips(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setattr(
        "typer.confirm",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt non-interactively")),
    )
    cli._confirm_params(yes=False)


def test_confirm_params_decline_aborts(monkeypatch):
    import typer

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: False)
    with pytest.raises(typer.Exit) as exc:
        cli._confirm_params(yes=False)
    assert exc.value.exit_code == 0  # user chose to abort — a clean exit, not an error


def test_confirm_params_accept_proceeds(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: True)
    cli._confirm_params(yes=False)  # must not raise


def test_checkpoint_yes_skips_prompt(monkeypatch):
    monkeypatch.setattr(
        "typer.confirm", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt with --yes"))
    )
    cli._checkpoint(yes=True)  # must not raise


def test_checkpoint_noninteractive_skips_prompt(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setattr(
        "typer.confirm",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt non-interactively")),
    )
    cli._checkpoint(yes=False)  # must not raise


def test_checkpoint_continue_proceeds(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: True)
    cli._checkpoint(yes=False)  # must not raise


def test_checkpoint_decline_aborts_cleanly(monkeypatch):
    import typer

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: False)
    with pytest.raises(typer.Exit) as exc:
        cli._checkpoint(yes=False)
    assert exc.value.exit_code == 0  # 'n' -> clean abort


def test_confirm_truncation_no_truncations_is_noop(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(
        "typer.confirm", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt"))
    )
    cli._confirm_truncation([], yes=False)  # nothing truncated -> no prompt, no raise


def test_confirm_truncation_yes_skips_prompt(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(
        "typer.confirm", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt with --yes"))
    )
    cli._confirm_truncation(["capped 60 rules -> 50"], yes=True)  # must not raise


def test_confirm_truncation_noninteractive_skips_prompt(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setattr(
        "typer.confirm", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt scripted"))
    )
    cli._confirm_truncation(["capped 60 rules -> 50"], yes=False)  # must not raise


def test_confirm_truncation_decline_aborts_cleanly(monkeypatch):
    import typer

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: False)
    with pytest.raises(typer.Exit) as exc:
        cli._confirm_truncation(["capped 60 rules -> 50"], yes=False)
    assert exc.value.exit_code == 0  # 'n' -> clean abort


def test_confirm_truncation_accept_proceeds(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: True)
    assert cli._confirm_truncation(["capped 60 rules -> 50"], yes=False) is True  # continue


def test_confirm_truncation_reselect_returns_false(monkeypatch):
    import questionary

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: False)  # decline "continue?"
    monkeypatch.setattr(questionary, "select", lambda *a, **k: types.SimpleNamespace(ask=lambda: "reselect"))
    # allow_reselect + "go back" -> return False (caller loops back to selection), no raise
    assert cli._confirm_truncation(["capped"], yes=False, allow_reselect=True) is False


def test_confirm_truncation_reselect_abort_exits(monkeypatch):
    import questionary
    import typer

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: False)  # decline "continue?"
    monkeypatch.setattr(questionary, "select", lambda *a, **k: types.SimpleNamespace(ask=lambda: "abort"))
    with pytest.raises(typer.Exit) as exc:
        cli._confirm_truncation(["capped"], yes=False, allow_reselect=True)
    assert exc.value.exit_code == 0  # abort -> clean exit


class _PolicyAcct:
    """Fake account whose get_network_policy_rpc returns `pol`, or raises NotFound if pol is None."""

    def __init__(self, pol):
        from databricks.sdk.errors import NotFound

        class _NP:
            def get_network_policy_rpc(self, network_policy_id):
                if pol is None:
                    raise NotFound("no such policy")
                return pol

        self.network_policies = _NP()


def _policy_with_ingress():
    from dbx_nwp_helper.core import policy

    return types.SimpleNamespace(
        ingress=policy.build_ingress_block([_allow_spec()], []),
        ingress_dry_run=None,
    )


def _allow_spec():
    return {
        "label": "r",
        "cidrs": ["1.2.3.4/32"],
        "destination": "all_destinations",
        "identity_type": "ALL_USERS",
        "identities": [],
    }


def test_confirm_overwrite_missing_policy_is_noop(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(
        "typer.confirm", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt"))
    )
    cli._confirm_overwrite_policy(_PolicyAcct(None), "p", "ingress", yes=False)  # NotFound -> no raise


def test_confirm_overwrite_permissive_policy_is_noop(monkeypatch):
    from dbx_nwp_helper.core import policy

    permissive = types.SimpleNamespace(ingress=policy.build_full_access_ingress(), ingress_dry_run=None)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(
        "typer.confirm", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt"))
    )
    cli._confirm_overwrite_policy(_PolicyAcct(permissive), "p", "ingress", yes=False)  # empty -> no raise


def test_confirm_overwrite_populated_yes_skips_prompt(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(
        "typer.confirm", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt with --yes"))
    )
    cli._confirm_overwrite_policy(_PolicyAcct(_policy_with_ingress()), "p", "ingress", yes=True)


def test_confirm_overwrite_populated_noninteractive_skips_prompt(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    monkeypatch.setattr(
        "typer.confirm", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt scripted"))
    )
    cli._confirm_overwrite_policy(_PolicyAcct(_policy_with_ingress()), "p", "ingress", yes=False)


def test_confirm_overwrite_populated_decline_aborts(monkeypatch):
    import typer

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: False)
    with pytest.raises(typer.Exit) as exc:
        cli._confirm_overwrite_policy(_PolicyAcct(_policy_with_ingress()), "p", "ingress", yes=False)
    assert exc.value.exit_code == 0


def test_confirm_overwrite_populated_accept_proceeds(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: True)
    cli._confirm_overwrite_policy(_PolicyAcct(_policy_with_ingress()), "p", "ingress", yes=False)


def test_run_analysis_returns_value_on_success():
    assert cli._run_analysis(lambda: "ok") == "ok"


def test_run_analysis_handles_inet_unsupported(capsys):
    import typer

    def boom():
        raise RuntimeError("[INET_FUNCTIONS_NOT_ENABLED] ip_cidr_contains is disabled or unsupported.")

    with pytest.raises(typer.Exit) as exc:
        cli._run_analysis(boom)
    assert exc.value.exit_code == 1
    assert "preview" in _plain(capsys.readouterr().out).lower()


def test_run_analysis_handles_missing_outbound_network_table(capsys):
    import typer

    # The reported failure: egress source system table absent on the workspace.
    def boom():
        raise RuntimeError(
            "[TABLE_OR_VIEW_NOT_FOUND] The table or view `system`.`access`.`outbound_network` "
            "cannot be found. Verify the spelling and correctness of the schema and catalog. "
            "SQLSTATE: 42P01; line 12 pos 9"
        )

    with pytest.raises(typer.Exit) as exc:
        cli._run_analysis(boom)
    assert exc.value.exit_code == 1
    out = _plain(capsys.readouterr().out)
    assert "system.access.outbound_network" in out
    assert "serverless egress" in out.lower()
    assert "Traceback" not in out


def test_run_analysis_handles_missing_audit_table(capsys):
    import typer

    def boom():
        raise RuntimeError(
            "[TABLE_OR_VIEW_NOT_FOUND] The table or view `system`.`access`.`audit` cannot be found. "
            "SQLSTATE: 42P01"
        )

    with pytest.raises(typer.Exit) as exc:
        cli._run_analysis(boom)
    assert exc.value.exit_code == 1
    out = _plain(capsys.readouterr().out)
    assert "system.access.audit" in out
    assert "system schema" in out.lower()


def test_run_analysis_missing_table_generic_fallback(capsys):
    import typer

    # Unparseable table name -> generic enablement guidance, still no traceback.
    def boom():
        raise RuntimeError("[TABLE_OR_VIEW_NOT_FOUND] something is missing. SQLSTATE: 42P01")

    with pytest.raises(typer.Exit) as exc:
        cli._run_analysis(boom)
    assert exc.value.exit_code == 1
    out = _plain(capsys.readouterr().out)
    assert "system schema" in out.lower()


def test_run_analysis_handles_warehouse_timeout(capsys):
    import typer

    # the reported failure: the databricks-sql connector exhausts its retry budget and raises
    def boom():
        raise RuntimeError(
            "Error during request to server. Retry request would exceed Retry policy max retry "
            "duration of 900.0 seconds"
        )

    with pytest.raises(typer.Exit) as exc:
        cli._run_analysis(boom)
    assert exc.value.exit_code == 1
    out = _plain(capsys.readouterr().out)
    assert "didn't complete" in out and "warehouse" in out


def test_run_analysis_reraises_unknown_errors():
    # an error we don't recognise must NOT be swallowed — it propagates unchanged
    def boom():
        raise ValueError("something unexpected")

    with pytest.raises(ValueError, match="something unexpected"):
        cli._run_analysis(boom)


def test_select_ingress_rules_filters_to_kept(monkeypatch):
    from dbx_nwp_helper.config import IngressConfig

    rows = [
        {
            "policy_target": "__ALL__",
            "rdap_owner": "Acme",
            "databricks_owned": [],
            "threat_feeds": [],
            "recommendation": "REVIEW",
            "minimal_cidrs": ["1.1.1.1/32"],
        },
        {
            "policy_target": "__ALL__",
            "rdap_owner": "Beta",
            "databricks_owned": [],
            "threat_feeds": [],
            "recommendation": "REVIEW",
            "minimal_cidrs": ["2.2.2.2/32"],
        },
        {
            "policy_target": "__ALL__",
            "rdap_owner": "Bad",
            "databricks_owned": [],
            "threat_feeds": ["ipsum"],
            "recommendation": "REVIEW",
            "minimal_cidrs": ["9.9.9.9/32"],
        },
    ]
    analysis = type("A", (), {})()
    analysis.suggestion_rows = [dict(r) for r in rows]
    analysis.suggestions = pd.DataFrame(rows)
    monkeypatch.setattr(cli, "_interactive", lambda yes: True)
    monkeypatch.setattr(cli, "_checkbox_keep", lambda title, choices: [("__ALL__", "Acme")])  # keep only Acme

    cli._select_ingress_rules(analysis, IngressConfig(select_rules=True, policy_framing="minimal"), yes=False)

    owners = set(analysis.suggestions["rdap_owner"])
    assert "Acme" in owners  # kept
    assert "Beta" not in owners  # deselected -> dropped
    assert "Bad" in owners  # threat row wasn't offered, so retained untouched
    keys = {(r["policy_target"], r["rdap_owner"]) for r in analysis.suggestion_rows}
    assert ("__ALL__", "Beta") not in keys


def test_select_ingress_rules_noop_without_flag(monkeypatch):
    from dbx_nwp_helper.config import IngressConfig

    analysis = type("A", (), {})()
    analysis.suggestion_rows = [
        {
            "policy_target": "__ALL__",
            "rdap_owner": "Acme",
            "databricks_owned": [],
            "threat_feeds": [],
            "recommendation": "R",
            "minimal_cidrs": ["1.1.1.1/32"],
        }
    ]
    analysis.suggestions = pd.DataFrame(analysis.suggestion_rows)
    monkeypatch.setattr(cli, "_interactive", lambda yes: True)
    called = []
    monkeypatch.setattr(cli, "_checkbox_keep", lambda t, c: called.append(1) or [])
    cli._select_ingress_rules(analysis, IngressConfig(select_rules=False), yes=False)  # flag off
    assert called == []  # never prompted


def test_select_egress_rules_filters_targets(monkeypatch):
    from dbx_nwp_helper.config import EgressConfig
    from dbx_nwp_helper.core import egress as eg

    a = eg.EgressAnalysis(
        observed=pd.DataFrame(),
        targets={
            eg.ALL_WORKSPACES: {"s3": {}, "gcs": {}, "azure": {}, "internet": {"keep.com": 5, "drop.com": 3}}
        },
    )
    a.fqdn_owner = {"keep.com": "X", "drop.com": "Y"}
    monkeypatch.setattr(cli, "_interactive", lambda yes: True)
    monkeypatch.setattr(cli, "_checkbox_keep", lambda t, c: [("internet", "keep.com")])
    cli._select_egress_rules(a, EgressConfig(select_rules=True), yes=False)
    assert eg.union(a.targets, "internet") == {"keep.com": 5}


def test_select_egress_rules_splits_fqdn_and_storage_prompts(monkeypatch):
    from dbx_nwp_helper.config import EgressConfig
    from dbx_nwp_helper.core import egress as eg

    a = eg.EgressAnalysis(
        observed=pd.DataFrame(),
        targets={
            eg.ALL_WORKSPACES: {
                "s3": {("my-bucket", "us-east-1"): 5},
                "gcs": {},
                "azure": {("acct1", "blob"): 3},
                "internet": {"api.openai.com": 10},
            }
        },
    )
    a.fqdn_owner = {}
    prompts = []  # (title, [choice titles]) per checkbox shown

    def capture(title, choices):
        prompts.append((title, [getattr(c, "title", "") for c in choices]))
        # keep only the internet FQDNs in each prompt (so the storage prompt deselects everything)
        return [c.value for c in choices if getattr(c, "value", (None,))[0] == "internet"]

    monkeypatch.setattr(cli, "_interactive", lambda yes: True)
    monkeypatch.setattr(cli, "_checkbox_keep", capture)
    cli._select_egress_rules(a, EgressConfig(select_rules=True), yes=False)

    # two distinct prompts: one for FQDNs, one for storage
    assert len(prompts) == 2
    fqdn_prompt, storage_prompt = prompts
    assert "FQDN" in fqdn_prompt[0] and any("api.openai.com" in t for t in fqdn_prompt[1])
    assert "storage" in storage_prompt[0]
    assert any("S3  my-bucket" in t for t in storage_prompt[1])
    assert any("Azure  acct1.blob" in t for t in storage_prompt[1])
    # deselecting the storage entries removes them; the FQDN is kept
    assert eg.union(a.targets, "s3") == {} and eg.union(a.targets, "azure") == {}
    assert eg.union(a.targets, "internet") == {"api.openai.com": 10}


def test_select_rules_noop_non_interactive(monkeypatch):
    # even with the flag on, a non-interactive session (no TTY) must not prompt
    from dbx_nwp_helper.config import IngressConfig

    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    called = []
    monkeypatch.setattr(cli, "_checkbox_keep", lambda t, c: called.append(1) or [])
    analysis = type("A", (), {})()
    analysis.suggestion_rows = []
    cli._select_ingress_rules(analysis, IngressConfig(select_rules=True), yes=False)
    assert called == []


def test_confirm_write_yes_proceeds():
    assert cli._confirm_write("dry_run", yes=True) is True


def test_confirm_write_interactive_decline(monkeypatch):
    monkeypatch.setattr("typer.confirm", lambda *a, **k: False)
    assert cli._confirm_write("enforce", yes=False) is False


def test_responsibility_warning_shown(capsys):
    from dbx_nwp_helper import console

    console.responsibility_warning("source IP addresses / CIDRs")
    out = capsys.readouterr().out
    assert "responsib" in out.lower()
    assert "security-enforcing" in out.lower()
    # mentions the reuse-the-JSON case, not just create-here
    assert "copy this JSON" in out or "copy" in out.lower()


def test_ensure_account_id_passthrough_when_set():
    from dbx_nwp_helper.config import Connection

    conn = Connection(account_id="already-set")
    cli._ensure_account_id(conn, "Creating a policy")  # no prompt, no raise
    assert conn.account_id == "already-set"


def test_ensure_account_id_noninteractive_errors(monkeypatch):
    import typer

    from dbx_nwp_helper.config import Connection

    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    with pytest.raises(typer.BadParameter):
        cli._ensure_account_id(Connection(account_id=""), "Creating a policy")


def test_ensure_account_id_prompts_interactive(monkeypatch):
    from dbx_nwp_helper.config import Connection

    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    class _Q:
        def ask(self):
            return "  1234567890  "

    monkeypatch.setattr("questionary.text", lambda *a, **k: _Q())
    conn = Connection(account_id="")
    cli._ensure_account_id(conn, "Creating a policy")
    assert conn.account_id == "1234567890"


def test_maybe_disable_ip_acls_noop_when_flag_false():
    class _WS:
        @property
        def workspace_conf(self):
            raise AssertionError("must not touch the workspace when the flag is off")

    cli._maybe_disable_ip_acls(False, [{"assigned": 42}], _WS())  # must not raise


def test_maybe_disable_ip_acls_skips_when_nothing_assigned():
    # apply errored / assigned nothing -> we must NOT strip the workspace's IP-ACL protection.
    class _WS:
        @property
        def workspace_conf(self):
            raise AssertionError("must not disable ACLs when no policy was assigned")

    cli._maybe_disable_ip_acls(True, [{"target": "x", "error": "boom"}], _WS())  # must not raise


def test_maybe_disable_ip_acls_runs_when_assigned():
    seen = {}

    class _Conf:
        def get_status(self, keys):
            return {"enableIpAccessLists": "true"}

        def set_status(self, contents):
            seen["set"] = contents

    class _WS:
        workspace_conf = _Conf()

    cli._maybe_disable_ip_acls(True, [{"assigned": 42, "policy_id": "p"}], _WS())
    assert seen["set"] == {"enableIpAccessLists": "false"}


def test_maybe_disable_ip_acls_warns_on_sdk_failure(capsys):
    # if disabling raises (e.g. no workspace-admin rights), the run must NOT crash — the policy is
    # already applied and assigned, so we warn and continue.
    class _Conf:
        def get_status(self, keys):
            raise RuntimeError("permission denied")

    class _WS:
        workspace_conf = _Conf()

    cli._maybe_disable_ip_acls(True, [{"assigned": 42, "policy_id": "p"}], _WS())  # must not raise
    out = capsys.readouterr().out
    assert "manually" in out.lower()


class _FakeWsClient:
    class _Cfg:
        host = "https://ws.cloud.databricks.com"

    config = _Cfg()

    def get_workspace_id(self):
        return 12345


def test_confirm_workspace_yes_displays_and_does_not_prompt(monkeypatch, capsys):
    import dbx_nwp_helper.auth as auth
    from dbx_nwp_helper.config import Connection

    monkeypatch.setattr(auth, "workspace_client", lambda conn: _FakeWsClient())
    monkeypatch.setattr(
        "typer.confirm", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not prompt with --yes"))
    )
    wc = cli._confirm_workspace(Connection(profile="myprof"), yes=True)
    assert isinstance(wc, _FakeWsClient)
    out = capsys.readouterr().out
    # the panel must surface all three so the target is unmistakable
    assert "12345" in out and "ws.cloud.databricks.com" in out and "myprof" in out


def test_confirm_workspace_decline_aborts(monkeypatch):
    import typer

    import dbx_nwp_helper.auth as auth
    from dbx_nwp_helper.config import Connection

    monkeypatch.setattr(auth, "workspace_client", lambda conn: _FakeWsClient())
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("typer.confirm", lambda *a, **k: False)
    with pytest.raises(typer.Exit) as exc:
        cli._confirm_workspace(Connection(profile="p"), yes=False)
    assert exc.value.exit_code == 0  # declining the wrong workspace is a clean abort


def test_confirm_workspace_bad_profile_exits_cleanly(monkeypatch, capsys):
    # A mistyped --profile must produce a clean, actionable message (not a raw SDK traceback).
    import typer

    import dbx_nwp_helper.auth as auth
    from dbx_nwp_helper.config import Connection

    monkeypatch.setattr(
        auth,
        "workspace_client",
        lambda conn: (_ for _ in ()).throw(
            ValueError("resolve: /Users/x/.databrickscfg has no acme-ws profile configured")
        ),
    )
    monkeypatch.setattr(cli, "_available_profiles", lambda: ["acme-dev", "acme-prod"])
    with pytest.raises(typer.Exit) as exc:
        cli._confirm_workspace(Connection(profile="acme-ws"), yes=True)
    assert exc.value.exit_code == 1
    out = capsys.readouterr().out
    assert "acme-ws" in out and "acme-dev" in out  # names the bad profile + lists available


def test_account_client_bad_profile_exits_cleanly(monkeypatch, capsys):
    import typer

    import dbx_nwp_helper.auth as auth
    from dbx_nwp_helper.config import Connection

    monkeypatch.setattr(
        auth,
        "account_client",
        lambda conn: (_ for _ in ()).throw(
            ValueError("resolve: /Users/x/.databrickscfg has no acct profile configured")
        ),
    )
    monkeypatch.setattr(cli, "_available_profiles", lambda: ["acct-admin"])
    with pytest.raises(typer.Exit) as exc:
        cli._account_client_or_exit(Connection(account_profile="acct"))
    assert exc.value.exit_code == 1
    out = capsys.readouterr().out
    assert "--account-profile" in out and "acct" in out


def test_workspace_client_other_valueerror_still_clean(monkeypatch, capsys):
    # A non-profile config error should also exit cleanly rather than traceback.
    import typer

    import dbx_nwp_helper.auth as auth
    from dbx_nwp_helper.config import Connection

    monkeypatch.setattr(
        auth,
        "workspace_client",
        lambda conn: (_ for _ in ()).throw(ValueError("default auth: cannot configure default credentials")),
    )
    with pytest.raises(typer.Exit) as exc:
        cli._confirm_workspace(Connection(profile=None), yes=True)
    assert exc.value.exit_code == 1
    assert "Databricks client" in capsys.readouterr().out


def test_note_policy_name_shows_normalized_id(capsys):
    cli._note_policy_name("My Policy")
    assert "my-policy" in capsys.readouterr().out


def test_note_policy_name_silent_when_clean_or_blank(capsys):
    cli._note_policy_name("clean-name")  # already normalised -> no notice
    cli._note_policy_name("")  # not set -> no notice
    assert capsys.readouterr().out == ""


def test_resolve_policy_name_skips_add_to_existing():
    # add_to_existing takes its id from --existing-policy-id, so no name is resolved.
    from dbx_nwp_helper.config import Connection, IngressConfig

    cfg = IngressConfig()
    cfg.apply.policy_action = "add_to_existing"
    cli._resolve_policy_name(cfg, Connection(profile="myprof"), object(), yes=True)
    assert cfg.policy_name == ""


def test_resolve_policy_name_ingress_defaults_to_profile():
    from dbx_nwp_helper.config import Connection, IngressConfig

    class _WC:
        def get_workspace_id(self):
            return 7

    cfg = IngressConfig(policy_scope="per_workspace")
    cli._resolve_policy_name(cfg, Connection(profile="egress-prof"), _WC(), yes=True)
    assert cfg.policy_name == "egress-prof"  # per_workspace uses it as the prefix


def test_write_tf_export_into_directory(tmp_path):
    payload = {"network_policy_id": "pol-x", "ingress": {"public_access": {"restriction_mode": "X"}}}
    dest = cli._write_tf_export(str(tmp_path), payload)
    assert dest.endswith("pol-x.tf")
    assert 'resource "databricks_account_network_policy" "pol_x"' in (
        (tmp_path / "pol-x.tf").read_text(encoding="utf-8")
    )


def test_export_writes_utf8_non_ascii_labels(tmp_path):
    # A non-ASCII rule label must write cleanly on any platform — Windows' default cp1252 would
    # otherwise raise UnicodeEncodeError, so both writers pin UTF-8.
    import json
    from pathlib import Path

    payload = {
        "network_policy_id": "pol",
        "ingress": {
            "public_access": {
                "restriction_mode": "RESTRICTED_ACCESS",
                "allow_rules": [{"label": "café-café", "destination": {"all_destinations": True}}],
            }
        },
    }
    tf = cli._write_tf_export(str(tmp_path), payload)
    js = cli._write_json_export(str(tmp_path), payload)
    assert "café-café" in Path(tf).read_text(encoding="utf-8")
    loaded = json.loads(Path(js).read_text(encoding="utf-8"))
    assert loaded["ingress"]["public_access"]["allow_rules"][0]["label"] == "café-café"


def test_write_json_export_to_directory_uses_policy_id_filename(tmp_path):
    import json
    from pathlib import Path

    dest = cli._write_json_export(str(tmp_path), {"network_policy_id": "my-acl", "egress": {}})
    assert dest == str(tmp_path / "my-acl.json")
    assert json.loads(Path(dest).read_text())["network_policy_id"] == "my-acl"


def test_write_json_export_creates_missing_parent_dirs(tmp_path):
    from pathlib import Path

    target = tmp_path / "nested" / "sub" / "policy.json"
    dest = cli._write_json_export(str(target), {"network_policy_id": "p"})
    assert dest == str(target) and Path(target).exists()


def test_write_json_export_bad_path_errors_cleanly(tmp_path):
    import typer

    # a path whose parent is a *file* can't be created -> clean Exit, not a traceback
    afile = tmp_path / "afile"
    afile.write_text("x")
    with pytest.raises(typer.Exit) as e:
        cli._write_json_export(str(afile / "policy.json"), {"network_policy_id": "p"})
    assert e.value.exit_code == 1


def test_confirm_overwrite_new_file_always_writes(tmp_path):
    # a path that doesn't exist yet never prompts
    assert cli._confirm_overwrite(tmp_path / "new.json", yes=False) is True


def test_confirm_overwrite_existing_kept_when_declined(monkeypatch, tmp_path):
    import typer

    existing = tmp_path / "policy.json"
    existing.write_text("old")
    # simulate an interactive terminal where the user declines the overwrite
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr(typer, "confirm", lambda *a, **k: False)
    assert cli._confirm_overwrite(existing, yes=False) is False
    # ...and --yes overwrites without prompting even when the file exists
    assert cli._confirm_overwrite(existing, yes=True) is True


def test_write_json_export_keeps_existing_when_declined(monkeypatch, tmp_path):
    import json

    dest = tmp_path / "my-acl.json"
    dest.write_text('{"network_policy_id": "OLD"}')
    monkeypatch.setattr(cli, "_confirm_overwrite", lambda d, yes: False)
    # a declined overwrite returns None and leaves the original file untouched
    assert cli._write_json_export(str(tmp_path), {"network_policy_id": "my-acl", "egress": {}}) is None
    assert json.loads(dest.read_text())["network_policy_id"] == "OLD"


def test_export_policy_overwrites_with_yes(tmp_path):
    import json

    # first write, then a second --yes write must overwrite both files silently
    payload_v1 = {"network_policy_id": "pol", "egress": {}}
    payload_v2 = {"network_policy_id": "pol", "egress": {"changed": True}}
    cli._export_policy(str(tmp_path), payload_v1, yes=True)
    cli._export_policy(str(tmp_path), payload_v2, yes=True)
    assert json.loads((tmp_path / "pol.json").read_text())["egress"] == {"changed": True}


def _fake_pol(ingress=None, dry=None, egress=None):
    return type("P", (), {"ingress": ingress, "ingress_dry_run": dry, "egress": egress})()


# existing = (existing_public, existing_private, migrating_restrictive_private, assigned_id)
def _existing(public=None, private=None, migrating_private=False, assigned_id="p1"):
    return (public, private, migrating_private, assigned_id)


def test_ingress_preflight_aborts_when_migrating_public_over_restrictive_public():
    import typer

    existing = _existing(public=object())  # assigned policy has a restrictive public block
    with pytest.raises(typer.Exit) as e:
        cli._ingress_preflight(object(), 42, "p1", yes=True, existing=existing, migrating_public=True)
    assert e.value.exit_code == 1


def test_ingress_preflight_no_public_abort_when_not_migrating_public():
    # existing restrictive public present but we're NOT migrating public (nothing to build) → it's
    # preserved, not clobbered, so no abort.
    existing = _existing(public=object())
    cli._ingress_preflight(object(), 42, "p1", yes=True, existing=existing, migrating_public=False)


def test_ingress_preflight_aborts_when_migrating_restrictive_private_over_existing_private():
    import typer

    existing = _existing(private=object(), migrating_private=True)
    with pytest.raises(typer.Exit) as e:
        cli._ingress_preflight(object(), 42, "p1", yes=True, existing=existing, migrating_public=False)
    assert e.value.exit_code == 1


def test_ingress_preflight_no_private_abort_when_not_migrating_restrictive_private():
    # existing restrictive private present, but we're not migrating a non-allow-all PAS (it's carried
    # forward instead) → no abort.
    existing = _existing(private=object(), migrating_private=False)
    cli._ingress_preflight(object(), 42, "p1", yes=True, existing=existing, migrating_public=True)


def test_ingress_preflight_proceeds_when_clean():
    cli._ingress_preflight(
        object(), 42, "new-id", yes=True, existing=_existing(), migrating_public=True
    )  # must not raise


def _wc(host):
    return type("WC", (), {"config": type("C", (), {"host": host})()})()


def _fake_pas(level, ids=None, name=None, pid="pas-1"):
    return type(
        "PAS",
        (),
        {
            "private_access_settings_id": pid,
            "private_access_settings_name": name,
            "private_access_level": type("E", (), {"value": level})(),
            "allowed_vpc_endpoint_ids": ids,
        },
    )()


def test_reconcile_existing_ingress_migrates_endpoint_pas(monkeypatch):
    from dbx_nwp_helper.config import IngressConfig

    monkeypatch.setattr(
        "dbx_nwp_helper.core.acl.read_workspace_pas",
        lambda a, w: (_fake_pas("ENDPOINT", ids=["vpce-a"], name="prod"), "ok"),
    )
    monkeypatch.setattr("dbx_nwp_helper.core.acl.existing_cbi_ingress", lambda a, w: ("p1", None, None, None))
    cfg = IngressConfig()
    ex_pub, ex_priv, migrating_private, _id = cli._reconcile_existing_ingress(
        object(), 42, _wc("https://dbc-x.cloud.databricks.com"), cfg, yes=True
    )
    assert migrating_private is True  # non-allow-all PAS
    assert cfg.private_access.as_dict()["restriction_mode"] == "RESTRICTED_ACCESS"


def test_reconcile_existing_ingress_allow_all_pas_does_not_loosen_restrictive_existing(monkeypatch):
    # allow-all PAS + existing restrictive CBI private → keep the stricter existing private block.
    from dbx_nwp_helper.config import IngressConfig
    from dbx_nwp_helper.core import policy

    existing_priv = policy.build_private_access_block("RESTRICTED_ACCESS", ["vpce-existing"])
    monkeypatch.setattr(
        "dbx_nwp_helper.core.acl.read_workspace_pas", lambda a, w: (_fake_pas("ACCOUNT"), "ok")
    )
    monkeypatch.setattr(
        "dbx_nwp_helper.core.acl.existing_cbi_ingress", lambda a, w: ("p1", None, existing_priv, None)
    )
    cfg = IngressConfig()
    _pub, _priv, migrating_private, _id = cli._reconcile_existing_ingress(
        object(), 42, _wc("https://x.gcp.databricks.com"), cfg, yes=True
    )
    assert migrating_private is False
    assert cfg.private_access is existing_priv  # stricter existing kept, not loosened to allow-all


def test_reconcile_existing_ingress_azure_skips_pas_but_copies_forward(monkeypatch):
    # Azure: never reads a PAS, but carries existing private + cross-workspace forward.
    from dbx_nwp_helper.config import IngressConfig

    seen = {"pas_read": False}

    def _read(a, w):
        seen["pas_read"] = True
        return None, "none"

    priv_sentinel, xws_sentinel = object(), object()
    monkeypatch.setattr("dbx_nwp_helper.core.acl.read_workspace_pas", _read)
    monkeypatch.setattr(
        "dbx_nwp_helper.core.acl.existing_cbi_ingress",
        lambda a, w: ("p1", None, priv_sentinel, xws_sentinel),
    )
    cfg = IngressConfig()
    cli._reconcile_existing_ingress(object(), 42, _wc("https://adb-1.2.azuredatabricks.net"), cfg, yes=True)
    assert seen["pas_read"] is False  # no PAS read on Azure
    assert cfg.private_access is priv_sentinel
    assert cfg.existing_xws is xws_sentinel


def test_reconcile_existing_ingress_noop_without_account():
    from dbx_nwp_helper.config import IngressConfig

    cfg = IngressConfig()
    assert cli._reconcile_existing_ingress(
        None, 42, _wc("https://x.cloud.databricks.com"), cfg, yes=True
    ) == (None, None, False, None)
    assert cfg.private_access is None and cfg.existing_public is None and cfg.existing_xws is None


def _egr(restricted=True, enforced=True):
    """A fake egress block matching NetworkPolicyEgress.network_access shape."""
    import types

    na = types.SimpleNamespace(
        restriction_mode="RESTRICTED_ACCESS" if restricted else "FULL_ACCESS",
        allowed_internet_destinations=None,
        allowed_storage_destinations=None,
        blocked_internet_destinations=None,
        policy_enforcement=types.SimpleNamespace(enforcement_mode="ENFORCED" if enforced else "DRY_RUN"),
    )
    return types.SimpleNamespace(network_access=na)


def test_ingress_preflight_aborts_when_new_id_drops_enforced_egress(monkeypatch):
    # A new ingress policy id rebinds the workspace to a FULL_ACCESS-egress policy, dropping the
    # assigned policy's ENFORCED egress -> abort (the egress guard re-reads the assigned policy).
    import typer

    monkeypatch.setattr(
        "dbx_nwp_helper.core.acl.assigned_policy", lambda a, w: ("p1", _fake_pol(egress=_egr(True, True)))
    )
    with pytest.raises(typer.Exit) as e:
        cli._ingress_preflight(
            object(),
            42,
            "different-id",
            yes=True,
            existing=_existing(assigned_id="p1"),
            migrating_public=True,
        )
    assert e.value.exit_code == 1


def test_ingress_preflight_same_id_keeps_egress(monkeypatch):
    # Updating the SAME policy id preserves its egress, so an enforced egress must NOT abort.
    monkeypatch.setattr(
        "dbx_nwp_helper.core.acl.assigned_policy", lambda a, w: ("p1", _fake_pol(egress=_egr(True, True)))
    )
    cli._ingress_preflight(
        object(), 42, "p1", yes=True, existing=_existing(assigned_id="p1"), migrating_public=True
    )  # same id -> must not raise


def test_egress_preflight_aborts_on_enforced_egress(monkeypatch):
    import typer

    monkeypatch.setattr(
        "dbx_nwp_helper.core.acl.assigned_policy", lambda a, w: ("p1", _fake_pol(egress=_egr(True, True)))
    )
    with pytest.raises(typer.Exit) as e:
        cli._egress_preflight(object(), 42, "new-id", yes=True)
    assert e.value.exit_code == 1


def test_egress_preflight_warns_on_dry_run_egress_then_proceeds(monkeypatch, capsys):
    monkeypatch.setattr(
        "dbx_nwp_helper.core.acl.assigned_policy",
        lambda a, w: ("p1", _fake_pol(egress=_egr(True, enforced=False))),
    )
    cli._egress_preflight(object(), 42, "p1", yes=True)  # same id -> no opposite-direction check
    assert "DRY-RUN egress" in capsys.readouterr().out


def test_egress_preflight_proceeds_on_full_access(monkeypatch):
    monkeypatch.setattr(
        "dbx_nwp_helper.core.acl.assigned_policy",
        lambda a, w: ("p1", _fake_pol(egress=_egr(restricted=False))),
    )
    cli._egress_preflight(object(), 42, "new-id", yes=True)  # must not raise


def test_egress_preflight_aborts_when_new_id_drops_enforced_ingress(monkeypatch):
    # New egress policy id rebinds to a FULL_ACCESS-ingress policy, dropping the assigned policy's
    # enforced ingress -> abort.
    import typer

    monkeypatch.setattr("dbx_nwp_helper.core.acl.public_restrictive", lambda ing: ing == "ENF")
    monkeypatch.setattr("dbx_nwp_helper.core.acl.private_or_xws_restrictive", lambda ing: False)
    monkeypatch.setattr(
        "dbx_nwp_helper.core.acl.assigned_policy",
        lambda a, w: ("p1", _fake_pol(ingress="ENF", egress=_egr(restricted=False))),
    )
    with pytest.raises(typer.Exit) as e:
        cli._egress_preflight(object(), 42, "different-id", yes=True)
    assert e.value.exit_code == 1


def test_egress_preflight_same_id_keeps_ingress(monkeypatch):
    monkeypatch.setattr("dbx_nwp_helper.core.acl.public_restrictive", lambda ing: ing == "ENF")
    monkeypatch.setattr("dbx_nwp_helper.core.acl.private_or_xws_restrictive", lambda ing: False)
    monkeypatch.setattr(
        "dbx_nwp_helper.core.acl.assigned_policy",
        lambda a, w: ("p1", _fake_pol(ingress="ENF", egress=_egr(restricted=False))),
    )
    cli._egress_preflight(object(), 42, "p1", yes=True)  # same id -> must not raise


def test_egress_preflight_proceeds_when_clean(monkeypatch):
    monkeypatch.setattr("dbx_nwp_helper.core.acl.assigned_policy", lambda a, w: (None, None))
    cli._egress_preflight(object(), 42, "new-id", yes=True)  # must not raise


def test_ingress_policy_name_with_add_to_existing_is_rejected():
    # per_workspace + --policy-name is now allowed (name = prefix); add_to_existing still isn't (the
    # id comes from --existing-policy-id).
    result = runner.invoke(
        cli.app,
        [
            "ingress",
            "--profile",
            "test",
            "--policy-name",
            "x",
            "--create-policy",
            "--policy-action",
            "add_to_existing",
            "--existing-policy-id",
            "some-id",
        ],
    )
    assert result.exit_code == 2
    assert "policy-name" in _plain(result.output)


def test_has_rules_helper():
    assert cli._has_rules({}) is False
    assert cli._has_rules({"__ALL__": {"allow": [], "deny": []}}) is False
    assert cli._has_rules({"__ALL__": {"allow": [{"cidrs": ["1.1.1.1/32"]}], "deny": []}}) is True
    assert cli._has_rules({"__ALL__": {"allow": [], "deny": [{"cidrs": ["9.9.9.0/24"]}]}}) is True


def _empty_analysis():
    return IngressAnalysis(
        candidates=pd.DataFrame(),
        suggestions=pd.DataFrame(),
        threat_matches=pd.DataFrame(),
        denied_requests=pd.DataFrame(columns=["source_ip"]),
        ip_acls=[],
        funnel={
            "total_rows": 0,
            "with_source_ip": 0,
            "ipv4": 0,
            "ipv6": 0,
            "successful": 0,
            "workspace_level": 0,
            "account_level": 0,
            "public_ipv4": 0,
            "distinct_public_ok": 0,
            "distinct_public_ok_ws": 0,
        },
    )


def test_ingress_create_with_no_rules_exits_nonzero(monkeypatch):
    # Stub the whole data path so no network is touched and analysis is empty.
    monkeypatch.setattr(cli, "_step", lambda _m: None)

    import dbx_nwp_helper.auth as auth
    import dbx_nwp_helper.sql as sqlmod
    from dbx_nwp_helper.core import ingress as ing
    from dbx_nwp_helper.core import ingress_rules as rules

    monkeypatch.setattr(auth, "workspace_client", lambda conn: object())
    monkeypatch.setattr(sqlmod, "resolve_warehouse", lambda conn: "/sql/1.0/warehouses/x")
    # Account auth is now resolved + verified UP FRONT (fail-fast), so stub it to succeed; the point
    # of this test is that no *apply* (write) happens when the empty analysis yields no rules.
    monkeypatch.setattr(cli, "_resolve_account_profile", lambda conn: None)
    monkeypatch.setattr(auth, "this_workspace_id", lambda conn: 42)
    monkeypatch.setattr(cli, "_account_client_or_exit", lambda conn, workspace_id=None: object())

    class _Conn:
        def __enter__(self):
            return object()

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(sqlmod, "connection", lambda conn, hp: _Conn())
    monkeypatch.setattr(ing, "analyze", lambda *a, **k: _empty_analysis())
    # the apply (the actual write) must never run when there are no rules.
    monkeypatch.setattr(
        rules,
        "apply",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("apply must not run when there are no rules")),
    )

    result = runner.invoke(
        cli.app,
        [
            "ingress",
            "--profile",
            "test",
            "--warehouse-http-path",
            "/sql/1.0/warehouses/x",
            "--account-id",
            "acc",
            "--create-policy",
            "--yes",
        ],
    )
    assert result.exit_code == 1
    assert "Nothing to apply" in result.stdout


# --- ported auth / account-resolution improvements ---------------------------------------------
def _sq(text: str) -> str:
    """Strip ANSI + all whitespace, so substring asserts survive Rich panel wrapping."""
    return "".join(_plain(text).split())


def test_account_host_from_workspace_host():
    f = cli.account_host_from_workspace_host
    # AWS prod / staging / vanity: replace the single workspace label with 'accounts'
    assert f("https://dbc-11112222-3333.cloud.databricks.com") == "https://accounts.cloud.databricks.com"
    assert (
        f("https://dbc-11112222-3333.staging.cloud.databricks.com/")
        == "https://accounts.staging.cloud.databricks.com"
    )
    assert f("https://acme.cloud.databricks.com") == "https://accounts.cloud.databricks.com"
    # GCP: two workspace-specific labels (<id>.<shard>) dropped; anchor on the base domain
    assert (
        f("https://1111111111111111.4.staging.gcp.databricks.com")
        == "https://accounts.staging.gcp.databricks.com"
    )
    assert f("https://2222222222222222.8.gcp.databricks.com") == "https://accounts.gcp.databricks.com"
    assert f("https://acme.gcp.databricks.com") == "https://accounts.gcp.databricks.com"
    # Azure fixed host (region label must NOT leak in)
    assert f("https://adb-0000000000000000.0.azuredatabricks.net") == "https://accounts.azuredatabricks.net"
    # undecidable / empty -> None (caller keeps its default; user can pin --account-host)
    assert f("https://databricks.acme.example") is None
    assert f("") is None and f(None) is None


def test_norm_host_strips_scheme_and_slash():
    assert cli._norm_host("https://accounts.azuredatabricks.net/") == "accounts.azuredatabricks.net"
    assert cli._norm_host("accounts.azuredatabricks.net") == "accounts.azuredatabricks.net"
    assert cli._norm_host("") == "" and cli._norm_host(None) == ""


_CFG = {
    "az-ws": {"host": "https://adb-1.7.azuredatabricks.net", "account_id": "aaaaaaaa"},
    "az-acct": {"host": "https://accounts.azuredatabricks.net", "account_id": "aaaaaaaa"},
    "aws-acct": {"host": "https://accounts.staging.cloud.databricks.com", "account_id": "bbbbbbbb"},
    "az-acct-dupe": {"host": "accounts.azuredatabricks.net", "account_id": "aaaaaaaa"},
}


def test_matching_account_profiles_matches_on_host_and_id(monkeypatch):
    monkeypatch.setattr(cli, "_read_config_profiles", lambda: _CFG)
    assert set(cli._matching_account_profiles("https://accounts.azuredatabricks.net", "aaaaaaaa")) == {
        "az-acct",
        "az-acct-dupe",
    }
    # right id but wrong host -> no match; right host but wrong id -> no match
    assert cli._matching_account_profiles("https://accounts.azuredatabricks.net", "bbbbbbbb") == []
    assert cli._matching_account_profiles("https://accounts.staging.cloud.databricks.com", "aaaaaaaa") == []
    assert cli._matching_account_profiles("", "aaaaaaaa") == []


def test_resolve_account_profile_single_match(monkeypatch, capsys):
    from dbx_nwp_helper.config import Connection

    monkeypatch.setattr(cli, "_read_config_profiles", lambda: {"az-acct": _CFG["az-acct"]})
    conn = Connection(account_host="https://accounts.azuredatabricks.net", account_id="aaaaaaaa")
    cli._resolve_account_profile(conn)
    assert conn.account_profile == "az-acct"
    assert "az-acct" in _sq(capsys.readouterr().out)


def test_resolve_account_profile_noop_when_explicit_or_no_match(monkeypatch):
    from dbx_nwp_helper.config import Connection

    monkeypatch.setattr(cli, "_read_config_profiles", lambda: _CFG)
    explicit = Connection(
        account_host="https://accounts.azuredatabricks.net", account_id="aaaaaaaa", account_profile="chosen"
    )
    cli._resolve_account_profile(explicit)
    assert explicit.account_profile == "chosen"
    nomatch = Connection(account_host="https://accounts.gcp.databricks.com", account_id="nope")
    cli._resolve_account_profile(nomatch)
    assert nomatch.account_profile is None


def test_resolve_account_host_derives_and_respects_explicit(capsys):
    from dbx_nwp_helper.config import Connection

    wc = type("WC", (), {"config": type("C", (), {"host": "https://acme.gcp.databricks.com"})()})()
    derived = Connection()  # account_host_explicit defaults False
    cli._resolve_account_host(derived, wc)
    assert derived.account_host == "https://accounts.gcp.databricks.com"
    pinned = Connection(account_host="https://accounts.cloud.databricks.com", account_host_explicit=True)
    cli._resolve_account_host(pinned, wc)
    assert pinned.account_host == "https://accounts.cloud.databricks.com"  # explicit respected


def test_default_account_id_from_workspace(capsys):
    from dbx_nwp_helper.config import Connection

    wc = type("WC", (), {"config": type("C", (), {"account_id": "aaaaaaaa"})()})()
    conn = Connection(account_id="")
    cli._default_account_id_from_workspace(conn, wc)
    assert conn.account_id == "aaaaaaaa"
    # an explicit --account-id is not overwritten
    explicit = Connection(account_id="explicit")
    cli._default_account_id_from_workspace(explicit, wc)
    assert explicit.account_id == "explicit"


def test_looks_like_account_console():
    f = cli._looks_like_account_console
    assert f("https://accounts.azuredatabricks.net") is True
    assert f("https://accounts.staging.cloud.databricks.com") is True
    assert f("https://adb-1.7.azuredatabricks.net") is False
    assert f("https://dbc-x.cloud.databricks.com") is False
    assert f("") is False


def _fake_account(ok=True, err=None):
    class _WS:
        def get(self, workspace_id):
            if not ok:
                raise err or RuntimeError("boom")
            return object()

    return type("Acct", (), {"workspaces": _WS()})()


def test_verify_account_access_returns_account_on_success():
    from dbx_nwp_helper.config import Connection

    acct = _fake_account(ok=True)
    assert cli._verify_account_access_or_exit(Connection(account_id="a"), acct, 42) is acct


def test_verify_account_access_exits_cleanly_on_rejection(capsys):
    import typer

    from dbx_nwp_helper.config import Connection

    conn = Connection(account_id="acc-123", account_host="https://accounts.azuredatabricks.net")
    with pytest.raises(typer.Exit) as exc:
        cli._verify_account_access_or_exit(conn, _fake_account(ok=False), 42)
    assert exc.value.exit_code == 1
    out = _sq(capsys.readouterr().out)
    assert "acc-123" in out and "--account-profile" in out


def test_confirm_workspace_rejects_account_console_profile(monkeypatch, capsys):
    import typer

    from dbx_nwp_helper.config import Connection

    wc = type("WC", (), {"config": type("C", (), {"host": "https://accounts.azuredatabricks.net"})()})()
    monkeypatch.setattr(cli, "_workspace_client_or_exit", lambda conn: wc)
    with pytest.raises(typer.Exit) as exc:
        cli._confirm_workspace(Connection(profile="az-acct"), yes=True)
    assert exc.value.exit_code == 1
    out = _sq(capsys.readouterr().out)
    assert "accountconsole" in out.lower() and "--account-profile" in out


# ---------------------------------------------------------------- IP ACL auto-detect / migrate prompt
def _analysis_with_acls(acls):
    return types.SimpleNamespace(ip_acls=acls)


def _acl(label="office", enabled=True, ips=("8.8.8.8",)):
    return {"label": label, "list_type": "ALLOW", "enabled": enabled, "ip_addresses": list(ips)}


def test_reconcile_ip_acls_no_enabled_lists_sets_false():
    from dbx_nwp_helper.config import IngressConfig

    cfg = IngressConfig()
    cli._reconcile_ip_acls(_analysis_with_acls([_acl(enabled=False)]), cfg, yes=True)
    assert cfg.migrate_ip_acls is False  # nothing enabled → nothing to migrate


def test_reconcile_ip_acls_non_interactive_migrates(capsys):
    from dbx_nwp_helper.config import IngressConfig

    cfg = IngressConfig()
    cli._reconcile_ip_acls(_analysis_with_acls([_acl(ips=("8.8.8.8", "1.1.1.1"))]), cfg, yes=True)
    assert cfg.migrate_ip_acls is True
    out = _sq(capsys.readouterr().out)
    # shows the actual IPs (not just a count) and notes it's migrating them all non-interactively
    assert "office" in out and "8.8.8.8" in out and "1.1.1.1" in out and "Non-interactive" in out


def test_reconcile_ip_acls_interactive_deselect_all(monkeypatch):
    from dbx_nwp_helper.config import IngressConfig

    monkeypatch.setattr(cli, "_interactive", lambda yes: True)
    monkeypatch.setattr(cli, "_checkbox_keep", lambda title, choices: [])  # user unchecks everything
    cfg = IngressConfig()
    cli._reconcile_ip_acls(_analysis_with_acls([_acl()]), cfg, yes=False)
    assert cfg.migrate_ip_acls is False  # nothing kept → build from traffic only


def test_reconcile_ip_acls_interactive_keep_all(monkeypatch):
    from dbx_nwp_helper.config import IngressConfig

    monkeypatch.setattr(cli, "_interactive", lambda yes: True)
    monkeypatch.setattr(cli, "_checkbox_keep", lambda title, choices: [c.value for c in choices])
    analysis = _analysis_with_acls([_acl(ips=("8.8.8.8", "1.1.1.1"))])
    cfg = IngressConfig()
    cli._reconcile_ip_acls(analysis, cfg, yes=False)
    assert cfg.migrate_ip_acls is True
    assert analysis.ip_acls[0]["ip_addresses"] == ["8.8.8.8", "1.1.1.1"]


def test_reconcile_ip_acls_inventory_shows_enabled_and_disabled(capsys):
    from dbx_nwp_helper.config import IngressConfig

    cfg = IngressConfig()
    analysis = _analysis_with_acls([_acl(label="on"), _acl(label="off", enabled=False, ips=("9.9.9.9",))])
    cli._reconcile_ip_acls(analysis, cfg, yes=True)  # non-interactive
    out = _sq(capsys.readouterr().out)
    assert "enabled" in out and "disabled" in out  # full inventory with per-list status
    assert "9.9.9.9" in out  # the disabled list's IP is shown too
    assert cfg.migrate_ip_acls is True  # there is an enabled list to migrate


def test_reconcile_ip_acls_non_interactive_only_disabled_not_migrated():
    from dbx_nwp_helper.config import IngressConfig

    cfg = IngressConfig()
    cli._reconcile_ip_acls(_analysis_with_acls([_acl(enabled=False, ips=("9.9.9.9",))]), cfg, yes=True)
    assert cfg.migrate_ip_acls is False  # only a dormant list → not auto-activated non-interactively


def test_reconcile_ip_acls_interactive_select_disabled_activates(monkeypatch, capsys):
    from dbx_nwp_helper.config import IngressConfig

    monkeypatch.setattr(cli, "_interactive", lambda yes: True)
    monkeypatch.setattr(cli, "_checkbox_keep", lambda title, choices: [c.value for c in choices])  # keep all
    analysis = _analysis_with_acls([_acl(label="dormant", enabled=False, ips=("9.9.9.9",))])
    cfg = IngressConfig()
    cli._reconcile_ip_acls(analysis, cfg, yes=False)
    assert cfg.migrate_ip_acls is True
    assert analysis.ip_acls[0]["enabled"] is True  # selecting a disabled list activates it for migration
    out = _sq(capsys.readouterr().out)
    assert "DISABLED" in out and "ACTIVE" in out  # warned that dormant rules are being activated


def test_reconcile_ip_acls_keep_enabled_only_preserves_disabled(monkeypatch):
    from dbx_nwp_helper.config import IngressConfig

    monkeypatch.setattr(cli, "_interactive", lambda yes: True)
    # keep only the pre-checked (enabled) entries, leaving the disabled one unselected
    monkeypatch.setattr(cli, "_checkbox_keep", lambda title, choices: [c.value for c in choices if c.checked])
    analysis = _analysis_with_acls([_acl(label="on"), _acl(label="off", enabled=False, ips=("9.9.9.9",))])
    cfg = IngressConfig()
    cli._reconcile_ip_acls(analysis, cfg, yes=False)
    assert cfg.migrate_ip_acls is True
    states = {(a["label"], a["enabled"]) for a in analysis.ip_acls}
    assert ("on", True) in states  # enabled list migrated
    assert ("off", False) in states  # disabled list preserved, left dormant


def test_reconcile_ip_acls_interactive_partial_selection_prunes(monkeypatch):
    from dbx_nwp_helper.config import IngressConfig

    monkeypatch.setattr(cli, "_interactive", lambda yes: True)
    # keep only the first entry of whatever is offered
    monkeypatch.setattr(cli, "_checkbox_keep", lambda title, choices: [choices[0].value])
    analysis = _analysis_with_acls([_acl(ips=("8.8.8.8", "1.1.1.1"))])
    cfg = IngressConfig()
    cli._reconcile_ip_acls(analysis, cfg, yes=False)
    assert cfg.migrate_ip_acls is True
    assert analysis.ip_acls[0]["ip_addresses"] == ["8.8.8.8"]  # pruned to the selected IP


def test_reconcile_ip_acls_interactive_cancel_aborts(monkeypatch):
    import typer

    from dbx_nwp_helper.config import IngressConfig

    monkeypatch.setattr(cli, "_interactive", lambda yes: True)
    monkeypatch.setattr(cli, "_checkbox_keep", lambda title, choices: None)  # Ctrl-C
    with pytest.raises(typer.Exit):
        cli._reconcile_ip_acls(_analysis_with_acls([_acl()]), cfg=IngressConfig(), yes=False)


# ---------------------------------------------------------------------------------- guide command
def test_guide_print_path_points_at_packaged_html():
    from pathlib import Path

    result = runner.invoke(cli.app, ["guide", "--print-path"])
    assert result.exit_code == 0
    printed = _plain(result.stdout).strip().splitlines()[-1].strip()
    p = Path(printed)
    assert p.name == "index.html" and p.exists()  # the packaged guide is really there


def test_guide_html_has_pdf_affordances():
    html = cli._guide_path().read_text()
    assert 'class="pdf-btn"' in html and "npgExpandAll" in html  # button + expand-all script
    assert "@media print" in html  # print stylesheet
    assert "location.hash==='#print'" in html  # headless render expands via the #print hash


def test_guide_pdf_renders_via_headless_browser(monkeypatch, tmp_path):
    import subprocess
    import types
    from pathlib import Path

    out = tmp_path / "guide.pdf"
    seen = {}
    monkeypatch.setattr(cli, "_find_chrome", lambda: "/fake/chrome")

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        pdf_arg = next(a for a in cmd if a.startswith("--print-to-pdf="))
        Path(pdf_arg.split("=", 1)[1]).write_bytes(b"%PDF-1.4\n")  # emulate the browser writing it
        return types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = runner.invoke(cli.app, ["guide", "--pdf", str(out)])
    assert result.exit_code == 0 and out.exists()
    assert any(a.startswith("--print-to-pdf=") for a in seen["cmd"])
    assert seen["cmd"][-1].endswith("#print")  # rendered with every section expanded


def test_guide_pdf_directory_gets_default_filename(monkeypatch, tmp_path):
    import subprocess
    import types
    from pathlib import Path

    seen = {}
    monkeypatch.setattr(cli, "_find_chrome", lambda: "/fake/chrome")

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        pdf_arg = next(a for a in cmd if a.startswith("--print-to-pdf="))
        Path(pdf_arg.split("=", 1)[1]).write_bytes(b"%PDF-1.4\n")
        return types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    # pass a directory, not a file — should get the default filename inside it
    result = runner.invoke(cli.app, ["guide", "--pdf", str(tmp_path)])
    assert result.exit_code == 0
    assert (tmp_path / "dbx-nwp-helper-guide.pdf").is_file()
    pdf_arg = next(a for a in seen["cmd"] if a.startswith("--print-to-pdf="))
    assert pdf_arg.endswith("dbx-nwp-helper-guide.pdf")


def test_guide_pdf_reports_failure_when_no_file_written(monkeypatch, tmp_path):
    # Regression: a directory used to pass the success check because it "exists"; now we require a
    # real file, so a browser run that writes nothing is reported as a failure, not a success.
    import subprocess
    import types

    monkeypatch.setattr(cli, "_find_chrome", lambda: "/fake/chrome")
    monkeypatch.setattr(
        subprocess, "run", lambda cmd, **kw: types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
    )
    result = runner.invoke(cli.app, ["guide", "--pdf", str(tmp_path / "out.pdf")])
    assert result.exit_code == 1
    assert not (tmp_path / "out.pdf").exists()


def test_guide_pdf_without_browser_points_to_button(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "_find_chrome", lambda: None)
    result = runner.invoke(cli.app, ["guide", "--pdf", str(tmp_path / "g.pdf")])
    assert result.exit_code == 1
    assert "Save as PDF" in _plain(result.stdout)  # falls back to the on-page button


# ---------------------------------------------------- threat-domain feed resolution (--block-threat-domains)
def test_resolve_threat_domain_feeds_noninteractive_keyless(monkeypatch):
    # No TTY / --yes and no abuse.ch key → only the keyless default feeds, no key, allowlist on.
    from dbx_nwp_helper import guided

    monkeypatch.delenv("DBX_NWP_ABUSE_CH_AUTH_KEY", raising=False)
    feeds, key, allowlist = guided.resolve_threat_domain_feeds(interactive=False)
    assert feeds == ["c2intel"]
    assert key is None
    assert allowlist is True


def test_resolve_threat_domain_feeds_noninteractive_with_key(monkeypatch):
    # With the env key set, the abuse.ch feeds activate automatically in headless runs.
    from dbx_nwp_helper import guided

    monkeypatch.setenv("DBX_NWP_ABUSE_CH_AUTH_KEY", "secret")
    feeds, key, allowlist = guided.resolve_threat_domain_feeds(interactive=False)
    assert feeds == ["c2intel", "threatfox", "urlhaus"]
    assert key == "secret"
    assert allowlist is True


# ------------------------------------------------------- threat-intel IP feed resolution (--block-threat-ips)
def test_resolve_threat_ip_feeds_headless_uses_all_feeds():
    # Headless (or no TTY) always loads every feed — the safe default for the always-on flagging path.
    from dbx_nwp_helper import guided
    from dbx_nwp_helper.config import THREAT_FEEDS

    assert guided.resolve_threat_ip_feeds(interactive=False, engaged=True) == list(THREAT_FEEDS)
    assert guided.resolve_threat_ip_feeds(interactive=False, engaged=False) == list(THREAT_FEEDS)


def test_resolve_threat_ip_feeds_interactive_off_skips_picker(monkeypatch):
    # Interactive but deny rules off → no checkbox, just all feeds (flagging still runs on all feeds).
    from dbx_nwp_helper import guided
    from dbx_nwp_helper.config import THREAT_FEEDS

    monkeypatch.setattr(
        guided.questionary, "checkbox", lambda *a, **k: pytest.fail("picker should not be shown")
    )
    assert guided.resolve_threat_ip_feeds(interactive=True, engaged=False) == list(THREAT_FEEDS)


def test_resolve_threat_ip_feeds_interactive_engaged_shows_picker(monkeypatch):
    # Interactive + engaged → the checkbox is shown and its selection is returned.
    from dbx_nwp_helper import guided

    monkeypatch.setattr(
        guided.questionary,
        "checkbox",
        lambda *a, **k: types.SimpleNamespace(ask=lambda: ["ipsum", "tor_exit"]),
    )
    assert guided.resolve_threat_ip_feeds(interactive=True, engaged=True) == ["ipsum", "tor_exit"]
