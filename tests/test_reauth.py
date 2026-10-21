"""Tests for the expired-credential detection + re-auth retry flow in cli.py."""

from __future__ import annotations

import pytest
import typer

from dbx_nwp_helper import cli
from dbx_nwp_helper.config import Connection


def test_is_expired_auth_matches_reauth_messages():
    assert cli._is_expired_auth("... you must reauthenticate ...")
    assert cli._is_expired_auth("invalid refresh token")
    assert cli._is_expired_auth("cannot get access token")
    assert cli._is_expired_auth("please run: databricks auth login --profile foo")


def test_is_expired_auth_ignores_unrelated_errors():
    assert not cli._is_expired_auth("default auth: cannot configure default credentials")
    assert not cli._is_expired_auth("profile configured but host missing")


def test_reauth_profile_prefers_profile_named_in_error():
    # the account client often resolves to a *different* auto-discovered profile than the one asked
    # for; re-auth must target the profile the SDK error actually names.
    msg = "Run: databricks auth login --profile acme-account."
    assert cli._reauth_profile(msg, fallback="acme-workspace") == "acme-account"


def test_reauth_profile_falls_back_when_unnamed():
    assert cli._reauth_profile("token expired", fallback="myprofile") == "myprofile"


def test_client_or_exit_retries_build_after_successful_reauth(monkeypatch):
    calls = {"n": 0}

    def build():
        calls["n"] += 1
        if calls["n"] == 1:
            raise ValueError("please reauthenticate: databricks auth login --profile p")
        return "client"

    monkeypatch.setattr(cli, "_reauthenticate", lambda profile: True)
    assert cli._client_or_exit(build, "p", "--profile") == "client"
    assert calls["n"] == 2  # built once (failed), re-authed, built again (succeeded)


def test_client_or_exit_exits_when_reauth_declined(monkeypatch):
    def build():
        raise ValueError("please reauthenticate: databricks auth login --profile p")

    monkeypatch.setattr(cli, "_reauthenticate", lambda profile: False)
    with pytest.raises(typer.Exit):
        cli._client_or_exit(build, "p", "--profile")


def test_client_or_exit_does_not_reauth_on_plain_config_error(monkeypatch):
    reauth_called = {"n": 0}

    def build():
        raise ValueError("default auth: cannot configure default credentials")

    def _reauth(profile):
        reauth_called["n"] += 1
        return True

    monkeypatch.setattr(cli, "_reauthenticate", _reauth)
    with pytest.raises(typer.Exit):
        cli._client_or_exit(build, "p", "--profile")
    assert reauth_called["n"] == 0  # never offered re-auth for a non-expiry error


def test_is_default_auth_failure_matches_no_credentials():
    assert cli._is_default_auth_failure("default auth: cannot configure default credentials")
    assert cli._is_default_auth_failure("Cannot configure default credentials, please check ...")


def test_is_default_auth_failure_ignores_expiry_and_profile_errors():
    # expired creds are a *different* remedy (re-auth), and a mistyped profile is handled elsewhere.
    assert not cli._is_default_auth_failure("please reauthenticate: databricks auth login --profile p")
    assert not cli._is_default_auth_failure("profile configured but host missing")


def test_client_or_exit_uses_custom_on_config_error(monkeypatch):
    # A non-reauthable ValueError must go to the supplied handler, not the default one.
    def build():
        raise ValueError("default auth: cannot configure default credentials")

    seen = {}

    def handler(e, profile, flag):
        seen["args"] = (str(e), profile, flag)
        raise typer.Exit(code=1)

    # If the default handler were used instead, this would flip and fail the assertion.
    monkeypatch.setattr(cli, "_profile_config_error", lambda *a, **k: seen.setdefault("default", True))
    with pytest.raises(typer.Exit):
        cli._client_or_exit(build, "acct-p", "--account-profile", on_config_error=handler)
    assert seen["args"] == (
        "default auth: cannot configure default credentials",
        "acct-p",
        "--account-profile",
    )
    assert "default" not in seen


def test_account_build_error_gives_account_admin_guidance(monkeypatch):
    banners = []
    monkeypatch.setattr(cli.console, "banner", lambda kind, msg: banners.append((kind, msg)))
    conn = Connection(account_id="0d26daa6", account_host="https://accounts.cloud.databricks.com")

    with pytest.raises(typer.Exit):
        cli._account_build_error(
            ValueError("default auth: cannot configure default credentials"), conn, "ws-p", "--profile"
        )

    assert len(banners) == 1
    kind, msg = banners[0]
    assert kind == "danger"
    # names the account, explains account auth is separate, and gives the exact login + doc pointer.
    assert "0d26daa6" in msg
    assert "account-level" in msg
    assert "--account-profile" in msg
    assert "databricks auth login --host https://accounts.cloud.databricks.com --account-id 0d26daa6" in msg
    assert "docs/account-admin-setup.md" in msg


def test_account_build_error_defers_on_other_errors(monkeypatch):
    # A construction failure that isn't "no credentials" (e.g. a bad profile) must fall through to
    # the standard profile/config handler, unchanged.
    called = {}
    monkeypatch.setattr(
        cli, "_profile_config_error", lambda e, profile, flag: called.update(args=(str(e), profile, flag))
    )
    monkeypatch.setattr(cli.console, "banner", lambda *a, **k: called.setdefault("banner", True))
    conn = Connection(account_id="123", account_host="https://accounts.cloud.databricks.com")

    cli._account_build_error(
        ValueError("no host configured for profile foo"), conn, "foo", "--account-profile"
    )

    assert called["args"] == ("no host configured for profile foo", "foo", "--account-profile")
    assert "banner" not in called  # no account-specific banner for a non-default-auth error
