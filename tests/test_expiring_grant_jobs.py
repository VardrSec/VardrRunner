"""Grant checks at claim/launch and persistent ambiguous-execution recovery."""

import os
import sys
import time
from contextlib import contextmanager
from datetime import timedelta
from unittest.mock import Mock, patch

import pytest
from rich.console import Console
from typer.testing import CliRunner

from vardrrunner import api, handlers, launch_guard, runner
from vardrrunner import credential_grants as grants
from vardrrunner.cli import app
from vardrrunner.commands import jobs
from vardrrunner.journal import Journal, Phase
from vardrrunner.recovery import reconcile

ISSUER = "https://map.example.test"
ORIGIN = "http://127.0.0.1:17001"
REFERENCE = "SYNTHETIC_GATE_TOKEN"


@pytest.fixture
def scenario(tmp_path, monkeypatch):
    case = {
        "id": "synthetic",
        "request": {"method": "GET", "url": ORIGIN + "/resource"},
        "identities": [{"id": "owner", "credential": {"type": "bearer", "value_env": REFERENCE}}],
    }
    job = {
        "id": "grant-job",
        "engagement_id": "eng",
        "tool_type": "vardrgate_api_test",
        "target_source": "config",
        "config": {"test_case": case},
    }
    client = Mock(spec=api.VardrMapClient)
    client.base = ISSUER
    client.claim_job.return_value = {"config": job["config"]}
    store = Journal(tmp_path / "run.sqlite3")
    monkeypatch.setattr(jobs.runner, "tool_available", lambda _: True)
    monkeypatch.setattr(jobs, "_make_run_dir", lambda: tmp_path)
    monkeypatch.setattr(jobs.resources, "ensure_free_space", lambda *_: None)
    grants.Store().approve(ISSUER, "eng", ORIGIN, "env", REFERENCE, 60)
    return job, client, store, case


def execute(scenario):
    job, client, store, _ = scenario
    jobs._execute_one(
        client,
        Console(quiet=True),
        job,
        True,
        journal_store=store,
        backend_url=ISSUER,
        expiring_grants=True,
    )


def test_revoke_while_operator_confirmation_prevents_claim(scenario, monkeypatch):
    job, client, _, _ = scenario
    monkeypatch.setattr(
        jobs, "_confirm", lambda *_: grants.Store().revoke(ISSUER, "eng", ORIGIN, "env", REFERENCE)
    )
    with patch.object(handlers.VardrGateHandler, "execute") as tool:
        execute(scenario)
    client.claim_job.assert_not_called()
    tool.assert_not_called()


def test_revoke_during_claim_response_prevents_execution(scenario):
    job, client, _, _ = scenario

    def claim(_):
        grants.Store().revoke(ISSUER, "eng", ORIGIN, "env", REFERENCE)
        return {"config": job["config"]}

    client.claim_job.side_effect = claim
    with patch.object(handlers.VardrGateHandler, "execute") as tool:
        execute(scenario)
    client.claim_job.assert_called_once()
    tool.assert_not_called()


@pytest.mark.skipif(os.name != "nt", reason="actual Windows process and journal failure recovery")
def test_post_creation_failure_stays_fenced_without_controlled(scenario, tmp_path):
    _, client, store, _ = scenario
    partial = tmp_path / "vardrgate_result.json"
    childpid = tmp_path / "child.pid"
    code = f"import os,time;open({str(childpid)!r},'w').write(str(os.getpid()));open({str(partial)!r},'w').write('{{}}');time.sleep(15)"

    @contextmanager
    def bad_exit():
        yield
        until = time.monotonic() + 3
        while not partial.exists() and time.monotonic() < until:
            time.sleep(0.01)
        raise grants.GrantError("injected_commit_failure")

    def run(*_):
        with launch_guard.install(bad_exit):
            runner._spawn_tool([sys.executable, "-c", code])

    with (
        patch.object(handlers.VardrGateHandler, "execute", side_effect=run),
        patch.object(handlers.VardrGateHandler, "upload") as upload,
    ):
        execute(scenario)
        record = store.unfinished()[0]
        assert record.command_profile["grant_policy"] == "expiring/1"
        assert not record.command_profile.get("controlled")
        assert record.phase == Phase.EXECUTING and record.status == "uncertain" and record.pid
        assert partial.exists()
        assert reconcile(store, client, ISSUER).deferred == 1
        upload.assert_not_called()
        client.complete_job.assert_not_called()


def test_cli_expiring_flags_route_exactly():
    cli = CliRunner()
    common = ["-e", "eng", "--origin", ORIGIN, "--env", REFERENCE]
    with patch("vardrrunner.commands.credentials.approve") as approve:
        result = cli.invoke(
            app, ["credentials", "approve", *common, "--issuer", ISSUER, "--expires-in", "60"]
        )
        assert result.exit_code == 0, result.output
        approve.assert_called_once_with(
            "eng", ORIGIN, REFERENCE, None, issuer=ISSUER, expires_in=60
        )
    with patch("vardrrunner.commands.credentials.revoke") as revoke:
        assert (
            cli.invoke(app, ["credentials", "revoke", *common, "--issuer", ISSUER]).exit_code == 0
        )
        revoke.assert_called_once_with("eng", ORIGIN, REFERENCE, None, issuer=ISSUER)
    with patch("vardrrunner.commands.credentials.list_approvals") as listing:
        assert cli.invoke(app, ["credentials", "approvals", "--issuer", ISSUER]).exit_code == 0
        listing.assert_called_once_with(issuer=ISSUER)
    with patch("vardrrunner.commands.jobs.run_jobs") as run:
        assert cli.invoke(app, ["jobs", "run", "--yes", "--expiring-grants"]).exit_code == 0
        run.assert_called_once_with(yes=True, expiring_grants=True)


def test_cli_grants_are_explicit_and_legacy_namespace_unchanged(monkeypatch):
    from vardrrunner import config

    monkeypatch.setenv(REFERENCE, "synthetic-do-not-disclose")
    cli = CliRunner()
    common = ["-e", "eng", "--origin", ORIGIN, "--env", REFERENCE]
    assert cli.invoke(app, ["credentials", "approve", *common, "--issuer", ISSUER]).exit_code == 2
    result = cli.invoke(
        app, ["credentials", "approve", *common, "--issuer", ISSUER, "--expires-in", "60"]
    )
    assert result.exit_code == 0, result.output
    assert not config.credential_approvals()
    assert "synthetic-do-not-disclose" not in result.output
    assert cli.invoke(app, ["credentials", "approvals", "--issuer", ISSUER]).exit_code == 0
    assert cli.invoke(app, ["credentials", "revoke", *common, "--issuer", ISSUER]).exit_code == 0
    assert cli.invoke(app, ["credentials", "revoke", *common, "--issuer", ISSUER]).exit_code == 1


def test_expiry_after_confirmation_before_claim(scenario, monkeypatch):
    # The fixture issued using the real clock; advance only after confirmation.
    original = grants.now
    monkeypatch.setattr(
        jobs,
        "_confirm",
        lambda *_: monkeypatch.setattr(grants, "now", lambda: original() + timedelta(minutes=2)),
    )
    with patch.object(handlers.VardrGateHandler, "execute") as tool:
        execute(scenario)
    scenario[1].claim_job.assert_not_called()
    tool.assert_not_called()


@pytest.mark.parametrize("seconds", ["0", "86401", "-1"])
def test_cli_ttl_bounds_never_create_grant(seconds):
    cli = CliRunner()
    result = cli.invoke(
        app,
        [
            "credentials",
            "approve",
            "-e",
            "eng",
            "--origin",
            ORIGIN,
            "--env",
            REFERENCE,
            "--issuer",
            ISSUER,
            "--expires-in",
            seconds,
        ],
    )
    assert result.exit_code == 2
    from vardrrunner import config

    assert grants.KEY not in config.load()
