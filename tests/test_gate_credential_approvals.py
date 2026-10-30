"""Operator-approved VardrGate credential references (ADR 0023).

A Gate case comes from the backend. The runner resolves one of its credential
references only if the operator approved that reference on this machine for the
job's engagement and every origin the case contacts, and it refuses any ${...}
reference outright, because VardrGate would expand it from its own environment.
"""

from io import StringIO
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from vardrrunner import config, configs, handlers, runner
from vardrrunner.commands import jobs

ENGAGEMENT = "eng-1"


def _case(**overrides):
    case = {
        "id": "owner-check",
        "identities": [
            {"id": "owner", "credential": {"type": "bearer", "value_env": "OWNER_TOKEN"}},
            {"id": "anon", "credential": {"type": "static_header", "header": "", "value": ""}},
        ],
        "request": {"method": "GET", "url": "https://api.example.com/users/42"},
    }
    case.update(overrides)
    return case


# --------------------------------------------------------------------------- #
# Origins and approvals
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("url", "origin"),
    [
        ("https://API.Example.com/users?id=1", "https://api.example.com"),
        ("https://api.example.com:443/x", "https://api.example.com"),
        ("http://api.example.com:80", "http://api.example.com"),
        ("https://api.example.com:8443/", "https://api.example.com:8443"),
        ("http://[::1]:5101/x", "http://[::1]:5101"),
    ],
)
def test_url_origin_normalizes_scheme_host_and_default_port(url, origin):
    assert config.url_origin(url) == origin


@pytest.mark.parametrize("url", ["", "api.example.com", "ftp://h/", "https://", "https://h:99999"])
def test_url_origin_refuses_what_is_not_an_http_origin(url):
    with pytest.raises(config.InvalidApproval):
        config.url_origin(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://user:password@api.example.com/users/42",
        "https://{{authority}}@api.example.com/users/42",
        "https://{{host}}.example.com/users/42",
    ],
)
def test_a_credential_target_cannot_change_authority_after_approval(url):
    config.approve_credential(ENGAGEMENT, "https://api.example.com", "env", "OWNER_TOKEN")
    case = _case(request={"method": "GET", "url": url})
    with patch("vardrrunner.handlers._resolve_one_credential") as resolve:
        with pytest.raises(configs.ConfigError, match="test case target"):
            handlers._resolve_identity_secrets(case, ENGAGEMENT)
        resolve.assert_not_called()


def test_setup_captures_in_paths_keep_the_approved_origin():
    case = _case(request={"method": "GET", "url": "https://api.example.com/users/{{id}}"})
    config.approve_credential(ENGAGEMENT, "https://api.example.com", "env", "OWNER_TOKEN")
    handlers.check_gate_case(case, ENGAGEMENT)


def test_approvals_are_idempotent_listed_and_revocable():
    first = config.approve_credential(ENGAGEMENT, "https://api.example.com/x", "env", "OWNER_TOKEN")
    config.approve_credential(ENGAGEMENT, "https://API.example.com", "env", "OWNER_TOKEN")
    assert config.credential_approvals() == [first]
    assert first == {
        "engagement_id": ENGAGEMENT,
        "origin": "https://api.example.com",
        "source": "env",
        "name": "OWNER_TOKEN",
    }
    assert config.revoke_credential(ENGAGEMENT, "https://api.example.com", "env", "OWNER_TOKEN")
    assert config.credential_approvals() == []
    assert not config.revoke_credential(ENGAGEMENT, "https://api.example.com", "env", "OWNER_TOKEN")


def test_an_approval_never_stores_a_value(monkeypatch):
    monkeypatch.setenv("OWNER_TOKEN", "do-not-store")
    config.approve_credential(ENGAGEMENT, "https://api.example.com", "env", "OWNER_TOKEN")
    assert "do-not-store" not in config.CONFIG_FILE.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("engagement", "source", "name"),
    [
        ("", "env", "OWNER_TOKEN"),
        ("eng 1", "env", "OWNER_TOKEN"),
        (ENGAGEMENT, "file", "OWNER_TOKEN"),
        (ENGAGEMENT, "env", "1BAD"),
        (ENGAGEMENT, "env", "BAD-NAME"),
        (ENGAGEMENT, "keychain", ""),
        (ENGAGEMENT, "keychain", "bad\naccount"),
    ],
)
def test_invalid_approvals_are_refused(engagement, source, name):
    with pytest.raises(config.InvalidApproval):
        config.approve_credential(engagement, "https://api.example.com", source, name)


# --------------------------------------------------------------------------- #
# check_gate_case
# --------------------------------------------------------------------------- #


def test_an_unapproved_reference_is_refused_with_the_command_to_approve_it(monkeypatch):
    monkeypatch.setenv("OWNER_TOKEN", "secret")
    with pytest.raises(configs.ConfigError) as exc:
        handlers.check_gate_case(_case(), ENGAGEMENT)
    message = str(exc.value)
    assert "not approved" in message
    assert "vardrrunner credentials approve --engagement eng-1" in message
    assert "--origin https://api.example.com --env OWNER_TOKEN" in message
    assert "secret" not in message


def test_an_approved_reference_passes(approve_gate_case):
    case = _case()
    handlers.check_gate_case(case, approve_gate_case(case, ENGAGEMENT))


def test_an_approval_for_another_engagement_does_not_count():
    config.approve_credential("eng-2", "https://api.example.com", "env", "OWNER_TOKEN")
    with pytest.raises(configs.ConfigError, match="not approved"):
        handlers.check_gate_case(_case(), ENGAGEMENT)


def test_every_origin_the_case_contacts_must_be_approved():
    config.approve_credential(ENGAGEMENT, "https://api.example.com", "env", "OWNER_TOKEN")
    case = _case(
        setup=[
            {"name": "login", "request": {"method": "GET", "url": "https://other.example/login"}}
        ]
    )
    with pytest.raises(configs.ConfigError, match="https://other.example"):
        handlers.check_gate_case(case, ENGAGEMENT)


def test_preflight_and_verifier_origins_are_checked_too():
    config.approve_credential(ENGAGEMENT, "https://api.example.com", "env", "OWNER_TOKEN")
    case = _case()
    case["identities"][0]["preflight"] = {"url": "https://idp.example/session"}
    with pytest.raises(configs.ConfigError, match="https://idp.example"):
        handlers.check_gate_case(case, ENGAGEMENT)

    case = _case(
        write_verification={
            "identity": {
                "id": "reader",
                "credential": {"type": "bearer", "value_env": "OWNER_TOKEN"},
            },
            "request": {"method": "GET", "url": "https://reader.example/state"},
        }
    )
    with pytest.raises(configs.ConfigError, match="https://reader.example"):
        handlers.check_gate_case(case, ENGAGEMENT)


def test_a_keychain_reference_needs_approval_too():
    case = _case()
    case["identities"][0]["credential"] = {"type": "bearer", "value_keychain": "owner"}
    with pytest.raises(configs.ConfigError, match="keychain reference 'owner'"):
        handlers.check_gate_case(case, ENGAGEMENT)
    config.approve_credential(ENGAGEMENT, "https://api.example.com", "keychain", "owner")
    handlers.check_gate_case(case, ENGAGEMENT)


@pytest.mark.parametrize(
    "place",
    [
        lambda c: c["request"].update(url="https://api.example.com/x?k=${VARDRMAP_API_KEY}"),
        lambda c: c["request"].update(headers={"X-Probe": "${VARDRMAP_API_KEY}"}),
        lambda c: c["request"].update(headers={"${VARDRMAP_API_KEY}": "x"}),
        lambda c: c["request"].update(body='{"k": "${VARDRMAP_API_KEY}"}'),
        lambda c: c["identities"][1]["credential"].update(header="${VARDRMAP_API_KEY}"),
    ],
)
def test_environment_references_are_refused_even_when_everything_is_approved(
    place, approve_gate_case
):
    case = _case()
    engagement = approve_gate_case(case, ENGAGEMENT)
    place(case)
    with pytest.raises(configs.ConfigError, match="environment reference"):
        handlers.check_gate_case(case, engagement)


def test_a_case_without_references_needs_no_approval():
    case = {
        "id": "anon",
        "identities": [{"id": "anon", "credential": {"type": "static_header", "header": ""}}],
    }
    handlers.check_gate_case(case, ENGAGEMENT)


def test_a_reference_without_a_target_url_is_refused():
    case = _case(request={"method": "GET"})
    with pytest.raises(configs.ConfigError, match="test case target"):
        handlers.check_gate_case(case, ENGAGEMENT)


# --------------------------------------------------------------------------- #
# Gate invocation and the job loop
# --------------------------------------------------------------------------- #


def test_gate_runs_the_resolved_job_literally(tmp_path):
    process = MagicMock()
    process.wait.return_value = 0
    with patch("vardrrunner.runner._spawn_tool", return_value=process) as spawn:
        runner.run_vardrgate({"config": {"test_case": {}}}, tmp_path / "result.json")
    assert "--literal-job" in spawn.call_args.args[0]


def _gate_job(case):
    return {
        "id": "job-1",
        "engagement_id": ENGAGEMENT,
        "tool_type": "vardrgate_api_test",
        "target_source": "config",
        "config": {"test_case": case},
    }


def _execute(job, tmp_path, execute=None):
    client = MagicMock()
    client.claim_job.return_value = {"config": job["config"]}
    out = StringIO()
    with (
        patch("vardrrunner.commands.jobs.runner.tool_available", return_value=True),
        patch("vardrrunner.commands.jobs.config.runs_dir", return_value=tmp_path),
        patch("vardrrunner.commands.jobs.resources.ensure_free_space"),
        patch("vardrrunner.commands.jobs._make_run_dir", return_value=tmp_path),
        patch("vardrrunner.commands.jobs.target_safety.load_deny_rules", return_value=()),
        patch.object(handlers.VardrGateHandler, "execute", execute or MagicMock(return_value=None)),
    ):
        jobs._execute_one(client, Console(file=out, width=200), job, yes=True)
    return client, out.getvalue()


def test_an_unapproved_job_fails_before_it_is_claimed(monkeypatch, tmp_path):
    monkeypatch.setenv("OWNER_TOKEN", "secret")
    execute = MagicMock()
    client, _ = _execute(_gate_job(_case()), tmp_path, execute)
    client.claim_job.assert_not_called()
    execute.assert_not_called()
    assert client.complete_job.call_args.args[1] == "failed"
    assert "not approved" in client.complete_job.call_args.kwargs["error"]


def test_an_approved_job_lists_its_references_and_runs_for_its_engagement(
    tmp_path, approve_gate_case
):
    case = _case()
    approve_gate_case(case, ENGAGEMENT)
    execute = MagicMock(return_value=None)
    client, output = _execute(_gate_job(case), tmp_path, execute)
    client.claim_job.assert_called_once_with("job-1")
    assert "credential owner: approved env reference OWNER_TOKEN" in output
    assert execute.call_args.args[2].engagement_id == ENGAGEMENT
