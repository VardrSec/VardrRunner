"""Fixed-origin proof, fail-closed receipts and actual lifecycle guard wiring."""

from unittest.mock import Mock, patch

import pytest
from rich.console import Console

from vardrrunner import (
    api,
    configs,
    controlled_jobs,
    execution_control,
    handlers,
    runner,
    target_budget,
)
from vardrrunner.commands import jobs
from vardrrunner.journal import Journal


def case():
    return {
        "id": "synthetic",
        "identities": [{"id": "owner", "credential": {"type": "static_header"}}],
        "request": {"method": "GET", "url": "https://API.example.test/object"},
        "setup": [
            {"name": "aux", "request": {"method": "GET", "url": "https://setup.example.test/start"}}
        ],
        "expected_access": [{"identity_id": "owner", "decision": "allow"}],
    }


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    binary = tmp_path / "synthetic-tool"
    binary.write_bytes(b"fixture")
    monkeypatch.setattr(runner, "program", lambda _: str(binary))
    cfg = configs.VardrGateConfig.from_dict({"test_case": case()})
    return cfg, target_budget.prepare(cfg)


def test_fixed_plan_binding_and_unsupported_profiles(prepared):
    cfg, (binding, plan) = prepared
    assert binding["origins"] == ["https://api.example.test:443", "https://setup.example.test:443"]
    assert binding["case_sha256"] == plan["case_hash"]
    assert {entry["phase"] for entry in plan["dispatches"]} == {"setup", "resource"}
    with pytest.raises(configs.ConfigError):
        target_budget.prepare(configs.HttpxConfig.from_dict({}))
    cfg.test_case["setup"][0]["capture"] = {"id": "body.id"}
    with pytest.raises(configs.ConfigError, match="unsupported"):
        target_budget.prepare(cfg)


@pytest.mark.parametrize("change", ["missing", "binding", "charged", "spent", "limit"])
def test_receipt_mismatch_refuses_owned_execution(prepared, change):
    _, (binding, _) = prepared
    receipt = {"binding": binding, "charged": 2, "spent": 2, "limit": 2}
    if change == "missing":
        receipt = None
    elif change == "binding":
        receipt["binding"] = {**binding, "origins": ["https://wrong.example:443"]}
    else:
        receipt[change] = True if change == "charged" else 1
    client = Mock(spec=api.VardrMapClient)
    client.base = "https://map.example.test"
    client.claim_controlled.side_effect = lambda ident, rid, **kw: {
        "execution_control": {
            "job_id": ident,
            "runner_id": rid,
            "origin": client.base,
            "lease_seconds": 10,
            "token": "synthetic-capability-" * 3,
            "target_budget": receipt,
        }
    }
    owned = controlled_jobs.OwnedClient(client)
    owned.target_binding = binding
    with pytest.raises(ValueError, match="no legacy fallback"):
        owned.claim_job("job")


def test_target_guard_is_passed_through_owned_job_lifecycle(prepared, tmp_path, monkeypatch):
    cfg, (binding, plan) = prepared
    client = Mock(spec=api.VardrMapClient)
    client.base = "https://map.example.test"

    def claim(ident, rid, **options):
        assert options == {"target_binding": binding}
        return {
            "config": {"test_case": cfg.test_case},
            "execution_control": {
                "job_id": ident,
                "runner_id": rid,
                "origin": client.base,
                "lease_seconds": 10,
                "token": "synthetic-capability-" * 3,
                "target_budget": {"binding": binding, "charged": 2, "spent": 2, "limit": 2},
            },
        }

    client.claim_controlled.side_effect = claim
    monkeypatch.setattr(runner, "tool_available", lambda _: True)
    monkeypatch.setattr(execution_control, "available", lambda: True)
    monkeypatch.setattr(jobs, "_make_run_dir", lambda: tmp_path)
    with patch.object(handlers.VardrGateHandler, "execute", return_value=None) as execute:
        jobs._execute_one(
            client,
            Console(quiet=True),
            {
                "id": "job",
                "engagement_id": "eng",
                "tool_type": "vardrgate_api_test",
                "target_source": "config",
                "config": {"test_case": cfg.test_case},
            },
            True,
            journal_store=Journal(tmp_path / "runs.db"),
            controlled=True,
            target_budget=True,
        )
    assert execute.call_args.kwargs["request_guard"] == plan
    assert execute.call_args.args[2].execution == plan["execution"]
    calls = client.execution_control.call_args_list
    finishes = [call for call in calls if call.kwargs.get("finish") is True]
    assert len(finishes) == 1
    owned_binding = {
        "runner_id": client.claim_controlled.call_args.args[1],
        "origin": client.base,
        "token": "synthetic-capability-" * 3,
    }
    assert finishes[0].args == ("job", {**owned_binding, "outcome": "completed"})
    assert finishes[0].kwargs == {"finish": True}
    for refresh in calls:
        if refresh is not finishes[0]:
            assert refresh.args == ("job", owned_binding)
            assert refresh.kwargs == {}


def test_target_budget_requires_control_before_contact(monkeypatch):
    import typer

    heartbeat = Mock()
    monkeypatch.setattr(jobs, "send_heartbeat", heartbeat)
    with pytest.raises(typer.Exit):
        jobs.run_jobs(target_budget=True)
    heartbeat.assert_not_called()
