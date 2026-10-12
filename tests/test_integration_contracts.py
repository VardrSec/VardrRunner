"""Cross-product queue contracts and operator-owned network settings."""

from unittest.mock import patch

import pytest

from vardrrunner.api import VardrMapClient
from vardrrunner.configs import ConfigError, JobEnvelope, VardrGateConfig
from vardrrunner.handlers import VardrGateHandler


@pytest.mark.parametrize(
    "ids",
    [
        {"program_id": "p"},
        {"engagement_id": "p"},
        {"program_id": "p", "engagement_id": "p"},
    ],
)
def test_pending_wire_ids_reach_envelope(ids):
    job = {"id": "job", "tool_type": "httpx", "target_source": "scope", **ids}
    client = VardrMapClient("https://example.test", "test")
    with patch.object(client, "get", return_value={"jobs": [job]}):
        assert JobEnvelope.from_dict(client.pending_jobs()[0]).engagement_id == "p"
    assert job == {"id": "job", "tool_type": "httpx", "target_source": "scope", **ids}


def test_conflicting_wire_ids_fail_before_execution():
    job = {
        "id": "job",
        "tool_type": "httpx",
        "target_source": "scope",
        "program_id": "a",
        "engagement_id": "b",
    }
    client = VardrMapClient("https://example.test", "test")
    with patch.object(client, "get", return_value={"jobs": [job]}):
        with pytest.raises(ConfigError, match="conflicting"):
            JobEnvelope.from_dict(client.pending_jobs()[0])


@pytest.mark.parametrize("value", [0, 86401, True, 1.5, "5"])
def test_gate_rejects_invalid_timeout(value):
    with pytest.raises(ConfigError):
        VardrGateConfig.from_dict({"test_case": {"id": "case"}, "timeout": value})


def test_gate_conflicting_timeouts():
    with pytest.raises(ConfigError, match="conflicting"):
        VardrGateConfig.from_dict(
            {"test_case": {"id": "case"}, "timeout": 5, "execution": {"timeout_seconds": 10}}
        )


@pytest.mark.parametrize(
    "local,requested,allowed",
    [
        (None, False, False),
        (None, True, False),
        ("0", True, False),
        ("true", True, False),
        ("1", False, True),
    ],
)
def test_private_targets_require_local_opt_in(monkeypatch, tmp_path, local, requested, allowed):
    monkeypatch.delenv("VARDRRUNNER_ALLOW_PRIVATE_TARGETS", raising=False)
    if local is not None:
        monkeypatch.setenv("VARDRRUNNER_ALLOW_PRIVATE_TARGETS", local)
    cfg = VardrGateConfig.from_dict(
        {
            "test_case": {"id": "case"},
            "timeout": 5,
            "execution": {"allow_private_targets": requested},
        }
    )
    with patch(
        "vardrrunner.runner.run_vardrgate",
        side_effect=lambda job, output, timeout=None: output.write_text(
            '{"executions":[],"findings":[]}'
        ),
    ) as run:
        VardrGateHandler().execute([], tmp_path, cfg)
    execution = run.call_args.args[0]["config"]["execution"]
    assert execution["allow_private_targets"] is allowed
    assert execution["timeout_seconds"] == run.call_args.kwargs["timeout"] == 5
    assert cfg.execution["allow_private_targets"] is requested
