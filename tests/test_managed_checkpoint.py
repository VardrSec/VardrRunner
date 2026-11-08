"""Checkpoint decisions; all Runner native dispatch and HTTP remain inert."""

import copy
import json

import pytest

from tests.test_managed_partial_results import stop
from tests.test_managed_results import entry_fixture as entry_fixture
from tests.test_managed_results import result_fixture as result_fixture
from tests.test_managed_results import specimen as specimen
from vardrrunner import configs, handlers, runner
from vardrrunner.authorization import results
from vardrrunner.authorization.codec import AuthorizationError

_GATE_EXECUTE = handlers.VardrGateHandler.execute


def progress(case):
    value = dict(
        test_case_id=case["id"],
        error="execution_in_progress",
        findings=[],
        executions=[],
        assessments=[],
        preflight=[],
    )
    expected = {row["identity_id"]: row["decision"] for row in case["expected_access"]}
    for index, identity in enumerate(case["identities"]):
        value["executions"].append(
            dict(
                identity_id=identity["id"],
                status_code=0,
                observed_outcome="error",
                error="execution_in_progress",
            )
        )
        value["assessments"].append(
            dict(
                identity_id=identity["id"],
                expected_access=expected[identity["id"]],
                decision="inconclusive",
                source="none",
                reason="execution_in_progress",
                execution_index=index,
                write_verification="not_configured",
            )
        )
    return value


@pytest.mark.parametrize("cause", ["local_emergency_stop", "remote_stop_requested", "tool_timeout"])
def test_confirmed_stop_promotes_checkpoint_without_changing_original(
    result_fixture, monkeypatch, cause
):
    t = result_fixture
    source, original, _ = stop(t, monkeypatch, raw=progress(t.f.s.case), cause=cause)
    output, _, _ = t.handle._returned_artifact
    retained = json.loads(output.read_bytes())
    assert (
        source.read_bytes() == original and json.loads(original)["error"] == "execution_in_progress"
    )
    assert retained["error"] == "execution_cancelled"
    assert retained["case_hash"] == t.handle.gate.plan["case_hash"]
    assert all(row["error"] == "execution_cancelled" for row in retained["executions"])
    assert all(row["reason"] == "execution_error" for row in retained["assessments"])
    assert t.handle.finalize_stopped(t.submit, t.finish) is True
    assert t.calls == ["submit", "finish"] and t.state["completion"]["outcome"] == "failed"


@pytest.mark.parametrize(
    "confirmed,cause",
    [(False, "local_emergency_stop"), (1, "tool_timeout"), (True, "observed_exit")],
)
def test_progress_marker_never_grants_confirmed_stop(result_fixture, monkeypatch, confirmed, cause):
    t = result_fixture
    source, original, _ = stop(
        t, monkeypatch, raw=progress(t.f.s.case), confirmed=confirmed, cause=cause
    )
    assert source.read_bytes() == original and t.handle._returned_artifact is None
    assert t.handle.finalize_stopped(t.submit, t.finish) is False and not t.calls


@pytest.mark.parametrize(
    "fault",
    [
        "identity",
        "missing_actor",
        "index",
        "bool_index",
        "status",
        "pending_decision",
        "findings",
        "case",
        "marker_list",
        "marker_dict",
    ],
)
def test_malformed_checkpoint_preserves_existing_stop_lane(result_fixture, monkeypatch, fault):
    t = result_fixture
    value = progress(t.f.s.case)
    if fault == "identity":
        value["executions"][0]["identity_id"] = "substituted"
    elif fault == "missing_actor":
        value["assessments"].pop()
    elif fault == "index":
        value["assessments"][0]["execution_index"] += 1
    elif fault == "bool_index":
        value["assessments"][0]["execution_index"] = False
    elif fault == "status":
        value["executions"][0]["status_code"] = 200
    elif fault == "pending_decision":
        value["assessments"][0]["decision"] = "allowed"
    elif fault == "findings":
        value["findings"] = [{"message": "not a completed evaluation"}]
    elif fault in {"marker_list", "marker_dict"}:
        value["error"] = [] if fault == "marker_list" else {}
    else:
        value["test_case_id"] = "another-case"
    source, original, _ = stop(t, monkeypatch, raw=value)
    assert source.read_bytes() == original and t.handle._returned_artifact is None
    assert t.handle._confirmed_stop is not None
    assert t.handle.finalize_stopped(t.submit, t.finish) is False and not t.calls
    if fault in {"marker_list", "marker_dict"}:
        with pytest.raises(AuthorizationError, match="managed_partial_result"):
            results.retain_stopped_artifact(t.handle, t.f.directory)


def test_checkpoint_keeps_completed_observations_and_assessment(result_fixture, monkeypatch):
    t = result_fixture
    value = progress(t.f.s.case)
    execution, assessment = value["executions"][0], value["assessments"][0]
    execution.update(
        status_code=200, observed_outcome="allowed", headers={"Content-Type": "application/json"}
    )
    execution.pop("error")
    assessment.update(decision="allowed", source="http_status", reason="status_only")
    expected = copy.deepcopy((execution, assessment))
    stop(t, monkeypatch, raw=value)
    retained = json.loads(t.handle._returned_artifact[0].read_bytes())
    assert (retained["executions"][0], retained["assessments"][0]) == expected


def test_checkpoint_on_normal_return_sends_no_result_or_completion(result_fixture):
    t = result_fixture
    case_hash = t.raw["case_hash"]
    t.raw.update(progress(t.f.s.case), case_hash=case_hash)
    t.handle.execute(t.f.directory)
    assert t.handle._confirmed_stop is None
    with pytest.raises(AuthorizationError, match="managed_checkpoint_not_final"):
        t.handle.finalize(t.submit, t.finish)
    assert not t.calls


def test_normal_handler_rejects_checkpoint_before_rebinding(result_fixture, monkeypatch):
    t = result_fixture
    original = json.dumps(progress(t.f.s.case))
    monkeypatch.setattr(handlers, "_resolve_identity_secrets", lambda case, engagement: case)

    def inert(job, output, **kwargs):
        output.write_text(original)
        return 0

    monkeypatch.setattr(runner, "run_vardrgate", inert)
    cfg = configs.VardrGateConfig.from_dict({"test_case": t.f.s.case, "execution": t.f.s.execution})
    with pytest.raises(runner.ToolError, match="checkpoint is not a final result"):
        _GATE_EXECUTE(handlers.VardrGateHandler(), [], t.f.directory, cfg)
    assert (t.f.directory / "vardrgate_result.json").read_text() == original
