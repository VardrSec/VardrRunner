"""Confirmed-stop evidence decisions; no native processes or signals are used."""

import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.test_managed_claim import entry_fixture as entry_fixture
from tests.test_managed_claim import specimen as specimen
from tests.test_managed_results import result_fixture as result_fixture
from vardrrunner import execution_control, handlers, launch_guard
from vardrrunner.authorization import results
from vardrrunner.authorization.codec import AuthorizationError, encoded
from vardrrunner.journal import Phase


def cancelled_artifact(case_id):
    return {
        "test_case_id": case_id,
        "executions": [
            {
                "identity_id": "owner",
                "status_code": 0,
                "observed_outcome": "error",
                "error": "execution_cancelled",
            }
        ],
        "findings": [],
        "assessments": [
            {
                "identity_id": "owner",
                "expected_access": "allow",
                "decision": "inconclusive",
                "source": "none",
                "reason": "execution_error",
                "execution_index": 0,
                "write_verification": "not_configured",
            }
        ],
        "error": "execution_cancelled",
    }


def stop(t, monkeypatch, *, raw=None, confirmed=True, cause="local_emergency_stop"):
    source = t.f.directory / "vardrgate_result.json"
    data = encoded(cancelled_artifact(t.f.s.case["id"]) if raw is None else raw)

    def inert(self, targets, directory, cfg, **kwargs):
        with launch_guard.boundary():
            pass
        t.f.journal.transition(t.handle.run_id, Phase.EXECUTING, pid=600001)
        source.write_bytes(data)
        raise execution_control.ExecutionStopped(cause, confirmed, pid=600001)

    monkeypatch.setattr(handlers.VardrGateHandler, "execute", inert)
    with pytest.raises(execution_control.ExecutionStopped) as stopped:
        t.handle.execute(t.f.directory)
    return source, data, stopped.value


@pytest.mark.parametrize("cause", ["local_emergency_stop", "remote_stop_requested", "tool_timeout"])
def test_confirmed_stop_keeps_original_and_publishes_only_failed_result(
    result_fixture, monkeypatch, cause
):
    t = result_fixture
    source, original, _ = stop(t, monkeypatch, cause=cause)
    record = t.f.journal.get(t.handle.run_id)
    output = Path(record.artifact_path)
    bound = json.loads(output.read_bytes())
    assert source.read_bytes() == original and output != source
    payload = bound.copy()
    provenance = payload.pop("provenance")
    assert payload == {**json.loads(original), "case_hash": t.handle.gate.plan["case_hash"]}
    assert provenance["case_hash"] == t.handle.gate.plan["case_hash"]
    assert provenance["case_snapshot"]["id"] == t.handle.gate.case["id"]
    assert provenance["tools"] == {
        "vardrgate_api_test": {
            "sha256": t.handle.gate.plan["tool_sha256"],
            "version": "unknown",
            "hash_basis": "approved_plan_not_observed",
        }
    }
    assert provenance["requires_new_review"] is True
    assert provenance["execution_authority"] is False
    assert provenance["independent_reproduction"] == "not_performed"
    assert record.pid is None and record.failure_reason == cause
    if os.name != "nt":
        assert output.stat().st_mode & 0o777 == 0o600
    assert t.handle.finalize_stopped(t.submit, t.finish) is True
    assert t.calls == ["submit", "finish"]
    assert t.state["completion"]["outcome"] == "failed"
    assert t.f.journal.get(t.handle.run_id).phase == Phase.FAILED
    assert t.f.journal.get(t.handle.run_id).failure_reason == cause
    send_stop = Mock()
    with pytest.raises(AuthorizationError, match="known_native_stop_required"):
        t.handle.report_stop(send_stop)
    send_stop.assert_not_called()


@pytest.mark.parametrize(
    "confirmed,cause",
    [(False, "local_emergency_stop"), (1, "tool_timeout"), (True, "observed_exit")],
)
def test_marker_never_supplies_native_stop_proof(result_fixture, monkeypatch, confirmed, cause):
    t = result_fixture
    stop(t, monkeypatch, confirmed=confirmed, cause=cause)
    assert t.handle.finalize_stopped(t.submit, t.finish) is False
    assert not t.calls and t.handle._returned_artifact is None
    assert t.f.journal.get(t.handle.run_id).pid == 600001


@pytest.mark.parametrize("fault", ["case", "marker", "shape", "oversize", "existing_destination"])
def test_invalid_or_unpublishable_partial_retains_existing_stop_lane(
    result_fixture, monkeypatch, fault
):
    t = result_fixture
    raw = cancelled_artifact(t.f.s.case["id"])
    if fault == "case":
        raw["test_case_id"] = "another-case"
    elif fault == "marker":
        raw["error"] = "not a cancellation marker"
    elif fault == "shape":
        raw["executions"] = "not a list"
    elif fault == "oversize":
        raw["executions"][0]["body"] = "x" * 512000
    else:
        (t.f.directory / "vardrgate_stopped_result.json").write_bytes(b"preserve existing bytes")
    source, original, _ = stop(t, monkeypatch, raw=raw)
    assert source.read_bytes() == original
    assert t.handle.finalize_stopped(t.submit, t.finish) is False and not t.calls
    assert t.handle._confirmed_stop is not None and t.handle._returned_artifact is None
    assert t.f.journal.get(t.handle.run_id).pid == 600001
    if fault == "existing_destination":
        assert (
            t.f.directory / "vardrgate_stopped_result.json"
        ).read_bytes() == b"preserve existing bytes"


@pytest.mark.parametrize("lost", ["submit", "finish"])
def test_partial_send_ambiguity_never_retries_or_switches_to_stop(
    result_fixture, monkeypatch, lost
):
    t = result_fixture
    stop(t, monkeypatch)

    def unknown(body):
        raise OSError("synthetic unknown reply")

    with pytest.raises(AuthorizationError, match="outcome_unknown"):
        t.handle.finalize_stopped(
            unknown if lost == "submit" else t.submit, unknown if lost == "finish" else t.finish
        )
    before = list(t.calls)
    with pytest.raises(AuthorizationError):
        t.handle.finalize_stopped(t.submit, t.finish)
    assert t.calls == before
    with pytest.raises(AuthorizationError, match="known_native_stop_required"):
        t.handle.report_stop(Mock(side_effect=AssertionError("stop fallback forbidden")))


def test_staged_artifact_tamper_sends_nothing_and_cannot_fall_back(result_fixture, monkeypatch):
    t = result_fixture
    stop(t, monkeypatch)
    output = t.handle._returned_artifact[0]
    output.write_bytes(output.read_bytes().replace(b"execution_cancelled", b"execution_changed!!"))
    with pytest.raises(AuthorizationError):
        t.handle.finalize_stopped(t.submit, t.finish)
    assert not t.calls
    with pytest.raises(AuthorizationError):
        t.handle.report_stop(Mock(side_effect=AssertionError("stop fallback forbidden")))


def test_empty_cancelled_setup_can_never_become_completed(result_fixture, monkeypatch):
    t = result_fixture
    raw = cancelled_artifact(t.f.s.case["id"])
    raw.update(executions=[], assessments=[], preflight=[])
    stop(t, monkeypatch, raw=raw)
    t.handle.finalize_stopped(t.submit, t.finish)
    assert t.state["completion"]["outcome"] == "failed"


def test_marker_on_normal_return_is_failure_without_manufacturing_stop_proof(result_fixture):
    t = result_fixture
    t.raw["error"] = "execution_cancelled"
    t.handle.execute(t.f.directory)
    assert t.handle._confirmed_stop is None
    assert t.handle.finalize_stopped(t.submit, t.finish) is False and not t.calls
    t.handle.finalize(t.submit, t.finish)
    assert t.state["completion"]["outcome"] == "failed"


def test_lost_partial_terminal_reply_uses_only_existing_readonly_observation(
    result_fixture, monkeypatch
):
    t = result_fixture
    stop(t, monkeypatch)

    def lost(body):
        t.finish(body)
        raise OSError("synthetic committed terminal reply lost")

    with pytest.raises(AuthorizationError, match="managed_finish_outcome_unknown"):
        t.handle.finalize_stopped(t.submit, lost)
    before = list(t.calls)
    assert results.reconcile(t.f.journal, t.handle.run_id, t.inspect) == "terminal_receipt_observed"
    assert t.calls == before + ["inspect"]
    record = t.f.journal.get(t.handle.run_id)
    assert record.phase == Phase.FAILED and record.failure_reason == "local_emergency_stop"


def test_bounded_reader_rejects_directory_and_real_hardlink(tmp_path):
    path = tmp_path / "result.json"
    path.write_bytes(b"{}")
    with pytest.raises(AuthorizationError):
        results._artifact_bytes(tmp_path, 512000)
    alias = tmp_path / "alias.json"
    os.link(path, alias)
    with pytest.raises(AuthorizationError):
        results._artifact_bytes(path, 512000)


def test_bounded_reader_rejects_real_symlink(tmp_path):
    path = tmp_path / "result.json"
    path.write_bytes(b"{}")
    alias = tmp_path / "alias.json"
    try:
        alias.symlink_to(path)
    except OSError as error:
        if os.name == "nt" and getattr(error, "winerror", None) == 1314:
            pytest.skip(
                "Real Windows symlink privilege unavailable; reparse rejection is checked separately"
            )
        raise
    with pytest.raises(AuthorizationError):
        results._artifact_bytes(alias, 512000)


def test_windows_reparse_flag_refuses_before_open_even_when_reported_regular(monkeypatch):
    path = Path("never-opened.json")
    info = SimpleNamespace(st_mode=0o100600, st_nlink=1, st_file_attributes=0x400, st_size=2)
    monkeypatch.setattr(Path, "lstat", lambda self: info)
    opened = Mock(side_effect=AssertionError("reparse path must never be opened"))
    monkeypatch.setattr(results.os, "open", opened)
    with pytest.raises(AuthorizationError, match="managed_partial_file"):
        results._artifact_bytes(path, 512000)
    opened.assert_not_called()


def test_reader_refuses_source_replacement_at_open(tmp_path, monkeypatch):
    path = tmp_path / "result.json"
    path.write_bytes(b"{}")
    original = results.os.open

    def replaced(candidate, flags, *args, **kwargs):
        if candidate == path:
            path.rename(tmp_path / "original.json")
            path.write_bytes(b"[]")
        return original(candidate, flags, *args, **kwargs)

    monkeypatch.setattr(results.os, "open", replaced)
    with pytest.raises(AuthorizationError, match="managed_partial_changed"):
        results._artifact_bytes(path, 512000)
    assert (tmp_path / "original.json").read_bytes() == b"{}"
