"""Bounded v2 composition, real journals/policy, inert tool and HTTP boundaries."""

import copy
import json
import threading
import time
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.test_managed_claim import entry_fixture as entry_fixture
from tests.test_managed_claim import specimen as specimen
from tests.test_managed_results import result_fixture as result_fixture
from tests.test_managed_worker import worker_fixture as worker_fixture
from tests.test_worker_admission import admission_document as admission_document
from vardrrunner import execution_control, handlers, launch_guard
from vardrrunner.authorization.codec import AuthorizationError, digest, encoded, fields, sign, unb64
from vardrrunner.authorization.results import BINDING
from vardrrunner.authorization.worker_admission import Admission
from vardrrunner.authorization.worker_binding import (
    SequenceStore,
    claim_association,
    sequence_holds,
)
from vardrrunner.journal import Phase
from vardrrunner.managed_worker import _EpochRefresh


@pytest.fixture
def sequence_worker(worker_fixture, monkeypatch):
    t = worker_fixture
    worker = t.make()
    worker.admission = replace(t.admission, max_attempts=2)
    worker.store = SequenceStore(t.f.journal)
    epochs, controls = [], []
    failure = {"done": False, "preflight": False}

    class Epoch:
        def __init__(self, sequence):
            self.sequence, self.active = sequence, True
            self.binding = None

        def require_active(self):
            if not self.active:
                raise AuthorizationError("sealed_epoch")

        def verified_lease(self, binding, lease, hard):
            self.require_active()
            fields(binding, BINDING)
            assert self.binding is None or self.binding == binding
            self.binding = copy.deepcopy(binding)

        def seal(self):
            self.require_active()
            self.active = False

        def quiescence_deadline(self):
            return 10

        def finished(self):
            assert not self.active and controls[-1].worker_quiescent()
            if failure["done"]:
                raise OSError("synthetic lost DONE ACK")
            t.calls.append("done")
            return str(self.sequence) * 64

    def begin(sequence):
        epoch = Epoch(sequence)
        epochs.append(epoch)
        return epoch

    t.owner.begin_attempt.side_effect = begin
    original = t.client.managed_post

    def next_job():
        s = t.f.s
        s.context = replace(s.context, job_id=s.context.job_id + "-next", fence=2)
        wire = s.claim["managed_authorization"]
        approval = json.loads(unb64(wire["approval"]["payload"]))
        approval["approval_id"] += "-next"
        approval["context"]["job_id"] = s.context.job_id
        wire["approval"] = sign(approval, bytes(range(32)), "approval")
        contract = json.loads(unb64(wire["contract"]["payload"]))
        contract.update(
            job_id=s.context.job_id,
            attempt_id=s.context.attempt_id + "-next",
            contract_id=contract["contract_id"] + "-next",
            approval_id=approval["approval_id"],
            fence=2,
            approval_sha256=digest(encoded(wire["approval"])),
        )
        wire["contract"] = sign(contract, bytes(range(32, 64)), "contract")
        s.context = replace(s.context, attempt_id=contract["attempt_id"])
        s.claim["execution_control"]["job_id"] = s.context.job_id
        s.reply.update(
            job_id=s.context.job_id,
            contract_id=contract["contract_id"],
            attempt_id=contract["attempt_id"],
            fence=2,
        )

    def rpc(path, body):
        operation = path.rsplit("/", 1)[-1]
        if operation == "runtime-idle-release":
            t.calls.append(operation)
            assert body["token"] == "x" * 40
            if isinstance(t.faults.get(operation), BaseException):
                raise t.faults[operation]
            binding = {k: body[k] for k in BINDING - {"job_id"}}
            binding["job_id"] = t.f.s.context.job_id
            ack = {
                "schema": "vardr.worker-idle-release/1",
                **{
                    k: body[k]
                    for k in (
                        "runtime_id",
                        "runtime_sha256",
                        "runtime_sequence",
                        "terminal_receipt_sha256",
                        "native_done_sha256",
                    )
                },
                "binding": binding,
                "released": True,
            }
            ack["receipt_sha256"] = digest(encoded(ack))
            if t.faults.get("release_ack_bool"):
                ack["binding"]["fence"] = True
            if body["runtime_sequence"] == 1:
                next_job()
            return ack
        reply = original(path, body)
        if operation == "claim":
            assert body["runtime_sequence"] == len(epochs)
        if operation == "runtime-bind":
            reply.update(
                schema="vardr.worker-runtime-binding/2", runtime_sequence=body["runtime_sequence"]
            )
        return reply

    t.client.managed_post = rpc

    def inert(self, targets, directory, cfg, **kwargs):
        with launch_guard.boundary():
            with t.f.journal._connection() as con:
                row = con.execute(
                    "SELECT * FROM managed_worker_attempts WHERE runtime_sequence=?", (len(epochs),)
                ).fetchone()
                assert row["state"] == "bound"
                claim = con.execute(
                    "SELECT * FROM managed_claim_intents WHERE run_id=?", (row["run_id"],)
                ).fetchone()
                assert claim["consumption_acknowledged"] == 1
            controls.append(execution_control.current())
            t.calls.append("native")
        output = directory / "vardrgate_result.json"
        output.write_text(
            json.dumps(
                {
                    "case_hash": kwargs["request_guard"]["case_hash"],
                    "test_case_id": cfg.test_case["id"],
                    "executions": [],
                    "findings": [],
                    "preflight": [{"status": "failed"}] if failure["preflight"] else [],
                }
            )
        )
        return output

    monkeypatch.setattr(handlers.VardrGateHandler, "execute", inert)
    return SimpleNamespace(t=t, worker=worker, epochs=epochs, controls=controls, failure=failure)


def test_two_jobs_keep_distinct_attempts_and_release_only_after_done(sequence_worker):
    s = sequence_worker
    assert s.worker.run().phase == Phase.DONE
    assert len(s.epochs) == len(s.controls) == 2 and s.controls[0] is not s.controls[1]
    assert [call for call in s.t.calls if call != "refresh"] == [
        "pending",
        "claim",
        "consume",
        "runtime-bind",
        "native",
        "result",
        "finish",
        "done",
        "runtime-idle-release",
        "pending",
        "claim",
        "consume",
        "runtime-bind",
        "native",
        "result",
        "finish",
        "done",
        "runtime-idle-release",
    ]
    with s.t.f.journal._connection() as con:
        rows = con.execute(
            "SELECT * FROM managed_worker_attempts ORDER BY runtime_sequence"
        ).fetchall()
        assert [row["state"] for row in rows] == ["released", "released"]
        assert rows[0]["run_id"] != rows[1]["run_id"] and rows[0]["binding"] != rows[1]["binding"]
        assert [claim_association(con, row["run_id"])["runtime_sequence"] for row in rows] == [1, 2]
        assert sequence_holds(con) == 0
        assert "x" * 40 not in "\n".join(con.iterdump())


@pytest.mark.parametrize("lost", [None, "result", "finish", "interrupt"])
def test_confirmed_partial_result_never_done_releases_or_claims_next(
    sequence_worker, monkeypatch, lost
):
    s = sequence_worker
    stopped = execution_control.ExecutionStopped("local_emergency_stop", True, pid=600001)

    def partial(self, targets, directory, cfg, **kwargs):
        with launch_guard.boundary():
            pass
        record = s.t.f.journal.list()[0]
        s.t.f.journal.transition(record.run_id, Phase.EXECUTING, pid=600001)
        (directory / "vardrgate_result.json").write_text(
            json.dumps(
                {
                    "test_case_id": cfg.test_case["id"],
                    "executions": [],
                    "findings": [],
                    "assessments": [],
                    "error": "execution_cancelled",
                }
            )
        )
        s.t.calls.append("native")
        raise stopped

    monkeypatch.setattr(handlers.VardrGateHandler, "execute", partial)
    if lost:
        s.t.faults["result" if lost == "interrupt" else lost] = (
            KeyboardInterrupt()
            if lost == "interrupt"
            else OSError("synthetic unknown result reply")
        )
    with pytest.raises(execution_control.ExecutionStopped) as caught:
        s.worker.run()
    assert caught.value is stopped
    assert s.t.calls.count("pending") == s.t.calls.count("claim") == s.t.calls.count("native") == 1
    assert "stopped" not in s.t.calls and "done" not in s.t.calls
    assert "runtime-idle-release" not in s.t.calls and "owner_finished" not in s.t.calls
    assert len(s.epochs) == 1
    with s.t.f.journal._connection() as con:
        assert sequence_holds(con) == 1
        result = con.execute("SELECT * FROM managed_result_intents").fetchone()
    assert result["outcome"] == "failed"
    assert (
        result["state"]
        == (
            {
                None: "terminal",
                "result": "result_in_flight",
                "finish": "finish_in_flight",
                "interrupt": "result_in_flight",
            }[lost]
        )
    )


def test_bounded_idle_after_healthy_release_does_not_reclaim(sequence_worker):
    s = sequence_worker
    original = s.t.client.managed_post

    def idle(path, body):
        if path.endswith("/pending") and "runtime-idle-release" in s.t.calls:
            s.t.calls.append("pending_idle")
            return {"jobs": [], "next_after": None}
        return original(path, body)

    s.t.client.managed_post = idle
    assert s.worker.run(wait_seconds=2, poll_seconds=0.5).phase == Phase.DONE
    assert s.t.calls.count("claim") == 1 and s.t.calls.count("pending_idle") == 4
    with s.t.f.journal._connection() as con:
        assert sequence_holds(con) == 0
        assert (
            con.execute("SELECT last_sequence FROM managed_worker_incarnations").fetchone()[0] == 1
        )
    with pytest.raises(AuthorizationError, match="already_invoked"):
        s.worker.store.reserve_runtime(
            s.worker.admission.runtime_id, s.worker.admission.runtime_sha256, 2
        )


def test_explicit_maximum_one_ends_after_one_healthy_attempt(sequence_worker):
    s = sequence_worker
    s.worker.admission = replace(s.worker.admission, max_attempts=1)
    assert s.worker.run().phase == Phase.DONE
    assert s.t.calls.count("claim") == 1 and len(s.epochs) == 1


@pytest.mark.parametrize(
    "fault",
    ["result", "finish", "done", "runtime-idle-release", "failed_completion", "release_ack_bool"],
)
def test_uncertain_or_failed_first_attempt_never_claims_next(sequence_worker, fault):
    s = sequence_worker
    if fault == "done":
        s.failure["done"] = True
    elif fault == "failed_completion":
        s.failure["preflight"] = True
    elif fault == "release_ack_bool":
        s.t.faults[fault] = True
    else:
        s.t.faults[fault] = OSError("synthetic lost ACK")
    with pytest.raises((AuthorizationError, OSError)):
        s.worker.run()
    assert s.t.calls.count("claim") == s.t.calls.count("pending") == 1
    with s.t.f.journal._connection() as con:
        assert sequence_holds(con) == 1
        row = con.execute("SELECT * FROM managed_worker_attempts").fetchone()
        assert row["release_ack"] is None
        if fault == "runtime-idle-release":
            assert s.t.f.journal.get(row["run_id"]).phase == Phase.DONE
            assert row["state"] == "release_in_flight" and row["native_done_sha256"] is not None


@pytest.mark.parametrize("mutation", ["gap", "max", "active", "ack_digest", "completion"])
def test_history_or_release_tampering_cannot_clear_holds(sequence_worker, mutation):
    s = sequence_worker
    s.worker.run()
    with s.t.f.journal._connection() as con:
        if mutation == "gap":
            con.execute("DELETE FROM managed_worker_attempts WHERE runtime_sequence=2")
        elif mutation == "max":
            con.execute("UPDATE managed_worker_incarnations SET max_attempts=0")
        elif mutation == "active":
            con.execute("UPDATE managed_worker_incarnations SET active_sequence=1")
        elif mutation == "ack_digest":
            row = con.execute(
                "SELECT release_ack FROM managed_worker_attempts WHERE runtime_sequence=1"
            ).fetchone()
            changed = json.loads(row[0])
            changed["receipt_sha256"] = "0" * 64
            con.execute(
                "UPDATE managed_worker_attempts SET release_ack=?,release_intent=? WHERE runtime_sequence=1",
                (encoded(changed).decode(), encoded(changed).decode()),
            )
        else:
            con.execute(
                "UPDATE managed_worker_attempts SET completion='{}' WHERE runtime_sequence=1"
            )
        with pytest.raises((AuthorizationError, KeyError)):
            sequence_holds(con)


def test_explicit_v2_admission_bounds_do_not_upgrade_v1(admission_document):
    from tests.test_worker_admission import NOW

    now = NOW
    assert Admission.parse(admission_document, now=now).max_attempts is None
    admission_document.update(schema="vardr.worker-admission/2", max_attempts=2)
    assert Admission.parse(admission_document, now=now).max_attempts == 2
    for bad in (True, 0, 33, "2"):
        admission_document["max_attempts"] = bad
        with pytest.raises(AuthorizationError):
            Admission.parse(admission_document, now=now)


def test_v2_entrypoint_refuses_legacy_admission_before_connect(worker_fixture, monkeypatch, capsys):
    from vardrrunner import managed_worker, worker_lifecycle

    t = worker_fixture
    monkeypatch.setattr(
        managed_worker.config, "require_auth", lambda: (t.admission.origin, "synthetic-key")
    )
    monkeypatch.setattr(
        managed_worker.identity,
        "load_or_create",
        lambda: SimpleNamespace(runner_id=t.admission.runner_id),
    )
    monkeypatch.setattr(managed_worker, "await_admission", lambda *args: t.admission)
    connect = Mock()
    monkeypatch.setattr(worker_lifecycle, "connect", connect)
    assert managed_worker.main([]) == 1
    connect.assert_not_called()
    assert t.calls == [] and capsys.readouterr().out == "managed_worker_held\n"


def test_finalization_returns_only_original_validated_durable_completion(result_fixture):
    t = result_fixture
    t.handle.execute(t.f.directory)
    actual = t.handle.finalize(t.submit, t.finish)
    assert actual == t.state["completion"] and actual is not t.state["completion"]
    assert t.f.journal.get(t.handle.run_id).phase == Phase.DONE


def test_sealed_epoch_rejects_late_refresh_and_bounded_join_refuses_reuse():
    entered, release = threading.Event(), threading.Event()
    epoch = Mock()
    active = [True]

    def require_active():
        if not active[0]:
            raise AuthorizationError("sealed_epoch")

    epoch.require_active.side_effect = require_active

    def blocked(body):
        entered.set()
        assert release.wait(3)
        return {"job_id": "a", "action": "continue", "lease_seconds": 10}

    refresh = _EpochRefresh(epoch, blocked)
    control = execution_control.Control(
        lambda: refresh({}), {"job_id": "a"}, 10, started=time.monotonic(), local_stop=lambda: False
    )
    control.__enter__()
    try:
        assert entered.wait(2)
        active[0] = False
        with pytest.raises(RuntimeError, match="quiescence"):
            control.quiesce(time.monotonic() + 0.01)
        assert not control.worker_quiescent()
        with pytest.raises(AuthorizationError, match="in_flight"):
            refresh.require_quiescent()
    finally:
        release.set()
        control.quiesce(time.monotonic() + 2)
    assert control.worker_quiescent()
    refresh.require_quiescent()
    assert control.deadline < time.monotonic() + 10
    with pytest.raises(AuthorizationError, match="sealed_epoch"):
        refresh({})
