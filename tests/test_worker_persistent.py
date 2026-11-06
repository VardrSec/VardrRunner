"""Inactive persistent composition with real journals/validators and inert I/O."""

import copy
import json
import threading
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest

from tests.test_managed_claim import entry_fixture as entry_fixture
from tests.test_managed_claim import specimen as specimen
from tests.test_managed_worker import worker_fixture as worker_fixture
from tests.test_worker_admission import admission_document as admission_document
from vardrrunner import api, credential_grants, execution_control, handlers, launch_guard
from vardrrunner.authorization.codec import AuthorizationError, digest, encoded, sign, unb64
from vardrrunner.authorization.results import BINDING
from vardrrunner.authorization.worker_admission import Admission
from vardrrunner.authorization.worker_persistent import PersistentStore


@pytest.fixture
def persistent_worker(worker_fixture, monkeypatch):
    t = worker_fixture
    worker = t.make()
    runner = "11111111-1111-4111-8111-111111111111"
    base_context = t.f.s.context
    base_claim = copy.deepcopy(t.f.s.claim)
    base_reply = copy.deepcopy(t.f.s.reply)
    base_approval = json.loads(unb64(base_claim["managed_authorization"]["approval"]["payload"]))
    base_contract = json.loads(unb64(base_claim["managed_authorization"]["contract"]["payload"]))
    settings = {
        "jobs": 1,
        "idle_polls": 0,
        "failed": False,
        "cancelled": False,
        "fault": None,
        "limits": {"max_attempts": None, "idle_timeout_seconds": None},
    }
    state = {"released": 0, "prepared": 0, "pending": 0}
    epochs, controls = [], []
    refresh_rejected = threading.Event()

    def stamp(value):
        return value.strftime("%Y-%m-%dT%H:%M:%SZ")

    def install(number):
        s = t.f.s
        instant = base_context.now + timedelta(seconds=s.ticks[0])
        claim = copy.deepcopy(base_claim)
        wire = claim["managed_authorization"]
        snapshot = wire["authority_snapshot"]
        snapshot["enrollment"]["runner_id"] = runner
        authority = digest(encoded(snapshot))
        approval = copy.deepcopy(base_approval)
        approval["approval_id"] = "approval-" + str(number)
        approval["approved_at"] = stamp(instant)
        permission = approval["context"]
        permission.update(runner_id=runner, job_id="job-" + str(number), authority_sha256=authority)
        for field in ("not_before", "testing_start"):
            permission[field] = stamp(instant - timedelta(seconds=1))
        for field in ("expires_at", "testing_end"):
            permission[field] = stamp(instant + timedelta(seconds=60))
        for grant in permission["credential_grants"]:
            grant["expires_at"] = stamp(instant + timedelta(seconds=60))
        wire["approval"] = sign(approval, bytes(range(32)), "approval")
        contract = copy.deepcopy(base_contract)
        contract.update(
            runner_id=runner,
            job_id=permission["job_id"],
            attempt_id="attempt-" + str(number),
            contract_id="contract-" + str(number),
            fence=1,
            approval_id=approval["approval_id"],
            approval_sha256=digest(encoded(wire["approval"])),
            issued_at=stamp(instant),
            expires_at=permission["expires_at"],
        )
        wire["contract"] = sign(contract, bytes(range(32, 64)), "contract")
        claim["execution_control"].update(runner_id=runner, job_id=permission["job_id"])
        s.context = replace(
            base_context,
            runner_id=runner,
            job_id=permission["job_id"],
            attempt_id=contract["attempt_id"],
            fence=1,
            authority_sha256=authority,
        )
        s.claim = claim
        s.reply = {
            **base_reply,
            "runner_id": runner,
            "job_id": permission["job_id"],
            "contract_id": contract["contract_id"],
            "attempt_id": contract["attempt_id"],
            "fence": 1,
            "authority_sha256": authority,
            "lease_expires_at": stamp(instant + timedelta(seconds=10)),
        }
        for _, source, name in handlers.credential_references(s.case):
            for origin in handlers._case_origins(s.case):
                credential_grants.Store().approve(
                    snapshot["origin"], s.context.engagement_id, origin, source, name, 60
                )
        state["prepared"] = number

    class Epoch:
        def __init__(self, number):
            self.number, self.active = number, True

        def require_active(self):
            if not self.active:
                raise AuthorizationError("sealed_epoch")

        def verified_lease(self, binding, lease, hard):
            self.require_active()
            assert set(binding) == BINDING

        def seal(self):
            self.active = False

        def quiescence_deadline(self):
            return t.f.s.ticks[0] + 10

        def finished(self):
            assert not self.active and controls[-1].worker_quiescent()
            assert not controls[-1].stop_reason()
            assert controls[-1].worker_reuse_safe()
            t.calls.append("done")
            return digest(encoded({"native_ack_sequence": str(self.number)}))

    def begin(number):
        epoch = Epoch(number)
        epochs.append(epoch)
        return epoch

    t.owner.begin_attempt.side_effect = begin
    original = t.client.managed_post

    def rpc(path, body):
        operation = path.rsplit("/", 1)[-1]
        if operation == "pending":
            state["pending"] += 1
            assert body["admission_sha256"] == worker.admission.admission_sha256
            assert body["cursor"] == {"last_sequence": str(state["released"]), "phase": "idle"}
            t.calls.append("pending")
            availability = {
                "state": "idle-ready",
                "observed_at": None,
                "fresh_until": None,
                "cursor": body["cursor"],
            }
            if settings["fault"] == "idle_transport" and state["pending"] == 1:
                raise api.ManagedTransportError("synthetic idle loss")
            if state["pending"] <= settings["idle_polls"]:
                return {"jobs": [], "next_after": None, "availability": availability}
            if state["released"] >= settings["jobs"]:
                if settings["jobs"] == 0:
                    return {"jobs": [], "next_after": None, "availability": availability}
                availability["state"] = "stopped"
                return {"jobs": [], "next_after": None, "availability": availability}
            if state["prepared"] != state["released"] + 1:
                install(state["released"] + 1)
            return {
                "jobs": [
                    {
                        "id": t.f.s.context.job_id,
                        "program_id": t.f.s.context.engagement_id,
                        "tool_type": "vardrgate_api_test",
                        "authorization_contract_required": True,
                        "config": {"test_case": copy.deepcopy(t.f.s.case)},
                        "plan": copy.deepcopy(t.f.s.claim["managed_authorization"]["plan"]),
                    }
                ],
                "next_after": None,
                "availability": availability,
            }
        if settings["fault"] == operation:
            t.calls.append(operation)
            raise api.ManagedTransportError("synthetic unknown mutation reply")
        if operation == "runtime-idle-release":
            t.calls.append(operation)
            assert type(body["runtime_sequence"]) is str
            binding = {key: body[key] for key in BINDING - {"job_id"}}
            binding["job_id"] = t.f.s.context.job_id
            ack = {
                "schema": "vardr.worker-idle-release/2",
                **{
                    key: body[key]
                    for key in (
                        "runtime_id",
                        "runtime_sha256",
                        "admission_sha256",
                        "runtime_sequence",
                        "terminal_receipt_sha256",
                        "native_done_sha256",
                    )
                },
                "binding": binding,
                "released": True,
            }
            ack["receipt_sha256"] = digest(encoded(ack))
            state["released"] += 1
            return ack
        if operation == "claim":
            assert body["runtime_sequence"] == str(len(epochs))
            assert body["admission_sha256"] == worker.admission.admission_sha256
        reply = original(path, body)
        if operation == "refresh" and settings["fault"] == "refresh_validation" and controls:
            reply["lease_seconds"] = True
            refresh_rejected.set()
        if operation == "runtime-bind":
            reply.update(
                schema="vardr.worker-runtime-binding/3",
                runtime_sequence=body["runtime_sequence"],
                admission_sha256=body["admission_sha256"],
            )
        return reply

    t.client.managed_post = rpc

    def inert(self, targets, directory, cfg, **kwargs):
        with launch_guard.boundary():
            controls.append(execution_control.current())
            t.calls.append("native")
        if settings["fault"] == "refresh_validation":
            assert refresh_rejected.wait(2)
            controls[-1].quiesce(t.f.s.ticks[0] + 2)
        output = directory / "vardrgate_result.json"
        result = {
            "test_case_id": cfg.test_case["id"],
            "case_hash": kwargs["request_guard"]["case_hash"],
            "executions": [],
            "findings": [],
            "preflight": [{"status": "failed"}] if settings["failed"] and len(epochs) == 1 else [],
        }
        if settings["cancelled"]:
            result["error"] = "execution_cancelled"
        output.write_text(json.dumps(result))
        return output

    monkeypatch.setattr(handlers.VardrGateHandler, "execute", inert)

    def configure():
        document = t.admission.to_document()
        del document["expires_at"]
        document.update(
            schema="vardr.worker-admission/3",
            mode="persistent",
            runner_id=runner,
            limits=settings["limits"],
            reporting_authority={"purpose": "worker-stop-only", "expires_at": None},
        )
        document["admission_sha256"] = digest(encoded(document))
        worker.admission = Admission.parse(document, now=base_context.now)
        worker.runner_id = runner
        worker.store = PersistentStore(t.f.journal)
        return worker

    return SimpleNamespace(
        worker=worker, configure=configure, t=t, settings=settings, state=state, epochs=epochs
    )


def test_more_than32_jobs_keep_each_claim_consume_result_and_release(persistent_worker):
    p = persistent_worker
    p.settings["jobs"] = 35
    with pytest.raises(AuthorizationError, match="worker_availability_held"):
        p.configure().run()
    assert p.state["released"] == len(p.epochs) == 35
    for operation in (
        "claim",
        "consume",
        "runtime-bind",
        "native",
        "result",
        "finish",
        "done",
        "runtime-idle-release",
    ):
        assert p.t.calls.count(operation) == 35
    with p.t.f.journal._connection() as con:
        assert (
            con.execute(
                "SELECT count(*) FROM managed_persistent_attempts WHERE state='released'"
            ).fetchone()[0]
            == 35
        )
        assert (
            con.execute("SELECT count(*) FROM authorization_contracts WHERE consumed=2").fetchone()[
                0
            ]
            == 35
        )


def test_late_job_after60_idle_seconds_gets_fresh_approval_and_grants(persistent_worker):
    p = persistent_worker
    p.settings.update(idle_polls=70)
    with pytest.raises(AuthorizationError, match="worker_availability_held"):
        p.configure().run(wait_seconds=10)
    assert p.t.f.s.ticks[0] >= 60 and p.state["released"] == 1
    assert p.t.calls.count("claim") == 1


def test_explicit_finite_count_and_naturally_failed_job_preserve_default_persistence(
    persistent_worker,
):
    p = persistent_worker
    p.settings.update(
        jobs=2, failed=True, limits={"max_attempts": "2", "idle_timeout_seconds": None}
    )
    p.configure().run()
    assert p.state["released"] == 2 and p.t.calls.count("done") == 2
    with p.t.f.journal._connection() as con:
        outcomes = [
            row[0]
            for row in con.execute("SELECT outcome FROM managed_result_intents ORDER BY rowid")
        ]
    assert outcomes == ["failed", "completed"]


def test_optional_idle_timeout_is_explicit_and_never_launches(persistent_worker):
    p = persistent_worker
    p.settings.update(jobs=0, limits={"max_attempts": None, "idle_timeout_seconds": 2})
    assert p.configure().run() is None  # The default 30s window respects explicit 2s idle.
    assert p.t.f.s.ticks[0] == 2 and not p.epochs and "claim" not in p.t.calls


@pytest.mark.parametrize("fault", ["claim", "result", "runtime-idle-release"])
def test_unknown_authority_rpc_never_retries_or_claims_next(persistent_worker, fault):
    p = persistent_worker
    p.settings.update(jobs=2, fault=fault)
    with pytest.raises((AuthorizationError, api.ManagedTransportError)):
        p.configure().run()
    assert p.t.calls.count("claim") == 1 and len(p.epochs) == 1
    assert p.t.calls.count(fault) == 1


def test_idle_discovery_transport_loss_retries_no_authority_mutation(persistent_worker):
    p = persistent_worker
    p.settings.update(
        fault="idle_transport", limits={"max_attempts": "1", "idle_timeout_seconds": None}
    )
    p.configure().run()
    assert p.state["pending"] == 2 and p.t.calls.count("claim") == p.state["released"] == 1


def test_cancelled_marker_cannot_be_reused_as_natural_failed_completion(persistent_worker):
    p = persistent_worker
    p.settings.update(cancelled=True, jobs=2)
    with pytest.raises(AuthorizationError, match="worker_normal_completion_required"):
        p.configure().run()
    assert p.t.calls.count("finish") == 1 and p.state["released"] == 0
    assert "done" not in p.t.calls and p.t.calls.count("claim") == 1


def test_full_managed_refresh_validation_failure_holds_after_terminal_result(persistent_worker):
    p = persistent_worker
    p.settings.update(fault="refresh_validation", failed=True, jobs=2)
    with pytest.raises(AuthorizationError, match="worker_refresh_reuse_held"):
        p.configure().run()
    assert p.t.calls.count("finish") == 1 and p.state["released"] == 0
    assert "done" not in p.t.calls and p.t.calls.count("claim") == 1
