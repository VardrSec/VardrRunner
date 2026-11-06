"""Real managed policy/journal composition with inert HTTP/native boundaries."""

import copy
import json
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.test_managed_claim import entry_fixture as entry_fixture
from tests.test_managed_claim import specimen as specimen
from tests.test_worker_admission import NOW
from tests.test_worker_admission import admission_document as admission_document
from vardrrunner import execution_control, handlers, launch_guard
from vardrrunner.authorization import results
from vardrrunner.authorization.codec import AuthorizationError
from vardrrunner.authorization.worker_admission import Admission
from vardrrunner.journal import Phase
from vardrrunner.managed_worker import Worker, await_admission, main


@pytest.fixture
def worker_fixture(entry_fixture, admission_document, monkeypatch, tmp_path):
    f = entry_fixture
    document = copy.deepcopy(admission_document)
    document.update(origin="https://map.example.test")
    admission = Admission.parse(document, now=f.s.context.now)
    # The shared signed reference vector predates the public UUID-only transport.
    # Admission parsing is exercised separately; these fixtures dispatch no tools.
    admission = replace(admission, runner_id=f.s.context.runner_id)
    calls, payloads = [], []
    faults = {"pending": None, "consume": None, "runtime-bind": None}
    terminal = {"receipt": None}

    def rpc(path, body):
        operation = path.rsplit("/", 1)[-1]
        calls.append(operation)
        payloads.append((operation, copy.deepcopy(body)))
        fault = faults.get(operation)
        if isinstance(fault, BaseException):
            raise fault
        if fault is not None:
            return copy.deepcopy(fault)
        if operation == "pending":
            return {
                "jobs": [
                    {
                        "id": f.s.context.job_id,
                        "program_id": f.s.context.engagement_id,
                        "tool_type": "vardrgate_api_test",
                        "authorization_contract_required": True,
                        "config": {"test_case": copy.deepcopy(f.s.case)},
                        "plan": copy.deepcopy(f.s.claim["managed_authorization"]["plan"]),
                    }
                ],
                "next_after": None,
            }
        if operation == "claim":
            assert body["runtime_id"] == admission.runtime_id
            assert body["runtime_sha256"] == admission.runtime_sha256
            return {**copy.deepcopy(f.s.claim), "config": {"test_case": copy.deepcopy(f.s.case)}}
        if operation == "refresh":
            return copy.deepcopy(f.s.reply)
        binding = {key: body[key] for key in results.BINDING - {"job_id"}}
        binding["job_id"] = f.s.context.job_id
        if operation == "consume":
            return {
                **binding,
                "authority_revision": f.s.context.authority_revision,
                "authority_sha256": f.s.context.authority_sha256,
                "schema": "vardr.managed-consumption/1",
                "consumed": True,
            }
        if operation == "runtime-bind":
            return {
                "schema": "vardr.worker-runtime-binding/1",
                **binding,
                "runtime_id": admission.runtime_id,
                "runtime_sha256": admission.runtime_sha256,
                "bound": True,
            }
        if operation == "result":
            terminal["receipt"] = results.receipt(
                binding,
                body["artifact_sha256"],
                f.s.claim["managed_authorization"]["plan"]["case_hash"],
            )
            return {
                "schema": "vardr.managed-result-receipt/1",
                **binding,
                "artifact_sha256": body["artifact_sha256"],
                "case_sha256": f.s.claim["managed_authorization"]["plan"]["case_hash"],
                "receipt_sha256": terminal["receipt"],
                "evidence_created": 0,
                "scan_items_created": 0,
            }
        assert operation == "finish"
        return {
            "schema": "vardr.managed-completion/1",
            **binding,
            "receipt_sha256": terminal["receipt"],
            "outcome": body["outcome"],
            "capacity_reserved": False,
        }

    owner = Mock()
    owner.finished.side_effect = lambda: calls.append("owner_finished")

    def inert(self, targets, directory, cfg, **kwargs):
        with launch_guard.boundary():
            with f.journal._connection() as con:
                assert (
                    con.execute("SELECT state FROM managed_runtime_bindings").fetchone()[0]
                    == "bound"
                )
                assert (
                    con.execute(
                        "SELECT consumption_acknowledged FROM managed_claim_intents"
                    ).fetchone()[0]
                    == 1
                )
            calls.append("native")
        artifact = directory / "vardrgate_result.json"
        artifact.write_text(
            json.dumps(
                {
                    "case_hash": f.s.claim["managed_authorization"]["plan"]["case_hash"],
                    "test_case_id": f.s.case["id"],
                    "executions": [],
                    "findings": [],
                }
            )
        )
        return artifact

    monkeypatch.setattr(handlers.VardrGateHandler, "execute", inert)
    client = SimpleNamespace(base=admission.origin, managed_post=rpc)

    def make():
        return Worker(
            client,
            f.journal,
            admission,
            f.s.anchors,
            owner,
            runner_id=f.s.context.runner_id,
            principal_sha256="f" * 64,
            allocated_seconds=30,
            output_root=tmp_path / "outputs",
            clock=lambda: f.s.context.now + timedelta(seconds=f.s.ticks[0]),
            monotonic=lambda: f.s.ticks[0],
            sleep=lambda seconds: f.s.ticks.__setitem__(0, f.s.ticks[0] + seconds),
        )

    return SimpleNamespace(
        make=make,
        calls=calls,
        payloads=payloads,
        faults=faults,
        owner=owner,
        f=f,
        client=client,
        admission=admission,
    )


def test_one_attempt_uses_existing_consume_bind_native_and_receipt_order(worker_fixture):
    t = worker_fixture
    record = t.make().run()
    assert record.phase == Phase.DONE
    assert [call for call in t.calls if call != "refresh"] == [
        "pending",
        "claim",
        "consume",
        "runtime-bind",
        "native",
        "result",
        "finish",
        "owner_finished",
    ]
    assert t.owner.verified_lease.call_count > 0
    with t.f.journal._connection() as con:
        dump = "\n".join(con.iterdump())
    assert "x" * 40 not in dump and "api.example.test" not in dump
    before = list(t.calls)
    with pytest.raises(AuthorizationError, match="worker_runtime_already_invoked"):
        t.make().run()
    assert t.calls == before


@pytest.mark.parametrize("stage", ["claim", "consume", "runtime-bind", "binding_ack_write"])
def test_unknown_consumption_or_binding_never_launches_or_claims_again(
    worker_fixture, monkeypatch, stage
):
    t = worker_fixture
    worker = t.make()
    if stage == "binding_ack_write":
        monkeypatch.setattr(
            worker.store, "acknowledge_binding", Mock(side_effect=OSError("synthetic write"))
        )
    else:
        t.faults[stage] = OSError("synthetic lost response")
    with pytest.raises(AuthorizationError):
        worker.run()
    assert "native" not in t.calls and "result" not in t.calls and "finish" not in t.calls
    t.owner.finished.assert_not_called()
    with t.f.journal._connection() as con:
        assert (
            con.execute("SELECT consumption_acknowledged FROM managed_claim_intents").fetchone()[0]
            == 0
        )
    before = list(t.calls)
    with pytest.raises(AuthorizationError, match="worker_unresolved_local_attempt"):
        t.make().run()
    assert t.calls == before


def test_missing_actual_native_context_refuses_before_discovery(worker_fixture, monkeypatch):
    t = worker_fixture
    monkeypatch.setattr(execution_control, "available", lambda: False)
    with pytest.raises(AuthorizationError, match="controlled_process_tree_unsupported"):
        t.make().run()
    assert t.calls == []


def test_owner_failure_after_verified_reply_holds_claim_before_consumption(worker_fixture):
    t = worker_fixture
    t.owner.verified_lease.side_effect = OSError("synthetic owner disconnect")
    with pytest.raises(AuthorizationError, match="claimed_handoff_held"):
        t.make().run()
    assert t.calls == ["pending", "claim", "refresh"]


def test_pending_polling_is_bounded_and_never_claims_without_work(worker_fixture):
    t = worker_fixture
    t.faults["pending"] = {"jobs": [], "next_after": None}
    assert t.make().run(wait_seconds=2, poll_seconds=0.5) is None
    assert t.calls == ["pending"] * 4
    assert t.f.s.ticks[0] == 2


def test_late_discovery_does_not_start_claim_after_wait_ceiling(worker_fixture):
    t = worker_fixture
    original = t.client.managed_post

    def delayed(path, body):
        reply = original(path, body)
        t.f.s.ticks[0] += 3
        return reply

    t.client.managed_post = delayed
    assert t.make().run(wait_seconds=2) is None
    assert t.calls == ["pending"]


def test_invalid_worker_arguments_never_echo_pasted_credentials(capsys):
    assert main(["--unrecognized", "synthetic-private-stop-secret"]) == 1
    output = capsys.readouterr()
    assert output.out == "managed_worker_held\n" and output.err == ""


def test_admission_wait_accepts_only_atomic_publication(admission_document, tmp_path):
    path = tmp_path / "admission.json"
    ticks = [0.0]

    def publish(seconds):
        ticks[0] += seconds
        path.write_text(json.dumps(admission_document))

    admission = await_admission(
        path,
        1,
        clock=lambda: NOW + timedelta(seconds=ticks[0]),
        monotonic=lambda: ticks[0],
        sleep=publish,
    )
    assert admission.runtime_id == admission_document["runtime_id"] and ticks[0] == 0.25


@pytest.mark.parametrize("malformed", [False, True])
def test_missing_or_bad_admission_never_waits_indefinitely(tmp_path, malformed):
    path = tmp_path / "admission.json"
    if malformed:
        path.write_text("{}")
    ticks = [0.0]
    with pytest.raises(AuthorizationError):
        await_admission(
            path,
            1,
            clock=lambda: NOW + timedelta(seconds=ticks[0]),
            monotonic=lambda: ticks[0],
            sleep=lambda seconds: ticks.__setitem__(0, ticks[0] + seconds),
        )
    assert ticks[0] == (0 if malformed else 1)


@pytest.mark.parametrize("value", ["0", "86401", "synthetic-private-secret"])
def test_invalid_profile_duration_fails_before_owner_or_transport(monkeypatch, capsys, value):
    monkeypatch.setenv("VARDRRUNNER_WORKER_DURATION_SECONDS", value)
    assert main([]) == 1
    output = capsys.readouterr()
    assert output.out == "managed_worker_held\n" and output.err == ""


def test_worker_refuses_dangling_ledger_even_without_unfinished_run(worker_fixture):
    t = worker_fixture
    t.make().run()
    with t.f.journal._connection() as con:
        con.execute("UPDATE authorization_contracts SET consumed=1")
    assert not t.f.journal.unfinished()
    before = list(t.calls)
    with pytest.raises(AuthorizationError, match="worker_unresolved_local_attempt"):
        t.make().run()
    assert t.calls == before
