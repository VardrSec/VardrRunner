"""Physical retirement closes metadata holds without inventing sequence ACKs."""

import copy

import pytest

import tests.test_managed_results as result_cases
from tests.test_managed_observations import entry_fixture as entry_fixture
from tests.test_managed_observations import public_reply
from tests.test_managed_observations import specimen as specimen
from vardrrunner.authorization import observations, stops
from vardrrunner.authorization.claim import ClaimError
from vardrrunner.authorization.codec import AuthorizationError, digest, encoded
from vardrrunner.authorization.reconciliation import local_holds, reconcile_managed
from vardrrunner.authorization.worker_binding import SequenceStore, claim_association
from vardrrunner.journal import Phase

RUNTIME = "00000000-0000-0000-0000-000000000051"


def linked(f, *, acknowledged=False):
    store = SequenceStore(f.journal)
    store.reserve_runtime(RUNTIME, "a" * 64, 2)

    def before(con, run_id):
        store.prepare_claim(
            con,
            run_id,
            runtime_id=RUNTIME,
            runtime_sha256="a" * 64,
            runtime_sequence=1,
            runner_id=f.s.context.runner_id,
            enrollment_id="original-enrollment",
        )

    if acknowledged:
        facade = f.make(before_claim_send=before)
        handle = facade.acquire(f.directory)
        return facade, handle

    def lost(_):
        raise OSError("synthetic lost response; no network")

    facade = f.make(claim=lost, before_claim_send=before)
    with pytest.raises(ClaimError, match="outcome_unknown"):
        facade.acquire(f.directory)
    return facade, None


def reply_for(f, facade, *, claimed=False, retired=True, handle=None):
    reply = public_reply(f, facade.run_id, handle.gate if handle else None)
    reply.update(
        schema="vardr.managed-claim-observation/3",
        runtime_id=RUNTIME,
        runtime_sha256="a" * 64,
        runtime_sequence=1,
        execution_state=None,
        capacity_reserved=False,
    )
    binding, terminal = None, None
    if claimed:
        binding = observations.binding(reply)
        terminal = {
            "schema": "vardr.managed-stop-receipt/1",
            **binding,
            "outcome": "failed",
            "cause": "observed_exit",
            "capacity_reserved": False,
            "receipt_sha256": stops.stop_hash(binding, "failed", "observed_exit"),
        }
        reply.update(stop=copy.deepcopy(terminal), execution_state="failed")
    else:
        reply["claim"] = None
    receipt = {
        "schema": "vardr.worker-retirement/2",
        "runtime_id": RUNTIME,
        "runtime_sha256": "a" * 64,
        "origin": reply["origin"],
        "runner_id": reply["runner_id"],
        "enrollment_id": "original-enrollment",
        "runtime_sequence": 1 if claimed else None,
        "last_sequence": 1 if claimed else 0,
        "binding": binding,
        "attempt_receipt": terminal,
        "report_sha256": "b" * 64,
        "retired": True,
    }
    receipt["receipt_sha256"] = digest(encoded(receipt))
    reply["runtime_retirement"] = receipt if retired else None
    return reply


@pytest.mark.parametrize(
    "server_claimed,acknowledged", [(False, False), (True, False), (True, True)]
)
def test_exact_retirement_releases_only_local_hold_and_preserves_all_send_and_ack_history(
    entry_fixture, server_claimed, acknowledged
):
    f = entry_fixture
    facade, handle = linked(f, acknowledged=acknowledged)
    reply = reply_for(f, facade, claimed=server_claimed, handle=handle)
    with f.journal._connection() as con:
        original = dict(con.execute("SELECT * FROM managed_claim_intents").fetchone())
        link = claim_association(con, facade.run_id)
    assert local_holds(f.journal) > 0
    status = reconcile_managed(
        f.journal, facade.run_id, f.s.context.runner_id, lambda _: copy.deepcopy(reply)
    )
    assert status.startswith("terminal_") and local_holds(f.journal) == 0
    assert f.journal.get(facade.run_id).phase == Phase.FAILED
    with f.journal._connection() as con:
        current = dict(con.execute("SELECT * FROM managed_claim_intents").fetchone())
        assert {k: v for k, v in original.items() if k != "state"} == {
            k: v for k, v in current.items() if k != "state"
        }
        assert claim_association(con, facade.run_id) == link
        attempt = con.execute("SELECT * FROM managed_worker_attempts").fetchone()
        assert attempt["state"] == "physical_retirement_observed"
        assert attempt["retired_from_state"] == "claim_prepared"
        assert attempt["binding"] is None
        assert all(
            attempt[key] is None
            for key in ("completion", "native_done_sha256", "release_intent", "release_ack")
        )
        incarnation = con.execute("SELECT * FROM managed_worker_incarnations").fetchone()
        assert incarnation["active_sequence"] is None
        assert (
            incarnation["retirement"]
            == attempt["retirement"]
            == encoded(reply["runtime_retirement"]).decode()
        )
    assert (
        reconcile_managed(f.journal, facade.run_id, f.s.context.runner_id, lambda _: reply)
        == status
    )
    with pytest.raises(AuthorizationError, match="already_invoked"):
        SequenceStore(f.journal).reserve_runtime(RUNTIME, "a" * 64, 2)


def test_no_retirement_keeps_unknown_sequence_held_and_sends_only_original_sequence(entry_fixture):
    f = entry_fixture
    facade, _ = linked(f)
    reply = reply_for(f, facade, retired=False)
    sent = []
    assert (
        reconcile_managed(
            f.journal,
            facade.run_id,
            f.s.context.runner_id,
            lambda body: sent.append(body) or reply,
        )
        == "held_no_terminal_receipt"
    )
    assert sent[0]["runtime_sequence"] == 1 and "token" not in sent[0]
    assert local_holds(f.journal) > 0
    with f.journal._connection() as con:
        attempt = con.execute("SELECT * FROM managed_worker_attempts").fetchone()
        assert attempt["state"] == "claim_prepared" and attempt["retirement"] is None


@pytest.mark.parametrize("change", ["pid", "artifact", "consume"])
def test_valid_retirement_does_not_hide_unexpected_local_execution_metadata(entry_fixture, change):
    f = entry_fixture
    facade, _ = linked(f)
    reply = reply_for(f, facade)
    with f.journal._connection() as con:
        if change == "pid":
            con.execute("UPDATE runs SET pid=12345")
        elif change == "artifact":
            con.execute("UPDATE runs SET artifact_sha256=?", ("c" * 64,))
        else:
            con.execute("UPDATE managed_claim_intents SET consumption_sent=1")
    with pytest.raises(AuthorizationError):
        reconcile_managed(f.journal, facade.run_id, f.s.context.runner_id, lambda _: reply)
    assert local_holds(f.journal) > 0
    with f.journal._connection() as con:
        assert con.execute("SELECT retirement FROM managed_worker_attempts").fetchone()[0] is None


def test_partial_sequence_schema_is_a_hold_and_read_does_not_recreate_it(entry_fixture):
    f = entry_fixture
    SequenceStore(f.journal)
    with f.journal._connection() as con:
        con.execute("DROP TABLE managed_worker_attempts")
    assert local_holds(f.journal) > 0
    with f.journal._connection() as con:
        assert (
            con.execute(
                "SELECT 1 FROM sqlite_master WHERE name='managed_worker_attempts'"
            ).fetchone()
            is None
        )


@pytest.mark.parametrize("stage", ["completion", "done", "release"])
def test_completed_attempt_with_lost_done_or_release_ack_requires_physical_retirement(
    entry_fixture, monkeypatch, stage
):
    f = entry_fixture
    store = SequenceStore(f.journal)
    store.reserve_runtime(RUNTIME, "a" * 64, 2)
    original_make = f.make

    def make(**kwargs):
        def before(con, run_id):
            store.prepare_claim(
                con,
                run_id,
                runtime_id=RUNTIME,
                runtime_sha256="a" * 64,
                runtime_sequence=1,
                runner_id=f.s.context.runner_id,
                enrollment_id="original-enrollment",
            )

        facade = original_make(before_claim_send=before, **kwargs)
        original_consume = facade._consume

        def consume(body):
            acknowledgement = original_consume(body)
            binding = {
                **{
                    key: body[key]
                    for key in (
                        "origin",
                        "runner_id",
                        "contract_id",
                        "attempt_id",
                        "fence",
                        "contract_sha256",
                    )
                },
                "job_id": f.s.context.job_id,
                "runtime_id": RUNTIME,
                "runtime_sha256": "a" * 64,
                "runtime_sequence": 1,
            }
            store.prepare_binding(facade.run_id, binding)
            store.acknowledge_binding(
                facade.run_id,
                binding,
                {"schema": "vardr.worker-runtime-binding/2", **binding, "bound": True},
            )
            return acknowledgement

        facade._consume = consume
        return facade

    monkeypatch.setattr(f, "make", make)
    t = result_cases.result_fixture.__wrapped__(f, monkeypatch)
    t.handle.execute(f.directory)
    completed = t.handle.finalize(t.submit, t.finish)
    store.completion(t.handle.run_id, completed)
    if stage in {"done", "release"}:
        store.done(t.handle.run_id, "d" * 64)
    if stage == "release":
        store.prepare_release(t.handle.run_id)
    assert f.journal.get(t.handle.run_id).phase == Phase.DONE
    assert local_holds(f.journal) > 0
    with f.journal._connection() as con:
        before = dict(con.execute("SELECT * FROM managed_worker_attempts").fetchone())
    reply = reply_for(f, t.handle, claimed=True, handle=t.handle)
    reply.update(
        result=copy.deepcopy(t.state["result"]),
        completion=copy.deepcopy(t.state["completion"]),
        stop=None,
        execution_state="completed",
    )
    reply["claim"]["consumed"] = True
    receipt = reply["runtime_retirement"]
    receipt["attempt_receipt"] = copy.deepcopy(t.state["completion"])
    receipt["receipt_sha256"] = digest(
        encoded({key: value for key, value in receipt.items() if key != "receipt_sha256"})
    )
    assert (
        reconcile_managed(f.journal, t.handle.run_id, f.s.context.runner_id, lambda _: reply)
        == "terminal_receipt_observed"
    )
    assert local_holds(f.journal) == 0
    assert f.journal.get(t.handle.run_id).phase == Phase.DONE
    assert t.calls == ["submit", "finish"]
    with f.journal._connection() as con:
        after = dict(con.execute("SELECT * FROM managed_worker_attempts").fetchone())
    assert after["state"] == "physical_retirement_observed"
    assert after["retired_from_state"] == before["state"]
    assert after["release_ack"] is None
    retained = set(before) - {"state", "retired_from_state", "retirement"}
    assert {key: before[key] for key in retained} == {key: after[key] for key in retained}
    # A later startup must still require the full retained physical proof, even
    # though the ordinary result journal already records a completed job.
    with f.journal._connection() as con:
        observed = dict(con.execute("SELECT * FROM managed_claim_observations").fetchone())
        con.execute("DELETE FROM managed_claim_observations")
    assert local_holds(f.journal) > 0
    with f.journal._connection() as con:
        con.execute(
            "INSERT INTO managed_claim_observations (run_id,snapshot,observed_at) VALUES (?,?,?)",
            (observed["run_id"], observed["snapshot"], observed["observed_at"]),
        )
    assert local_holds(f.journal) == 0
    abbreviated = {
        key: receipt[key]
        for key in (
            "runtime_id",
            "runtime_sha256",
            "origin",
            "runner_id",
            "enrollment_id",
            "retired",
        )
    }
    abbreviated["receipt_sha256"] = digest(encoded(abbreviated))
    poisoned = copy.deepcopy(reply)
    poisoned["runtime_retirement"] = abbreviated
    with f.journal._connection() as con:
        con.execute(
            "UPDATE managed_worker_attempts SET retirement=?", (encoded(abbreviated).decode(),)
        )
        con.execute(
            "UPDATE managed_worker_incarnations SET retirement=?", (encoded(abbreviated).decode(),)
        )
        con.execute(
            "UPDATE managed_claim_observations SET snapshot=?", (encoded(poisoned).decode(),)
        )
    assert local_holds(f.journal) > 0
