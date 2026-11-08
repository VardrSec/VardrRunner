"""Exact retired-incarnation proof closes only a durably linked unbound send."""

import copy
import json

import pytest

from tests.test_managed_observations import entry_fixture as entry_fixture
from tests.test_managed_observations import lost_claim
from tests.test_managed_observations import specimen as specimen
from vardrrunner.authorization import observations
from vardrrunner.authorization.claim import ClaimError
from vardrrunner.authorization.codec import AuthorizationError, digest, encoded
from vardrrunner.authorization.ledger import AuthorizationLedger
from vardrrunner.authorization.reconciliation import local_holds, reconcile_managed
from vardrrunner.authorization.worker_binding import WorkerStore, claim_association
from vardrrunner.journal import Phase

RUNTIME = "00000000-0000-0000-0000-000000000031"


@pytest.fixture
def linked(entry_fixture):
    f = entry_fixture
    store = WorkerStore(f.journal)
    store.reserve_runtime(RUNTIME, "a" * 64)

    def send(_):
        raise OSError("synthetic unknown send; no network")

    facade = f.make(
        claim=send,
        before_claim_send=lambda con, run_id: store.prepare_claim(
            con,
            run_id,
            runtime_id=RUNTIME,
            runtime_sha256="a" * 64,
            runner_id=f.s.context.runner_id,
            enrollment_id="enrollment-fixture",
        ),
    )
    with pytest.raises(ClaimError, match="claim_outcome_unknown"):
        facade.acquire(f.directory)
    return f, facade


def reply_for(f, facade, *, retired=True):
    root, _ = observations.original(f.journal, facade.run_id, f.s.context.runner_id)
    receipt = {
        "schema": "vardr.worker-unbound-retirement/1",
        "runtime_id": RUNTIME,
        "runtime_sha256": "a" * 64,
        "origin": root["origin"],
        "runner_id": root["runner_id"],
        "enrollment_id": "enrollment-fixture",
        "report_sha256": "b" * 64,
        "bound": False,
        "retired": True,
    }
    receipt["receipt_sha256"] = digest(encoded(receipt))
    return {
        "schema": "vardr.managed-claim-observation/2",
        **root,
        "claim": None,
        "execution_state": None,
        "capacity_reserved": False,
        "result": None,
        "completion": None,
        "stop": None,
        "runtime_retirement": receipt if retired else None,
    }


def reconcile(f, facade, reply):
    return reconcile_managed(f.journal, facade.run_id, f.s.context.runner_id, lambda _: reply)


def test_exact_unbound_retirement_preserves_tombstones_and_ack_history(linked):
    f, facade = linked
    reply = reply_for(f, facade)
    with f.journal._connection() as con:
        original = dict(con.execute("SELECT * FROM managed_claim_intents").fetchone())
        link = claim_association(con, facade.run_id)
    assert local_holds(f.journal) > 0
    assert reconcile(f, facade, reply) == "terminal_runtime_unbound_retired"
    assert local_holds(f.journal) == 0 and not f.journal.unfinished()
    run = f.journal.get(facade.run_id)
    assert run.phase == Phase.FAILED and run.status == "not_claimed" and run.pid is None
    assert run.failure_reason == "not_claimed_by_retired_runtime"
    with f.journal._connection() as con:
        claim = dict(con.execute("SELECT * FROM managed_claim_intents").fetchone())
        assert claim_association(con, facade.run_id) == link
    assert {k: v for k, v in claim.items() if k != "state"} == {
        k: v for k, v in original.items() if k != "state"
    }
    assert claim["state"] == "runtime_unbound_retired"
    assert reconcile(f, facade, reply) == "terminal_runtime_unbound_retired"
    assert f.journal.get(facade.run_id).warnings == run.warnings
    with pytest.raises(AuthorizationError, match="already_reserved"):
        f.make().acquire(f.directory)
    assert local_holds(f.journal) == 0


def test_linked_absence_stays_held_and_sends_only_original_runtime_pair(linked):
    f, facade = linked
    sent = []
    reply = reply_for(f, facade, retired=False)
    observations.observe(
        f.journal, facade.run_id, f.s.context.runner_id, lambda body: sent.append(body) or reply
    )
    assert sent[0]["runtime_id"] == RUNTIME and sent[0]["runtime_sha256"] == "a" * 64
    assert "enrollment_id" not in sent[0] and "job_id" not in sent[0]
    assert reconcile(f, facade, reply) == "held_no_terminal_receipt"
    assert local_holds(f.journal) > 0


def test_older_unlinked_intent_cannot_adopt_a_supplied_runtime_receipt(entry_fixture):
    f = entry_fixture
    facade = lost_claim(f)
    reply = reply_for(f, facade)
    with pytest.raises(AuthorizationError):
        reconcile(f, facade, reply)
    reply.pop("runtime_retirement")
    reply["schema"] = "vardr.managed-claim-observation/1"
    assert reconcile(f, facade, reply) == "held_no_terminal_receipt"
    with f.journal._connection() as con:
        assert not con.execute(
            "SELECT 1 FROM sqlite_master WHERE name='managed_runtime_bindings'"
        ).fetchone()
    assert local_holds(f.journal) > 0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("runtime_id", "00000000-0000-0000-0000-000000000032"),
        ("runtime_sha256", "c" * 64),
        ("origin", "https://other.example.test"),
        ("runner_id", "another-runner"),
        ("enrollment_id", "another-enrollment"),
        ("bound", True),
        ("retired", False),
        ("report_sha256", "INVALID"),
        ("schema", "vardr.worker-unbound-retirement/2"),
    ],
)
def test_foreign_or_invalid_receipt_never_closes_unknown_send(linked, field, value):
    f, facade = linked
    reply = reply_for(f, facade)
    receipt = reply["runtime_retirement"]
    receipt[field] = value
    receipt["receipt_sha256"] = digest(
        encoded({k: v for k, v in receipt.items() if k != "receipt_sha256"})
    )
    with pytest.raises(AuthorizationError):
        reconcile(f, facade, reply)
    assert local_holds(f.journal) > 0 and f.journal.unfinished()


@pytest.mark.parametrize("change", ["hash", "extra", "downgrade", "claim", "capacity"])
def test_strict_v2_shape_and_unbound_receipt_domain(linked, change):
    f, facade = linked
    reply = reply_for(f, facade)
    if change == "hash":
        reply["runtime_retirement"]["receipt_sha256"] = "f" * 64
    elif change == "extra":
        reply["runtime_retirement"]["success"] = True
    elif change == "downgrade":
        reply["schema"] = "vardr.managed-claim-observation/1"
        reply.pop("runtime_retirement")
    elif change == "claim":
        reply["claim"] = {}
    else:
        reply["capacity_reserved"] = True
    with pytest.raises(AuthorizationError):
        reconcile(f, facade, reply)
    assert local_holds(f.journal) > 0


@pytest.mark.parametrize("change", ["pid", "artifact", "consume", "ledger", "terminal"])
def test_local_execution_or_foreign_terminal_metadata_keeps_hold(linked, change):
    f, facade = linked
    reply = reply_for(f, facade)
    if change == "ledger":
        AuthorizationLedger(f.journal)
    with f.journal._connection() as con:
        if change == "pid":
            con.execute("UPDATE runs SET pid=12345")
        elif change == "artifact":
            con.execute("UPDATE runs SET artifact_sha256=?", ("c" * 64,))
        elif change == "consume":
            con.execute("UPDATE managed_claim_intents SET consumption_sent=1")
        elif change == "terminal":
            con.execute("UPDATE runs SET phase=?", (Phase.FAILED.value,))
        else:
            con.execute(
                "INSERT INTO authorization_contracts VALUES (?,?,?,?,?,?,?,?)",
                ("issuer", "contract", "approval", 1, f.s.context.job_id, "attempt", 1, 0),
            )
    with pytest.raises(AuthorizationError):
        reconcile(f, facade, reply)
    assert local_holds(f.journal) > 0


def test_link_changed_during_rpc_is_not_recorded_or_retired(linked):
    f, facade = linked
    reply = reply_for(f, facade)

    def inspect(_):
        with f.journal._connection() as con:
            document = claim_association(con, facade.run_id)
            document["enrollment_id"] = "changed-during-rpc"
            con.execute(
                "UPDATE managed_runtime_bindings SET claim_link=?", (encoded(document).decode(),)
            )
        return reply

    with pytest.raises(AuthorizationError, match="runtime_observation_source_changed"):
        reconcile_managed(f.journal, facade.run_id, f.s.context.runner_id, inspect)
    with f.journal._connection() as con:
        assert con.execute("SELECT count(*) FROM managed_claim_observations").fetchone()[0] == 0
    assert local_holds(f.journal) > 0


def test_retired_receipt_cannot_regress_and_corrupt_audit_stays_held(linked):
    f, facade = linked
    reply = reply_for(f, facade)
    reconcile(f, facade, reply)
    with pytest.raises(AuthorizationError, match="observed_runtime_retirement_regressed"):
        observations.observe(
            f.journal,
            facade.run_id,
            f.s.context.runner_id,
            lambda _: reply_for(f, facade, retired=False),
        )
    changed = copy.deepcopy(reply)
    changed["runtime_retirement"]["report_sha256"] = "e" * 64
    changed["runtime_retirement"]["receipt_sha256"] = digest(
        encoded({k: v for k, v in changed["runtime_retirement"].items() if k != "receipt_sha256"})
    )
    with pytest.raises(AuthorizationError, match="observed_runtime_retirement_regressed"):
        reconcile(f, facade, changed)
    with f.journal._connection() as con:
        con.execute("UPDATE runs SET warnings_json=?", (json.dumps([]),))
    assert local_holds(f.journal) > 0
