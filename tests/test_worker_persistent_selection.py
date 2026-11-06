"""Provisional selections never invent issued history or source-only epoch proof."""

import copy
import json

import pytest

from tests.test_worker_persistent_observations import admission_document as admission_document
from tests.test_worker_persistent_observations import entry_fixture as entry_fixture
from tests.test_worker_persistent_observations import linked_reply, prepare_unknown
from tests.test_worker_persistent_observations import persistent_worker as persistent_worker
from tests.test_worker_persistent_observations import specimen as specimen
from tests.test_worker_persistent_observations import worker_fixture as worker_fixture
from vardrrunner.authorization.claim import ClaimError, ClaimStore
from vardrrunner.authorization.codec import AuthorizationError, encoded
from vardrrunner.authorization.reconciliation import local_holds, reconcile_managed
from vardrrunner.authorization.worker_binding import claim_association
from vardrrunner.authorization.worker_persistent import PersistentStore, persistent_holds


@pytest.fixture
def selected(persistent_worker, monkeypatch):
    p = persistent_worker
    p.configure()
    original = ClaimStore.prepare_send

    def known_pre_rpc_failure(store, *args, **kwargs):
        original(store, *args, **kwargs)
        raise AuthorizationError("synthetic_pre_rpc_failure")

    monkeypatch.setattr(ClaimStore, "prepare_send", known_pre_rpc_failure)
    with pytest.raises(ClaimError, match="local_claim_denied_before_rpc"):
        p.worker.run()
    p.t.owner.begin_attempt.assert_not_called()
    assert "claim" not in p.t.calls and "native" not in p.t.calls
    with p.t.f.journal._connection() as con:
        row = dict(con.execute("SELECT * FROM managed_persistent_selections").fetchone())
        link = claim_association(con, row["run_id"])
    return p, row, link


def test_selected_proposal_leaves_actual_head_untouched_and_retirement_is_idempotent(selected):
    p, row, link = selected
    journal = p.t.f.journal
    assert local_holds(journal) > 0
    with journal._connection() as con:
        before = dict(con.execute("SELECT * FROM managed_persistent_incarnations").fetchone())
        assert (
            before["last_sequence"] == 0
            and before["history_head"] is before["active_sequence"] is None
        )
        assert con.execute("SELECT count(*) FROM managed_persistent_attempts").fetchone()[0] == 0
    p.worker.store.retire_selection(row["run_id"])
    p.worker.store.retire_selection(row["run_id"])
    assert local_holds(journal) == 0
    with journal._connection() as con:
        trace = []
        con.set_trace_callback(trace.append)
        assert persistent_holds(con, full=True) == 0
        assert (
            dict(con.execute("SELECT * FROM managed_persistent_incarnations").fetchone()) == before
        )
        after = dict(con.execute("SELECT * FROM managed_persistent_selections").fetchone())
        assert {key: value for key, value in row.items() if key != "state"} == {
            key: value for key, value in after.items() if key != "state"
        }
        assert (
            after["state"] == "preclaim_retired" and claim_association(con, row["run_id"]) == link
        )
        assert not any(
            sql.lstrip().upper().startswith(("CREATE", "INSERT", "UPDATE", "DELETE", "ALTER"))
            for sql in trace
        )
    assert p.worker.store.denied_selection(link["origin"], link["job_id"])
    assert not p.worker.store.denied_selection(link["origin"], "another-job")


@pytest.mark.parametrize("change", ["pid", "artifact", "consumption", "claim_state", "fingerprint"])
def test_changed_source_never_becomes_a_known_no_send_retirement(selected, change):
    p, row, link = selected
    with p.t.f.journal._connection() as con:
        if change == "pid":
            con.execute("UPDATE runs SET pid=12345")
        elif change == "artifact":
            con.execute("UPDATE runs SET artifact_sha256=?", ("a" * 64,))
        elif change == "consumption":
            con.execute("UPDATE managed_claim_intents SET consumption_sent=1")
        elif change == "claim_state":
            con.execute("UPDATE managed_claim_intents SET state='claim_unknown'")
        else:
            bad = {**link, "case_sha256": "f" * 64}
            con.execute(
                "UPDATE managed_persistent_selections SET claim_link=?", (encoded(bad).decode(),)
            )
    with pytest.raises(AuthorizationError):
        p.worker.store.retire_selection(row["run_id"])
    assert local_holds(p.t.f.journal) > 0
    with p.t.f.journal._connection() as con:
        assert (
            con.execute("SELECT state FROM managed_persistent_selections").fetchone()[0]
            == "selected"
        )


def test_prepared_selection_rolls_back_with_original_send_markers(persistent_worker, monkeypatch):
    p = persistent_worker
    p.configure()
    original = p.worker.store.prepare_selection

    def fail_inside_transaction(*args, **kwargs):
        original(*args, **kwargs)
        raise AuthorizationError("synthetic_selection_transaction_failure")

    monkeypatch.setattr(p.worker.store, "prepare_selection", fail_inside_transaction)
    with pytest.raises(ClaimError, match="local_claim_denied_before_rpc"):
        p.worker.run()
    with p.t.f.journal._connection() as con:
        assert con.execute("SELECT count(*) FROM managed_persistent_selections").fetchone()[0] == 0
        assert con.execute("SELECT count(*) FROM managed_persistent_attempts").fetchone()[0] == 0
        claim = con.execute("SELECT * FROM managed_claim_intents").fetchone()
        assert claim["utc_anchor"] is claim["mono_anchor"] is None
        assert (
            con.execute("SELECT last_sequence FROM managed_persistent_incarnations").fetchone()[0]
            == 0
        )
    p.t.owner.begin_attempt.assert_not_called()
    assert "claim" not in p.t.calls


def test_promotion_failure_does_not_leave_half_an_issued_history(persistent_worker, monkeypatch):
    p = persistent_worker
    p.configure()
    original = p.worker.store.prepare_claim

    def fail_promotion(*args, **kwargs):
        original(*args, **kwargs)
        raise AuthorizationError("synthetic_promotion_commit_failure")

    monkeypatch.setattr(p.worker.store, "prepare_claim", fail_promotion)
    with pytest.raises(ClaimError, match="claim_outcome_unknown"):
        p.worker.run()
    assert p.t.calls.count("claim") == 1
    with p.t.f.journal._connection() as con:
        assert con.execute("SELECT count(*) FROM managed_persistent_attempts").fetchone()[0] == 0
        assert (
            con.execute("SELECT state FROM managed_persistent_selections").fetchone()[0]
            == "selected"
        )
        assert (
            con.execute("SELECT last_sequence FROM managed_persistent_incarnations").fetchone()[0]
            == 0
        )
        assert persistent_holds(con) > 0


@pytest.mark.parametrize(
    "table",
    [
        "managed_persistent_incarnations",
        "managed_persistent_attempts",
        "managed_persistent_selections",
    ],
)
def test_partial_schema_is_never_recreated_by_constructor(entry_fixture, table):
    journal = entry_fixture.journal
    PersistentStore(journal)
    queries = {
        "managed_persistent_incarnations": "DROP TABLE managed_persistent_incarnations",
        "managed_persistent_attempts": "DROP TABLE managed_persistent_attempts",
        "managed_persistent_selections": "DROP TABLE managed_persistent_selections",
    }
    with journal._connection() as con:
        con.execute(queries[table])
    with pytest.raises(AuthorizationError, match="schema_incomplete"):
        PersistentStore(journal)
    assert local_holds(journal) > 0
    with journal._connection() as con:
        assert con.execute("SELECT 1 FROM sqlite_master WHERE name=?", (table,)).fetchone() is None


def test_lost_claim_reply_keeps_proposal_and_actual_zero_even_when_server_issued(persistent_worker):
    p = persistent_worker
    row, link = prepare_unknown(p)
    assert row["state"] == "selected"
    reply = linked_reply(p, row, link, claimed=True)
    assert reconcile_managed(
        p.t.f.journal, row["run_id"], link["runner_id"], lambda _: reply
    ).startswith("terminal_")
    with p.t.f.journal._connection() as con:
        parent = con.execute("SELECT * FROM managed_persistent_incarnations").fetchone()
        assert (
            parent["last_sequence"] == 0
            and json.loads(parent["retirement"])["last_sequence"] == "1"
        )
        assert con.execute("SELECT count(*) FROM managed_persistent_attempts").fetchone()[0] == 0
        assert con.execute("SELECT contract FROM managed_claim_intents").fetchone()[0] is None
    assert local_holds(p.t.f.journal) == 0


def test_crash_between_generic_no_send_retirement_and_selection_retirement_requires_physical_proof(
    selected,
):
    p, row, link = selected
    journal = p.t.f.journal
    with journal._connection() as con:
        claim_before = dict(con.execute("SELECT * FROM managed_claim_intents").fetchone())
    run_before = journal.get(row["run_id"])
    absent = linked_reply(p, row, link, retired=False)
    assert (
        reconcile_managed(journal, row["run_id"], link["runner_id"], lambda _: absent)
        == "held_no_retirement_receipt"
    )
    assert local_holds(journal) > 0
    closed = linked_reply(p, row, link)
    sent = []
    assert (
        reconcile_managed(
            journal,
            row["run_id"],
            link["runner_id"],
            lambda body: sent.append(body) or copy.deepcopy(closed),
        )
        == "terminal_runtime_preclaim_retired"
    )
    assert len(sent) == 1 and local_holds(journal) == 0
    assert journal.get(row["run_id"]) == run_before
    with journal._connection() as con:
        assert dict(con.execute("SELECT * FROM managed_claim_intents").fetchone()) == claim_before
        assert con.execute("SELECT count(*) FROM managed_persistent_attempts").fetchone()[0] == 0
        assert (
            con.execute("SELECT last_sequence FROM managed_persistent_incarnations").fetchone()[0]
            == 0
        )
        observed = dict(con.execute("SELECT * FROM managed_claim_observations").fetchone())
        con.execute("DELETE FROM managed_claim_observations")
    assert local_holds(journal) > 0
    with journal._connection() as con:
        con.execute(
            "INSERT INTO managed_claim_observations(run_id,snapshot,observed_at) VALUES(?,?,?)",
            (observed["run_id"], observed["snapshot"], observed["observed_at"]),
        )
    assert local_holds(journal) == 0
    with journal._connection() as con:
        con.execute("UPDATE runs SET artifact_sha256=?", ("f" * 64,))
    assert local_holds(journal) > 0
