"""Physical v3 retirement closes metadata holds without reconstructing authority."""

import copy
import json

import pytest

from tests.test_worker_persistent_observations import admission_document as admission_document
from tests.test_worker_persistent_observations import entry_fixture as entry_fixture
from tests.test_worker_persistent_observations import linked_reply, prepare_unknown, rehash
from tests.test_worker_persistent_observations import persistent_worker as persistent_worker
from tests.test_worker_persistent_observations import specimen as specimen
from tests.test_worker_persistent_observations import worker_fixture as worker_fixture
from vardrrunner import api
from vardrrunner.authorization import observations, results
from vardrrunner.authorization.codec import AuthorizationError, encoded
from vardrrunner.authorization.reconciliation import local_holds, reconcile_managed
from vardrrunner.authorization.worker_binding import claim_association
from vardrrunner.journal import Phase


@pytest.mark.parametrize(
    "fault,server_claimed",
    [("claim", False), ("claim", True), ("consume", True), ("runtime-bind", True)],
)
def test_exact_original_observation_retires_only_local_metadata_and_preserves_ack_history(
    persistent_worker, fault, server_claimed
):
    p = persistent_worker
    row, link = prepare_unknown(p, fault=fault)
    reply = linked_reply(p, row, link, claimed=server_claimed)
    if fault == "runtime-bind":
        reply["claim"]["consumed"] = True
    journal = p.t.f.journal
    with journal._connection() as con:
        original = dict(con.execute("SELECT * FROM managed_claim_intents").fetchone())
    assert local_holds(journal) > 0
    sent = []
    status = reconcile_managed(
        journal,
        row["run_id"],
        link["runner_id"],
        lambda body: sent.append(body) or copy.deepcopy(reply),
    )
    assert status.startswith("terminal_") and local_holds(journal) == 0
    assert len(sent) == 1 and sent[0]["admission_sha256"] == link["admission_sha256"]
    assert sent[0]["runtime_sequence"] == link["runtime_sequence"]
    assert p.t.calls.count("claim") == 1 and "native" not in p.t.calls
    with journal._connection() as con:
        current = dict(con.execute("SELECT * FROM managed_claim_intents").fetchone())
        assert {key: value for key, value in original.items() if key != "state"} == {
            key: value for key, value in current.items() if key != "state"
        }
        assert claim_association(con, row["run_id"]) == link
        issued = con.execute("SELECT * FROM managed_persistent_attempts").fetchone()
        after = (
            dict(issued)
            if issued is not None
            else dict(con.execute("SELECT * FROM managed_persistent_selections").fetchone())
        )
        retained = set(row) - {"state", "retired_from_state", "retirement"}
        assert {key: row[key] for key in retained} == {key: after[key] for key in retained}
        assert (
            after["state"] == "physical_retirement_observed"
            and after["retired_from_state"] == row["state"]
        )
        assert issued is None or after["release_ack"] is None
        parent = con.execute("SELECT * FROM managed_persistent_incarnations").fetchone()
        assert parent["state"] == "retired" and parent["active_sequence"] is None
        if row["state"] == "selected":
            assert (
                issued is None and parent["last_sequence"] == 0 and parent["history_head"] is None
            )
    assert reconcile_managed(journal, row["run_id"], link["runner_id"], lambda _: reply) == status


def test_original_key_unavailable_never_clears_the_unknown_runtime(persistent_worker):
    p = persistent_worker
    row, link = prepare_unknown(p)
    before = p.t.f.journal.get(row["run_id"])
    sent = []

    def unavailable(body):
        sent.append(body)
        raise api.ManagedTransportError("synthetic original key revoked")

    with pytest.raises(AuthorizationError, match="observation_unavailable"):
        reconcile_managed(p.t.f.journal, row["run_id"], link["runner_id"], unavailable)
    assert len(sent) == 1 and local_holds(p.t.f.journal) > 0
    assert p.t.f.journal.get(row["run_id"]) == before


def test_no_retirement_and_wrong_selected_sequence_remain_held(persistent_worker):
    p = persistent_worker
    row, link = prepare_unknown(p)
    reply = linked_reply(p, row, link, retired=False)
    journal = p.t.f.journal
    assert (
        reconcile_managed(journal, row["run_id"], link["runner_id"], lambda _: reply)
        == "held_no_terminal_receipt"
    )
    assert local_holds(journal) > 0
    wrong = linked_reply(p, row, link)
    wrong["runtime_sequence"] = "2"
    with pytest.raises(AuthorizationError):
        reconcile_managed(journal, row["run_id"], link["runner_id"], lambda _: wrong)
    assert local_holds(journal) > 0


@pytest.mark.parametrize("stage", ["completion", "done", "release", "release_applied"])
def test_completed_job_still_requires_retirement_for_lost_done_or_release(
    persistent_worker, monkeypatch, stage
):
    p = persistent_worker
    p.settings.update(jobs=2)
    if stage == "release":
        p.settings["fault"] = "runtime-idle-release"
    worker = p.configure()

    if stage == "release_applied":
        original_rpc = p.t.client.managed_post

        def lost_release_reply(path, body):
            reply = original_rpc(path, body)
            if path.endswith("/runtime-idle-release"):
                raise api.ManagedTransportError("synthetic accepted release reply lost")
            return reply

        p.t.client.managed_post = lost_release_reply

    def storage_unknown(*_):
        raise AuthorizationError("synthetic_completion_metadata_unknown")

    if stage == "completion":
        monkeypatch.setattr(worker.store, "done", storage_unknown)
    elif stage == "done":
        monkeypatch.setattr(worker.store, "prepare_release", storage_unknown)
    with pytest.raises((AuthorizationError, api.ManagedTransportError)):
        worker.run()
    journal = p.t.f.journal
    with journal._connection() as con:
        row = dict(con.execute("SELECT * FROM managed_persistent_attempts").fetchone())
        link = claim_association(con, row["run_id"])
        result = dict(con.execute("SELECT * FROM managed_result_intents").fetchone())
        claim_before = dict(con.execute("SELECT * FROM managed_claim_intents").fetchone())
    assert journal.get(row["run_id"]).phase == Phase.DONE and local_holds(journal) > 0
    reply = linked_reply(p, row, link, claimed=True)
    binding = observations.binding(reply)
    reply.update(
        result={
            "schema": "vardr.managed-result-receipt/1",
            **binding,
            **{key: result[key] for key in ("artifact_sha256", "case_sha256", "receipt_sha256")},
            "evidence_created": 0,
            "scan_items_created": 0,
        },
        completion=json.loads(row["completion"]),
        stop=None,
        execution_state="completed",
    )
    reply["claim"]["consumed"] = True
    reply["runtime_retirement"]["attempt_receipt"] = copy.deepcopy(reply["completion"])
    if stage == "release_applied":
        assert p.state["released"] == 1
        reply["runtime_retirement"].update(
            runtime_sequence=None, binding=None, attempt_receipt=None
        )
    rehash(reply)
    sent = []
    assert (
        reconcile_managed(
            journal, row["run_id"], link["runner_id"], lambda body: sent.append(body) or reply
        )
        == "terminal_receipt_observed"
    )
    assert len(sent) == 1 and local_holds(journal) == 0
    assert journal.get(row["run_id"]).phase == Phase.DONE
    assert (
        p.t.calls.count("claim") == 1
        and p.t.calls.count("result") == 1
        and p.t.calls.count("finish") == 1
    )
    with journal._connection() as con:
        after = dict(con.execute("SELECT * FROM managed_persistent_attempts").fetchone())
        claim_after = dict(con.execute("SELECT * FROM managed_claim_intents").fetchone())
        assert claim_before == claim_after
        retained = set(row) - {"state", "retired_from_state", "retirement"}
        assert {key: row[key] for key in retained} == {key: after[key] for key in retained}
        assert after["release_ack"] is None and after["retired_from_state"] == row["state"]
        observed = dict(con.execute("SELECT * FROM managed_claim_observations").fetchone())
        con.execute("DELETE FROM managed_claim_observations")
    assert local_holds(journal) > 0
    with journal._connection() as con:
        con.execute(
            "INSERT INTO managed_claim_observations(run_id,snapshot,observed_at) VALUES(?,?,?)",
            (observed["run_id"], observed["snapshot"], observed["observed_at"]),
        )
    assert local_holds(journal) == 0
    poisoned = copy.deepcopy(reply)
    poisoned["runtime_retirement"]["admission_sha256"] = "f" * 64
    rehash(poisoned)
    with journal._connection() as con:
        con.execute(
            "UPDATE managed_persistent_incarnations SET retirement=?",
            (encoded(poisoned["runtime_retirement"]).decode(),),
        )
        con.execute(
            "UPDATE managed_persistent_attempts SET retirement=?",
            (encoded(poisoned["runtime_retirement"]).decode(),),
        )
        con.execute(
            "UPDATE managed_claim_observations SET snapshot=?", (encoded(poisoned).decode(),)
        )
    assert local_holds(journal) > 0


def test_partial_persistent_schema_is_a_read_only_hold(entry_fixture):
    journal = entry_fixture.journal
    with journal._connection() as con:
        con.execute("CREATE TABLE managed_persistent_incarnations(runtime_id TEXT PRIMARY KEY)")
    assert local_holds(journal) > 0
    with journal._connection() as con:
        assert (
            con.execute(
                "SELECT 1 FROM sqlite_master WHERE name='managed_persistent_attempts'"
            ).fetchone()
            is None
        )


def test_retiring_an_earlier_released_job_never_substitutes_the_later_job_receipt(
    persistent_worker,
):
    p = persistent_worker
    p.settings.update(jobs=2)
    worker = p.configure()
    original_rpc = p.t.client.managed_post

    def second_release_unknown(path, body):
        if path.endswith("/runtime-idle-release") and body["runtime_sequence"] == "2":
            p.settings["fault"] = "runtime-idle-release"
        return original_rpc(path, body)

    p.t.client.managed_post = second_release_unknown
    with pytest.raises(api.ManagedTransportError):
        worker.run()
    journal = p.t.f.journal
    with journal._connection() as con:
        rows = [
            dict(row)
            for row in con.execute(
                "SELECT * FROM managed_persistent_attempts ORDER BY runtime_sequence"
            )
        ]
        links = [claim_association(con, row["run_id"]) for row in rows]
        claims = [
            dict(
                con.execute(
                    "SELECT * FROM managed_claim_intents WHERE run_id=?", (row["run_id"],)
                ).fetchone()
            )
            for row in rows
        ]
        intents = [
            dict(
                con.execute(
                    "SELECT * FROM managed_result_intents WHERE run_id=?", (row["run_id"],)
                ).fetchone()
            )
            for row in rows
        ]
    assert [row["state"] for row in rows] == ["released", "release_in_flight"]
    replies = []
    for row, link, claim, intent in zip(rows, links, claims, intents, strict=True):
        reply = linked_reply(p, row, link, claimed=True)
        binding = {key: json.loads(row["binding"])[key] for key in results.BINDING}
        reply["claim"].update(
            **{
                key: binding[key]
                for key in ("contract_id", "attempt_id", "fence", "contract_sha256")
            },
            authority_sha256=claim["authority_sha256"],
            consumed=True,
        )
        reply.update(
            result={
                "schema": "vardr.managed-result-receipt/1",
                **binding,
                **{
                    key: intent[key] for key in ("artifact_sha256", "case_sha256", "receipt_sha256")
                },
                "evidence_created": 0,
                "scan_items_created": 0,
            },
            completion=json.loads(row["completion"]),
            stop=None,
            execution_state="completed",
        )
        reply["runtime_retirement"].update(
            runtime_sequence="2",
            last_sequence="2",
            binding={key: json.loads(rows[1]["binding"])[key] for key in results.BINDING},
            attempt_receipt=json.loads(rows[1]["completion"]),
        )
        rehash(reply)
        replies.append(reply)
    assert (
        replies[0]["completion"]["job_id"]
        != replies[0]["runtime_retirement"]["attempt_receipt"]["job_id"]
    )
    assert (
        reconcile_managed(journal, rows[0]["run_id"], links[0]["runner_id"], lambda _: replies[0])
        == "terminal_receipt_observed"
    )
    assert local_holds(journal) > 0
    with journal._connection() as con:
        first = dict(
            con.execute(
                "SELECT * FROM managed_persistent_attempts WHERE runtime_sequence=1"
            ).fetchone()
        )
        second = dict(
            con.execute(
                "SELECT * FROM managed_persistent_attempts WHERE runtime_sequence=2"
            ).fetchone()
        )
        assert (
            first["completion"] == rows[0]["completion"]
            and first["release_ack"] == rows[0]["release_ack"]
        )
        assert second == rows[1]
    assert (
        reconcile_managed(journal, rows[1]["run_id"], links[1]["runner_id"], lambda _: replies[1])
        == "terminal_receipt_observed"
    )
    assert local_holds(journal) == 0 and p.t.calls.count("claim") == 2
