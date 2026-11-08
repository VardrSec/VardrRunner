"""Persistent metadata fences with actual signed claims and inert execution."""

import copy
import json
import sqlite3

import pytest

from tests.test_managed_claim import entry_fixture as entry_fixture
from tests.test_managed_claim import specimen as specimen
from tests.test_worker_admission import admission_document as admission_document
from tests.test_worker_persistent import persistent_worker as persistent_worker
from tests.test_worker_persistent import worker_fixture as worker_fixture
from vardrrunner import api
from vardrrunner.authorization.codec import AuthorizationError, digest, encoded
from vardrrunner.authorization.worker_binding import SequenceStore, claim_association
from vardrrunner.authorization.worker_persistent import (
    association,
    persistent_holds,
    release_document,
)


@pytest.fixture
def released(persistent_worker):
    p = persistent_worker
    p.settings.update(jobs=2, limits={"max_attempts": "2", "idle_timeout_seconds": None})
    p.configure().run()
    return p


@pytest.fixture
def release_unknown(persistent_worker):
    p = persistent_worker
    p.settings.update(jobs=2, fault="runtime-idle-release")
    with pytest.raises((AuthorizationError, api.ManagedTransportError)):
        p.configure().run()
    return p


def test_released_history_keeps_original_links_tokens_and_read_only_audit(released):
    p = released
    with p.t.f.journal._connection() as con:
        rows = con.execute(
            "SELECT * FROM managed_persistent_attempts ORDER BY runtime_sequence"
        ).fetchall()
        assert len(rows) == 2
        trace = []
        con.set_trace_callback(trace.append)
        for index, row in enumerate(rows, 1):
            link = claim_association(con, row["run_id"])
            assert link == association(con, row["run_id"])
            assert link["schema"] == "vardr.worker-claim-association/3"
            assert link["runtime_sequence"] == str(index)
            assert link["admission_sha256"] == p.worker.admission.admission_sha256
        assert persistent_holds(con) == persistent_holds(con, full=True) == 0
        assert not any(
            sql.lstrip().upper().startswith(("CREATE", "UPDATE", "INSERT", "DELETE", "ALTER"))
            for sql in trace
        )
        assert "x" * 40 not in "\n".join(con.iterdump())


@pytest.mark.parametrize(
    "statement",
    [
        "DELETE FROM managed_persistent_attempts WHERE runtime_sequence=1",
        "DELETE FROM managed_persistent_attempts WHERE runtime_sequence=2",
        "UPDATE managed_persistent_incarnations SET history_head=NULL",
        "UPDATE managed_persistent_attempts SET previous_sequence=NULL WHERE runtime_sequence=2",
        "UPDATE managed_persistent_incarnations SET state='active',active_sequence=NULL",
    ],
)
def test_sql_head_predecessor_and_null_backstops_prevent_history_loss(released, statement):
    with released.t.f.journal._connection() as con:
        assert con.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        with pytest.raises(sqlite3.IntegrityError):
            con.execute(statement)
        assert persistent_holds(con, full=True) == 0


def test_restarting_same_incarnation_never_adopts_its_closed_history(released):
    p = released
    admission = p.worker.admission
    with pytest.raises(AuthorizationError, match="already_invoked"):
        p.worker.store.reserve_runtime(
            admission.runtime_id,
            admission.runtime_sha256,
            admission.max_attempts,
            admission_sha256=admission.admission_sha256,
            admission_snapshot=admission.to_document(),
        )
    assert p.t.calls.count("claim") == 2


def test_unknown_release_holds_even_after_durable_job_completion(release_unknown):
    p = release_unknown
    with p.t.f.journal._connection() as con:
        row = con.execute("SELECT * FROM managed_persistent_attempts").fetchone()
        assert row["state"] == "release_in_flight"
        assert persistent_holds(con) > 0 and persistent_holds(con, full=True) > 0
        assert con.execute("SELECT consumed FROM authorization_contracts").fetchone()[0] == 2
    assert p.t.calls.count("claim") == p.t.calls.count("runtime-idle-release") == 1


@pytest.mark.parametrize("field", ["released", "sequence", "fence", "policy", "terminal"])
def test_changed_release_ack_cannot_clear_the_original_send_fence(release_unknown, field):
    p = release_unknown
    with p.t.f.journal._connection() as con:
        row = con.execute("SELECT * FROM managed_persistent_attempts").fetchone()
        original = json.loads(row["release_intent"])
    bad = copy.deepcopy(original)
    if field == "released":
        bad["released"] = 1
    elif field == "sequence":
        bad["runtime_sequence"] = 1
    elif field == "fence":
        bad["binding"]["fence"] = True
    elif field == "policy":
        bad["admission_sha256"] = "f" * 64
    else:
        bad["terminal_receipt_sha256"] = "f" * 64
    bad["receipt_sha256"] = digest(
        encoded({key: value for key, value in bad.items() if key != "receipt_sha256"})
    )
    with pytest.raises(AuthorizationError):
        p.worker.store.acknowledge_release(row["run_id"], bad)
    with p.t.f.journal._connection() as con:
        assert (
            con.execute("SELECT release_ack FROM managed_persistent_attempts").fetchone()[0] is None
        )
        assert persistent_holds(con) > 0


def test_persisted_boolean_integer_equivalence_never_passes_audit(release_unknown):
    p = release_unknown
    with p.t.f.journal._connection() as con:
        row = con.execute("SELECT * FROM managed_persistent_attempts").fetchone()
        bad = json.loads(row["release_intent"])
        bad["binding"]["fence"] = True
        bad["receipt_sha256"] = digest(
            encoded({key: value for key, value in bad.items() if key != "receipt_sha256"})
        )
        con.execute(
            "UPDATE managed_persistent_attempts SET release_intent=?", (encoded(bad).decode(),)
        )
    with p.t.f.journal._connection() as con, pytest.raises(AuthorizationError):
        persistent_holds(con)


@pytest.mark.parametrize("value", [True, 1.0])
def test_release_digest_never_canonicalizes_a_malformed_nested_completion(release_unknown, value):
    with release_unknown.t.f.journal._connection() as con:
        row = dict(con.execute("SELECT * FROM managed_persistent_attempts").fetchone())
    completion = json.loads(row["completion"])
    completion["fence"] = value
    row["completion"] = encoded(completion).decode()
    with pytest.raises(AuthorizationError, match="normal_completion"):
        release_document(row)


def test_cross_protocol_duplicate_link_is_never_an_upgrade(released):
    p = released
    SequenceStore(p.t.f.journal)
    with p.t.f.journal._connection() as con:
        row = con.execute("SELECT * FROM managed_persistent_attempts LIMIT 1").fetchone()
        con.execute(
            "INSERT INTO managed_worker_attempts(runtime_id,runtime_sequence,runtime_sha256,run_id,claim_link,state) VALUES(?,1,?,?,?,'claim_prepared')",
            (row["runtime_id"], row["runtime_sha256"], row["run_id"], "{}"),
        )
    with p.t.f.journal._connection() as con:
        with pytest.raises(AuthorizationError):
            claim_association(con, row["run_id"])
        with pytest.raises(AuthorizationError):
            persistent_holds(con, full=True)
