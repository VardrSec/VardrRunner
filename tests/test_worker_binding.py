"""Runtime admission/ACK tombstones with real managed claims; no tool execution."""

import copy
import json
import sqlite3

import pytest

from tests.test_managed_claim import entry_fixture as entry_fixture
from tests.test_managed_claim import specimen as specimen
from vardrrunner.authorization.codec import AuthorizationError, digest, encoded
from vardrrunner.authorization.results import BINDING
from vardrrunner.authorization.worker_binding import WorkerStore, claim_association
from vardrrunner.journal import Phase

RUNTIME_ID = "c52c1acc-5c25-4419-ae3b-90e14f744e3d"
RUNTIME_SHA256 = "1" * 64
ENROLLMENT_ID = "fixture-enrollment"


def linked_entry(f, *, claim=None, after_link=None):
    store = WorkerStore(f.journal)
    store.reserve_runtime(RUNTIME_ID, RUNTIME_SHA256)

    def before(con, run_id):
        store.prepare_claim(
            con,
            run_id,
            runtime_id=RUNTIME_ID,
            runtime_sha256=RUNTIME_SHA256,
            runner_id=f.s.context.runner_id,
            enrollment_id=ENROLLMENT_ID,
        )
        if after_link is not None:
            after_link(con, run_id)

    kwargs = {"before_claim_send": before}
    if claim is not None:
        kwargs["claim"] = claim
    return store, f.make(**kwargs)


def test_claim_link_is_committed_before_rpc_and_survives_post_consume_binding(entry_fixture):
    f = entry_fixture
    seen = []

    def rpc(body):
        with f.journal._connection() as con:
            run_id = con.execute("SELECT run_id FROM managed_claim_intents").fetchone()[0]
            link = claim_association(con, run_id)
            assert (
                con.execute("SELECT state FROM managed_claim_intents").fetchone()[0]
                == "claim_in_flight"
            )
        assert link["enrollment_id"] == ENROLLMENT_ID
        assert link["runner_id"] == f.s.context.runner_id
        seen.append(link)
        return {**copy.deepcopy(f.s.claim), "config": {"test_case": copy.deepcopy(f.s.case)}}

    store, entry = linked_entry(f, claim=rpc)
    handle = entry.acquire(f.directory)
    assert len(seen) == 1
    binding = {key: handle.gate.binding[key] for key in BINDING - {"contract_sha256"}}
    binding.update(
        contract_sha256=digest(encoded(handle.gate.envelope)),
        runtime_id=RUNTIME_ID,
        runtime_sha256=RUNTIME_SHA256,
    )
    f.journal.transition(handle.run_id, Phase.EXECUTING)
    handle.store.consumption(handle.run_id, handle._owner, acknowledged=False)
    store.prepare_binding(handle.run_id, binding)
    store.acknowledge_binding(
        handle.run_id,
        binding,
        {"schema": "vardr.worker-runtime-binding/1", **binding, "bound": True},
    )
    with f.journal._connection() as con:
        assert claim_association(con, handle.run_id) == seen[0]
        assert (
            con.execute("SELECT claim_link FROM managed_runtime_bindings").fetchone()[0]
            == encoded(seen[0]).decode()
        )


def test_metadata_hook_failure_rolls_back_link_and_send_markers_before_local_retirement(
    entry_fixture,
):
    f = entry_fixture

    def fail(con, run_id):
        assert claim_association(con, run_id) is not None
        raise OSError("synthetic metadata transaction failure")

    _, entry = linked_entry(f, after_link=fail)
    with pytest.raises(AuthorizationError, match="denied_before_rpc"):
        entry.acquire(f.directory)
    assert f.rpc == []
    with f.journal._connection() as con:
        runtime = con.execute("SELECT * FROM managed_runtime_bindings").fetchone()
        claim = con.execute("SELECT * FROM managed_claim_intents").fetchone()
        assert (runtime["state"], runtime["run_id"], runtime["claim_link"]) == (
            "waiting",
            None,
            None,
        )
        assert (claim["utc_anchor"], claim["mono_anchor"]) == (None, None)
        assert claim["state"] == "preclaim_retired"
        assert claim_association(con, entry.run_id) is None


def test_lost_claim_reply_retains_readable_original_link_without_reconstructing_claim(
    entry_fixture,
):
    f = entry_fixture

    def lost(body):
        raise OSError("synthetic lost reply")

    _, entry = linked_entry(f, claim=lost)
    with pytest.raises(AuthorizationError, match="claim_outcome_unknown"):
        entry.acquire(f.directory)
    with f.journal._connection() as con:
        link = claim_association(con, entry.run_id)
        claim = con.execute("SELECT * FROM managed_claim_intents").fetchone()
        assert claim["contract"] is None and claim["consumption_acknowledged"] == 0
        assert link["schema"] == "vardr.worker-claim-association/1"
        assert link["runtime_id"] == RUNTIME_ID and link["enrollment_id"] == ENROLLMENT_ID
        con.execute("UPDATE managed_claim_intents SET state='runtime_unbound_retired'")
        con.execute(
            "UPDATE runs SET phase=?,status='not_claimed' WHERE run_id=?",
            (Phase.FAILED.value, entry.run_id),
        )
        assert claim_association(con, entry.run_id) == link


@pytest.mark.parametrize(
    "change",
    ["plan", "case", "association", "origin", "runtime_hash", "noncanonical", "missing_link"],
)
def test_claim_link_reader_refuses_changed_original_fingerprints(entry_fixture, change):
    f = entry_fixture
    _, entry = linked_entry(f)
    handle = entry.acquire(f.directory)
    with f.journal._connection() as con:
        if change in {"plan", "case", "association"}:
            statements = {
                "plan": "UPDATE managed_claim_intents SET plan_sha256=?",
                "case": "UPDATE managed_claim_intents SET case_sha256=?",
                "association": "UPDATE managed_claim_intents SET association_sha256=?",
            }
            con.execute(statements[change], ("f" * 64,))
        elif change == "origin":
            con.execute("UPDATE runs SET backend_url='https://other.example.test'")
        elif change == "runtime_hash":
            con.execute("UPDATE managed_runtime_bindings SET runtime_sha256=?", ("f" * 64,))
        elif change == "missing_link":
            con.execute("UPDATE managed_runtime_bindings SET claim_link=NULL")
        else:
            value = json.loads(
                con.execute("SELECT claim_link FROM managed_runtime_bindings").fetchone()[0]
            )
            con.execute(
                "UPDATE managed_runtime_bindings SET claim_link=?", (json.dumps(value, indent=2),)
            )
        with pytest.raises(AuthorizationError):
            claim_association(con, handle.run_id)


def test_legacy_reader_creates_no_schema_and_additive_migration_does_not_upgrade_old_link(
    entry_fixture,
):
    empty = sqlite3.connect(":memory:")
    try:
        assert claim_association(empty, "legacy-run") is None
        assert empty.execute("SELECT name FROM sqlite_master").fetchall() == []
    finally:
        empty.close()
    f = entry_fixture
    with f.journal._connection() as con:
        con.execute(
            "CREATE TABLE managed_runtime_bindings (runtime_id TEXT PRIMARY KEY,runtime_sha256 TEXT NOT NULL,run_id TEXT UNIQUE,binding TEXT,state TEXT NOT NULL)"
        )
        con.execute(
            "INSERT INTO managed_runtime_bindings VALUES (?,?,?,'{}','bound')",
            (RUNTIME_ID, RUNTIME_SHA256, "legacy-run"),
        )
        assert claim_association(con, "legacy-run") is None
    WorkerStore(f.journal)
    with f.journal._connection() as con:
        row = con.execute("SELECT * FROM managed_runtime_bindings").fetchone()
        assert (
            row["claim_link"] is None and row["run_id"] == "legacy-run" and row["state"] == "bound"
        )
        assert claim_association(con, "legacy-run") is None


@pytest.fixture
def binding_fixture(entry_fixture):
    f = entry_fixture
    handle = f.make().acquire(f.directory)
    binding = {key: handle.gate.binding[key] for key in BINDING - {"contract_sha256"}}
    binding.update(
        contract_sha256=digest(encoded(handle.gate.envelope)),
        runtime_id=RUNTIME_ID,
        runtime_sha256=RUNTIME_SHA256,
    )
    store = WorkerStore(f.journal)
    store.reserve_runtime(RUNTIME_ID, RUNTIME_SHA256)
    f.journal.transition(handle.run_id, Phase.EXECUTING)
    handle.store.consumption(handle.run_id, handle._owner, acknowledged=False)
    return f, handle, store, binding


def test_runtime_invocation_cannot_be_reused_after_process_loss(binding_fixture):
    f, _, _, _ = binding_fixture
    restarted = WorkerStore(f.journal)
    with pytest.raises(AuthorizationError, match="worker_runtime_already_invoked"):
        restarted.reserve_runtime(RUNTIME_ID, RUNTIME_SHA256)


def test_binding_send_is_one_shot_and_only_exact_ack_is_durable(binding_fixture):
    f, handle, store, binding = binding_fixture
    store.prepare_binding(handle.run_id, binding)
    assert store.get(handle.run_id)["state"] == "bind_in_flight"
    with pytest.raises(AuthorizationError, match="worker_runtime_binding_already_attempted"):
        WorkerStore(f.journal).prepare_binding(handle.run_id, binding)
    ack = {"schema": "vardr.worker-runtime-binding/1", **binding, "bound": True}
    store.acknowledge_binding(handle.run_id, binding, ack)
    retained = store.get(handle.run_id)
    assert json.loads(retained["binding"]) == binding and retained["state"] == "bound"
    with f.journal._connection() as con:
        dump = "\n".join(con.iterdump())
        claim = con.execute("SELECT * FROM managed_claim_intents").fetchone()
    assert "x" * 40 not in dump
    assert claim["consumption_acknowledged"] == 0  # Only the original caller may acknowledge.
    assert f.journal.get(handle.run_id).phase == Phase.EXECUTING


@pytest.mark.parametrize(
    "field,value",
    [("bound", 1), ("fence", True), ("runtime_sha256", "2" * 64), ("attempt_id", "other")],
)
def test_mismatched_or_ambiguous_ack_retains_send_fence(binding_fixture, field, value):
    _, handle, store, binding = binding_fixture
    store.prepare_binding(handle.run_id, binding)
    ack = {"schema": "vardr.worker-runtime-binding/1", **copy.deepcopy(binding), "bound": True}
    ack[field] = value
    with pytest.raises(AuthorizationError):
        store.acknowledge_binding(handle.run_id, binding, ack)
    assert store.get(handle.run_id)["state"] == "bind_in_flight"


@pytest.mark.parametrize("change", ["acknowledged", "foreign_attempt", "artifact", "unregistered"])
def test_binding_requires_original_unacknowledged_consumption(binding_fixture, change):
    f, handle, store, binding = binding_fixture
    if change == "acknowledged":
        handle.store.consumption(handle.run_id, handle._owner, acknowledged=True)
    elif change == "foreign_attempt":
        binding["attempt_id"] = "foreign"
    elif change == "artifact":
        with f.journal._connection() as con:
            con.execute(
                "UPDATE runs SET artifact_sha256=? WHERE run_id=?", ("3" * 64, handle.run_id)
            )
    else:
        binding["runtime_id"] = "unregistered"
    with pytest.raises(AuthorizationError):
        store.prepare_binding(handle.run_id, binding)
    with f.journal._connection() as con:
        assert (
            con.execute(
                "SELECT count(*) FROM managed_runtime_bindings WHERE run_id IS NOT NULL"
            ).fetchone()[0]
            == 0
        )
