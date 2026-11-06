"""Runtime admission/ACK tombstones with real managed claims; no tool execution."""

import copy
import json

import pytest

from tests.test_managed_claim import entry_fixture as entry_fixture
from tests.test_managed_claim import specimen as specimen
from vardrrunner.authorization.codec import AuthorizationError, digest, encoded
from vardrrunner.authorization.results import BINDING
from vardrrunner.authorization.worker_binding import WorkerStore
from vardrrunner.journal import Phase

RUNTIME_ID = "c52c1acc-5c25-4419-ae3b-90e14f744e3d"
RUNTIME_SHA256 = "1" * 64


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
