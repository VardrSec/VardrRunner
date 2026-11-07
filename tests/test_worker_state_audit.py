"""Offline inspection of isolated real journals; no providers or physical workers."""

import copy
import json
import sqlite3
from contextlib import contextmanager
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from tests.test_worker_persistent_observations import admission_document as admission_document
from tests.test_worker_persistent_observations import entry_fixture as entry_fixture
from tests.test_worker_persistent_observations import linked_reply, prepare_unknown, rehash
from tests.test_worker_persistent_observations import persistent_worker as persistent_worker
from tests.test_worker_persistent_observations import specimen as specimen
from tests.test_worker_persistent_observations import worker_fixture as worker_fixture
from vardrrunner import api, config, identity
from vardrrunner.authorization import worker_inspection as inspection
from vardrrunner.authorization.codec import AuthorizationError
from vardrrunner.authorization.reconciliation import (
    local_holds,
    local_holds_connection,
    reconcile_managed,
)
from vardrrunner.cli import app
from vardrrunner.journal import Journal

FIELDS = {
    "schema",
    "status",
    "reason",
    "complete",
    "binding",
    "parent",
    "counts",
    "retirement_receipt_sha256",
    "global_holds",
}


def selection(p, tmp_path, *, reserve=False):
    worker = p.configure() if reserve else p.worker
    admission = worker.admission
    if reserve:
        worker.store.reserve_runtime(
            admission.runtime_id,
            admission.runtime_sha256,
            admission.max_attempts,
            admission_sha256=admission.admission_sha256,
            admission_snapshot=admission.to_document(),
        )
    selected_identity = tmp_path / "existing-identity.json"
    selected_identity.write_text(
        json.dumps(
            {
                "identity_schema_version": 1,
                "runner_id": admission.runner_id,
                "name": "private-name-canary",
                "hostname": "private-host-canary",
            }
        )
    )
    selected_identity.chmod(0o600)
    return {
        "journal": str(p.t.f.journal.path),
        "identity": str(selected_identity),
        "runner_id": admission.runner_id,
        "runtime_id": admission.runtime_id,
        "runtime_sha256": admission.runtime_sha256,
        "admission_sha256": admission.admission_sha256,
    }


def held(document, *, complete=False):
    assert set(document) == FIELDS and document["schema"] == inspection.SCHEMA
    assert document["status"] == "held" and document["complete"] is complete
    if not complete:
        assert document["counts"] is document["global_holds"] is document["parent"] is None
        assert document["retirement_receipt_sha256"] is None
    assert "canary" not in json.dumps(document)


def test_genuine_parent_zero_is_empty_unissued_without_a_retirement(persistent_worker, tmp_path):
    p = persistent_worker
    selected = selection(p, tmp_path, reserve=True)
    with (
        patch.object(Journal, "__init__", side_effect=AssertionError("no constructor")),
        patch.object(
            identity, "load_or_create", side_effect=AssertionError("no identity creation")
        ),
    ):
        document = inspection.inspect_worker_state(**selected)
    assert set(document) == FIELDS
    assert document["status"] == "empty_unissued" and document["complete"] is True
    assert document["counts"] == dict(
        attempts=0, selections=0, associated_runs=0, associated_claims=0
    )
    assert document["parent"] == dict(
        state="idle", last_sequence="0", head_sequence=None, active_sequence=None
    )
    assert document["global_holds"] == 0 and document["retirement_receipt_sha256"] is None
    assert "private-name-canary" not in json.dumps(document)
    assert "private-host-canary" not in json.dumps(document)


def test_original_unissued_selection_retirement_is_retired_not_parent_zero_na(
    persistent_worker, tmp_path
):
    p = persistent_worker
    row, link = prepare_unknown(p)
    reply = linked_reply(p, row, link)
    journal = p.t.f.journal
    assert reconcile_managed(
        journal, row["run_id"], link["runner_id"], lambda _: copy.deepcopy(reply)
    ).startswith("terminal_")
    selected = selection(p, tmp_path)
    document = inspection.inspect_worker_state(**selected)
    assert document["status"] == "retired" and document["complete"] is True
    assert document["counts"] == dict(
        attempts=0, selections=1, associated_runs=1, associated_claims=1
    )
    assert document["parent"]["last_sequence"] == "0"
    assert document["retirement_receipt_sha256"] == reply["runtime_retirement"]["receipt_sha256"]
    assert document["global_holds"] == 0


def test_earlier_released_history_remains_released_after_exact_later_retirement(
    persistent_worker, tmp_path
):
    p = persistent_worker
    p.settings["jobs"] = 3
    worker = p.configure()
    original_rpc = p.t.client.managed_post

    def rpc(path, body):
        if path.endswith("/claim") and p.state["released"] == 2:
            raise api.ManagedTransportError("synthetic third claim unknown")
        return original_rpc(path, body)

    p.t.client.managed_post = rpc
    with pytest.raises(AuthorizationError, match="unknown"):
        worker.run()
    journal = p.t.f.journal
    with journal._connection() as con:
        row = dict(
            con.execute(
                "SELECT * FROM managed_persistent_selections WHERE runtime_sequence=3"
            ).fetchone()
        )
        from vardrrunner.authorization.worker_binding import claim_association

        link = claim_association(con, row["run_id"])
        before = [
            dict(item)
            for item in con.execute(
                "SELECT * FROM managed_persistent_attempts ORDER BY runtime_sequence"
            )
        ]
    reply = linked_reply(p, row, link)
    reply["runtime_retirement"]["last_sequence"] = "2"
    rehash(reply)
    reconcile_managed(journal, row["run_id"], link["runner_id"], lambda _: reply)
    document = inspection.inspect_worker_state(**selection(p, tmp_path))
    assert document["status"] == "retired" and document["global_holds"] == 0
    assert document["counts"] == dict(
        attempts=2, selections=3, associated_runs=3, associated_claims=3
    )
    with journal._connection() as con:
        assert [
            dict(item)
            for item in con.execute(
                "SELECT * FROM managed_persistent_attempts ORDER BY runtime_sequence"
            )
        ] == before
    assert [item["state"] for item in before] == ["released", "released"]


@pytest.mark.parametrize(
    "change", ["missing", "schema", "partial", "wrong_digest", "wrong_runner", "orphan"]
)
def test_missing_incomplete_or_mismatched_state_never_reports_zero(
    persistent_worker, tmp_path, change
):
    p = persistent_worker
    selected = selection(p, tmp_path, reserve=True)
    if change == "missing":
        selected["journal"] = str(tmp_path / "absent" / "journal.sqlite3")
    elif change == "wrong_digest":
        selected["admission_sha256"] = "f" * 64
    elif change == "wrong_runner":
        selected["runner_id"] = "22222222-2222-4222-8222-222222222222"
    else:
        orphan_id = None
        if change == "orphan":
            orphan_id = p.t.f.journal.begin(
                job_id="orphan",
                backend_url="https://map.example.test",
                engagement_id="eng-1",
                job_type="x",
                tool="x",
                target_source="x",
            ).run_id
        with p.t.f.journal._connection() as con:
            if change == "schema":
                con.execute("PRAGMA user_version=0")
            elif change == "partial":
                con.execute("DROP TABLE managed_persistent_selections")
            else:
                con.execute(
                    "INSERT INTO managed_persistent_selections(run_id,runtime_id,runtime_sequence,runtime_sha256,admission_sha256,claim_link,state) VALUES(?,?,?,?,?,?,?)",
                    (
                        orphan_id,
                        selected["runtime_id"],
                        1,
                        selected["runtime_sha256"],
                        selected["admission_sha256"],
                        "{}",
                        "selected",
                    ),
                )
    held(inspection.inspect_worker_state(**selected))
    assert not (tmp_path / "absent").exists()


def test_live_or_unrelated_holds_are_complete_held_facts(persistent_worker, tmp_path):
    p = persistent_worker
    selected = selection(p, tmp_path, reserve=True)
    p.t.f.journal.begin(
        job_id="unrelated",
        backend_url="https://map.example.test",
        engagement_id="eng-1",
        job_type="x",
        tool="x",
        target_source="x",
    )
    document = inspection.inspect_worker_state(**selected)
    held(document, complete=True)
    assert document["reason"] == "local_holds" and document["global_holds"] > 0


def test_done_release_without_physical_retirement_is_complete_held(persistent_worker, tmp_path):
    p = persistent_worker
    with pytest.raises(AuthorizationError, match="worker_availability_held"):
        p.configure().run()
    document = inspection.inspect_worker_state(**selection(p, tmp_path))
    held(document, complete=True)
    assert document["reason"] == "runtime_unretired" and document["global_holds"] == 0
    assert document["counts"]["attempts"] == 1


def test_missing_original_observation_is_incomplete(persistent_worker, tmp_path):
    p = persistent_worker
    row, link = prepare_unknown(p)
    reply = linked_reply(p, row, link)
    journal = p.t.f.journal
    reconcile_managed(journal, row["run_id"], link["runner_id"], lambda _: reply)
    selected = selection(p, tmp_path)
    with journal._connection() as con:
        con.execute("DELETE FROM managed_claim_observations")
    held(inspection.inspect_worker_state(**selected))


def test_wal_committed_state_is_observed_without_immutable_or_checkpoint(
    persistent_worker, tmp_path, monkeypatch
):
    p = persistent_worker
    selected = selection(p, tmp_path, reserve=True)
    connection = sqlite3.connect(selected["journal"])
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("UPDATE managed_persistent_incarnations SET state='idle'")
        connection.commit()
        calls = []
        real_connection = inspection.journal_connection

        @contextmanager
        def observe(path, *, readonly=False):
            assert readonly is True
            with real_connection(path, readonly=readonly) as con:
                con.set_trace_callback(calls.append)
                yield con

        monkeypatch.setattr(inspection, "journal_connection", observe)
        assert inspection.inspect_worker_state(**selected)["status"] == "empty_unissued"
        assert calls.count("BEGIN") == 1 and calls[-1] == "ROLLBACK"
        assert not any(
            any(
                word in query.upper()
                for word in ("CHECKPOINT", "INSERT", "UPDATE", "DELETE", "CREATE", "ALTER")
            )
            for query in calls
        )
    finally:
        connection.close()


def test_cooperative_exhaustion_inside_full_audit_is_held_not_partial_zero(
    persistent_worker, tmp_path, monkeypatch
):
    p = persistent_worker
    selected = selection(p, tmp_path, reserve=True)
    original = inspection.local_holds_connection

    # Build an unresolved row before the snapshot; no writer runs during inspection.
    p.t.f.journal.begin(
        job_id="first-pending",
        backend_url="https://map.example.test",
        engagement_id="eng-1",
        job_type="x",
        tool="x",
        target_source="x",
    )
    monkeypatch.setattr(
        inspection,
        "local_holds_connection",
        lambda con, **_: original(
            con,
            checkpoint=lambda: (_ for _ in ()).throw(inspection.InspectionExpired()),
            strict=True,
        ),
    )
    document = inspection.inspect_worker_state(**selected)
    held(document)
    assert document["reason"] == "inspection_budget_exhausted"


def test_existing_full_audit_and_same_connection_delegate_have_identical_results(
    persistent_worker, tmp_path
):
    p = persistent_worker
    selection(p, tmp_path, reserve=True)
    journal = p.t.f.journal
    with journal._connection() as con:
        assert local_holds_connection(con) == local_holds(journal) == 0
    journal.begin(
        job_id="held",
        backend_url="https://map.example.test",
        engagement_id="eng-1",
        job_type="x",
        tool="x",
        target_source="x",
    )
    with journal._connection() as con:
        assert local_holds_connection(con) == local_holds(journal) > 0


@pytest.mark.parametrize(
    "value", ["pasted-secret-canary", "", "../private-canary", "\x00private-canary"]
)
def test_bad_known_selections_emit_fixed_json_without_cleanup_or_default_reads(tmp_path, value):
    selected = dict(
        journal=value,
        identity=value,
        runner_id=value,
        runtime_id=value,
        runtime_sha256=value,
        admission_sha256=value,
    )
    args = ["worker-state"]
    for key, item in selected.items():
        args.extend(["--" + key.replace("_", "-"), item])
    with (
        patch("vardrrunner.cli.process_runner.cleanup_sensitive_temp_dirs") as cleanup,
        patch.object(config, "load", side_effect=AssertionError("no config")),
        patch.object(identity, "load_or_create", side_effect=AssertionError("no defaults")),
        patch.object(Journal, "__init__", side_effect=AssertionError("no migration")),
    ):
        result = CliRunner().invoke(app, args)
    assert result.exit_code == 1
    document = json.loads(result.stdout)
    held(document)
    assert document["reason"] == "selection_invalid"
    assert value not in result.stdout if value else True
    cleanup.assert_not_called()


def test_identity_reader_is_bounded_noncreating_and_refuses_noncanonical_identity(tmp_path):
    path = tmp_path / "identity.json"
    with pytest.raises(identity.IdentityError):
        identity.read_existing(path)
    assert not path.exists()
    for raw in (b"x" * 8193, b"{}", b'{"identity_schema_version":true}'):
        path.write_bytes(raw)
        path.chmod(0o600)
        with pytest.raises(identity.IdentityError):
            identity.read_existing(path)


@pytest.mark.parametrize(
    "field,value",
    [
        ("runner_id", True),
        ("runtime_id", None),
        ("runtime_sha256", 1),
        ("admission_sha256", "A" * 64),
        ("runtime_id", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"),
    ],
)
def test_selection_types_and_canonical_values_fail_before_storage(field, value, monkeypatch):
    selected = dict(
        journal="unused",
        identity="unused",
        runner_id="11111111-1111-4111-8111-111111111111",
        runtime_id="22222222-2222-4222-8222-222222222222",
        runtime_sha256="a" * 64,
        admission_sha256="b" * 64,
    )
    selected[field] = value
    monkeypatch.setattr(
        inspection, "read_existing", lambda _: pytest.fail("storage must not be read")
    )
    document = inspection.inspect_worker_state(**selected)
    held(document)
    assert document["reason"] == "selection_invalid" and document["binding"] is None


@pytest.mark.parametrize("missing", [False, True])
def test_top_level_cli_closes_output_and_never_uses_defaults_or_constructors(
    persistent_worker, tmp_path, missing
):
    selected = selection(persistent_worker, tmp_path, reserve=True)
    if missing:
        selected["identity"] = str(tmp_path / "private-identity-path-canary")
    args = ["worker-state"]
    for key, value in selected.items():
        args.extend(["--" + key.replace("_", "-"), value])
    with (
        patch("vardrrunner.cli.process_runner.cleanup_sensitive_temp_dirs") as cleanup,
        patch.object(config, "load", side_effect=AssertionError("no default config")),
        patch.object(config, "get_api_key", side_effect=AssertionError("no keychain")),
        patch.object(
            identity, "load_or_create", side_effect=AssertionError("no identity constructor")
        ),
        patch.object(Journal, "__init__", side_effect=AssertionError("no journal constructor")),
        patch(
            "vardrrunner.credential_grants.Store.__init__",
            side_effect=AssertionError("no grants Store"),
        ),
        patch(
            "vardrrunner.authorization.worker_persistent.PersistentStore.__init__",
            side_effect=AssertionError("no worker Store"),
        ),
    ):
        result = CliRunner().invoke(app, args)
    assert result.exit_code == (1 if missing else 0)
    document = json.loads(result.stdout)
    assert set(document) == FIELDS
    assert "canary" not in result.stdout and "private-host" not in result.stdout
    if missing:
        held(document)
        assert document["reason"] == "identity_unavailable"
    else:
        assert document["status"] == "empty_unissued"
    cleanup.assert_not_called()


def test_rehashed_parent_retirement_still_requires_unchanged_original_observation(
    persistent_worker, tmp_path
):
    p = persistent_worker
    row, link = prepare_unknown(p)
    reply = linked_reply(p, row, link)
    journal = p.t.f.journal
    reconcile_managed(journal, row["run_id"], link["runner_id"], lambda _: reply)
    selected = selection(p, tmp_path)
    poisoned = copy.deepcopy(reply)
    poisoned["runtime_retirement"]["report_sha256"] = "f" * 64
    rehash(poisoned)
    from vardrrunner.authorization.codec import encoded

    canonical = encoded(poisoned["runtime_retirement"]).decode()
    with journal._connection() as con:
        con.execute("UPDATE managed_persistent_incarnations SET retirement=?", (canonical,))
        con.execute("UPDATE managed_persistent_selections SET retirement=?", (canonical,))
    held(inspection.inspect_worker_state(**selected))


def test_sql_progress_exhaustion_is_held_with_no_counts(persistent_worker, tmp_path, monkeypatch):
    selected = selection(persistent_worker, tmp_path, reserve=True)
    real_connection = inspection.journal_connection

    @contextmanager
    def expire_during_sql(path, *, readonly=False):
        with real_connection(path, readonly=readonly) as con:
            yield Proxy(con)

    class Proxy:
        def __init__(self, con):
            object.__setattr__(self, "con", con)

        def __getattr__(self, name):
            return getattr(self.con, name)

        def __setattr__(self, name, value):
            setattr(self.con, name, value)

        def set_progress_handler(self, callback, instructions):
            assert instructions == 1000 and callback() == 0
            con = self.con
            con.set_progress_handler(lambda: 1, 1)
            monkeypatch.setattr(inspection.time, "monotonic", lambda: float("inf"))

    monkeypatch.setattr(inspection, "journal_connection", expire_during_sql)
    document = inspection.inspect_worker_state(**selected)
    held(document)
    assert document["reason"] == "inspection_budget_exhausted"


BOOTSTRAP_RUNNER = "33333333-3333-4333-8333-333333333333"
BOOTSTRAP_FIELDS = {
    "schema",
    "status",
    "reason",
    "complete",
    "runner_id",
    "worker_history",
    "global_holds",
}


def bootstrap_paths(directory, *, runner_id=BOOTSTRAP_RUNNER, journal=None):
    journal = directory / "first-worker.sqlite3" if journal is None else journal
    selected = directory / "first-worker-identity.json"
    selected.write_text(
        json.dumps(
            {
                "identity_schema_version": 1,
                "runner_id": runner_id,
                "name": "private-name-canary",
                "hostname": "private-host-canary",
            }
        ),
        encoding="utf-8",
    )
    selected.chmod(0o600)
    return {"journal": str(journal), "identity": str(selected), "runner_id": runner_id}


def test_bootstrap_audit_reads_existing_clear_journal_without_constructors(tmp_path):
    selected = bootstrap_paths(tmp_path)
    path = tmp_path / "first-worker.sqlite3"
    Journal(path)
    before = path.read_bytes()
    with patch.object(Journal, "__init__", side_effect=AssertionError("no constructor")):
        value = inspection.inspect_worker_bootstrap(**selected)
    assert value == {
        "schema": inspection.BOOTSTRAP_SCHEMA,
        "status": "clear",
        "reason": None,
        "complete": True,
        "runner_id": BOOTSTRAP_RUNNER,
        "worker_history": False,
        "global_holds": 0,
    }
    assert path.read_bytes() == before
    assert "canary" not in json.dumps(value)


def test_bootstrap_audit_missing_journal_has_no_count_claim_or_created_file(tmp_path):
    selected = bootstrap_paths(tmp_path)
    with patch.object(inspection, "journal_connection", side_effect=AssertionError("no open")):
        value = inspection.inspect_worker_bootstrap(**selected)
    assert set(value) == BOOTSTRAP_FIELDS and value["schema"] == inspection.BOOTSTRAP_SCHEMA
    assert value["status"] == "held" and value["reason"] == "journal_not_initialized"
    assert value["complete"] is False and value["global_holds"] is value["worker_history"] is None
    assert sorted(path.name for path in tmp_path.iterdir()) == ["first-worker-identity.json"]


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_bootstrap_audit_orphaned_sidecars_are_inconsistent_without_creation(tmp_path, suffix):
    selected = bootstrap_paths(tmp_path)
    sidecar = tmp_path / ("first-worker.sqlite3" + suffix)
    sidecar.write_bytes(b"synthetic-sidecar")
    value = inspection.inspect_worker_bootstrap(**selected)
    assert value["status"] == "held" and value["reason"] == "state_inconsistent"
    assert value["complete"] is False and value["global_holds"] is None
    assert (
        not (tmp_path / "first-worker.sqlite3").exists()
        and sidecar.read_bytes() == b"synthetic-sidecar"
    )


def test_bootstrap_audit_existing_unrelated_hold_is_a_complete_hold(tmp_path):
    selected = bootstrap_paths(tmp_path)
    journal = Journal(tmp_path / "first-worker.sqlite3")
    journal.begin(
        job_id="fixture-hold",
        backend_url="https://map.example.test",
        engagement_id="fixture",
        job_type="x",
        tool="x",
        target_source="x",
    )
    value = inspection.inspect_worker_bootstrap(**selected)
    assert value["status"] == "held" and value["reason"] == "local_holds"
    assert (
        value["complete"] is True and value["worker_history"] is False and value["global_holds"] > 0
    )


def test_bootstrap_audit_idle_unissued_original_worker_is_existing_history(
    persistent_worker, tmp_path
):
    original = selection(persistent_worker, tmp_path, reserve=True)
    journal = persistent_worker.t.f.journal.path
    selected = bootstrap_paths(journal.parent, runner_id=original["runner_id"], journal=journal)
    value = inspection.inspect_worker_bootstrap(**selected)
    assert value["status"] == "held" and value["reason"] == "worker_history_present"
    assert (
        value["complete"] is True and value["worker_history"] is True and value["global_holds"] == 0
    )


def test_bootstrap_audit_wrong_identity_unknown_schema_and_relative_paths_hold(tmp_path):
    selected = bootstrap_paths(tmp_path)
    journal = Journal(tmp_path / "first-worker.sqlite3")
    wrong = {**selected, "runner_id": "44444444-4444-4444-8444-444444444444"}
    assert inspection.inspect_worker_bootstrap(**wrong)["reason"] == "state_inconsistent"
    invalid = {**selected, "identity": "relative.json"}
    assert inspection.inspect_worker_bootstrap(**invalid)["reason"] == "selection_invalid"
    with journal._connection() as con:
        con.execute("CREATE TABLE managed_worker_unknown (fixture INTEGER)")
    value = inspection.inspect_worker_bootstrap(**selected)
    assert value["status"] == "held" and value["reason"] == "state_inconsistent"
    assert value["complete"] is False and value["worker_history"] is None


def test_bootstrap_audit_passes_original_file_identity_and_never_reports_partial_zero(
    tmp_path, monkeypatch
):
    selected = bootstrap_paths(tmp_path)
    path = tmp_path / "first-worker.sqlite3"
    Journal(path)
    info = path.lstat()
    with patch.object(
        inspection, "journal_connection", side_effect=OSError("synthetic replacement")
    ) as connection:
        value = inspection.inspect_worker_bootstrap(**selected)
    connection.assert_called_once_with(
        path, readonly=True, expected_identity=(info.st_dev, info.st_ino)
    )
    assert value["status"] == "held" and value["reason"] == "journal_unavailable"
    assert value["complete"] is False and value["worker_history"] is value["global_holds"] is None
    monkeypatch.setattr(inspection, "INSPECTION_SECONDS", 0)
    value = inspection.inspect_worker_bootstrap(**selected)
    assert value["reason"] == "inspection_budget_exhausted" and value["global_holds"] is None
