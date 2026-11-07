"""One exact original-run reconciliation, with isolated real SQL and inert HTTP."""

import copy
import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from typer.testing import CliRunner

from tests.test_worker_persistent_observations import admission_document as admission_document
from tests.test_worker_persistent_observations import entry_fixture as entry_fixture
from tests.test_worker_persistent_observations import linked_reply, prepare_unknown, rehash
from tests.test_worker_persistent_observations import persistent_worker as persistent_worker
from tests.test_worker_persistent_observations import specimen as specimen
from tests.test_worker_persistent_observations import worker_fixture as worker_fixture
from tests.test_worker_persistent_preclaim import queued_denial
from tests.test_worker_state_audit import selection
from vardrrunner import api, config
from vardrrunner.authorization import observations
from vardrrunner.authorization import worker_inspection as inspection
from vardrrunner.authorization import worker_reconciliation as worker
from vardrrunner.authorization.codec import AuthorizationError, encoded
from vardrrunner.authorization.reconciliation import reconcile_managed, retire_preclaim
from vardrrunner.authorization.worker_binding import claim_association
from vardrrunner.cli import app
from vardrrunner.commands import worker_reconcile as command
from vardrrunner.journal import Journal, JournalError, journal_path_identity

FIELDS = {
    "schema",
    "status",
    "reason",
    "complete",
    "binding",
    "selected_run_id",
    "selected_sequence",
    "reconciliation_state",
    "remaining_local_holds",
    "retirement_receipt_sha256",
}


def invoke(selected):
    args = ["worker-reconcile"]
    for name, value in selected.items():
        args.extend(["--" + name.replace("_", "-"), value])
    result = CliRunner().invoke(app, args)
    output = json.loads(result.stdout)
    assert set(output) == FIELDS and output["schema"] == worker.SCHEMA
    assert "canary" not in result.stdout
    return result, output


def client_for(monkeypatch, p, reply):
    credentials = Mock(return_value=(p.worker.admission.origin, "private-key-canary"))
    monkeypatch.setattr(config, "require_auth", credentials)
    send = Mock(side_effect=lambda *_: copy.deepcopy(reply))
    client = SimpleNamespace(base=p.worker.admission.origin, managed_post=send)
    factory = Mock(return_value=client)
    monkeypatch.setattr(command.api, "VardrMapClient", factory)
    return credentials, factory, send


def deny_auth(monkeypatch):
    credentials = Mock(side_effect=AssertionError("no credential/default lookup"))
    constructor = Mock(side_effect=AssertionError("no Journal constructor/migration"))
    monkeypatch.setattr(config, "require_auth", credentials)
    monkeypatch.setattr(command, "Journal", SimpleNamespace(open_existing=constructor))
    return credentials, constructor


def released_reply(p, row, link, *, last):
    reply = linked_reply(p, row, link, claimed=True)
    with p.t.f.journal._connection() as con:
        claim = dict(
            con.execute(
                "SELECT * FROM managed_claim_intents WHERE run_id=?", (row["run_id"],)
            ).fetchone()
        )
        intent = dict(
            con.execute(
                "SELECT * FROM managed_result_intents WHERE run_id=?", (row["run_id"],)
            ).fetchone()
        )
    binding = {
        key: json.loads(row["binding"])[key]
        for key in (
            "origin",
            "job_id",
            "runner_id",
            "contract_id",
            "attempt_id",
            "fence",
            "contract_sha256",
        )
    }
    reply["claim"].update(
        **{key: binding[key] for key in ("contract_id", "attempt_id", "fence", "contract_sha256")},
        authority_sha256=claim["authority_sha256"],
        consumed=True,
    )
    reply.update(
        result={
            "schema": "vardr.managed-result-receipt/1",
            **binding,
            **{key: intent[key] for key in ("artifact_sha256", "case_sha256", "receipt_sha256")},
            "evidence_created": 0,
            "scan_items_created": 0,
        },
        completion=json.loads(row["completion"]),
        stop=None,
        execution_state="completed",
    )
    reply["runtime_retirement"].update(
        runtime_sequence=None,
        last_sequence=str(last),
        binding=None,
        attempt_receipt=None,
    )
    rehash(reply)
    return reply


def test_normal_pending_run_needs_no_external_runid_and_uses_one_original_observation(
    persistent_worker, tmp_path, monkeypatch
):
    p = persistent_worker
    row, link = prepare_unknown(p)
    selected = selection(p, tmp_path)
    reply = linked_reply(p, row, link)
    credentials, factory, send = client_for(monkeypatch, p, reply)
    calls = list(p.t.calls)
    result, document = invoke(selected)
    assert result.exit_code == 0 and document["status"] == "reconciled"
    assert document["complete"] is True and document["remaining_local_holds"] == 0
    assert document["selected_run_id"] == row["run_id"] and document["selected_sequence"] == "1"
    assert document["retirement_receipt_sha256"] == reply["runtime_retirement"]["receipt_sha256"]
    credentials.assert_called_once_with()
    factory.assert_called_once_with(p.worker.admission.origin, "private-key-canary")
    assert send.call_count == 1 and p.t.calls == calls
    path, body = send.call_args.args
    assert path == f"/jobs/{link['job_id']}/managed/observation"
    assert (
        body["runtime_sequence"] == "1" and body["admission_sha256"] == selected["admission_sha256"]
    )
    assert inspection.inspect_worker_state(**selected)["status"] == "retired"


def test_exact_released_head_retires_parent_without_rewriting_earlier_done_release(
    persistent_worker, tmp_path, monkeypatch
):
    p = persistent_worker
    p.settings.update(jobs=2, limits={"max_attempts": "2", "idle_timeout_seconds": None})
    p.configure().run()
    with p.t.f.journal._connection() as con:
        rows = [
            dict(row)
            for row in con.execute(
                "SELECT * FROM managed_persistent_attempts ORDER BY runtime_sequence"
            )
        ]
        link = claim_association(con, rows[-1]["run_id"])
    selected = selection(p, tmp_path)
    reply = released_reply(p, rows[-1], link, last=2)
    _, _, send = client_for(monkeypatch, p, reply)
    result, document = invoke(selected)
    assert result.exit_code == 0 and document["selected_run_id"] == rows[-1]["run_id"]
    assert document["selected_sequence"] == "2" and send.call_count == 1
    with p.t.f.journal._connection() as con:
        first = dict(
            con.execute(
                "SELECT * FROM managed_persistent_attempts WHERE runtime_sequence=1"
            ).fetchone()
        )
    assert first == rows[0] and first["state"] == "released"


def test_unique_unissued_selection_is_preferred_to_older_released_head(
    persistent_worker, tmp_path, monkeypatch
):
    p = persistent_worker
    p.settings["jobs"] = 2
    original = p.t.client.managed_post

    def second_unknown(path, body):
        if path.endswith("/claim") and p.state["released"] == 1:
            raise api.ManagedTransportError("synthetic second claim unknown")
        return original(path, body)

    p.t.client.managed_post = second_unknown
    with pytest.raises(AuthorizationError, match="unknown"):
        p.configure().run()
    with p.t.f.journal._connection() as con:
        pending = dict(
            con.execute(
                "SELECT * FROM managed_persistent_selections WHERE state='selected'"
            ).fetchone()
        )
        first = dict(con.execute("SELECT * FROM managed_persistent_attempts").fetchone())
        link = claim_association(con, pending["run_id"])
    reply = linked_reply(p, pending, link)
    reply["runtime_retirement"]["last_sequence"] = "1"
    rehash(reply)
    selected = selection(p, tmp_path)
    _, _, send = client_for(monkeypatch, p, reply)
    result, document = invoke(selected)
    assert result.exit_code == 0 and document["selected_run_id"] == pending["run_id"]
    assert document["selected_sequence"] == "2" and send.call_count == 1
    with p.t.f.journal._connection() as con:
        assert dict(con.execute("SELECT * FROM managed_persistent_attempts").fetchone()) == first


def test_genuine_empty_runtime_is_offline_na_without_fake_run_or_retirement(
    persistent_worker, tmp_path, monkeypatch
):
    selected = selection(persistent_worker, tmp_path, reserve=True)
    auth, constructor = deny_auth(monkeypatch)
    with patch("vardrrunner.cli.process_runner.cleanup_sensitive_temp_dirs") as cleanup:
        result, document = invoke(selected)
    assert result.exit_code == 0 and document["status"] == "empty_unissued"
    assert document["selected_run_id"] is document["selected_sequence"] is None
    assert document["retirement_receipt_sha256"] is None and document["remaining_local_holds"] == 0
    auth.assert_not_called()
    constructor.assert_not_called()
    cleanup.assert_not_called()
    audit = inspection.inspect_worker_state(**selected)
    assert audit["schema"] == "vardr.worker-state-audit/1" and set(audit) == {
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


def test_already_retired_runtime_uses_no_credentials_or_second_observation(
    persistent_worker, tmp_path, monkeypatch
):
    p = persistent_worker
    row, link = prepare_unknown(p)
    reply = linked_reply(p, row, link)
    reconcile_managed(p.t.f.journal, row["run_id"], link["runner_id"], lambda _: reply)
    selected = selection(p, tmp_path)
    auth, constructor = deny_auth(monkeypatch)
    result, document = invoke(selected)
    assert result.exit_code == 0 and document["status"] == "already_retired"
    assert document["selected_run_id"] is None and document["remaining_local_holds"] == 0
    auth.assert_not_called()
    constructor.assert_not_called()


@pytest.mark.parametrize(
    "field,value",
    [
        ("runner_id", "private-selection-canary"),
        ("runtime_sha256", "A" * 64),
        ("admission_sha256", True),
        ("journal", "\x00private-path-canary"),
    ],
)
def test_invalid_selections_are_fixed_held_before_storage_credentials_or_constructor(
    field, value, monkeypatch
):
    selected = dict(
        journal="unused",
        identity="unused",
        runner_id="11111111-1111-4111-8111-111111111111",
        runtime_id="22222222-2222-4222-8222-222222222222",
        runtime_sha256="a" * 64,
        admission_sha256="b" * 64,
    )
    selected[field] = value
    auth, constructor = deny_auth(monkeypatch)
    document, candidate, _ = worker.select_candidate(**selected)
    assert document["status"] == "held" and document["reason"] == "selection_invalid"
    assert (
        document["complete"] is False
        and document["remaining_local_holds"] is None
        and candidate is None
    )
    assert "canary" not in json.dumps(document)
    auth.assert_not_called()
    constructor.assert_not_called()


@pytest.mark.parametrize(
    "change", ["missing", "schema", "partial", "wrong_admission", "wrong_identity"]
)
def test_missing_schema_binding_or_original_identity_is_held_before_auth(
    persistent_worker, tmp_path, monkeypatch, change
):
    p = persistent_worker
    selected = selection(p, tmp_path, reserve=True)
    if change == "missing":
        selected["journal"] = str(tmp_path / "absent" / "journal.sqlite3")
    elif change == "wrong_admission":
        selected["admission_sha256"] = "f" * 64
    elif change == "wrong_identity":
        selected["identity"] = str(tmp_path / "private-identity-canary")
    else:
        with p.t.f.journal._connection() as con:
            con.execute(
                "PRAGMA user_version=0"
                if change == "schema"
                else "DROP TABLE managed_persistent_selections"
            )
    auth, constructor = deny_auth(monkeypatch)
    result, document = invoke(selected)
    assert result.exit_code == 1 and document["status"] == "held"
    assert document["complete"] is False and document["remaining_local_holds"] is None
    assert not (tmp_path / "absent").exists()
    auth.assert_not_called()
    constructor.assert_not_called()


def test_two_valid_pending_associations_are_held_without_list_guessing_or_auth(
    persistent_worker, tmp_path, monkeypatch
):
    p = persistent_worker
    row, _ = prepare_unknown(p)
    with p.t.f.journal._connection() as con:
        for table in ("runs", "managed_claim_intents", "managed_persistent_selections"):
            data = dict(
                con.execute(f"SELECT * FROM {table} WHERE run_id=?", (row["run_id"],)).fetchone()
            )
            data["run_id"] = "f" * 32
            if table == "runs":
                data["job_id"] = "ambiguous-second"
            elif table == "managed_claim_intents":
                data["job"] = "ambiguous-second"
            else:
                link = json.loads(data["claim_link"])
                link["job_id"] = "ambiguous-second"
                data["claim_link"] = encoded(link).decode()
            columns = list(data)
            con.execute(
                f"INSERT INTO {table} ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
                list(data.values()),
            )
    selected = selection(p, tmp_path)
    auth, constructor = deny_auth(monkeypatch)
    result, document = invoke(selected)
    assert result.exit_code == 1 and document["reason"] == "ambiguous_pending_selection"
    assert document["complete"] is True and document["selected_run_id"] is None
    auth.assert_not_called()
    constructor.assert_not_called()


def test_closed_preclaim_parent0_needs_original_observation_not_empty_or_fake_retirement(
    persistent_worker, tmp_path, monkeypatch
):
    p = persistent_worker
    p.configure()
    queued_denial(p, monkeypatch, late=True)
    original = p.t.client.managed_post
    pending = 0

    def stop_after_denial(path, body):
        nonlocal pending
        reply = original(path, body)
        if path.endswith("/pending"):
            pending += 1
            if pending > 1:
                reply["jobs"] = []
                reply["availability"]["state"] = "stopped"
        return reply

    p.t.client.managed_post = stop_after_denial
    with pytest.raises(AuthorizationError, match="worker_availability_held"):
        p.worker.run()
    with p.t.f.journal._connection() as con:
        row = con.execute("SELECT * FROM managed_persistent_selections").fetchone()
        assert row["state"] == "preclaim_retired"
        run_id = row["run_id"]
    inspected = Mock(side_effect=AssertionError("existing early return performs no observation"))
    assert (
        reconcile_managed(p.t.f.journal, run_id, p.worker.runner_id, inspected)
        == "local_preclaim_retired"
    )
    inspected.assert_not_called()
    selected = selection(p, tmp_path)
    auth, constructor = deny_auth(monkeypatch)
    result, document = invoke(selected)
    assert result.exit_code == 1 and document["reason"] == "original_reconciliation_unavailable"
    assert document["remaining_local_holds"] is None and document["selected_run_id"] is None
    assert inspection.inspect_worker_state(**selected)["status"] == "held"
    auth.assert_called_once_with()
    constructor.assert_not_called()


@pytest.mark.parametrize("retired", [False, True])
def test_missing_retirement_or_unavailable_original_key_never_retries_or_succeeds(
    persistent_worker, tmp_path, monkeypatch, retired
):
    p = persistent_worker
    row, link = prepare_unknown(p)
    selected = selection(p, tmp_path)
    _, _, send = client_for(monkeypatch, p, linked_reply(p, row, link, retired=retired))
    if retired:
        send.side_effect = api.ManagedTransportError("private-transport-canary")
    result, document = invoke(selected)
    assert result.exit_code == 1 and document["status"] == "held" and send.call_count == 1
    assert inspection.inspect_worker_state(**selected)["status"] == "held"


def test_origin_mismatch_refuses_before_journal_constructor_or_network(
    persistent_worker, tmp_path, monkeypatch
):
    p = persistent_worker
    row, link = prepare_unknown(p)
    selected = selection(p, tmp_path)
    _, factory, send = client_for(monkeypatch, p, linked_reply(p, row, link))
    factory.return_value.base = "https://wrong.example.test"
    constructor = Mock(side_effect=AssertionError("no wrong-origin mutation"))
    monkeypatch.setattr(command, "Journal", SimpleNamespace(open_existing=constructor))
    result, document = invoke(selected)
    assert result.exit_code == 1 and document["complete"] is False
    send.assert_not_called()
    constructor.assert_not_called()


def test_exact_association_guard_precedes_preclaim_write_and_original_network(
    persistent_worker, tmp_path
):
    p = persistent_worker
    row, _ = prepare_unknown(p)
    selection(p, tmp_path)
    store = p.t.f.journal
    before = store.get(row["run_id"])
    with pytest.raises(AuthorizationError, match="original_worker_association_required"):
        retire_preclaim(store, row["run_id"], expected_association=b"{}")
    with pytest.raises(AuthorizationError, match="original_worker_association_required"):
        observations.original(store, row["run_id"], p.worker.runner_id, expected_association=b"{}")
    assert store.get(row["run_id"]) == before


def test_candidate_selection_has_no32_job_or_history_list_ceiling(persistent_worker, tmp_path):
    p = persistent_worker
    p.settings.update(jobs=35, limits={"max_attempts": "35", "idle_timeout_seconds": None})
    p.configure().run()
    selected = selection(p, tmp_path)
    document, candidate, audit = worker.select_candidate(**selected)
    assert candidate is not None and candidate.runtime_sequence == "35"
    assert document["status"] == "selected" and audit["counts"]["attempts"] == 35


def test_inspection_budget_failure_has_no_partial_zero_or_auth(
    persistent_worker, tmp_path, monkeypatch
):
    selected = selection(persistent_worker, tmp_path, reserve=True)
    monkeypatch.setattr(
        inspection._Budget, "check", lambda _: (_ for _ in ()).throw(inspection.InspectionExpired())
    )
    auth, constructor = deny_auth(monkeypatch)
    result, document = invoke(selected)
    assert result.exit_code == 1 and document["reason"] == "inspection_budget_exhausted"
    assert document["complete"] is False and document["remaining_local_holds"] is None
    auth.assert_not_called()
    constructor.assert_not_called()


def test_one_observation_guard_blocks_accidental_second_original_request(
    persistent_worker, tmp_path, monkeypatch
):
    p = persistent_worker
    row, link = prepare_unknown(p)
    selected = selection(p, tmp_path)
    _, candidate, _ = worker.select_candidate(**selected)
    assert candidate is not None
    body = {
        key: link[key]
        for key in (
            "origin",
            "runner_id",
            "plan_sha256",
            "case_sha256",
            "association_sha256",
            "runtime_id",
            "runtime_sha256",
            "admission_sha256",
            "runtime_sequence",
        )
    }
    sent = Mock(return_value=linked_reply(p, row, link))

    def accidental_second(journal, run_id, runner_id, inspect, **kwargs):
        assert (
            run_id == candidate.run_id and kwargs["expected_association"] == candidate.association
        )
        inspect(copy.deepcopy(body))
        inspect(copy.deepcopy(body))

    monkeypatch.setattr(worker, "reconcile_managed", accidental_second)
    with pytest.raises(AuthorizationError, match="worker_observation_already_attempted"):
        worker.reconcile_candidate(p.t.f.journal, candidate, p.worker.runner_id, sent)
    assert sent.call_count == 1


@pytest.mark.parametrize("change", ["missing", "replaced", "schema"])
def test_selected_original_db_is_never_recreated_replaced_or_migrated(
    persistent_worker, tmp_path, monkeypatch, change
):
    p = persistent_worker
    row, link = prepare_unknown(p)
    selected = selection(p, tmp_path)
    _, candidate, _ = worker.select_candidate(**selected)
    assert candidate is not None
    path = p.t.f.journal.path
    old_identity = candidate.journal_identity
    assert old_identity == journal_path_identity(path)
    _, _, send = client_for(monkeypatch, p, linked_reply(p, row, link))

    def auth_after_change():
        if change == "schema":
            with p.t.f.journal._connection() as con:
                con.execute("PRAGMA user_version=0")
        else:
            data = path.read_bytes()
            path.rename(path.with_suffix(".old"))
            if change == "replaced":
                path.write_bytes(data)
                assert journal_path_identity(path) != old_identity
        return p.worker.admission.origin, "private-key-canary"

    monkeypatch.setattr(config, "require_auth", auth_after_change)
    migration = Mock(side_effect=AssertionError("no create/migrate/repair"))
    monkeypatch.setattr(Journal, "_migrate", migration)
    result, document = invoke(selected)
    assert result.exit_code == 1 and document["complete"] is False
    assert document["remaining_local_holds"] is None
    send.assert_not_called()
    migration.assert_not_called()
    if change == "missing":
        assert not path.exists()


def test_noncreating_repository_requires_original_identity_on_every_connection(
    persistent_worker, tmp_path, monkeypatch
):
    p = persistent_worker
    row, _ = prepare_unknown(p)
    selected = selection(p, tmp_path)
    _, candidate, _ = worker.select_candidate(**selected)
    assert candidate is not None
    migration = Mock(side_effect=AssertionError("no migration"))
    monkeypatch.setattr(Journal, "_migrate", migration)
    store = Journal.open_existing(p.t.f.journal.path, expected_identity=candidate.journal_identity)
    assert store.get(row["run_id"]) == p.t.f.journal.get(row["run_id"])
    # An ordinary WAL-backed transaction retains the original DB identity.
    with store._connection() as con:
        con.execute("UPDATE runs SET updated_at=updated_at WHERE run_id=?", (row["run_id"],))
    assert journal_path_identity(store.path) == candidate.journal_identity
    data = store.path.read_bytes()
    store.path.rename(store.path.with_suffix(".old"))
    store.path.write_bytes(data)
    with pytest.raises(JournalError, match="identity changed"):
        store.get(row["run_id"])
    missing = tmp_path / "not-created" / "journal.sqlite3"
    with pytest.raises(JournalError):
        Journal.open_existing(missing, expected_identity=candidate.journal_identity)
    assert not missing.parent.exists()
    migration.assert_not_called()


def add_pending(p, original_run):
    with p.t.f.journal._connection() as con:
        for table in ("runs", "managed_claim_intents", "managed_persistent_selections"):
            data = dict(
                con.execute(f"SELECT * FROM {table} WHERE run_id=?", (original_run,)).fetchone()
            )
            data["run_id"] = "e" * 32
            if table == "runs":
                data["job_id"] = "changed-pending"
            elif table == "managed_claim_intents":
                data["job"] = "changed-pending"
            else:
                link = json.loads(data["claim_link"])
                link["job_id"] = "changed-pending"
                data["claim_link"] = encoded(link).decode()
            columns = list(data)
            con.execute(
                f"INSERT INTO {table} ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
                list(data.values()),
            )


@pytest.mark.parametrize("when", ["before_post", "after_reply", "before_record"])
def test_changed_structural_candidate_cannot_post_or_record_retirement(
    persistent_worker, tmp_path, monkeypatch, when
):
    p = persistent_worker
    row, link = prepare_unknown(p)
    selected = selection(p, tmp_path)
    _, _, send = client_for(monkeypatch, p, linked_reply(p, row, link))
    if when == "before_post":

        def auth_changed():
            add_pending(p, row["run_id"])
            return p.worker.admission.origin, "private-key-canary"

        monkeypatch.setattr(config, "require_auth", auth_changed)
    elif when == "after_reply":

        def changed_reply(*_):
            add_pending(p, row["run_id"])
            return linked_reply(p, row, link)

        send.side_effect = changed_reply
    else:
        original = observations.ObservationStore.record

        def changed_record(self, *args, **kwargs):
            add_pending(p, row["run_id"])
            return original(self, *args, **kwargs)

        monkeypatch.setattr(observations.ObservationStore, "record", changed_record)
    before = p.t.f.journal.get(row["run_id"])
    result, document = invoke(selected)
    assert result.exit_code == 1 and document["status"] == "held"
    assert document["complete"] is False and document["remaining_local_holds"] is None
    assert send.call_count == (0 if when == "before_post" else 1)
    assert p.t.f.journal.get(row["run_id"]) == before
    with p.t.f.journal._connection() as con:
        assert (
            con.execute("SELECT retirement FROM managed_persistent_incarnations").fetchone()[0]
            is None
        )
        exists = con.execute(
            "SELECT 1 FROM sqlite_master WHERE name='managed_claim_observations'"
        ).fetchone()
        if exists:
            assert con.execute("SELECT COUNT(*) FROM managed_claim_observations").fetchone()[0] == 0


def test_result_write_guards_reject_wrong_original_without_changing_done_history(
    persistent_worker, tmp_path
):
    from vardrrunner.authorization.results import ResultStore
    from vardrrunner.authorization.stops import StopStore

    p = persistent_worker
    p.settings.update(jobs=1, limits={"max_attempts": "1", "idle_timeout_seconds": None})
    p.configure().run()
    selection(p, tmp_path)
    with p.t.f.journal._connection() as con:
        run_id = con.execute("SELECT run_id FROM managed_persistent_attempts").fetchone()[0]
    store = ResultStore(p.t.f.journal)
    record = store.get(run_id)
    before = p.t.f.journal.get(run_id)
    with pytest.raises(AuthorizationError, match="original_worker_association_required"):
        store.result_ack(run_id, observed=True, expected_association=b"{}")
    with pytest.raises(AuthorizationError, match="original_worker_association_required"):
        store.close(run_id, record, expected_association=b"{}")
    with pytest.raises(AuthorizationError, match="original_worker_association_required"):
        StopStore(p.t.f.journal).close(run_id, record, expected_association=b"{}")
    assert p.t.f.journal.get(run_id) == before and store.get(run_id) == record


def test_post_write_replaced_same_binding_db_cannot_supply_final_retirement_audit(
    persistent_worker, tmp_path, monkeypatch
):
    p = persistent_worker
    row, link = prepare_unknown(p)
    selected = selection(p, tmp_path)
    _, _, send = client_for(monkeypatch, p, linked_reply(p, row, link))
    original = command.inspect_worker_state
    observed = []

    def replaced_before_final(**kwargs):
        path = p.t.f.journal.path
        expected = kwargs["expected_journal_identity"]
        assert journal_path_identity(path) == expected
        # The replacement is a complete retired DB with precisely the same
        # public binding. It is still not the originally selected file.
        assert original(**selected)["status"] == "retired"
        data = path.read_bytes()
        path.rename(path.with_suffix(".original"))
        path.write_bytes(data)
        assert journal_path_identity(path) != expected
        assert original(**selected)["status"] == "retired"
        observed.append(original(**kwargs))
        return observed[-1]

    monkeypatch.setattr(command, "inspect_worker_state", replaced_before_final)
    result, document = invoke(selected)
    assert send.call_count == 1 and result.exit_code == 1
    assert len(observed) == 1 and observed[0]["status"] == "held"
    assert document["status"] == "held" and document["complete"] is False
    assert document["remaining_local_holds"] is document["retirement_receipt_sha256"] is None


def closed_preclaim_cohort(p, monkeypatch, count):
    """Use the actual persistent model's late-grant denial, never fabricated runs."""
    from tests.test_worker_persistent_preclaim import approve, revoke
    from vardrrunner.authorization.claim import ClaimStore

    p.configure()
    original_post = p.t.client.managed_post
    original_prepare = ClaimStore.prepare_send
    pending = 0
    paths = []

    def prepare_then_revoke(store, run_id, *args, **kwargs):
        original_prepare(store, run_id, *args, **kwargs)
        if store.journal.get(run_id).job_id.startswith("closed-denied-"):
            revoke(p)

    def pending_denied(path, body):
        nonlocal pending
        paths.append(path)
        if path.endswith("/pending"):
            approve(p)
        reply = original_post(path, body)
        if path.endswith("/pending"):
            pending += 1
            if pending <= count:
                assert reply["jobs"]
                job = copy.deepcopy(reply["jobs"][0])
                job["id"] = f"closed-denied-{pending:03d}"
                reply["jobs"], reply["next_after"] = [job], job["id"]
            else:
                reply["jobs"] = []
                reply["availability"]["state"] = "stopped"
        return reply

    monkeypatch.setattr(ClaimStore, "prepare_send", prepare_then_revoke)
    p.t.client.managed_post = pending_denied
    with pytest.raises(AuthorizationError, match="worker_availability_held"):
        p.worker.run()
    assert p.epochs == [] and "native" not in p.t.calls
    p.t.owner.begin_attempt.assert_not_called()
    assert not any(path.endswith("/claim") for path in paths)
    with p.t.f.journal._connection() as con:
        rows = [
            dict(row)
            for row in con.execute("SELECT * FROM managed_persistent_selections ORDER BY run_id")
        ]
        assert len(rows) == count and all(row["state"] == "preclaim_retired" for row in rows)
        assert con.execute("SELECT count(*) FROM managed_persistent_attempts").fetchone()[0] == 0
        link = claim_association(con, rows[0]["run_id"])
    return rows, link


def tombstone_rows(p):
    with p.t.f.journal._connection() as con:
        return {
            table: [dict(row) for row in con.execute(f"SELECT * FROM {table} ORDER BY run_id")]
            for table in ("runs", "managed_claim_intents", "managed_persistent_selections")
        }


def parent_row(p):
    with p.t.f.journal._connection() as con:
        return dict(con.execute("SELECT * FROM managed_persistent_incarnations").fetchone())


@pytest.mark.parametrize("count", [1, 2, 33])
def test_preclaim_parent0_original_receipt_retires_only_parent_and_keeps_all_tombstones(
    persistent_worker, tmp_path, monkeypatch, count
):
    p = persistent_worker
    rows, link = closed_preclaim_cohort(p, monkeypatch, count)
    selected = selection(p, tmp_path)
    before = tombstone_rows(p)
    reply = linked_reply(p, rows[0], link)
    _, _, send = client_for(monkeypatch, p, reply)
    result, document = invoke(selected)
    assert result.exit_code == 0 and document["status"] == "reconciled"
    assert document["reconciliation_state"] == "terminal_preclaim_parent_retired"
    assert document["selected_run_id"] == min(row["run_id"] for row in rows)
    assert document["selected_sequence"] == "1" and send.call_count == 1
    assert document["retirement_receipt_sha256"] == reply["runtime_retirement"]["receipt_sha256"]
    assert tombstone_rows(p) == before
    audit = inspection.inspect_worker_state(**selected)
    assert audit["status"] == "retired" and audit["global_holds"] == 0
    assert audit["parent"] == {
        "state": "retired",
        "last_sequence": "0",
        "head_sequence": None,
        "active_sequence": None,
    }
    assert audit["counts"] == {
        "attempts": 0,
        "selections": count,
        "associated_runs": count,
        "associated_claims": count,
    }
    auth, constructor = deny_auth(monkeypatch)
    result, document = invoke(selected)
    assert result.exit_code == 0 and document["status"] == "already_retired"
    auth.assert_not_called()
    constructor.assert_not_called()
    assert tombstone_rows(p) == before


@pytest.mark.parametrize(
    "change", ["unknown_claim", "pid", "wrong_admission", "wrong_plan", "issued_row"]
)
def test_malformed_preclaim_cohort_never_reaches_credentials_or_parent_retirement(
    persistent_worker, tmp_path, monkeypatch, change
):
    p = persistent_worker
    rows, _ = closed_preclaim_cohort(p, monkeypatch, 2)
    selected = selection(p, tmp_path)
    with p.t.f.journal._connection() as con:
        run_id = rows[-1]["run_id"]
        if change == "unknown_claim":
            con.execute(
                "UPDATE managed_claim_intents SET state='claim_unknown' WHERE run_id=?", (run_id,)
            )
        elif change == "pid":
            con.execute("UPDATE runs SET pid=123 WHERE run_id=?", (run_id,))
        elif change == "wrong_admission":
            con.execute(
                "UPDATE managed_persistent_selections SET admission_sha256=? WHERE run_id=?",
                ("e" * 64, run_id),
            )
        elif change == "wrong_plan":
            con.execute(
                "UPDATE managed_claim_intents SET plan_sha256=? WHERE run_id=?", ("e" * 64, run_id)
            )
        else:
            row = rows[-1]
            con.execute(
                "INSERT INTO managed_persistent_attempts(runtime_id,runtime_sequence,previous_sequence,runtime_sha256,admission_sha256,run_id,claim_link,state) VALUES(?,1,NULL,?,?,?,?, 'claim_prepared')",
                (
                    row["runtime_id"],
                    row["runtime_sha256"],
                    row["admission_sha256"],
                    run_id,
                    row["claim_link"],
                ),
            )
    auth, constructor = deny_auth(monkeypatch)
    result, document = invoke(selected)
    assert result.exit_code == 1 and document["status"] == "held"
    assert parent_row(p)["state"] == "idle" and parent_row(p)["retirement"] is None
    auth.assert_not_called()
    constructor.assert_not_called()


def test_mixed_selected_row_cannot_be_classified_as_closed_preclaim_parent0(
    persistent_worker, monkeypatch
):
    from vardrrunner.authorization.worker_persistent import preclaim_parent_anchor

    p = persistent_worker
    rows, _ = closed_preclaim_cohort(p, monkeypatch, 2)
    with p.t.f.journal._connection() as con:
        con.execute(
            "UPDATE managed_persistent_selections SET state='selected' WHERE run_id=?",
            (rows[-1]["run_id"],),
        )
    with p.t.f.journal._connection() as con:
        with pytest.raises(AuthorizationError, match="preclaim_parent0_cohort"):
            preclaim_parent_anchor(con, p.worker.admission.runtime_id)


@pytest.mark.parametrize(
    "change", ["missing", "plan", "admission", "last", "bound", "claim", "digest", "transport"]
)
def test_preclaim_parent0_requires_exact_positive_original_retirement(
    persistent_worker, tmp_path, monkeypatch, change
):
    p = persistent_worker
    rows, link = closed_preclaim_cohort(p, monkeypatch, 1)
    selected = selection(p, tmp_path)
    before = tombstone_rows(p)
    reply = linked_reply(p, rows[0], link)
    if change == "missing":
        reply["runtime_retirement"] = None
    elif change == "plan":
        reply["plan_sha256"] = "e" * 64
    elif change == "admission":
        reply["runtime_retirement"]["admission_sha256"] = "e" * 64
        rehash(reply)
    elif change == "last":
        reply["runtime_retirement"]["last_sequence"] = "1"
        rehash(reply)
    elif change == "bound":
        reply["runtime_retirement"]["runtime_sequence"] = "1"
        rehash(reply)
    elif change == "claim":
        reply["claim"] = {}
    elif change == "digest":
        reply["runtime_retirement"]["receipt_sha256"] = "e" * 64
    _, _, send = client_for(monkeypatch, p, reply)
    if change == "transport":
        send.side_effect = api.ManagedTransportError("original-key-canary-unavailable")
    result, document = invoke(selected)
    assert result.exit_code == 1 and document["status"] == "held" and send.call_count == 1
    assert parent_row(p)["retirement"] is None and tombstone_rows(p) == before


@pytest.mark.parametrize("when", ["before_post", "after_post"])
def test_preclaim_cohort_drift_does_not_retire_parent(
    persistent_worker, tmp_path, monkeypatch, when
):
    p = persistent_worker
    rows, link = closed_preclaim_cohort(p, monkeypatch, 2)
    selected = selection(p, tmp_path)
    reply = linked_reply(p, rows[0], link)
    _, _, send = client_for(monkeypatch, p, reply)

    def drift():
        with p.t.f.journal._connection() as con:
            con.execute(
                "UPDATE managed_persistent_selections SET state='selected' WHERE run_id=?",
                (rows[-1]["run_id"],),
            )

    if when == "before_post":

        def changed_auth():
            drift()
            return p.worker.admission.origin, "private-key-canary"

        monkeypatch.setattr(config, "require_auth", changed_auth)
    else:

        def changed_reply(*_):
            drift()
            return copy.deepcopy(reply)

        send.side_effect = changed_reply
    result, document = invoke(selected)
    assert result.exit_code == 1 and document["status"] == "held"
    assert send.call_count == (0 if when == "before_post" else 1)
    assert parent_row(p)["retirement"] is None


@pytest.mark.parametrize("when", ["before_post", "after_post"])
def test_even_valid_closed_cohort_membership_addition_is_not_silently_adopted(
    persistent_worker, tmp_path, monkeypatch, when
):
    p = persistent_worker
    rows, link = closed_preclaim_cohort(p, monkeypatch, 3)
    # Temporarily withhold, then restore, an actual model-created third tombstone.
    # No RunRecord/claim/selection is fabricated to obtain the positive proof.
    run_id = rows[-1]["run_id"]
    saved = {}
    with p.t.f.journal._connection() as con:
        for table in ("runs", "managed_claim_intents", "managed_persistent_selections"):
            saved[table] = dict(
                con.execute(f"SELECT * FROM {table} WHERE run_id=?", (run_id,)).fetchone()
            )
        for table in ("managed_persistent_selections", "managed_claim_intents", "runs"):
            con.execute(f"DELETE FROM {table} WHERE run_id=?", (run_id,))
    selected = selection(p, tmp_path)
    reply = linked_reply(p, rows[0], link)
    _, _, send = client_for(monkeypatch, p, reply)

    def restore():
        with p.t.f.journal._connection() as con:
            for table, data in saved.items():
                columns = list(data)
                con.execute(
                    f"INSERT INTO {table} ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
                    list(data.values()),
                )

    if when == "before_post":

        def changed_auth():
            restore()
            return p.worker.admission.origin, "private-key-canary"

        monkeypatch.setattr(config, "require_auth", changed_auth)
    else:

        def changed_reply(*_):
            restore()
            return copy.deepcopy(reply)

        send.side_effect = changed_reply
    result, document = invoke(selected)
    assert result.exit_code == 1 and document["status"] == "held"
    assert send.call_count == (0 if when == "before_post" else 1)
    assert parent_row(p)["retirement"] is None


def unrelated_hold(p):
    return p.t.f.journal.begin(
        job_id="unrelated-held",
        backend_url=p.worker.admission.origin,
        engagement_id="eng-1",
        job_type="x",
        tool="x",
        target_source="x",
    )


@pytest.mark.parametrize("when", ["before", "during_post", "after_commit"])
def test_preclaim_retirement_never_clears_or_conceals_unrelated_global_hold(
    persistent_worker, tmp_path, monkeypatch, when
):
    from vardrrunner.authorization.reconciliation import local_holds

    p = persistent_worker
    rows, link = closed_preclaim_cohort(p, monkeypatch, 1)
    selected = selection(p, tmp_path)
    reply = linked_reply(p, rows[0], link)
    _, _, send = client_for(monkeypatch, p, reply)
    held = []
    if when == "before":
        held.append(unrelated_hold(p))
    elif when == "during_post":

        def changed_reply(*_):
            held.append(unrelated_hold(p))
            return copy.deepcopy(reply)

        send.side_effect = changed_reply
    else:
        original = command.inspect_worker_state

        def changed_final(**kwargs):
            held.append(unrelated_hold(p))
            return original(**kwargs)

        monkeypatch.setattr(command, "inspect_worker_state", changed_final)
    result, document = invoke(selected)
    assert result.exit_code == 1 and document["status"] == "held"
    assert send.call_count == (0 if when == "before" else 1)
    assert len(held) == 1 and p.t.f.journal.get(held[0].run_id) == held[0]
    assert local_holds(p.t.f.journal) > 0
    assert (parent_row(p)["state"] == "retired") == (when == "after_commit")
    if when == "after_commit":
        audit = inspection.inspect_worker_state(**selected)
        assert audit["complete"] is True and audit["global_holds"] > 0 and audit["status"] == "held"
        auth, constructor = deny_auth(monkeypatch)
        result, document = invoke(selected)
        assert result.exit_code == 1 and document["reason"] == "global_holds_remain"
        auth.assert_not_called()
        constructor.assert_not_called()


def test_closed_tombstone_ancestry_constraint_stays_intact_after_parent_retirement(
    persistent_worker, tmp_path, monkeypatch
):
    from vardrrunner.authorization.worker_persistent import retire_incarnation_observation

    p = persistent_worker
    rows, link = closed_preclaim_cohort(p, monkeypatch, 1)
    selected = selection(p, tmp_path)
    reply = linked_reply(p, rows[0], link)
    client_for(monkeypatch, p, reply)
    assert invoke(selected)[0].exit_code == 0
    before = tombstone_rows(p)
    with pytest.raises(AuthorizationError, match="worker_selection_issued_changed"):
        with p.t.f.journal._connection() as con:
            con.execute("BEGIN IMMEDIATE")
            retire_incarnation_observation(con, rows[0]["run_id"], reply["runtime_retirement"])
    assert tombstone_rows(p) == before


@pytest.mark.parametrize("change", ["delete_observation", "wrong_original_plan", "changed_receipt"])
def test_retired_preclaim_parent_requires_retained_exact_original_anchor(
    persistent_worker, tmp_path, monkeypatch, change
):
    p = persistent_worker
    rows, link = closed_preclaim_cohort(p, monkeypatch, 1)
    selected = selection(p, tmp_path)
    reply = linked_reply(p, rows[0], link)
    client_for(monkeypatch, p, reply)
    assert invoke(selected)[0].exit_code == 0
    before = tombstone_rows(p)
    with p.t.f.journal._connection() as con:
        if change == "delete_observation":
            con.execute(
                "DELETE FROM managed_claim_observations WHERE run_id=?", (rows[0]["run_id"],)
            )
        else:
            bad = copy.deepcopy(reply)
            if change == "wrong_original_plan":
                bad["plan_sha256"] = "e" * 64
            else:
                bad["runtime_retirement"]["report_sha256"] = "e" * 64
                rehash(bad)
            con.execute(
                "UPDATE managed_claim_observations SET snapshot=? WHERE run_id=?",
                (encoded(bad).decode(), rows[0]["run_id"]),
            )
    audit = inspection.inspect_worker_state(**selected)
    assert audit["status"] == "held" and audit["complete"] is False and audit["counts"] is None
    assert tombstone_rows(p) == before


def test_preclaim_original_observation_regression_cannot_retire_parent(
    persistent_worker, tmp_path, monkeypatch
):
    p = persistent_worker
    rows, link = closed_preclaim_cohort(p, monkeypatch, 1)
    selected = selection(p, tmp_path)
    first = linked_reply(p, rows[0], link)
    observations.observe(
        p.t.f.journal, rows[0]["run_id"], p.worker.runner_id, lambda _: copy.deepcopy(first)
    )
    before = tombstone_rows(p)
    changed = copy.deepcopy(first)
    changed["runtime_retirement"]["report_sha256"] = "e" * 64
    rehash(changed)
    _, _, send = client_for(monkeypatch, p, changed)
    result, document = invoke(selected)
    assert result.exit_code == 1 and document["status"] == "held" and send.call_count == 1
    assert parent_row(p)["retirement"] is None and tombstone_rows(p) == before


def test_preclaim_wrong_configured_origin_never_posts_or_retires_parent(
    persistent_worker, tmp_path, monkeypatch
):
    p = persistent_worker
    rows, link = closed_preclaim_cohort(p, monkeypatch, 1)
    selected = selection(p, tmp_path)
    before = tombstone_rows(p)
    _, factory, send = client_for(monkeypatch, p, linked_reply(p, rows[0], link))
    factory.return_value.base = "https://wrong.example.test"
    result, document = invoke(selected)
    assert result.exit_code == 1 and document["status"] == "held"
    send.assert_not_called()
    assert parent_row(p)["retirement"] is None and tombstone_rows(p) == before


@pytest.mark.parametrize("when", ["before_post", "after_post"])
def test_preclaim_replaced_selected_db_is_never_adopted(
    persistent_worker, tmp_path, monkeypatch, when
):
    p = persistent_worker
    rows, link = closed_preclaim_cohort(p, monkeypatch, 1)
    selected = selection(p, tmp_path)
    reply = linked_reply(p, rows[0], link)
    _, _, send = client_for(monkeypatch, p, reply)

    def replace():
        path = p.t.f.journal.path
        old = journal_path_identity(path)
        data = path.read_bytes()
        path.rename(path.with_suffix(".original"))
        path.write_bytes(data)
        assert journal_path_identity(path) != old

    if when == "before_post":

        def changed_auth():
            replace()
            return p.worker.admission.origin, "private-key-canary"

        monkeypatch.setattr(config, "require_auth", changed_auth)
    else:

        def changed_reply(*_):
            replace()
            return copy.deepcopy(reply)

        send.side_effect = changed_reply
    result, document = invoke(selected)
    assert result.exit_code == 1 and document["status"] == "held"
    assert send.call_count == (0 if when == "before_post" else 1)
    assert parent_row(p)["retirement"] is None


@pytest.mark.parametrize("phase", ["before_post", "before_parent_write"])
def test_preclaim_inspection_expiry_is_held_without_partial_zero_or_parent_write(
    persistent_worker, tmp_path, monkeypatch, phase
):
    p = persistent_worker
    rows, link = closed_preclaim_cohort(p, monkeypatch, 1)
    selected = selection(p, tmp_path)
    _, _, send = client_for(monkeypatch, p, linked_reply(p, rows[0], link))
    real_budget = inspection._Budget
    made = []

    def budget():
        item = real_budget()
        made.append(item)
        if len(made) == (2 if phase == "before_post" else 3):
            item.deadline = float("-inf")
        return item

    monkeypatch.setattr(inspection, "_Budget", budget)
    result, document = invoke(selected)
    assert result.exit_code == 1 and document["status"] == "held"
    assert document["complete"] is False and document["remaining_local_holds"] is None
    assert send.call_count == (0 if phase == "before_post" else 1)
    assert parent_row(p)["retirement"] is None
