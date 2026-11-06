"""Known local denials with real signed claims/journal and inert tool/HTTP I/O."""

import copy
from unittest.mock import Mock

import pytest

from tests.test_managed_claim import entry_fixture as entry_fixture
from tests.test_managed_claim import specimen as specimen
from tests.test_managed_worker import worker_fixture as worker_fixture
from tests.test_worker_admission import admission_document as admission_document
from tests.test_worker_persistent import persistent_worker as persistent_worker
from vardrrunner import credential_grants, handlers
from vardrrunner.authorization.claim import ClaimError, ClaimStore, LocalPreclaimDenied
from vardrrunner.authorization.codec import AuthorizationError
from vardrrunner.authorization.worker_persistent import persistent_holds
from vardrrunner.managed_worker import _DeferredEpoch


def approve(p):
    s = p.t.f.s
    for _, source, name in handlers.credential_references(s.case):
        for origin in handlers._case_origins(s.case):
            credential_grants.Store().approve(
                p.worker.admission.origin, s.context.engagement_id, origin, source, name, 60
            )


def revoke(p):
    s = p.t.f.s
    _, source, name = handlers.credential_references(s.case)[0]
    assert credential_grants.Store().revoke(
        p.worker.admission.origin,
        s.context.engagement_id,
        handlers._case_origins(s.case)[0],
        source,
        name,
    )


def queued_denial(p, monkeypatch, *, late=False, repeat=False):
    """Expose one denied first job, then the original fresh signed healthy job."""
    original = p.t.client.managed_post
    pending, paths = [], []
    denied = []

    def rpc(path, body):
        paths.append(path)
        reply = original(path, body)
        if not path.endswith("/pending"):
            return reply
        pending.append(copy.deepcopy(body))
        if not reply["jobs"]:
            return reply
        if not denied:
            job = copy.deepcopy(reply["jobs"][0])
            job["id"] = "denied-first"
            if not late:
                job["config"]["test_case"]["identities"][0]["credential"]["value_env"] = (
                    "UNAPPROVED_FIXTURE_TOKEN"
                )
            denied.append(job)
            reply["jobs"] = [job]
            reply["next_after"] = None if repeat else job["id"]
        elif repeat and len(pending) == 2:
            if late:
                approve(p)  # Remediation never resurrects the old unique job reservation.
            reply["jobs"] = [copy.deepcopy(denied[0])]
            reply["next_after"] = None
        elif late:
            approve(p)
        return reply

    p.t.client.managed_post = rpc
    if late:
        prepare = ClaimStore.prepare_send

        def prepare_then_revoke(store, run_id, *args, **kwargs):
            prepare(store, run_id, *args, **kwargs)
            if store.journal.get(run_id).job_id == "denied-first":
                revoke(p)  # Outside the committed journal writer transaction.

        monkeypatch.setattr(ClaimStore, "prepare_send", prepare_then_revoke)
    return pending, paths


def assert_one_issued(p):
    assert len(p.epochs) == p.state["released"] == 1
    p.t.owner.begin_attempt.assert_called_once_with(1)
    with p.t.f.journal._connection() as con:
        parent = con.execute("SELECT * FROM managed_persistent_incarnations").fetchone()
        assert parent["last_sequence"] == 1 and parent["active_sequence"] is None
        assert con.execute("SELECT count(*) FROM managed_persistent_attempts").fetchone()[0] == 1
        assert (
            con.execute("SELECT count(*) FROM authorization_contracts WHERE consumed=2").fetchone()[
                0
            ]
            == 1
        )
        assert persistent_holds(con) == 0


def test_initial_missing_grant_then_healthy_job_after60_idle_uses_first_issued_sequence(
    persistent_worker, monkeypatch
):
    p = persistent_worker
    p.settings.update(idle_polls=70, limits={"max_attempts": "1", "idle_timeout_seconds": None})
    p.configure()
    pending, paths = queued_denial(p, monkeypatch)
    p.worker.run(wait_seconds=10)
    assert p.t.f.s.ticks[0] > 60
    assert pending[-1]["after"] == "denied-first"
    assert not any("/jobs/denied-first/" in path for path in paths)
    with p.t.f.journal._connection() as con:
        assert con.execute("SELECT count(*) FROM runs").fetchone()[0] == 1
    assert_one_issued(p)


def test_late_grant_denial_retains_no_send_tombstone_and_does_not_issue_epoch(
    persistent_worker, monkeypatch
):
    p = persistent_worker
    p.settings["limits"] = {"max_attempts": "1", "idle_timeout_seconds": None}
    p.configure()
    pending, paths = queued_denial(p, monkeypatch, late=True)
    p.worker.run()
    assert pending[-1]["after"] == "denied-first"
    assert not any("/jobs/denied-first/" in path for path in paths)
    with p.t.f.journal._connection() as con:
        denied = con.execute("SELECT * FROM runs WHERE job_id='denied-first'").fetchone()
        claim = con.execute(
            "SELECT * FROM managed_claim_intents WHERE run_id=?", (denied["run_id"],)
        ).fetchone()
        assert denied["status"] == "not_claimed" and denied["pid"] is None
        assert claim["state"] == "preclaim_retired"
        assert claim["consumption_sent"] == claim["consumption_acknowledged"] == 0
        assert claim["contract"] is None
    assert_one_issued(p)


def test_repeated_late_denied_job_does_not_create_another_run_or_retry_claim(
    persistent_worker, monkeypatch
):
    p = persistent_worker
    p.settings["limits"] = {"max_attempts": "1", "idle_timeout_seconds": None}
    p.configure()
    pending, paths = queued_denial(p, monkeypatch, late=True, repeat=True)
    p.worker.run()
    assert len(pending) == 3 and p.t.f.s.ticks[0] >= 2
    assert not any("/jobs/denied-first/" in path for path in paths)
    with p.t.f.journal._connection() as con:
        assert (
            con.execute("SELECT count(*) FROM runs WHERE job_id='denied-first'").fetchone()[0] == 1
        )
    assert_one_issued(p)


def test_initial_denial_can_be_rechecked_after_a_fresh_local_grant(persistent_worker):
    p = persistent_worker
    p.settings["limits"] = {"max_attempts": "1", "idle_timeout_seconds": None}
    p.configure()
    original = p.t.client.managed_post
    pending = []

    def rpc(path, body):
        reply = original(path, body)
        if path.endswith("/pending"):
            pending.append(True)
            revoke(p) if len(pending) == 1 else approve(p)
        return reply

    p.t.client.managed_post = rpc
    p.worker.run()
    assert len(pending) == 2 and p.t.calls.count("claim") == 1
    with p.t.f.journal._connection() as con:
        assert con.execute("SELECT count(*) FROM runs").fetchone()[0] == 1
    assert_one_issued(p)


def test_unknown_claim_keeps_proposal_hold_without_promoting_or_retrying(persistent_worker):
    p = persistent_worker
    p.settings.update(jobs=2, fault="claim")
    with pytest.raises(ClaimError, match="claim_outcome_unknown"):
        p.configure().run()
    assert p.t.calls.count("claim") == 1 and len(p.epochs) == 1
    assert "native" not in p.t.calls and p.state["released"] == 0
    with p.t.f.journal._connection() as con:
        parent = con.execute("SELECT * FROM managed_persistent_incarnations").fetchone()
        assert parent["last_sequence"] == 0 and parent["active_sequence"] is None
        assert con.execute("SELECT count(*) FROM managed_persistent_attempts").fetchone()[0] == 0
        assert persistent_holds(con) > 0


def test_owner_begin_failure_is_sticky_and_never_becomes_a_skippable_denial(persistent_worker):
    p = persistent_worker
    p.t.owner.begin_attempt.side_effect = credential_grants.GrantError("grant_missing_or_replaced")
    with pytest.raises(ClaimError, match="local_claim_denied_before_rpc"):
        p.configure().run()
    assert p.t.owner.begin_attempt.call_count == 1 and p.epochs == []
    assert "claim" not in p.t.calls and "native" not in p.t.calls
    with p.t.f.journal._connection() as con:
        assert persistent_holds(con) > 0


def test_selection_storage_error_cannot_be_classified_as_a_local_grant_denial(
    persistent_worker, monkeypatch
):
    p = persistent_worker
    p.configure()
    monkeypatch.setattr(
        p.worker.store,
        "prepare_selection",
        Mock(side_effect=credential_grants.GrantError("grant_missing_or_replaced")),
    )
    with pytest.raises(ClaimError, match="local_claim_denied_before_rpc"):
        p.worker.run()
    p.t.owner.begin_attempt.assert_not_called()
    assert "claim" not in p.t.calls and p.state["pending"] == 1


@pytest.mark.parametrize("failure", ["retirement", "source_proof"])
def test_failed_no_send_retirement_proof_never_continues(persistent_worker, monkeypatch, failure):
    p = persistent_worker
    p.configure()
    queued_denial(p, monkeypatch, late=True)
    if failure == "retirement":
        monkeypatch.setattr(
            p.worker.store, "retire_selection", Mock(side_effect=OSError("synthetic"))
        )
    else:
        monkeypatch.setattr(
            "vardrrunner.authorization.reconciliation.retire_preclaim",
            Mock(side_effect=AuthorizationError("synthetic")),
        )
    with pytest.raises((OSError, AuthorizationError)):
        p.worker.run()
    p.t.owner.begin_attempt.assert_not_called()
    assert "claim" not in p.t.calls and p.state["pending"] == 1


@pytest.mark.parametrize(
    "reason",
    [
        "grant_state_unavailable",
        "missing_or_stale_grant_state",
        "stale_grant_catalog",
        "grant_clock_rollback",
        "malformed_grant_catalog",
    ],
)
def test_initial_custody_catalog_and_clock_failures_hold(persistent_worker, monkeypatch, reason):
    p = persistent_worker
    monkeypatch.setattr(
        handlers, "check_gate_case", Mock(side_effect=credential_grants.GrantError(reason))
    )
    with pytest.raises(credential_grants.GrantError, match=reason):
        p.configure().run()
    p.t.owner.begin_attempt.assert_not_called()
    assert "claim" not in p.t.calls and p.state["pending"] == 1


def test_initial_classification_is_opt_in(entry_fixture, monkeypatch):
    f = entry_fixture
    monkeypatch.setattr(
        handlers,
        "check_gate_case",
        Mock(side_effect=credential_grants.GrantError("grant_missing_or_replaced")),
    )
    with pytest.raises(credential_grants.GrantError):
        f.make().acquire(f.directory)
    with pytest.raises(LocalPreclaimDenied):
        f.make(classify_local_denials=True).acquire(f.directory)
    assert f.rpc == []


def test_opaque_claim_callback_grant_error_is_unknown_not_a_skippable_denial(entry_fixture):
    f = entry_fixture
    claim = Mock(side_effect=credential_grants.GrantError("grant_missing_or_replaced"))
    with pytest.raises(ClaimError, match="claim_outcome_unknown"):
        f.make(classify_local_denials=True, claim=claim).acquire(f.directory)
    claim.assert_called_once()


def test_deferred_epoch_is_assigned_once_and_never_reads_a_later_owner_epoch():
    actual, later = Mock(), Mock()
    owner = Mock()
    owner.begin_attempt.side_effect = [actual, later]
    deferred = _DeferredEpoch(owner, 1)
    with pytest.raises(AuthorizationError, match="worker_epoch_not_entered"):
        deferred.verified_lease({}, 1, 2)
    owner.begin_attempt.assert_not_called()
    deferred.begin()
    deferred.verified_lease({"pinned": True}, 1, 2)
    actual.verified_lease.assert_called_once_with({"pinned": True}, 1, 2)
    later.verified_lease.assert_not_called()
    with pytest.raises(AuthorizationError, match="worker_epoch_already_entered"):
        deferred.begin()
