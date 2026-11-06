"""Sequence-bound observation cannot borrow another job's terminal evidence."""

import copy

import pytest

from vardrrunner.authorization import observations, results, stops
from vardrrunner.authorization.codec import AuthorizationError, digest, encoded


def specimen(sequence=2, *, last=1, active=None, claimed=False):
    root = {
        "origin": "https://map.example.test",
        "job_id": "selected-job",
        "runner_id": "selected-runner",
        "plan_sha256": "1" * 64,
        "case_sha256": "2" * 64,
        "association_sha256": "3" * 64,
    }
    association = {
        "schema": "vardr.worker-claim-association/2",
        **root,
        "runtime_id": "00000000-0000-0000-0000-000000000041",
        "runtime_sha256": "4" * 64,
        "enrollment_id": "original-enrollment",
        "runtime_sequence": sequence,
    }
    own = {
        **{key: root[key] for key in ("origin", "job_id", "runner_id")},
        "contract_id": "00000000-0000-0000-0000-000000000042",
        "attempt_id": "00000000-0000-0000-0000-000000000043",
        "fence": 1,
        "contract_sha256": "5" * 64,
    }
    reply = {
        "schema": "vardr.managed-claim-observation/3",
        **root,
        **{key: association[key] for key in ("runtime_id", "runtime_sha256", "runtime_sequence")},
        "claim": None,
        "execution_state": None,
        "capacity_reserved": False,
        "result": None,
        "completion": None,
        "stop": None,
    }
    if claimed:
        reply["claim"] = {
            **{key: own[key] for key in ("contract_id", "attempt_id", "fence", "contract_sha256")},
            "consumed": True,
            "authority_revision": 1,
            "authority_sha256": "6" * 64,
        }
        receipt = results.receipt(own, "7" * 64, root["case_sha256"])
        reply["result"] = {
            "schema": "vardr.managed-result-receipt/1",
            **own,
            "artifact_sha256": "7" * 64,
            "case_sha256": root["case_sha256"],
            "receipt_sha256": receipt,
            "evidence_created": 5,
            "scan_items_created": 0,
        }
        reply["completion"] = {
            "schema": "vardr.managed-completion/1",
            **own,
            "outcome": "completed",
            "capacity_reserved": False,
            "receipt_sha256": receipt,
        }
        reply["execution_state"] = "completed"
    physical_binding, terminal = None, None
    if active is not None:
        physical_binding = own if active == sequence else {**own, "job_id": "another-job"}
        terminal = (
            copy.deepcopy(reply["completion"])
            if active == sequence and claimed
            else {
                "schema": "vardr.managed-stop-receipt/1",
                **physical_binding,
                "outcome": "failed",
                "cause": "observed_exit",
                "capacity_reserved": False,
                "receipt_sha256": stops.stop_hash(physical_binding, "failed", "observed_exit"),
            }
        )
    reply["runtime_retirement"] = {
        "schema": "vardr.worker-retirement/2",
        **{
            key: association[key]
            for key in ("runtime_id", "runtime_sha256", "origin", "runner_id", "enrollment_id")
        },
        "runtime_sequence": active,
        "last_sequence": last,
        "binding": physical_binding,
        "attempt_receipt": terminal,
        "report_sha256": "8" * 64,
        "retired": True,
    }
    rehash(reply)
    return root, association, reply


def rehash(reply):
    receipt = reply["runtime_retirement"]
    receipt["receipt_sha256"] = digest(
        encoded({key: value for key, value in receipt.items() if key != "receipt_sha256"})
    )


def validate(root, association, reply):
    observations.validate(reply, root, {"contract": None}, association)


@pytest.mark.parametrize(
    "sequence,last,active", [(1, 0, None), (2, 1, None), (2, 1, 1), (32, 31, 31)]
)
def test_exact_retired_incarnation_proves_only_the_later_sequence_was_never_issued(
    sequence, last, active
):
    root, association, reply = specimen(sequence, last=last, active=active)
    before = copy.deepcopy(reply)
    validate(root, association, reply)
    assert reply == before and reply["claim"] is None
    assert reply["result"] is reply["completion"] is reply["stop"] is None


@pytest.mark.parametrize("active", [None, 1, 2])
def test_completed_history_remains_bound_to_its_own_job_after_later_runtime_activity(active):
    last = 1 if active == 1 else 2
    root, association, reply = specimen(1, last=last, active=active, claimed=True)
    validate(root, association, reply)
    if active == 2:
        reply["completion"] = copy.deepcopy(reply["runtime_retirement"]["attempt_receipt"])
        with pytest.raises(AuthorizationError):
            validate(root, association, reply)


@pytest.mark.parametrize("last", [2, 3, 32])
def test_claim_absence_cannot_retire_a_sequence_that_may_have_been_issued(last):
    root, association, reply = specimen(2, last=last)
    with pytest.raises(AuthorizationError, match="runtime_retirement_sequence_binding"):
        validate(root, association, reply)


@pytest.mark.parametrize(
    "key,value",
    [
        ("runtime_sequence", True),
        ("runtime_sequence", 0),
        ("runtime_sequence", 1),
        ("runtime_sequence", 33),
        ("runtime_id", "00000000-0000-0000-0000-000000000099"),
        ("runtime_sha256", "9" * 64),
        ("schema", "vardr.managed-claim-observation/2"),
    ],
)
def test_wrong_echo_or_protocol_version_never_matches_the_original_link(key, value):
    root, association, reply = specimen()
    reply[key] = value
    with pytest.raises(AuthorizationError):
        validate(root, association, reply)


@pytest.mark.parametrize(
    "key,value",
    [
        ("last_sequence", True),
        ("last_sequence", -1),
        ("last_sequence", 33),
        ("runtime_sequence", 1),
        ("retired", False),
        ("enrollment_id", "replacement-enrollment"),
        ("runtime_sha256", "9" * 64),
        ("schema", "vardr.worker-unbound-retirement/1"),
    ],
)
def test_retirement_identity_and_cursor_are_checked_even_with_a_matching_recomputed_hash(
    key, value
):
    root, association, reply = specimen()
    reply["runtime_retirement"][key] = value
    rehash(reply)
    with pytest.raises(AuthorizationError):
        validate(root, association, reply)


@pytest.mark.parametrize("change", ["active", "binding", "terminal", "hash", "extra"])
def test_partial_or_malformed_physical_receipt_cannot_be_used_as_sequence_evidence(change):
    root, association, reply = specimen(active=1)
    receipt = reply["runtime_retirement"]
    if change == "active":
        receipt["runtime_sequence"] = None
    elif change == "binding":
        receipt["binding"]["origin"] = "https://other.example.test"
    elif change == "terminal":
        receipt["attempt_receipt"]["outcome"] = "completed"
    elif change == "extra":
        receipt["renewal"] = True
    rehash(reply)
    if change == "hash":
        receipt["receipt_sha256"] = "f" * 64
    with pytest.raises(AuthorizationError):
        validate(root, association, reply)


def test_absence_without_final_retirement_is_only_an_observation():
    root, association, reply = specimen()
    reply["runtime_retirement"] = None
    validate(root, association, reply)
    assert reply["claim"] is None and reply["runtime_retirement"] is None
