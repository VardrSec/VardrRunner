"""Original-key v3 observations preserve exact counters and selected job evidence."""

import copy
import json
from unittest.mock import Mock

import pytest

from tests.test_sequence_retirement_observation import specimen as finite_specimen
from tests.test_worker_persistent import admission_document as admission_document
from tests.test_worker_persistent import entry_fixture as entry_fixture
from tests.test_worker_persistent import persistent_worker as persistent_worker
from tests.test_worker_persistent import specimen as specimen
from tests.test_worker_persistent import worker_fixture as worker_fixture
from vardrrunner.authorization import observations, stops
from vardrrunner.authorization.codec import AuthorizationError, digest, encoded, unb64
from vardrrunner.authorization.worker_binding import claim_association


def observation_specimen(sequence=35, *, last=34, active=None, claimed=False):
    root, association, reply = finite_specimen(sequence, last=last, active=active, claimed=claimed)
    association.update(
        schema="vardr.worker-claim-association/3",
        runtime_sequence=str(sequence),
        admission_sha256="a" * 64,
    )
    reply.update(
        schema="vardr.managed-claim-observation/4",
        runtime_sequence=str(sequence),
        admission_sha256=association["admission_sha256"],
    )
    retirement = reply["runtime_retirement"]
    retirement.update(
        schema="vardr.worker-retirement/3",
        last_sequence=str(last),
        runtime_sequence=str(active) if active is not None else None,
        admission_sha256=association["admission_sha256"],
    )
    rehash(reply)
    return root, association, reply


def rehash(reply):
    receipt = reply["runtime_retirement"]
    receipt["receipt_sha256"] = digest(
        encoded({key: value for key, value in receipt.items() if key != "receipt_sha256"})
    )


def prepare_unknown(p, *, fault="claim"):
    """Use the actual pre-send journal hook; all HTTP/native fixture I/O is inert."""
    p.settings.update(jobs=2, fault=fault)
    with pytest.raises(AuthorizationError, match="unknown"):
        p.configure().run()
    with p.t.f.journal._connection() as con:
        row = con.execute("SELECT * FROM managed_persistent_attempts").fetchone()
        if row is None:
            row = con.execute("SELECT * FROM managed_persistent_selections").fetchone()
        link = claim_association(con, row["run_id"])
    return dict(row), link


def linked_reply(p, row, link, *, claimed=False, retired=True):
    f = p.t.f
    root, _ = observations.original(f.journal, row["run_id"], link["runner_id"])
    envelope = f.s.claim["managed_authorization"]["contract"]
    payload = json.loads(unb64(envelope["payload"]))
    reply = {
        "schema": "vardr.managed-claim-observation/4",
        **root,
        **{
            key: link[key]
            for key in ("runtime_id", "runtime_sha256", "admission_sha256", "runtime_sequence")
        },
        "claim": {
            **{key: payload[key] for key in ("contract_id", "attempt_id", "fence")},
            "contract_sha256": digest(encoded(envelope)),
            "consumed": False,
            "authority_revision": f.s.context.authority_revision,
            "authority_sha256": f.s.context.authority_sha256,
        },
        "execution_state": None,
        "capacity_reserved": False,
        "result": None,
        "completion": None,
        "stop": None,
    }
    binding, terminal = None, None
    if claimed:
        binding = observations.binding(reply)
        terminal = {
            "schema": "vardr.managed-stop-receipt/1",
            **binding,
            "outcome": "failed",
            "cause": "observed_exit",
            "capacity_reserved": False,
            "receipt_sha256": stops.stop_hash(binding, "failed", "observed_exit"),
        }
        reply.update(stop=copy.deepcopy(terminal), execution_state="failed")
    else:
        reply["claim"] = None
    receipt = {
        "schema": "vardr.worker-retirement/3",
        **{
            key: link[key]
            for key in (
                "runtime_id",
                "runtime_sha256",
                "admission_sha256",
                "origin",
                "runner_id",
                "enrollment_id",
            )
        },
        "runtime_sequence": link["runtime_sequence"] if claimed else None,
        "last_sequence": link["runtime_sequence"] if claimed else "0",
        "binding": binding,
        "attempt_receipt": terminal,
        "report_sha256": "b" * 64,
        "retired": True,
    }
    receipt["receipt_sha256"] = digest(encoded(receipt))
    reply["runtime_retirement"] = receipt if retired else None
    return reply


@pytest.mark.parametrize(
    "sequence,last,active",
    [(1, 0, None), (35, 34, 34), (2**53 + 1, 2**53, None), (2**63 - 1, 2**63 - 2, 2**63 - 2)],
)
def test_full_signed64_decimal_cursor_proves_only_the_unissued_selected_attempt(
    sequence, last, active
):
    root, association, reply = observation_specimen(sequence, last=last, active=active)
    original = copy.deepcopy(reply)
    observations.validate(reply, root, {"contract": None}, association)
    assert reply == original and reply["claim"] is None


@pytest.mark.parametrize("active", [None, 1, 35])
def test_historical_completed_job_is_not_replaced_by_later_physical_retirement(active):
    root, association, reply = observation_specimen(
        1, last=1 if active == 1 else 35, active=active, claimed=True
    )
    observations.validate(reply, root, {"contract": None}, association)
    if active == 35:
        reply["completion"] = copy.deepcopy(reply["runtime_retirement"]["attempt_receipt"])
        with pytest.raises(AuthorizationError):
            observations.validate(reply, root, {"contract": None}, association)


@pytest.mark.parametrize("value", [True, 35, 35.0, "035", "+35", "3.5e1", str(2**63)])
def test_v3_echo_never_accepts_json_numbers_or_noncanonical_decimal(value):
    root, association, reply = observation_specimen()
    reply["runtime_sequence"] = value
    with pytest.raises(AuthorizationError):
        observations.validate(reply, root, {"contract": None}, association)


@pytest.mark.parametrize(
    "field,value",
    [
        ("last_sequence", 34),
        ("last_sequence", "035"),
        ("last_sequence", "35"),
        ("runtime_sequence", 34),
        ("admission_sha256", "f" * 64),
        ("enrollment_id", "replacement"),
        ("retired", 1),
        ("schema", "vardr.worker-retirement/2"),
    ],
)
def test_recomputed_hash_cannot_hide_wrong_admission_cursor_or_retirement_version(field, value):
    root, association, reply = observation_specimen(active=34)
    reply["runtime_retirement"][field] = value
    rehash(reply)
    with pytest.raises(AuthorizationError):
        observations.validate(reply, root, {"contract": None}, association)


@pytest.mark.parametrize("change", ["binding", "terminal", "hash", "extra", "echo", "schema"])
def test_same_attempt_requires_full_canonical_terminal_and_exact_selected_context(change):
    root, association, reply = observation_specimen(35, last=35, active=35, claimed=True)
    if change == "binding":
        reply["runtime_retirement"]["binding"]["job_id"] = "another-job"
    elif change == "terminal":
        reply["runtime_retirement"]["attempt_receipt"]["receipt_sha256"] = "f" * 64
    elif change == "extra":
        reply["runtime_retirement"]["expires_at"] = None
    elif change == "echo":
        reply["admission_sha256"] = "f" * 64
    elif change == "schema":
        reply["schema"] = "vardr.managed-claim-observation/3"
    rehash(reply)
    if change == "hash":
        reply["runtime_retirement"]["receipt_sha256"] = "f" * 64
    with pytest.raises(AuthorizationError):
        observations.validate(reply, root, {"contract": None}, association)


def test_original_durable_link_alone_selects_v4_request_without_any_capability(persistent_worker):
    p = persistent_worker
    row, link = prepare_unknown(p)
    reply = linked_reply(p, row, link, retired=False)
    sent = []
    before = p.t.f.journal.get(row["run_id"])
    assert (
        observations.observe(
            p.t.f.journal, row["run_id"], link["runner_id"], lambda body: sent.append(body) or reply
        )
        == reply
    )
    assert len(sent) == 1 and set(sent[0]) == observations.ROOT - {"job_id"} | {
        "runtime_id",
        "runtime_sha256",
        "runtime_sequence",
        "admission_sha256",
    }
    assert (
        sent[0]["runtime_sequence"] == "1"
        and sent[0]["admission_sha256"] == link["admission_sha256"]
    )
    assert p.t.f.journal.get(row["run_id"]) == before
    assert p.t.calls.count("claim") == 1 and "native" not in p.t.calls


def test_replacement_runner_identity_is_refused_before_observation_rpc(persistent_worker):
    p = persistent_worker
    row, _ = prepare_unknown(p)
    inspect = Mock()
    with pytest.raises(AuthorizationError, match="original_runner_required"):
        observations.observe(p.t.f.journal, row["run_id"], "replacement-runner", inspect)
    inspect.assert_not_called()


@pytest.mark.parametrize(
    "corruption", ["duplicate", "noncanonical", "association", "retirement_disappears"]
)
def test_cached_observation_cannot_regress_or_hide_noncanonical_metadata(
    persistent_worker, corruption
):
    p = persistent_worker
    row, link = prepare_unknown(p)
    reply = linked_reply(p, row, link)
    journal = p.t.f.journal
    observations.observe(journal, row["run_id"], link["runner_id"], lambda _: reply)
    with journal._connection() as con:
        original = con.execute("SELECT snapshot FROM managed_claim_observations").fetchone()[0]
        poisoned = original
        if corruption == "duplicate":
            poisoned = '{"schema":"vardr.managed-claim-observation/4",' + original[1:]
        elif corruption == "noncanonical":
            poisoned = " " + original
        elif corruption == "association":
            changed = copy.deepcopy(reply)
            changed["admission_sha256"] = "f" * 64
            poisoned = encoded(changed).decode()
        else:
            reply = {**reply, "runtime_retirement": None}
        con.execute("UPDATE managed_claim_observations SET snapshot=?", (poisoned,))
    with pytest.raises(AuthorizationError):
        observations.observe(journal, row["run_id"], link["runner_id"], lambda _: reply)
    with journal._connection() as con:
        assert (
            con.execute("SELECT snapshot FROM managed_claim_observations").fetchone()[0] == poisoned
        )


@pytest.mark.parametrize("change", ["claim_fence", "claim_consumed", "stop_fence"])
def test_cached_numeric_boolean_equivalence_is_not_a_valid_canonical_history(
    persistent_worker, change
):
    p = persistent_worker
    row, link = prepare_unknown(p)
    reply = linked_reply(p, row, link, claimed=True)
    journal = p.t.f.journal
    observations.observe(journal, row["run_id"], link["runner_id"], lambda _: reply)
    poisoned = copy.deepcopy(reply)
    if change == "claim_fence":
        poisoned["claim"]["fence"] = True
    elif change == "claim_consumed":
        poisoned["claim"]["consumed"] = 0
    else:
        poisoned["stop"]["fence"] = True
    with journal._connection() as con:
        con.execute(
            "UPDATE managed_claim_observations SET snapshot=?", (encoded(poisoned).decode(),)
        )
    with pytest.raises(AuthorizationError):
        observations.observe(journal, row["run_id"], link["runner_id"], lambda _: reply)
