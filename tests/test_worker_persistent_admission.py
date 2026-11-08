"""Inactive v3 metadata fixtures; these grant no runtime or execution authority."""

import copy
from dataclasses import replace
from datetime import timedelta

import pytest

from tests.test_worker_admission import NOW
from tests.test_worker_admission import admission_document as admission_document
from vardrrunner.authorization.codec import AuthorizationError, digest, encoded
from vardrrunner.authorization.persistent_codec import MAX_SEQUENCE, sequence64
from vardrrunner.authorization.worker_admission import Admission


@pytest.fixture
def persistent_document(admission_document):
    value = copy.deepcopy(admission_document)
    del value["expires_at"]
    value.update(
        schema="vardr.worker-admission/3",
        mode="persistent",
        limits={"max_attempts": None, "idle_timeout_seconds": None},
        reporting_authority={"purpose": "worker-stop-only", "expires_at": None},
    )
    value["admission_sha256"] = digest(encoded(value))
    return value


def test_persistent_admission_has_no_implicit_finite_session_or_job_authority(persistent_document):
    admission = Admission.parse(persistent_document, now=NOW)
    admission.require_current(
        now=NOW + timedelta(days=365), origin=admission.origin, runner_id=admission.runner_id
    )
    assert admission.expires_at is admission.max_attempts is admission.idle_timeout_seconds is None
    assert admission.mode == "persistent" and admission.to_document() == persistent_document
    snapshot = admission.to_document()
    snapshot["identity"]["owner_nonce"] = "5" * 64
    assert admission.to_document() == persistent_document


@pytest.mark.parametrize("value", ["1", "33", "9007199254740993", str(MAX_SEQUENCE)])
def test_explicit_finite_controls_preserve_exact_int64(persistent_document, value):
    del persistent_document["admission_sha256"]
    persistent_document["limits"] = {"max_attempts": value, "idle_timeout_seconds": 86400}
    persistent_document["admission_sha256"] = digest(encoded(persistent_document))
    admission = Admission.parse(persistent_document, now=NOW)
    assert admission.max_attempts == int(value) and admission.idle_timeout_seconds == 86400
    assert admission.to_document() == persistent_document


@pytest.mark.parametrize(
    "value", [True, 1, 1.0, "", "01", "+1", "-1", "1.0", " 1", "١", str(MAX_SEQUENCE + 1)]
)
def test_decimal_sequence_never_coerces_or_wraps(value):
    with pytest.raises(AuthorizationError):
        sequence64(value, minimum=1)


@pytest.mark.parametrize(
    "change", ["identity", "mode", "limits", "reporting", "legacy_expiry", "legacy_maximum", "hash"]
)
def test_v3_snapshot_rejects_drift_and_legacy_ambiguity(persistent_document, change):
    if change == "identity":
        persistent_document["identity"]["owner_nonce"] = "5" * 64
    elif change == "mode":
        persistent_document["mode"] = "finite"
    elif change == "limits":
        persistent_document["limits"]["max_attempts"] = "32"
    elif change == "reporting":
        persistent_document["reporting_authority"]["purpose"] = "execution"
    elif change == "legacy_expiry":
        persistent_document["expires_at"] = "2026-11-06T00:00:00Z"
    elif change == "legacy_maximum":
        persistent_document["max_attempts"] = 32
    else:
        persistent_document["admission_sha256"] = "0" * 64
    with pytest.raises(AuthorizationError):
        Admission.parse(persistent_document, now=NOW)


def test_live_local_policy_mutation_is_not_enabled_by_frozen_dataclass(persistent_document):
    admission = Admission.parse(persistent_document, now=NOW)
    changed = replace(admission, max_attempts=33)
    with pytest.raises(AuthorizationError, match="worker_admission_hash"):
        changed.require_current(now=NOW, origin=changed.origin, runner_id=changed.runner_id)
