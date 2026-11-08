"""Public admission parsing never supplies an owner or execution capability."""

import copy
from datetime import datetime, timedelta, timezone

import pytest

from vardrrunner.authorization.codec import AuthorizationError, digest, encoded
from vardrrunner.authorization.worker_admission import Admission

NOW = datetime(2026, 11, 5, tzinfo=timezone.utc)


@pytest.fixture
def admission_document():
    identity = {
        "daemon_id": "synthetic-daemon",
        "container_id": "1" * 64,
        "image_id": "sha256:" + "2" * 64,
        "project": "synthetic-worker",
        "started_at": "2026-11-05T00:00:00.123456789Z",
        "owner_nonce": "3" * 64,
    }
    return {
        "schema": "vardr.worker-admission/1",
        "runtime_id": "c52c1acc-5c25-4419-ae3b-90e14f744e3d",
        "runtime_sha256": digest(encoded(identity)),
        "enrollment_id": "enrollment-1",
        "runner_id": "ab6a22cf-29ae-4925-9fba-59aa331d4058",
        "origin": "https://map.example.test/backend",
        "capability_sha256": "4" * 64,
        "identity": identity,
        "expires_at": "2026-11-06T00:00:00Z",
    }


def test_admission_is_exact_public_binding_with_no_owner_capability(admission_document):
    original = copy.deepcopy(admission_document)
    admission = Admission.parse(admission_document, now=NOW)
    admission.require_current(now=NOW, origin=admission.origin, runner_id=admission.runner_id)
    assert admission.identity == original["identity"]
    admission_document["identity"]["owner_nonce"] = "5" * 64
    assert admission.identity == original["identity"]
    assert not hasattr(admission, "secret")


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", "unknown"),
        ("runtime_id", "not-a-uuid"),
        ("runner_id", 1),
        ("runtime_sha256", "0" * 64),
        ("capability_sha256", "0"),
        ("origin", "http://localhost"),
        ("origin", "https://user:secret@map.example.test"),
        ("expires_at", "2026-11-05T00:00:00Z"),
        ("secret", "never-allowed"),
    ],
)
def test_malformed_expired_or_secret_admission_refused(admission_document, field, value):
    admission_document[field] = value
    with pytest.raises(AuthorizationError):
        Admission.parse(admission_document, now=NOW)


@pytest.mark.parametrize("change", ["origin", "runner_id", "expiry", "identity"])
def test_current_admission_cannot_drift(admission_document, change):
    admission = Admission.parse(admission_document, now=NOW)
    now, origin, runner_id = NOW, admission.origin, admission.runner_id
    if change == "origin":
        origin = "https://other.example.test"
    elif change == "runner_id":
        runner_id = "other"
    elif change == "expiry":
        now += timedelta(days=1)
    else:
        admission.identity["owner_nonce"] = "6" * 64
    with pytest.raises(AuthorizationError, match="worker_admission_unavailable"):
        admission.require_current(now=now, origin=origin, runner_id=runner_id)
