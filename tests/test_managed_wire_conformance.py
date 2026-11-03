"""Map wire vectors through the one Runner validator, not managed runtime proof."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from vardrrunner.authorization.codec import AuthorizationError, TrustAnchor, unb64
from vardrrunner.authorization.contracts import ValidationContext
from vardrrunner.authorization.ledger import AuthorizationLedger
from vardrrunner.journal import Journal


def test_map_wire_vector_shared_validator_and_single_use(tmp_path):
    vector = json.loads(
        (Path(__file__).parent / "fixtures" / "authorization" / "managed-wire-v1.json").read_text()
    )
    anchors = tuple(
        TrustAnchor(
            a["issuer_id"],
            a["key_id"],
            unb64(a["public_key"]),
            frozenset(a["purposes"]),
            frozenset(a["origins"]),
        )
        for a in vector["trust"]
    )
    permission = vector["context"]
    runtime = ValidationContext(
        permission["runner_id"],
        permission["engagement_id"],
        permission["job_id"],
        "attempt-1",
        1,
        "map",
        datetime(2026, 11, 2, 18, tzinfo=timezone.utc),
        1,
        vector["plan"]["tool_sha256"],
        permission["authority_sha256"],
        managed_status_verified=True,
    )
    ledger = AuthorizationLedger(Journal(tmp_path / "synthetic.sqlite3"), monotonic=lambda: 0)
    ledger.set_state(
        "managed-fixture", permission["engagement_id"], 1, False, permission["authority_sha256"]
    )
    args = (
        vector["contract"],
        vector["approval"],
        vector["plan"],
        vector["case"],
        vector["execution"],
        anchors,
        runtime,
    )
    assert ledger.consume(*args)["execution_index"] == 1
    with pytest.raises(AuthorizationError, match="replayed"):
        ledger.consume(*args)
