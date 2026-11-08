"""The two explicit file consumers share bounded, strict public-trust input."""

import copy
import os
from pathlib import Path

import pytest

from vardrrunner.authorization.codec import AuthorizationError, decoded, encoded
from vardrrunner.authorization.documents import (
    MAX_DOCUMENT_BYTES,
    read_anchors,
    read_bytes,
    read_document,
)

VECTORS = Path(__file__).parent / "fixtures/authorization"


def test_reference_documents_and_trust_are_read_without_changing_bytes():
    path = VECTORS / "plan.json"
    assert read_bytes(path) == path.read_bytes()
    assert read_document(path) == decoded(path.read_bytes())
    assert read_anchors(VECTORS / "trust.json")[0].public_key


def test_size_and_nonregular_file_refuse(tmp_path):
    path = tmp_path / "oversized.json"
    path.write_bytes(b"x" * (MAX_DOCUMENT_BYTES + 1))
    with pytest.raises(AuthorizationError):
        read_bytes(path)
    with pytest.raises(AuthorizationError):
        read_bytes(tmp_path)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO fixture unsupported")
def test_fifo_refuses_without_waiting_for_a_writer(tmp_path):
    path = tmp_path / "input-fifo"
    os.mkfifo(path)
    with pytest.raises(AuthorizationError):
        read_bytes(path)


@pytest.mark.parametrize(
    "kind", ["revoked_type", "key_size", "extra", "duplicate", "purpose_type", "origin_type"]
)
def test_malformed_trust_is_not_enrollment(tmp_path, kind):
    data = copy.deepcopy(read_document(VECTORS / "trust.json"))
    if kind == "revoked_type":
        data[0]["revoked"] = []
    elif kind == "key_size":
        data[0]["public_key"] = "YQ"
    elif kind == "extra":
        data[0]["unknown"] = "untrusted"
    elif kind == "duplicate":
        data.append(copy.deepcopy(data[0]))
    elif kind == "purpose_type":
        data[0]["purposes"] = "approval"
    else:
        data[0]["origins"] = ["arbitrary"]
    path = tmp_path / "trust.json"
    path.write_bytes(encoded(data))
    with pytest.raises(AuthorizationError):
        read_anchors(path)
