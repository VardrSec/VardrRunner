"""Bounded public worker admission metadata; never termination or execution proof."""

from __future__ import annotations

import copy
import re
import uuid
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlsplit

from vardrrunner.journal import normalize_backend_url

from .codec import AuthorizationError, digest, encoded, fields, identifier, integer, require
from .contracts import timestamp

ADMISSION_FIELDS = {
    "schema",
    "runtime_id",
    "runtime_sha256",
    "enrollment_id",
    "runner_id",
    "origin",
    "capability_sha256",
    "identity",
    "expires_at",
}
IDENTITY_FIELDS = {"daemon_id", "container_id", "image_id", "project", "started_at", "owner_nonce"}


def hash_value(value: object) -> str:
    require(type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value) is not None, "worker_hash")
    return str(value)


def _uuid(value: object) -> str:
    require(type(value) is str, "worker_identity")
    try:
        parsed = str(uuid.UUID(str(value)))
    except ValueError:
        raise AuthorizationError("worker_identity") from None
    require(parsed == value, "worker_identity")
    return parsed


@dataclass(frozen=True)
class Admission:
    """Public binding that still requires live lifecycle-owner verification."""

    runtime_id: str
    runtime_sha256: str
    enrollment_id: str
    runner_id: str
    origin: str
    capability_sha256: str
    identity: dict
    expires_at: datetime
    max_attempts: int | None = None

    @classmethod
    def parse(cls, value: dict, *, now: datetime) -> Admission:
        sequenced = value.get("schema") == "vardr.worker-admission/2"
        fields(value, ADMISSION_FIELDS | ({"max_attempts"} if sequenced else set()))
        require(
            value["schema"] in {"vardr.worker-admission/1", "vardr.worker-admission/2"},
            "worker_admission_schema",
        )
        maximum = integer(value["max_attempts"], 1, 32) if sequenced else None
        identity = fields(value["identity"], IDENTITY_FIELDS)
        require(len(encoded(value)) <= 8192, "worker_admission_size")
        for key in ("daemon_id", "image_id", "project", "started_at"):
            require(
                type(identity[key]) is str
                and 0 < len(identity[key]) <= 200
                and all(32 < ord(char) < 127 for char in identity[key]),
                "worker_runtime_identity",
            )
        hash_value(identity["container_id"])
        hash_value(identity["owner_nonce"])
        runtime_sha256 = hash_value(value["runtime_sha256"])
        require(digest(encoded(identity)) == runtime_sha256, "worker_runtime_hash")
        origin = value["origin"]
        require(
            type(origin) is str
            and len(origin) <= 500
            and urlsplit(origin).scheme == "https"
            and bool(urlsplit(origin).hostname)
            and normalize_backend_url(origin) == origin,
            "worker_origin",
        )
        expiry = timestamp(value["expires_at"])
        require(now.tzinfo is not None and expiry > now, "worker_admission_expired")
        return cls(
            _uuid(value["runtime_id"]),
            runtime_sha256,
            identifier(value["enrollment_id"]),
            _uuid(value["runner_id"]),
            origin,
            hash_value(value["capability_sha256"]),
            copy.deepcopy(identity),
            expiry,
            maximum,
        )

    def require_current(self, *, now: datetime, origin: str, runner_id: str) -> None:
        require(
            now.tzinfo is not None
            and now < self.expires_at
            and self.origin == origin
            and self.runner_id == runner_id
            and digest(encoded(self.identity)) == self.runtime_sha256,
            "worker_admission_unavailable",
        )
