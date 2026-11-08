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
from .persistent_codec import parse_limits, wire_sequence64

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
PERSISTENT_FIELDS = (ADMISSION_FIELDS - {"expires_at"}) | {
    "mode",
    "limits",
    "reporting_authority",
    "admission_sha256",
}


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
    expires_at: datetime | None
    max_attempts: int | None = None
    mode: str | None = None
    admission_sha256: str | None = None
    idle_timeout_seconds: int | None = None

    @classmethod
    def parse(cls, value: dict, *, now: datetime) -> Admission:
        persistent = value.get("schema") == "vardr.worker-admission/3"
        sequenced = value.get("schema") == "vardr.worker-admission/2"
        fields(
            value,
            PERSISTENT_FIELDS
            if persistent
            else ADMISSION_FIELDS | ({"max_attempts"} if sequenced else set()),
        )
        require(
            value["schema"]
            in {"vardr.worker-admission/1", "vardr.worker-admission/2", "vardr.worker-admission/3"},
            "worker_admission_schema",
        )
        maximum = integer(value["max_attempts"], 1, 32) if sequenced else None
        idle: int | None = None
        admission_hash: str | None = None
        if persistent:
            require(value["mode"] == "persistent", "worker_admission_mode")
            maximum, idle = parse_limits(value["limits"])
            require(
                value["reporting_authority"] == {"purpose": "worker-stop-only", "expires_at": None},
                "worker_reporting_policy",
            )
            admission_hash = hash_value(value["admission_sha256"])
            require(
                admission_hash
                == digest(
                    encoded({key: item for key, item in value.items() if key != "admission_sha256"})
                ),
                "worker_admission_hash",
            )
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
        expiry = None if persistent else timestamp(value["expires_at"])
        require(
            now.tzinfo is not None and (persistent or (expiry is not None and expiry > now)),
            "worker_admission_expired",
        )
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
            "persistent" if persistent else None,
            admission_hash,
            idle,
        )

    def to_document(self) -> dict:
        """Return the immutable public snapshot, validating its v3 policy digest."""
        value = {
            "schema": "vardr.worker-admission/3"
            if self.mode == "persistent"
            else "vardr.worker-admission/1"
            if self.max_attempts is None
            else "vardr.worker-admission/2",
            **{
                key: getattr(self, key)
                for key in (
                    "runtime_id",
                    "runtime_sha256",
                    "enrollment_id",
                    "runner_id",
                    "origin",
                    "capability_sha256",
                )
            },
            "identity": copy.deepcopy(self.identity),
        }
        require(self.mode in {None, "persistent"}, "worker_admission_mode")
        if self.mode == "persistent":
            require(self.expires_at is None, "worker_admission_mode")
            maximum = (
                None if self.max_attempts is None else wire_sequence64(self.max_attempts, minimum=1)
            )
            if self.idle_timeout_seconds is not None:
                integer(self.idle_timeout_seconds, 1, 86400)
            value.update(
                mode="persistent",
                limits={"max_attempts": maximum, "idle_timeout_seconds": self.idle_timeout_seconds},
                reporting_authority={"purpose": "worker-stop-only", "expires_at": None},
            )
            require(digest(encoded(value)) == self.admission_sha256, "worker_admission_hash")
            value["admission_sha256"] = self.admission_sha256
        else:
            require(isinstance(self.expires_at, datetime), "worker_admission_expired")
            assert self.expires_at is not None
            value["expires_at"] = self.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")
            if self.max_attempts is not None:
                value["max_attempts"] = integer(self.max_attempts, 1, 32)
        return value

    def require_current(self, *, now: datetime, origin: str, runner_id: str) -> None:
        require(
            now.tzinfo is not None
            and (
                (self.mode == "persistent" and self.expires_at is None)
                or (self.expires_at is not None and now < self.expires_at)
            )
            and self.origin == origin
            and self.runner_id == runner_id
            and digest(encoded(self.identity)) == self.runtime_sha256,
            "worker_admission_unavailable",
        )
        if self.mode == "persistent":
            self.to_document()
