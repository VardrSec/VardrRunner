"""Bounded exact-byte documents and purpose-separated Ed25519 envelopes."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any


class AuthorizationError(ValueError):
    """A fixed reason code, never untrusted document content."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise AuthorizationError(reason)


def fields(value: Any, names: set[str]) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == names, "invalid_fields")
    return value


def identifier(value: Any) -> str:
    require(
        isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value) is not None,
        "invalid_identifier",
    )
    return value


def integer(value: Any, minimum: int = 0, maximum: int = 2**53 - 1) -> int:
    require(type(value) is int and minimum <= value <= maximum, "invalid_integer")
    return value


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encoded(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def decoded(data: bytes, maximum: int = 1024 * 1024) -> Any:
    require(isinstance(data, bytes) and 0 < len(data) <= maximum, "document_size")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_key")
            result[key] = value
        return result

    def constant(_: str) -> None:
        raise AuthorizationError("invalid_number")

    try:
        result = json.loads(data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AuthorizationError("malformed_document") from exc

    def depth(value: Any, level: int = 0) -> None:
        require(level <= 32, "document_depth")
        if isinstance(value, dict):
            for child in value.values():
                depth(child, level + 1)
        elif isinstance(value, list):
            for child in value:
                depth(child, level + 1)

    depth(result)
    return result


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(value: Any) -> bytes:
    require(
        isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None,
        "invalid_base64",
    )
    try:
        data = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError as exc:
        raise AuthorizationError("invalid_base64") from exc
    require(b64(data) == value, "invalid_base64")
    return data


@dataclass(frozen=True)
class TrustAnchor:
    issuer_id: str
    key_id: str
    public_key: bytes
    purposes: frozenset[str]
    origins: frozenset[str]
    revoked: bool = False


def sign(payload: dict, private_key: bytes, purpose: str) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    require(purpose in {"approval", "contract"}, "invalid_purpose")
    data = encoded(payload)
    return {
        "format": "vardr.authorization-envelope/1",
        "purpose": purpose,
        "payload": b64(data),
        "signature": b64(
            Ed25519PrivateKey.from_private_bytes(private_key).sign(_message(purpose, data))
        ),
    }


def _message(purpose: str, data: bytes) -> bytes:
    return b"VardrSec.AuthorizationContract.v1\0" + purpose.encode("ascii") + b"\0" + data


def verify(envelope: dict, anchors: tuple[TrustAnchor, ...], purpose: str) -> dict:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    fields(envelope, {"format", "purpose", "payload", "signature"})
    require(
        envelope["format"] == "vardr.authorization-envelope/1" and envelope["purpose"] == purpose,
        "envelope_version_or_purpose",
    )
    data = unb64(envelope["payload"])
    payload = decoded(data, 256 * 1024)
    require(isinstance(payload, dict), "invalid_payload")
    issuer = fields(payload.get("issuer"), {"id", "key_id"})
    anchor = next(
        (a for a in anchors if a.issuer_id == issuer["id"] and a.key_id == issuer["key_id"]), None
    )
    require(anchor is not None, "unknown_issuer")
    assert anchor is not None
    require(
        not anchor.revoked
        and purpose in anchor.purposes
        and payload.get("origin") in anchor.origins,
        "issuer_not_authorized",
    )
    try:
        Ed25519PublicKey.from_public_bytes(anchor.public_key).verify(
            unb64(envelope["signature"]), _message(purpose, data)
        )
    except (InvalidSignature, ValueError) as exc:
        raise AuthorizationError("invalid_signature") from exc
    return payload
