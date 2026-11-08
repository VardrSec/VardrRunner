"""Shared bounded file inputs for explicit operator-selected reference trust."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .codec import TrustAnchor, decoded, fields, identifier, require, unb64

MAX_DOCUMENT_BYTES = 1024 * 1024


def read_bytes(path: str | Path) -> bytes:
    require(stat.S_ISREG(Path(path).stat().st_mode), "document_file_type")
    # Nonblocking open plus fstat refuses FIFOs/devices without waiting for input.
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "document_file_type")
        data = stream.read(MAX_DOCUMENT_BYTES + 1)
    require(0 < len(data) <= MAX_DOCUMENT_BYTES, "document_size")
    return data


def read_document(path: str | Path):
    return decoded(read_bytes(path))


def read_anchors(path: str | Path) -> tuple[TrustAnchor, ...]:
    data = read_document(path)
    require(isinstance(data, list) and 0 < len(data) <= 100, "invalid_trust_store")
    anchors = []
    for a in data:
        fields(a, {"issuer_id", "key_id", "public_key", "purposes", "origins", "revoked"})
        public = unb64(a["public_key"])
        require(len(public) == 32 and type(a["revoked"]) is bool, "invalid_trust_store")
        for name, allowed in (
            ("purposes", {"approval", "contract"}),
            ("origins", {"standalone", "map"}),
        ):
            values = a[name]
            require(isinstance(values, list) and bool(values), "invalid_trust_store")
            require(all(isinstance(v, str) and v in allowed for v in values), "invalid_trust_store")
            require(len(set(values)) == len(values), "invalid_trust_store")
        anchors.append(
            TrustAnchor(
                identifier(a["issuer_id"]),
                identifier(a["key_id"]),
                public,
                frozenset(a["purposes"]),
                frozenset(a["origins"]),
                a["revoked"],
            )
        )
    require(
        len({(a.issuer_id, a.key_id) for a in anchors}) == len(anchors),
        "ambiguous_trust_store",
    )
    return tuple(anchors)
