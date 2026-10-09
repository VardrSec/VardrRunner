"""Versioned methodology checklists, shipped with the package.

``methodologies.json`` holds the recognised methodologies an engagement can be
planned against — the OWASP API Security Top 10 and the OWASP Web Security
Testing Guide — each pinned to an exact edition so a report can cite which one
was used.

**A checklist item is a suggestion, never a claim of coverage.** The data
deliberately carries no status, no tick-box and no "done": an item says what to
look at and which job types relate to it, and nothing more. Whether an
engagement has actually covered it can only come from that engagement's own
evidence — the jobs that ran, the findings they produced, the API operations
tested — which lives in VardrMap, not here. Storing coverage alongside the
checklist would let a methodology item be marked satisfied because a scanner
ran, and a false claim of methodology coverage in a client report is worse than
no claim at all.

``evidence`` records which side of that line an item can even reach:

- ``"tooling"`` — a job type here can produce evidence that bears on the item.
  Evidence of a candidate, still: a nuclei match is not a confirmed finding.
- ``"manual"`` — nothing in VardrMap can evidence it. Business logic, session
  handling and authentication flows are in this group, and an assessment that
  reports them as covered because a scan passed is simply wrong. Such an item may
  still name a job type under ``suggests`` where one is worth a look; ``evidence``
  is the authority on what a run actually proves.

Only identifiers, official titles and source URLs are referenced from OWASP (CC
BY-SA 4.0, credited per methodology in ``attribution``). The ``look_at`` and
``suggests`` fields are this project's own notes.
"""

from __future__ import annotations

import json
import re
from importlib import resources
from typing import Any

RESOURCE = "methodologies.json"
SCHEMA_VERSION = 1

EVIDENCE_KINDS = frozenset({"tooling", "manual"})
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:_-]{0,40}$")


class MethodologyError(RuntimeError):
    """The shipped methodology data is missing, malformed, or names an unknown tool."""


_cache: dict[str, Any] | None = None


def load() -> dict[str, Any]:
    """Load and validate the methodologies shipped with this package."""
    global _cache
    if _cache is None:
        text = resources.files("vardrrunner").joinpath(RESOURCE).read_text("utf-8")
        _cache = validate(json.loads(text))
    return _cache


def validate(data: Any) -> dict[str, Any]:
    """Reject data that is malformed, unversioned, or carries a coverage claim."""
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        raise MethodologyError("methodology data has an unsupported schema")
    methodologies = data.get("methodologies")
    if not isinstance(methodologies, dict) or not methodologies:
        raise MethodologyError("methodology data lists no methodologies")
    for key, entry in methodologies.items():
        if not _ID.match(key):
            raise MethodologyError(f"{key!r} is not a usable methodology id")
        if not isinstance(entry, dict):
            raise MethodologyError(f"{key}: entry is not an object")
        for field in ("title", "version", "source", "attribution"):
            if not isinstance(entry.get(field), str) or not entry[field]:
                raise MethodologyError(f"{key}: missing {field}")
        if not entry["source"].startswith("https://"):
            raise MethodologyError(f"{key}: source must be an HTTPS URL")
        items = entry.get("items")
        if not isinstance(items, list) or not items:
            raise MethodologyError(f"{key}: lists no items")
        seen: set[str] = set()
        for item in items:
            _validate_item(key, item, seen)
    return data


def _validate_item(key: str, item: Any, seen: set[str]) -> None:
    if not isinstance(item, dict):
        raise MethodologyError(f"{key}: item is not an object")
    item_id = item.get("id")
    if not isinstance(item_id, str) or not _ID.match(item_id):
        raise MethodologyError(f"{key}: item has an invalid id")
    if item_id in seen:
        raise MethodologyError(f"{key}: duplicate item id {item_id}")
    seen.add(item_id)
    for field in ("title", "look_at", "source"):
        if not isinstance(item.get(field), str) or not item[field]:
            raise MethodologyError(f"{key} {item_id}: missing {field}")
    if not item["source"].startswith("https://"):
        raise MethodologyError(f"{key} {item_id}: source must be an HTTPS URL")
    if item.get("evidence") not in EVIDENCE_KINDS:
        raise MethodologyError(f"{key} {item_id}: evidence must be one of {sorted(EVIDENCE_KINDS)}")
    suggests = item.get("suggests")
    if not isinstance(suggests, list) or any(not isinstance(t, str) for t in suggests):
        raise MethodologyError(f"{key} {item_id}: suggests must be a list of job types")
    # A "manual" item may still suggest a job type — nuclei can hint at broken
    # authentication without evidencing it — because `evidence` is the authority
    # on what a run proves, and saying where to look is useful. What is refused
    # is a suggestion naming a job type that does not exist, which would send an
    # operator or an agent after a tool this runner cannot run.
    unknown = [t for t in suggests if t not in _job_types()]
    if unknown:
        raise MethodologyError(f"{key} {item_id}: unknown job type(s) {unknown}")
    # Coverage is not representable here, by design: it comes from an
    # engagement's own evidence. A data file that could carry a tick would let a
    # methodology item read as satisfied because a scanner ran.
    present = [name for name in ("status", "covered", "done", "coverage") if name in item]
    if present:
        raise MethodologyError(
            f"{key} {item_id}: a checklist item carries no coverage state (found {present}) — "
            "coverage comes from the engagement's own evidence, never from this data"
        )


def _job_types() -> frozenset[str]:
    """The job types a suggestion may name. Imported late to avoid a cycle."""
    from vardrrunner import handlers

    return frozenset(handlers.REGISTRY)


def summaries() -> list[dict[str, Any]]:
    """One row per methodology: what it is, which edition, and how big."""
    return [
        {
            "id": key,
            "title": entry["title"],
            "version": entry["version"],
            "source": entry["source"],
            "items": len(entry["items"]),
            "tooling_items": sum(1 for i in entry["items"] if i["evidence"] == "tooling"),
            "manual_items": sum(1 for i in entry["items"] if i["evidence"] == "manual"),
        }
        for key, entry in sorted(load()["methodologies"].items())
    ]


def get(methodology_id: str) -> dict[str, Any]:
    """One methodology with its items, or raise MethodologyError if unknown."""
    methodologies = load()["methodologies"]
    entry = methodologies.get(methodology_id)
    if entry is None:
        raise MethodologyError(
            f"unknown methodology {methodology_id!r}; available: {sorted(methodologies)}"
        )
    return entry
