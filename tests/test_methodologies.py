"""Methodology checklists: the shipped data, and what the schema refuses to express.

The important property is negative. A checklist item must not be able to carry
coverage: an engagement covers a methodology item through its own jobs and
findings, and a data file that could hold a tick would let an item read as
satisfied because a scanner ran. A false claim of methodology coverage in a
client report is worse than no claim.
"""

from __future__ import annotations

import pytest

from vardrrunner import handlers, methodologies


def _entry(**overrides):
    item = {
        "id": "X1",
        "title": "Something",
        "look_at": "Where to look.",
        "source": "https://example.test/x1",
        "suggests": ["httpx"],
        "evidence": "tooling",
    }
    item.update(overrides.pop("item", {}))
    entry = {
        "title": "Example",
        "version": "1.0",
        "source": "https://example.test/",
        "attribution": "Example attribution.",
        "items": [item],
    }
    entry.update(overrides)
    return {"schema_version": 1, "methodologies": {"example": entry}}


# ── the shipped data ────────────────────────────────────────────────────────


def test_shipped_data_loads_and_is_versioned():
    rows = {row["id"]: row for row in methodologies.summaries()}
    assert set(rows) == {"owasp-api-top10", "owasp-wstg"}
    # A report that cites "the OWASP Top 10" is uncheckable; the edition is the point.
    assert rows["owasp-api-top10"]["version"] == "2023"
    assert rows["owasp-wstg"]["version"] == "4.2"
    assert rows["owasp-api-top10"]["items"] == 10
    assert rows["owasp-wstg"]["items"] == 12


def test_every_methodology_credits_its_source():
    for key, entry in methodologies.load()["methodologies"].items():
        assert entry["source"].startswith("https://"), key
        assert "CC BY-SA" in entry["attribution"], key
        for item in entry["items"]:
            assert item["source"].startswith("https://"), (key, item["id"])


def test_every_suggested_job_type_is_one_the_runner_can_run():
    """A suggestion naming a tool this runner lacks sends the operator nowhere.

    This caught `ffuf` being suggested while its handler lived on an unmerged
    branch.
    """
    for key, entry in methodologies.load()["methodologies"].items():
        for item in entry["items"]:
            for tool in item["suggests"]:
                assert tool in handlers.REGISTRY, (key, item["id"], tool)


def test_no_shipped_item_claims_coverage():
    for entry in methodologies.load()["methodologies"].values():
        for item in entry["items"]:
            assert not {"status", "covered", "done", "coverage"} & set(item)


def test_both_methodologies_have_items_nothing_here_can_evidence():
    """If every item were automatable the distinction would be decorative.

    Business logic, authentication flows and session handling are not reachable
    by any job type, and an assessment that reports them covered because a scan
    passed is wrong.
    """
    for key, entry in methodologies.load()["methodologies"].items():
        kinds = {item["evidence"] for item in entry["items"]}
        assert kinds == {"tooling", "manual"}, key


def test_get_returns_one_methodology_and_rejects_an_unknown_id():
    entry = methodologies.get("owasp-api-top10")
    assert entry["items"][0]["id"] == "API1:2023"
    with pytest.raises(methodologies.MethodologyError, match="unknown methodology"):
        methodologies.get("owasp-top-42")


# ── what the schema refuses ─────────────────────────────────────────────────


def test_a_coverage_field_is_refused():
    """The whole point: coverage is not representable in this data."""
    for field in ("status", "covered", "done", "coverage"):
        with pytest.raises(methodologies.MethodologyError, match="no coverage state"):
            methodologies.validate(_entry(item={field: "yes"}))


@pytest.mark.parametrize(
    "data, match",
    [
        ({"schema_version": 2, "methodologies": {}}, "unsupported schema"),
        ({"methodologies": {}}, "unsupported schema"),
        ({"schema_version": 1, "methodologies": {}}, "no methodologies"),
        ({"schema_version": 1, "methodologies": []}, "no methodologies"),
        ("not a dict", "unsupported schema"),
    ],
)
def test_malformed_documents_are_refused(data, match):
    with pytest.raises(methodologies.MethodologyError, match=match):
        methodologies.validate(data)


@pytest.mark.parametrize(
    "overrides, match",
    [
        ({"title": ""}, "missing title"),
        ({"version": ""}, "missing version"),
        ({"attribution": ""}, "missing attribution"),
        ({"source": "http://example.test/"}, "must be an HTTPS URL"),
        ({"items": []}, "lists no items"),
        ({"items": "nope"}, "lists no items"),
    ],
)
def test_bad_methodology_entries_are_refused(overrides, match):
    with pytest.raises(methodologies.MethodologyError, match=match):
        methodologies.validate(_entry(**overrides))


@pytest.mark.parametrize(
    "item, match",
    [
        ({"id": "has space"}, "invalid id"),
        ({"id": ""}, "invalid id"),
        ({"title": ""}, "missing title"),
        ({"look_at": ""}, "missing look_at"),
        ({"source": "http://example.test/x"}, "must be an HTTPS URL"),
        ({"evidence": "partial"}, "evidence must be one of"),
        ({"evidence": None}, "evidence must be one of"),
        ({"suggests": "httpx"}, "must be a list"),
        ({"suggests": [3]}, "must be a list"),
        ({"suggests": ["dalfox"]}, "unknown job type"),
    ],
)
def test_bad_items_are_refused(item, match):
    with pytest.raises(methodologies.MethodologyError, match=match):
        methodologies.validate(_entry(item=item))


def test_duplicate_item_ids_are_refused():
    data = _entry()
    entry = data["methodologies"]["example"]
    entry["items"] = [entry["items"][0], dict(entry["items"][0])]
    with pytest.raises(methodologies.MethodologyError, match="duplicate item id"):
        methodologies.validate(data)


def test_a_manual_item_may_still_suggest_where_to_look():
    """`evidence` is the authority on what a run proves; a hint is still useful."""
    methodologies.validate(_entry(item={"evidence": "manual", "suggests": ["nuclei"]}))


def test_an_unusable_methodology_id_is_refused():
    data = _entry()
    data["methodologies"]["not a key"] = data["methodologies"].pop("example")
    with pytest.raises(methodologies.MethodologyError, match="not a usable methodology id"):
        methodologies.validate(data)
