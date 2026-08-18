import pytest

from vardrrunner import compatibility


def test_advertisement_is_stable_and_sorted():
    payload = compatibility.advertisement()
    assert payload["runner_version"]
    assert payload["job_schema_versions"] == [1]
    assert payload["capabilities"] == sorted(payload["capabilities"])
    assert "stop_work" in payload["capabilities"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [("1.2.3", (1, 2, 3)), ("1.2.3-rc.1", (1, 2, 3)), ("0.0.1+build", (0, 0, 1))],
)
def test_version_tuple(value, expected):
    assert compatibility.version_tuple(value) == expected


@pytest.mark.parametrize("value", ["1", "1.2", "v1.2.3", "01.2.3", "bad"])
def test_version_tuple_rejects_invalid_versions(value):
    with pytest.raises(ValueError):
        compatibility.version_tuple(value)


def test_legacy_or_non_object_response_is_compatible():
    assert compatibility.evaluate(None).compatible
    assert compatibility.evaluate({"ok": True}).compatible


def test_minimum_and_maximum_runner_versions_block():
    too_old = compatibility.evaluate(
        {"compatibility": {"min_runner_version": "2.0.0"}}, current_version="1.0.0"
    )
    too_new = compatibility.evaluate(
        {"compatibility": {"max_runner_version": "0.9.0"}}, current_version="1.0.0"
    )
    assert too_old.level is compatibility.CompatibilityLevel.BLOCK
    assert too_new.level is compatibility.CompatibilityLevel.BLOCK


def test_missing_capability_and_schema_overlap_block():
    report = compatibility.evaluate(
        {
            "compatibility": {
                "required_capabilities": ["future_capability"],
                "job_schema_versions": [99],
            }
        }
    )
    assert report.level is compatibility.CompatibilityLevel.BLOCK
    assert len(report.messages) == 2


@pytest.mark.parametrize(
    "metadata",
    [
        "bad",
        {"min_runner_version": "not-semver"},
        {"required_capabilities": "stop_work"},
        {"job_schema_versions": "1"},
    ],
)
def test_malformed_metadata_warns_without_blocking(metadata):
    report = compatibility.evaluate({"compatibility": metadata})
    assert report.level is compatibility.CompatibilityLevel.WARN
    assert report.compatible


def test_invalid_local_version_fails_closed():
    report = compatibility.evaluate({"compatibility": {}}, current_version="development")
    assert report.level is compatibility.CompatibilityLevel.BLOCK
