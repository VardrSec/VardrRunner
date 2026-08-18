from types import SimpleNamespace
from unittest.mock import patch

import pytest

from vardrrunner import resources


def test_default_limits(monkeypatch):
    for name in (
        resources.ENV_MAX_TARGETS,
        resources.ENV_MAX_ARTIFACT_MB,
        resources.ENV_MAX_CONCURRENT_JOBS,
        resources.ENV_MIN_FREE_DISK_MB,
    ):
        monkeypatch.delenv(name, raising=False)
    assert resources.load_limits() == resources.DEFAULT_LIMITS


def test_environment_limits(monkeypatch):
    monkeypatch.setenv(resources.ENV_MAX_TARGETS, "12")
    monkeypatch.setenv(resources.ENV_MAX_ARTIFACT_MB, "3")
    monkeypatch.setenv(resources.ENV_MAX_CONCURRENT_JOBS, "2")
    monkeypatch.setenv(resources.ENV_MIN_FREE_DISK_MB, "4")
    limits = resources.load_limits()
    assert limits.max_targets == 12
    assert limits.max_artifact_bytes == 3 * 1024**2
    assert limits.max_concurrent_jobs == 2
    assert limits.min_free_disk_bytes == 4 * 1024**2


@pytest.mark.parametrize(
    ("name", "value"),
    [
        (resources.ENV_MAX_TARGETS, "zero"),
        (resources.ENV_MAX_TARGETS, "0"),
        (resources.ENV_MAX_ARTIFACT_MB, "10241"),
        (resources.ENV_MAX_CONCURRENT_JOBS, "9"),
        (resources.ENV_MIN_FREE_DISK_MB, "-1"),
    ],
)
def test_invalid_environment_limits_fail_closed(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(resources.ResourceLimitError, match=name):
        resources.load_limits()


def test_free_space_uses_existing_parent_and_returns_free_bytes(tmp_path):
    free = 900 * 1024**2
    with patch(
        "vardrrunner.resources.shutil.disk_usage", return_value=SimpleNamespace(free=free)
    ) as du:
        assert resources.ensure_free_space(tmp_path / "future" / "run", 500) == free
    du.assert_called_once_with(tmp_path)


def test_free_space_breach_and_lookup_failure_are_classified(tmp_path):
    with patch("vardrrunner.resources.shutil.disk_usage", return_value=SimpleNamespace(free=10)):
        with pytest.raises(resources.ResourceLimitError, match="reserve breached"):
            resources.ensure_free_space(tmp_path, 11)
    with patch("vardrrunner.resources.shutil.disk_usage", side_effect=OSError("disk gone")):
        with pytest.raises(resources.ResourceLimitError, match="determine"):
            resources.ensure_free_space(tmp_path, 0)


def test_artifact_limit(tmp_path):
    artifact = tmp_path / "output.jsonl"
    artifact.write_bytes(b"1234")
    assert resources.enforce_artifact(artifact, 4) == 4
    with pytest.raises(resources.ResourceLimitError, match="artifact exceeds"):
        resources.enforce_artifact(artifact, 3)
    with pytest.raises(resources.ResourceLimitError, match="inspect"):
        resources.enforce_artifact(tmp_path / "missing", 3)
