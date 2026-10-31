"""Suite-wide isolation for local runner state."""

import os

# The suite exercises the optional Nmap integration, so opt in before any import reads the
# variable. tests/test_nmap_optional.py checks the default (disabled) behavior in fresh
# interpreters.
os.environ.setdefault("VARDRRUNNER_ENABLE_NMAP", "1")

import pytest

from vardrrunner import api, config, identity, updates


@pytest.fixture(autouse=True)
def isolated_journal(tmp_path, monkeypatch, request):
    """Never let tests read or write the operator's real execution journal."""
    monkeypatch.setattr(config, "JOURNAL_FILE", tmp_path / "runner-journal.sqlite3")
    # Nor the real config file, which holds approved Gate credential references.
    monkeypatch.setattr(config, "CONFIG_FILE", tmp_path / "config.json")
    monkeypatch.setattr(identity, "identity_file", lambda: tmp_path / "runner-identity.json")
    # Never resolve, install, or delete the operator's real managed tools either.
    monkeypatch.setattr(config, "TOOLS_DIR", tmp_path / "tools")
    monkeypatch.setattr(config, "DATA_DIR", tmp_path / "data")
    # Nor the operator's cached release check, which `--version` and `status` read.
    monkeypatch.setattr(updates, "cache_file", lambda: tmp_path / "update-check.json")

    # `doctor` now asks the registry; no test may reach PyPI. Tests that need a release
    # patch fetch_release_metadata themselves; test_api exercises the real one with a
    # mocked transport.
    if request.module.__name__.rsplit(".", 1)[-1] != "test_api":

        def _no_registry(timeout: int = 10) -> dict:
            raise api.ReleaseMetadataError("network disabled in tests")

        monkeypatch.setattr(api, "fetch_release_metadata", _no_registry)


@pytest.fixture
def approve_gate_case():
    """Approve every credential reference a Gate case uses, as an operator would."""
    from vardrrunner import handlers

    def approve(test_case: dict, engagement_id: str = "eng-1") -> str:
        refs = handlers.credential_references(test_case)
        origins = handlers._case_origins(test_case) if refs else []
        for _identity, source, name in refs:
            for origin in origins:
                config.approve_credential(engagement_id, origin, source, name)
        return engagement_id

    return approve
