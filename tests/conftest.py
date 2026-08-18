"""Suite-wide isolation for local runner state."""

import pytest

from vardrrunner import config, identity


@pytest.fixture(autouse=True)
def isolated_journal(tmp_path, monkeypatch):
    """Never let tests read or write the operator's real execution journal."""
    monkeypatch.setattr(config, "JOURNAL_FILE", tmp_path / "runner-journal.sqlite3")
    monkeypatch.setattr(identity, "identity_file", lambda: tmp_path / "runner-identity.json")
