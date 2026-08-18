"""Suite-wide isolation for local runner state."""

import pytest

from vardrrunner import config


@pytest.fixture(autouse=True)
def isolated_journal(tmp_path, monkeypatch):
    """Never let tests read or write the operator's real execution journal."""
    monkeypatch.setattr(config, "JOURNAL_FILE", tmp_path / "runner-journal.sqlite3")
