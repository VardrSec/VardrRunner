"""Public inspection contracts, also executable against the unchanged baseline."""

import json
from unittest.mock import patch

from typer.testing import CliRunner

from vardrrunner import identity
from vardrrunner.cli import app


def test_bad_selection_is_fixed_json_and_does_not_run_startup_cleanup():
    args = ["worker-state"]
    for name in (
        "journal",
        "identity",
        "runner-id",
        "runtime-id",
        "runtime-sha256",
        "admission-sha256",
    ):
        args += ["--" + name, "private-selection-canary"]
    with patch("vardrrunner.cli.process_runner.cleanup_sensitive_temp_dirs") as cleanup:
        result = CliRunner().invoke(app, args)
    assert result.exit_code == 1
    document = json.loads(result.stdout)
    assert document["status"] == "held" and document["complete"] is False
    assert document["reason"] == "selection_invalid"
    assert document["counts"] is document["global_holds"] is None
    assert "private-selection-canary" not in result.stdout
    cleanup.assert_not_called()


def test_noncreating_identity_reader_refuses_absent_file_without_creating_parent(tmp_path):
    reader = getattr(identity, "read_existing", None)
    assert callable(reader), "noncreating_identity_reader_required"
    path = tmp_path / "absent" / "identity.json"
    try:
        reader(path)
    except identity.IdentityError:
        pass
    else:
        raise AssertionError("missing_identity_must_refuse")
    assert not path.parent.exists()
