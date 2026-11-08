"""Public fixed-error contract; also runs against unchanged090 for clean red."""

import json
from unittest.mock import patch

from typer.testing import CliRunner

from vardrrunner.cli import app


def test_worker_reconcile_bad_selection_is_fixed_json_without_startup_cleanup():
    args = ["worker-reconcile"]
    for name in (
        "journal",
        "identity",
        "runner-id",
        "runtime-id",
        "runtime-sha256",
        "admission-sha256",
    ):
        args.extend(["--" + name, "private-selection-canary"])
    with patch("vardrrunner.cli.process_runner.cleanup_sensitive_temp_dirs") as cleanup:
        result = CliRunner().invoke(app, args)
    assert result.exit_code == 1
    document = json.loads(result.stdout)
    assert document["status"] == "held" and document["reason"] == "selection_invalid"
    assert document["complete"] is False and document["remaining_local_holds"] is None
    assert "private-selection-canary" not in result.stdout
    cleanup.assert_not_called()
