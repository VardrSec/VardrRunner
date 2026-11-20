"""Exercise the exact release inventory check without executing a release."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml


@pytest.fixture(scope="module")
def inventory_check():
    workflow = Path(__file__).parents[1] / ".github/workflows/release.yml"
    steps = yaml.safe_load(workflow.read_text(encoding="utf-8"))["jobs"]["build"]["steps"]
    by_id = {step["id"]: step for step in steps if "id" in step}
    for step in (by_id["generate_sbom"], by_id["verify_sbom"]):
        assert not step.get("if") and not step.get("continue-on-error")
    assert by_id["verify_sbom"]["shell"] == "python"
    return by_id["verify_sbom"]["run"]


@pytest.mark.parametrize(
    "payload,accepted",
    [
        ({"bomFormat": "CycloneDX", "components": [{"name": "example"}]}, True),
        ({"bomFormat": "CycloneDX", "components": []}, False),
        ({}, False),
    ],
)
def test_required_release_inventory(inventory_check, tmp_path, payload, accepted):
    (tmp_path / "sbom.cdx.json").write_text(json.dumps(payload))
    result = subprocess.run(
        [sys.executable, "-c", inventory_check], cwd=tmp_path, capture_output=True
    )
    assert (result.returncode == 0) is accepted
