"""Exercise the exact release inventory check without executing a release."""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "payload,accepted",
    [
        ({"bomFormat": "CycloneDX", "components": [{"name": "example"}]}, True),
        ({"bomFormat": "CycloneDX", "components": []}, False),
        ({}, False),
    ],
)
def test_required_release_inventory(tmp_path, payload, accepted):
    workflow = (Path(__file__).parents[1] / ".github/workflows/release.yml").read_text()
    step = workflow.split("- name: Generate SBOM (CycloneDX)", 1)[1].split(
        "- name: Store release artifacts", 1
    )[0]
    assert "continue-on-error" not in step
    command = re.search(r'python -c "(.+)"', step).group(1)
    (tmp_path / "sbom.cdx.json").write_text(json.dumps(payload))
    result = subprocess.run([sys.executable, "-c", command], cwd=tmp_path, capture_output=True)
    assert (result.returncode == 0) is accepted
