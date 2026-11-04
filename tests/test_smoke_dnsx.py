"""Opt-in managed DNSx parser smoke; no DNS queries or egress proof."""

import os
from pathlib import Path

import pytest

from vardrrunner import config, runner, toolchain

pytestmark = [
    pytest.mark.smoke,
    pytest.mark.skipif(
        os.environ.get("VARDRRUNNER_SMOKE") != "1", reason="explicit smoke opt-in required"
    ),
]


def test_real_pinned_dnsx_accepts_update_check_flag(tmp_path, monkeypatch):
    managed = os.environ.get("VARDRRUNNER_SMOKE_MANAGED_DIR")
    if not managed:
        pytest.skip("provide an existing verified managed-tools directory; no PATH fallback")
    monkeypatch.setattr(config, "TOOLS_DIR", Path(managed))
    status = toolchain.status("dnsx", "dnsx")
    assert status.source == "managed" and status.installed_version == status.pinned_version
    home = tmp_path / "home"
    home.mkdir()
    for name in ("HOME", "USERPROFILE", "XDG_CONFIG_HOME", "APPDATA", "LOCALAPPDATA"):
        monkeypatch.setenv(name, str(home))
    # Version exits before DNSx's update branch. This proves flag recognition
    # only, not adapter DNS behavior or absence of auxiliary traffic during scans.
    runner._run_tool(
        [runner.program("dnsx"), "-disable-update-check", "-version"], None, "dnsx", 10
    )
