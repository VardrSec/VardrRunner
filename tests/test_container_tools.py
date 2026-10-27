"""An image's immutable tools must not disappear behind the state volume."""

import os
import subprocess
import sys
from pathlib import Path


def test_tools_directory_override_does_not_move_state(tmp_path):
    tools = tmp_path / "image-tools"
    env = {**os.environ, "VARDRRUNNER_TOOLS_DIR": str(tools)}
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from vardrrunner import config; print(config.tools_dir()); print(config.config_dir())",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    tool_path, state_path = result.stdout.strip().splitlines()
    assert Path(tool_path) == tools
    assert Path(state_path) == Path.home() / ".vardrmap"
