"""Source-built image tools retain hash verification and honest provenance."""

import hashlib
import json
import runpy
from pathlib import Path
from unittest.mock import Mock

import pytest

from vardrrunner import toolchain

helper = runpy.run_path(str(Path(__file__).parents[1] / "container/katana_install.py"))


@pytest.fixture
def source_build(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    binary = b"synthetic source-build fixture"
    (source / "katana").write_bytes(binary)
    (source / "katana.sha256").write_text(hashlib.sha256(binary).hexdigest() + "  /out/katana\n")
    lines = ["/out/katana: go1.27.3"]
    modules = {helper["MODULE"]: "v1.8.0", **helper["PATCHES"]}
    for name, version in modules.items():
        kind = "mod" if name == helper["MODULE"] else "dep"
        lines.append(f"\t{kind}\t{name}\t{version}\th1:{'A' * 43}=")
    (source / "build-info.txt").write_text("\n".join(lines) + "\n")
    (source / "go.mod").write_text("module synthetic-build\n")
    (source / "go.sum").write_text("synthetic checksum fixture\n")
    tools = tmp_path / "tools"
    monkeypatch.setenv("VARDRRUNNER_TOOLS_DIR", str(tools))
    probe = Mock()
    monkeypatch.setattr(toolchain, "_check_version", probe)
    toolchain._verified.clear()
    return source, tools, probe


def test_source_build_records_origin_and_keeps_runtime_hash_checks(source_build):
    source, tools, probe = source_build
    helper["install_source"](source)
    probe.assert_called_once_with(probe.call_args.args[0], "katana", "1.8.0", ["-version"])
    entry = json.loads((tools / "tools.lock.json").read_text())["tools"]["katana"]
    assert entry["origin"]["kind"] == "go-module-source"
    assert "asset_sha256" not in entry  # It must not claim an upstream archive check.
    assert toolchain.status("katana", "katana").detail == "verified source build"
    assert Path(toolchain.resolve("katana", "katana")) == tools / "katana"
    for name, digest in entry["origin"]["provenance_sha256"].items():
        assert (
            hashlib.sha256((tools / "provenance/katana" / name).read_bytes()).hexdigest() == digest
        )
    (tools / "katana").write_bytes(b"tampered binary")
    with pytest.raises(toolchain.ToolIntegrityError):
        toolchain.resolve("katana", "katana")


@pytest.mark.parametrize(
    ("filename", "old", "new"),
    [
        ("katana", "synthetic", "corrupted"),
        ("build-info.txt", "v1.8.0", "v1.9.0"),
        ("build-info.txt", "v5.9.2", "v5.7.2"),
        ("build-info.txt", "go1.27.3", "go1.26.0"),
        ("katana.sha256", "  /out/katana", "invalid-checksum"),
        ("build-info.txt", "h1:", "invalid:"),
        ("build-info.txt", "\tdep\t", "\t=>\t"),
    ],
)
def test_unverified_source_artifact_never_executes_or_installs(source_build, filename, old, new):
    source, tools, probe = source_build
    path = source / filename
    path.write_text(path.read_text().replace(old, new))
    with pytest.raises(ValueError):
        helper["install_source"](source)
    probe.assert_not_called()
    assert not (tools / "katana").exists()
    assert not (tools / "tools.lock.json").exists()


def test_source_helper_refuses_to_replace_an_existing_install(source_build):
    source, tools, probe = source_build
    helper["install_source"](source)
    receipt = (tools / "tools.lock.json").read_bytes()
    probe.reset_mock()
    with pytest.raises(ValueError, match="Refuse to replace"):
        helper["install_source"](source)
    probe.assert_not_called()
    assert (tools / "tools.lock.json").read_bytes() == receipt
