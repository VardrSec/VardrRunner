"""Source-built image tools retain hash verification and honest provenance."""

import hashlib
import json
import runpy
from pathlib import Path
from unittest.mock import Mock

import pytest

from vardrrunner import toolchain

helper = runpy.run_path(str(Path(__file__).parents[1] / "container/go_tool_install.py"))


@pytest.fixture(params=["katana", "dnsx", "naabu"])
def source_build(tmp_path, monkeypatch, request):
    name = request.param
    build = helper["BUILDS"][name]
    version = toolchain.load_manifest()["tools"][name]["version"]
    source = tmp_path / "source"
    source.mkdir()
    binary = b"synthetic source-build fixture"
    (source / name).write_bytes(binary)
    (source / (name + ".sha256")).write_text(hashlib.sha256(binary).hexdigest() + "  binary\n")
    lines = [f"/out/{name}: go1.27.3"]
    modules = {build["module"]: "v" + version, **build["patches"]}
    for module, module_version in modules.items():
        kind = "mod" if module == build["module"] else "dep"
        lines.append(f"\t{kind}\t{module}\t{module_version}\th1:{'A' * 43}=")
    (source / "build-info.txt").write_text("\n".join(lines) + "\n")
    (source / "go.mod").write_text("module synthetic-build\n")
    (source / "go.sum").write_text("synthetic checksum fixture\n")
    tools = tmp_path / "tools"
    monkeypatch.setenv("VARDRRUNNER_TOOLS_DIR", str(tools))
    probe = Mock()
    monkeypatch.setattr(toolchain, "_check_version", probe)
    toolchain._verified.clear()
    return source, tools, probe, name, version


def test_source_build_records_origin_and_keeps_runtime_hash_checks(source_build):
    source, tools, probe, name, version = source_build
    helper["install_source"](source, name)
    probe.assert_called_once_with(probe.call_args.args[0], name, version, ["-version"])
    entry = json.loads((tools / "tools.lock.json").read_text())["tools"][name]
    assert entry["origin"]["kind"] == "go-module-source"
    assert "asset_sha256" not in entry  # It must not claim an upstream archive check.
    assert entry["origin"]["module"] == helper["BUILDS"][name]["module"]
    assert toolchain.status(name, name).detail == "verified source build"
    assert Path(toolchain.resolve(name, name)) == tools / name
    for filename, digest in entry["origin"]["provenance_sha256"].items():
        assert (
            hashlib.sha256((tools / "provenance" / name / filename).read_bytes()).hexdigest()
            == digest
        )
    (tools / name).write_bytes(b"tampered binary")
    with pytest.raises(toolchain.ToolIntegrityError):
        toolchain.resolve(name, name)


@pytest.mark.parametrize(
    "mutation",
    ["binary", "version", "dependency", "compiler", "checksum", "module_hash", "replacement"],
)
def test_unverified_source_artifact_never_executes_or_installs(source_build, mutation):
    source, tools, probe, name, version = source_build
    filename, old, new = {
        "binary": (name, "synthetic", "corrupted"),
        "version": ("build-info.txt", "v" + version, "v0.0.0"),
        "dependency": ("build-info.txt", "v0.60.0", "v0.55.0"),
        "compiler": ("build-info.txt", "go1.27.3", "go1.26.0"),
        "checksum": (name + ".sha256", "  binary", "invalid-checksum"),
        "module_hash": ("build-info.txt", "h1:", "invalid:"),
        "replacement": ("build-info.txt", "\tdep\t", "\t=>\t"),
    }[mutation]
    path = source / filename
    path.write_text(path.read_text().replace(old, new))
    with pytest.raises(ValueError):
        helper["install_source"](source, name)
    probe.assert_not_called()
    assert not (tools / name).exists()
    assert not (tools / "tools.lock.json").exists()


def test_source_helper_refuses_to_replace_an_existing_install(source_build):
    source, tools, probe, name, _ = source_build
    helper["install_source"](source, name)
    receipt = (tools / "tools.lock.json").read_bytes()
    probe.reset_mock()
    with pytest.raises(ValueError, match="Refuse to replace"):
        helper["install_source"](source, name)
    probe.assert_not_called()
    assert (tools / "tools.lock.json").read_bytes() == receipt
