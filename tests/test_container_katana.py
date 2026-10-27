"""Source-built image tools retain hash verification and honest provenance."""

import hashlib
import json
import runpy
from pathlib import Path
from unittest.mock import Mock

import pytest

from vardrrunner import toolchain

helper = runpy.run_path(str(Path(__file__).parents[1] / "container/go_tool_install.py"))


def _source_build(tmp_path, monkeypatch, name):
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
        if name == "gau" and kind == "mod":
            lines.append(f"\tmod\t{module}\t(devel)\t")
        else:
            lines.append(f"\t{kind}\t{module}\t{module_version}\th1:{'A' * 43}=")
    (source / "build-info.txt").write_text("\n".join(lines) + "\n")
    (source / "go.mod").write_text("module synthetic-build\n")
    (source / "go.sum").write_text("synthetic checksum fixture\n")
    if name == "gau":
        upstream = {**helper["GAU_UPSTREAM"], "Origin": {"Hash": helper["GAU_COMMIT"]}}
        (source / "upstream-module.json").write_text(json.dumps(upstream))
        for filename in ("go.mod", "go.sum", "LICENSE"):
            content = b"synthetic upstream fixture\n"
            (source / ("upstream." + filename)).write_bytes(content)
            monkeypatch.setitem(
                helper["GAU_UPSTREAM_FILES"],
                "upstream." + filename,
                hashlib.sha256(content).hexdigest(),
            )
        for key, patch in list(helper["GAU_PATCHES"].items()):
            before = b"synthetic fixture\n" + patch["old"].encode() + b"\n"
            after = before.replace(patch["old"].encode(), patch["new"].encode())
            monkeypatch.setitem(
                helper["GAU_PATCHES"],
                key,
                {
                    **patch,
                    "before": hashlib.sha256(before).hexdigest(),
                    "after": hashlib.sha256(after).hexdigest(),
                },
            )
            (source / f"{key}.original.go").write_bytes(before)
            (source / f"{key}.patched.go").write_bytes(after)
    tools = tmp_path / "tools"
    monkeypatch.setenv("VARDRRUNNER_TOOLS_DIR", str(tools))
    probe = Mock()
    monkeypatch.setattr(toolchain, "_check_version", probe)
    toolchain._verified.clear()
    return source, tools, probe, name, version


@pytest.fixture(params=["katana", "dnsx", "naabu", "gau"])
def source_build(tmp_path, monkeypatch, request):
    return _source_build(tmp_path, monkeypatch, request.param)


@pytest.fixture
def gau_build(tmp_path, monkeypatch):
    return _source_build(tmp_path, monkeypatch, "gau")


def test_source_build_records_origin_and_keeps_runtime_hash_checks(source_build):
    source, tools, probe, name, version = source_build
    helper["install_source"](source, name)
    version_args = toolchain.load_manifest()["tools"][name].get("version_args", ["-version"])
    probe.assert_called_once_with(probe.call_args.args[0], name, version, version_args)
    entry = json.loads((tools / "tools.lock.json").read_text())["tools"][name]
    assert entry["origin"]["kind"] == "go-module-source"
    assert "asset_sha256" not in entry  # It must not claim an upstream archive check.
    assert entry["origin"]["module"] == helper["BUILDS"][name]["module"]
    expected = "verified source build" + ("; reviewed source patches" if name == "gau" else "")
    assert toolchain.status(name, name).detail == expected
    if name == "gau":
        assert entry["origin"]["modules"][helper["BUILDS"][name]["module"]] == {
            "version": "(devel)",
            "checksum": None,
        }
        assert entry["origin"]["upstream_module"]["Sum"] == helper["GAU_UPSTREAM"]["Sum"]
        assert set(entry["origin"]["source_patches"]) == {"flags", "worker", "main", "output"}
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
        "version": ("build-info.txt", "(devel)" if name == "gau" else "v" + version, "v0.0.0"),
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


@pytest.mark.parametrize(
    "filename",
    [
        "flags.original.go",
        "worker.patched.go",
        "upstream-module.json",
        "main.patched.go",
        "upstream.go.mod",
    ],
)
def test_gau_unreviewed_source_never_executes(gau_build, filename):
    source, tools, probe, name, _ = gau_build
    path = source / filename
    if filename.endswith(".json"):
        data = json.loads(path.read_text())
        data["Sum"] = "h1:" + "B" * 43 + "="
        path.write_text(json.dumps(data))
    else:
        path.write_bytes(path.read_bytes() + b"unreviewed")
    with pytest.raises(ValueError):
        helper["install_source"](source, name)
    probe.assert_not_called()
    assert not (tools / name).exists()


@pytest.mark.parametrize("tamper", [False, True])
def test_gau_builder_applies_only_reviewed_source_substitutions(gau_build, tmp_path, tamper):
    source, _, probe, _, _ = gau_build
    build = tmp_path / "build"
    copied = build / "source"
    copied.mkdir(parents=True)
    (build / "upstream-module.json").write_bytes((source / "upstream-module.json").read_bytes())
    for filename in ("go.mod", "go.sum", "LICENSE"):
        (copied / filename).write_bytes((source / ("upstream." + filename)).read_bytes())
    for key, patch in helper["GAU_PATCHES"].items():
        target = copied / patch["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((source / f"{key}.original.go").read_bytes())
    if tamper:
        (copied / "runner/flags/flags.go").write_bytes(b"unreviewed source")
        with pytest.raises(ValueError, match="reviewed upstream"):
            helper["patch_gau"](build)
    else:
        helper["patch_gau"](build)
        for key, patch in helper["GAU_PATCHES"].items():
            assert (copied / patch["path"]).read_bytes() == (
                source / f"{key}.patched.go"
            ).read_bytes()
        assert (
            helper["gau_provenance"](build / "provenance")["upstream_module"]["commit"]
            == helper["GAU_COMMIT"]
        )
    probe.assert_not_called()
