"""Source-built image tools retain hash verification and honest provenance."""

import hashlib
import io
import json
import runpy
import tarfile
from pathlib import Path
from unittest.mock import Mock

import pytest

from vardrrunner import toolchain

helper = runpy.run_path(str(Path(__file__).parents[1] / "container/go_tool_install.py"))


def test_reviewed_openpgp_inputs_keep_exact_bytes():
    root = Path(__file__).parents[1] / "container/nuclei-openpgp"
    pgp = helper["nuclei_openpgp"]
    assert pgp.digest(root / "backport.patch") == pgp.PATCH_SHA256
    assert pgp.digest(root / "changes.json") == pgp.CHANGES_SHA256


def test_container_builders_match_provenance_compiler():
    root = Path(__file__).parents[1]
    digest = "08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c"
    expected = f"golang:{helper['COMPILER'].removeprefix('go')}@sha256:{digest}"
    for filename in ("Dockerfile", "Dockerfile.worker", "Dockerfile.worker.persistent"):
        builders = [
            line.split()[1]
            for line in (root / filename).read_text().splitlines()
            if line.startswith("FROM golang:")
        ]
        assert builders, filename
        assert all(builder == expected for builder in builders), filename


def _source_build(tmp_path, monkeypatch, name):
    build = helper["BUILDS"][name]
    version = toolchain.load_manifest()["tools"][name]["version"]
    source = tmp_path / "source"
    source.mkdir()
    binary = b"synthetic source-build fixture"
    (source / name).write_bytes(binary)
    (source / (name + ".sha256")).write_text(hashlib.sha256(binary).hexdigest() + "  binary\n")
    lines = [f"/out/{name}: go1.27.4"]
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
    for filename in ("dependency-notices.tar.gz", "GO-LICENSE"):
        (source / filename).write_bytes(b"synthetic retained legal artifact\n")
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
    if name in helper["OPENPGP_TOOLS"]:
        pgp = helper["nuclei_openpgp"]
        license_data = b"synthetic retained license"
        archive = source / pgp.FILES[0]
        with tarfile.open(archive, "w") as tar:
            entry = tarfile.TarInfo("LICENSE")
            entry.size = len(license_data)
            tar.addfile(entry, io.BytesIO(license_data))
        for filename, constant in zip(
            pgp.FILES[:3], ("SOURCE_SHA256", "PATCH_SHA256", "ZIP_SHA256"), strict=True
        ):
            path = source / filename
            if not path.exists():
                path.write_bytes(b"synthetic review evidence")
            monkeypatch.setattr(pgp, constant, hashlib.sha256(path.read_bytes()).hexdigest())
        (source / pgp.FILES[3]).write_bytes(license_data)
        with (source / "build-info.txt").open("a") as stream:
            stream.write(f"\tdep\t{pgp.MODULE}\t{pgp.VERSION}\n\t=>\t{pgp.REPLACEMENT}\t(devel)\n")
        events = [
            {"Action": "pass", "Test": test, "Package": pgp.MODULE + "/github"}
            for test in (
                "TestGitService_CreateSignedCommitWithKey",
                "TestExpiredLegacySigningKeyRejected",
                "TestCryptoCompatibilityAudit",
            )
        ]
        events.append({"Action": "pass", "Package": pgp.MODULE + "/github"})
        (source / "openpgp-tests.json").write_text("\n".join(json.dumps(e) for e in events))
    tools = tmp_path / "tools"
    monkeypatch.setenv("VARDRRUNNER_TOOLS_DIR", str(tools))
    probe = Mock()
    monkeypatch.setattr(toolchain, "_check_version", probe)
    toolchain._verified.clear()
    return source, tools, probe, name, version


@pytest.fixture(params=["katana", "dnsx", "naabu", "gau", "httpx", "subfinder", "ffuf", "nuclei"])
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
    expected = "verified source build" + (
        "; reviewed source patches" if name == "gau" or name in helper["OPENPGP_TOOLS"] else ""
    )
    assert toolchain.status(name, name).detail == expected
    if name == "gau":
        assert entry["origin"]["modules"][helper["BUILDS"][name]["module"]] == {
            "version": "(devel)",
            "checksum": None,
        }
        assert entry["origin"]["upstream_module"]["Sum"] == helper["GAU_UPSTREAM"]["Sum"]
        assert set(entry["origin"]["source_patches"]) == {"flags", "worker", "main", "output"}
    assert Path(toolchain.resolve(name, name)) == tools / name
    assert {"dependency-notices.tar.gz", "GO-LICENSE"} <= set(entry["origin"]["provenance_sha256"])
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
        "dependency": ("build-info.txt", "v0.62.0", "v0.55.0"),
        "compiler": ("build-info.txt", "go1.27.4", "go1.27.3"),
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


@pytest.mark.parametrize("name", ["katana", "dnsx", "naabu", "httpx", "subfinder", "nuclei"])
def test_stale_crypto_module_is_refused_before_execution(tmp_path, monkeypatch, name):
    source, tools, probe, _, _ = _source_build(tmp_path, monkeypatch, name)
    info = source / "build-info.txt"
    fixed = helper["BUILDS"][name]["patches"]["golang.org/x/crypto"]
    info.write_text(info.read_text().replace(fixed, "v0.58.0"))
    with pytest.raises(ValueError):
        helper["install_source"](source, name)
    probe.assert_not_called()
    assert not (tools / name).exists()


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


@pytest.mark.parametrize(
    ("module", "version"),
    [("github.com/go-jose/go-jose/v4", value) for value in (None, "v4.1.4", "v4.1.5")]
    + [
        ("github.com/projectdiscovery/ldapserver", value)
        for value in (None, "v1.0.2-0.20240219154113-dcc758ebc0cb")
    ],
)
def test_nuclei_rejects_missing_or_unreviewed_dependencies(tmp_path, monkeypatch, module, version):
    source, tools, probe, name, _ = _source_build(tmp_path, monkeypatch, "nuclei")
    path = source / "build-info.txt"
    reviewed = helper["BUILDS"]["nuclei"]["patches"][module]
    lines = []
    for line in path.read_text().splitlines():
        if module in line:
            if version is None:
                continue
            line = line.replace(reviewed, version)
        lines.append(line)
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(ValueError, match="Required source dependency patch is missing"):
        helper["install_source"](source, name)
    probe.assert_not_called()
    assert not (tools / name).exists()
    assert not (tools / "tools.lock.json").exists()


@pytest.mark.parametrize(
    ("module", "old_version"),
    [("github.com/andybalholm/brotli", "v1.2.0"), ("github.com/klauspost/compress", "v1.18.7")],
)
def test_vulnerable_decompressor_provenance_is_rejected(source_build, module, old_version):
    source, tools, probe, name, _ = source_build
    expected = helper["BUILDS"][name]["patches"].get(module)
    if expected is None:
        pytest.skip("This tool does not require this dependency override")
    info = source / "build-info.txt"
    info.write_text(info.read_text().replace(f"{module}\t{expected}", f"{module}\t{old_version}"))
    with pytest.raises(ValueError):
        helper["install_source"](source, name)
    probe.assert_not_called()
    assert not (tools / "tools.lock.json").exists()


@pytest.mark.parametrize("name", ["dnsx", "httpx", "naabu", "nuclei"])
@pytest.mark.parametrize("kind", ["path", "module", "version", "missing", "source", "test"])
def test_tools_reject_unreviewed_replacement_or_missing_evidence(tmp_path, monkeypatch, name, kind):
    source, _, _, name, _ = _source_build(tmp_path, monkeypatch, name)
    pgp = helper["nuclei_openpgp"]
    info = source / "build-info.txt"
    text = info.read_text()
    if kind == "path":
        info.write_text(text.replace(pgp.REPLACEMENT, "/src/arbitrary"))
    elif kind == "module":
        info.write_text(text.replace(pgp.MODULE, "example.invalid/arbitrary"))
    elif kind == "version":
        info.write_text(text.replace(pgp.VERSION, "v30.0.0"))
    elif kind == "missing":
        info.write_text("\n".join(line for line in text.splitlines() if "=>" not in line))
    elif kind == "source":
        (source / pgp.FILES[0]).write_bytes(b"tampered")
    else:
        (source / "openpgp-tests.json").write_text('{"Action":"fail"}\n')
    with pytest.raises(ValueError):
        helper["install_source"](source, name)


@pytest.mark.parametrize("fault", ["archive", "manifest", "original", "range", "output"])
def test_openpgp_prepare_rejects_tampered_inputs_and_invalid_ranges(tmp_path, monkeypatch, fault):
    import zipfile

    pgp = helper["nuclei_openpgp"]
    archive = tmp_path / "upstream.zip"
    original = b"synthetic source\n"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr(pgp.MODULE + "@" + pgp.VERSION + "/LICENSE", original)
    changes_dir = tmp_path / "changes"
    changes_dir.mkdir()
    (changes_dir / "backport.patch").write_bytes(b"synthetic patch")
    change = {
        "before_sha256": hashlib.sha256(original).hexdigest(),
        "after_sha256": hashlib.sha256(original).hexdigest(),
        "edits": [],
    }
    if fault == "original":
        change["before_sha256"] = "0" * 64
    elif fault == "range":
        change["edits"] = [{"start": 0, "end": len(original) + 1, "replacement": ""}]
    manifest = changes_dir / "changes.json"
    manifest.write_text(json.dumps({"LICENSE": change}))
    monkeypatch.setattr(pgp, "ZIP_SHA256", hashlib.sha256(archive.read_bytes()).hexdigest())
    monkeypatch.setattr(pgp, "CHANGES_SHA256", hashlib.sha256(manifest.read_bytes()).hexdigest())
    monkeypatch.setattr(pgp, "PATCH_SHA256", hashlib.sha256(b"synthetic patch").hexdigest())
    monkeypatch.setattr(pgp, "SOURCE_SHA256", "0" * 64)
    if fault == "archive":
        archive.write_bytes(b"tampered archive")
    elif fault == "manifest":
        manifest.write_text("{}")
    with pytest.raises(ValueError):
        pgp.prepare(archive, changes_dir, tmp_path / "source", tmp_path / "evidence")
