"""One local redacted evidence copy; no tool, Map, credentials or authority restoration."""

import hashlib
import json
import os
import shutil
import sqlite3
import stat
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

import pytest
import typer

from vardrrunner import api, config, manifests, resources, runner
from vardrrunner.commands import audit
from vardrrunner.journal import Journal, JournalError, Phase


def root_owner_observation(monkeypatch, uid):
    """Synthetic root-owner observation only; every other stat attribute stays real."""
    original = Path.stat

    class ObservedRoot:
        def __init__(self, observed):
            self.observed = observed
            self.st_uid = uid

        def __getattr__(self, name):
            return getattr(self.observed, name)

    def observed(path, *args, **kwargs):
        result = original(path, *args, **kwargs)
        return ObservedRoot(result) if path == Path(path.anchor) else result

    monkeypatch.setattr(Path, "stat", observed)


@pytest.fixture
def seeded(tmp_path, monkeypatch, request):
    if not audit._private_directories_supported():
        pytest.skip("portable artifact export requires POSIX directory-FD controls")
    if request.node.name != "test_real_capacity_export":
        # This runtime reports '/' owned by65534. Do not relax product ownership
        # policy. Unit cases simulate rootUID0; actual-host case below does not.
        root_owner_observation(monkeypatch, 0)
    journal = Journal(config.journal_file())
    source = tmp_path / "source"
    source.mkdir()

    def make(raw=None, phase=Phase.DONE):
        artifact = source / "source.json"
        artifact.write_bytes(
            raw
            if raw is not None
            else json.dumps(
                {
                    "fixture_only": True,
                    "case_hash": "a" * 64,
                    "assessments": [
                        {
                            "identity_id": "owner",
                            "decision": "allowed",
                            "credential_status": "verified",
                        }
                    ],
                    "password": "synthetic-never-export",
                    "note": "vmap_syntheticneverexport",
                }
            ).encode()
        )
        record = journal.begin(
            job_id="fixture",
            backend_url="",
            engagement_id="local-workspace",
            job_type="vardrgate_api_test",
            tool="vardrgate_api_test",
            target_source="explicit",
            command_profile={"fixture_only": True, "token": "synthetic-profile-only"},
        )
        for state in (
            Phase.VALIDATING,
            Phase.TARGETS_RESOLVED,
            Phase.CLAIMING,
            Phase.CLAIMED,
            Phase.EXECUTING,
        ):
            journal.transition(
                record.run_id, state, run_dir=str(source), upload_state="not_applicable"
            )
        journal.attach_artifact(record.run_id, artifact)
        if phase is not None:
            journal.finish(record.run_id, phase, status="fixture_only")
        return SimpleNamespace(
            journal=journal,
            record=journal.get(record.run_id),
            source=source,
            artifact=artifact,
            output=tmp_path / "portable",
        )

    def forbidden(*args, **kwargs):
        raise AssertionError("Export must not authenticate, resolve providers or execute")

    monkeypatch.setattr(config, "require_auth", forbidden)
    monkeypatch.setattr(api, "VardrMapClient", forbidden)
    monkeypatch.setattr(runner, "program", forbidden)
    return make


@pytest.fixture
def capacity(monkeypatch):
    # Finite simulated observation only for new unit cases; policy remains unchanged.
    monkeypatch.setattr(resources.shutil, "disk_usage", lambda _: SimpleNamespace(free=2 * 1024**3))


def invoke(f):
    audit.export_run(f.record.run_id, f.output)


def test_redacted_copy_has_original_provenance_and_its_own_portable_hash(seeded, capacity, capsys):
    f = seeded()
    original = f.artifact.read_bytes()
    other = f.journal.begin(
        job_id="unrelated",
        backend_url="",
        engagement_id="other-engagement",
        job_type="fixture",
        tool="fixture",
        target_source="explicit",
    )
    f.journal.finish(other.run_id, Phase.SKIPPED, status="fixture_only")
    database_before = config.journal_file().read_bytes()
    nearby = f.source / "credentials.json"
    nearby.write_text('"synthetic-private-nearby"')
    invoke(f)
    assert {p.name for p in f.output.iterdir()} == {"artifact.json", "audit.json", "manifest.json"}
    derivative = (f.output / "artifact.json").read_bytes()
    document = json.loads(derivative)
    assert document["case_hash"] == "a" * 64 and document["assessments"][0]["decision"] == "allowed"
    assert document["assessments"][0]["credential_status"] == "***REDACTED***"
    manifest = json.loads((f.output / "manifest.json").read_text())
    history = json.loads((f.output / "audit.json").read_text())
    assert history["run_count"] == 1 and len(history["runs"]) == 1
    provenance = history["runs"][0]
    assert provenance["run_id"] == f.record.run_id
    assert provenance["artifact_sha256"] == hashlib.sha256(original).hexdigest()
    assert provenance["artifact_path"] == str(f.artifact)
    assert manifest["artifact_sha256"] == hashlib.sha256(derivative).hexdigest()
    assert manifest["artifact_size"] == len(derivative)
    assert manifest["artifact_path"] == "artifact.json" and manifest["run_dir"] == "."
    assert manifest["warnings"][-1]["code"] == "redacted_export"
    assert manifest["warnings"][-1]["source_artifact_sha256"] == provenance["artifact_sha256"]
    assert manifest["phase"] == "done" and manifest["status"] == "fixture_only"
    assert f.artifact.read_bytes() == original and f.journal.get(f.record.run_id) == f.record
    assert config.journal_file().read_bytes() == database_before
    emitted = capsys.readouterr().out + "".join(p.read_text() for p in f.output.iterdir())
    for secret in (
        "synthetic-never-export",
        "vmap_syntheticneverexport",
        "synthetic-profile-only",
        "synthetic-private-nearby",
    ):
        assert secret not in emitted
    assert other.run_id not in emitted and "other-engagement" not in emitted
    assert stat.S_IMODE(f.output.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in f.output.iterdir())


def test_real_capacity_export(seeded):
    try:
        audit._protected_parent(config.journal_file().parent)
    except audit.ExportError:
        pytest.skip("actual host has unsupported ancestor ownership; fresh C must verify")
    if (
        resources.shutil.disk_usage(config.journal_file().parent).free
        < resources.load_limits().min_free_disk_bytes + 1024**2
    ):
        pytest.skip(
            "actual host below unchanged reserve plus test output; fresh C must run this case"
        )
    f = seeded()
    invoke(f)
    assert (f.output / "manifest.json").is_file()


def test_untrusted_ancestor_owner_is_refused_without_policy_relaxation(tmp_path, monkeypatch):
    if not audit._private_directories_supported():
        pytest.skip("POSIX ownership policy")
    root_owner_observation(monkeypatch, os.geteuid() + 65432)
    with pytest.raises(audit.ExportError, match="unprotected_output_parent"):
        audit._protected_parent(tmp_path)


def test_reserve_includes_exact_serialized_output_bytes(seeded, monkeypatch):
    f = seeded()
    observed = []
    monkeypatch.setattr(
        resources, "ensure_free_space", lambda path, minimum: observed.append(minimum)
    )
    invoke(f)
    assert observed == [
        resources.load_limits().min_free_disk_bytes
        + sum(p.stat().st_size for p in f.output.iterdir())
    ]


@pytest.mark.parametrize("phase", [Phase.FAILED, Phase.STOP_WORK, Phase.INTERRUPTED])
def test_partial_terminal_status_is_not_promoted(seeded, capacity, phase):
    f = seeded(phase=phase)
    invoke(f)
    assert json.loads((f.output / "manifest.json").read_text())["phase"] == phase.value


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b'{"a":1e999}',
        b"[]",
        b"not-json",
        b"\xff",
        b'{"a":' * 13 + b"0" + b"}" * 13,
        b'{"a":' * 1100 + b"0" + b"}" * 1100,
    ],
)
def test_ambiguous_nonfinite_or_unsupported_json_is_refused(seeded, capacity, raw, capsys):
    f = seeded(raw)
    with pytest.raises(typer.Exit):
        invoke(f)
    assert not f.output.exists()
    assert "not-json" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "kind", ["active", "pid", "digest", "size", "missing", "suffix", "outside"]
)
def test_record_or_artifact_mismatch_is_refused(seeded, capacity, kind):
    f = seeded(phase=None if kind == "active" else Phase.DONE)
    changes = {}
    if kind == "pid":
        changes["pid"] = 12345
    if kind == "digest":
        changes["artifact_sha256"] = "0" * 64
    if kind == "size":
        changes["artifact_size"] = audit.EXPORT_ARTIFACT_LIMIT + 1
    if kind == "missing":
        changes["artifact_path"] = str(f.source / "absent.json")
    if kind in {"suffix", "outside"}:
        selected = f.source / "one.jsonl" if kind == "suffix" else f.source.parent / "outside.json"
        shutil.copyfile(f.artifact, selected)
        changes["artifact_path"] = str(selected)
    if changes:
        f.journal.transition(f.record.run_id, f.record.phase, **changes)
    with pytest.raises(typer.Exit):
        invoke(f)
    assert not f.output.exists()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "directory", "parent_link"])
def test_special_source_paths_are_refused_without_reading_them(seeded, capacity, kind):
    f = seeded()
    if kind == "hardlink":
        os.link(f.artifact, f.source / "retained-hardlink.json")
    elif kind == "parent_link":
        kept = f.source.with_name("retained-source")
        f.source.rename(kept)
        f.source.symlink_to(kept, target_is_directory=True)
    else:
        f.artifact.rename(f.source / "retained-original.json")
        if kind == "symlink":
            f.artifact.symlink_to(f.source / "retained-original.json")
        if kind == "fifo":
            os.mkfifo(f.artifact)
        if kind == "directory":
            f.artifact.mkdir()
    with pytest.raises(typer.Exit):
        invoke(f)
    assert not f.output.exists()


@pytest.mark.parametrize("kind", ["existing", "dangling_link", "inside_source", "public_parent"])
def test_output_must_be_new_and_protected(seeded, capacity, kind):
    f = seeded()
    if kind == "existing":
        f.output.mkdir()
    if kind == "dangling_link":
        f.output.symlink_to(f.output.with_name("missing-target"))
    if kind == "inside_source":
        f.output = f.source / "export"
    if kind == "public_parent":
        parent = f.output.parent / "public"
        parent.mkdir(mode=0o777)
        parent.chmod(0o777)
        f.output = parent / "export"
    with pytest.raises(typer.Exit):
        invoke(f)
    if kind == "existing":
        assert list(f.output.iterdir()) == []
    elif kind != "dangling_link":
        assert not f.output.exists()


def test_no_room_above_reserve_refuses_before_creating_output(seeded, monkeypatch):
    f = seeded()
    monkeypatch.setattr(
        resources.shutil,
        "disk_usage",
        lambda _: SimpleNamespace(free=resources.load_limits().min_free_disk_bytes),
    )
    with pytest.raises(typer.Exit):
        invoke(f)
    assert not f.output.exists()


def test_missing_or_future_journal_is_not_created_or_migrated(tmp_path, monkeypatch):
    path = tmp_path / "missing" / "journal.sqlite3"
    with pytest.raises(JournalError):
        Journal.read_existing(path, "anything")
    assert not path.parent.exists()
    future = tmp_path / "future.sqlite3"
    with closing(sqlite3.connect(future)) as con, con:
        con.execute("PRAGMA user_version=999")
    before = future.read_bytes()
    with pytest.raises(JournalError):
        Journal.read_existing(future, "anything")
    assert future.read_bytes() == before


def test_unsupported_platform_refuses_without_journal_or_output(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "_private_directories_supported", lambda: False)
    output = tmp_path / "export"
    with pytest.raises(typer.Exit):
        audit.export_run("any-id", output)
    assert not output.exists() and not config.journal_file().exists()


def test_unknown_run_refuses_without_output(seeded, capacity):
    f = seeded()
    with pytest.raises(typer.Exit):
        audit.export_run("missing-run", f.output)
    assert not f.output.exists()


def test_source_replaced_between_stat_and_open_is_refused(seeded, capacity, monkeypatch):
    f = seeded()
    original = f.artifact.read_bytes()
    lstat = Path.lstat
    calls = 0

    def replaced(path, *args, **kwargs):
        nonlocal calls
        observed = lstat(path, *args, **kwargs)
        if path == f.artifact:
            calls += 1
            if calls == 2:
                f.artifact.rename(f.source / "retained-original.json")
                f.artifact.write_bytes(original)  # Same bytes/hash; different file identity.
        return observed

    monkeypatch.setattr(Path, "lstat", replaced)
    with pytest.raises(typer.Exit):
        invoke(f)
    assert not f.output.exists()


@pytest.mark.parametrize("kind", ["derivative", "metadata"])
def test_serialized_copy_limits_fail_before_output(seeded, capacity, monkeypatch, kind):
    f = seeded()
    if kind == "derivative":
        monkeypatch.setattr(audit, "EXPORT_ARTIFACT_LIMIT", f.artifact.stat().st_size)
    else:
        monkeypatch.setattr(audit, "EXPORT_METADATA_LIMIT", 1)
    with pytest.raises(typer.Exit):
        invoke(f)
    assert not f.output.exists()


def test_record_recheck_uses_fresh_reads_and_retains_partial_output(seeded, capacity, monkeypatch):
    f = seeded()
    write = manifests.write_exclusive

    def changed(path, data, **kwargs):
        result = write(path, data, **kwargs)
        if path.name == "audit.json":
            f.journal.transition(
                f.record.run_id, f.record.phase, warnings_json='[{"code":"changed"}]'
            )
        return result

    monkeypatch.setattr(manifests, "write_exclusive", changed)
    with pytest.raises(typer.Exit):
        invoke(f)
    assert (f.output / "artifact.json").is_file() and (f.output / "audit.json").is_file()
    assert not (f.output / "manifest.json").exists()


@pytest.mark.parametrize("kind", ["symlink", "directory"])
def test_destination_swap_cannot_redirect_fd_bound_writes(seeded, capacity, monkeypatch, kind):
    f = seeded()
    victim = f.output.with_name("victim")
    victim.mkdir()
    retained = f.output.with_name("retained-partial")
    write = manifests.write_exclusive

    def swapped(path, data, **kwargs):
        if path.name == "artifact.json":
            f.output.rename(retained)
            if kind == "symlink":
                f.output.symlink_to(victim, target_is_directory=True)
            else:
                victim.rename(f.output)
        return write(path, data, **kwargs)

    monkeypatch.setattr(manifests, "write_exclusive", swapped)
    with pytest.raises(typer.Exit):
        invoke(f)
    assert list((victim if kind == "symlink" else f.output).iterdir()) == []
    assert (retained / "artifact.json").is_file() and not (retained / "manifest.json").exists()


def test_write_failure_retains_redacted_partial_without_exposing_exception(
    seeded, capacity, monkeypatch, capsys
):
    f = seeded()

    def failed(_):
        raise OSError("vmap_synthetic_fs_error_do_not_emit")

    monkeypatch.setattr(manifests.os, "fsync", failed)
    with pytest.raises(typer.Exit):
        invoke(f)
    assert (f.output / "artifact.json").is_file()
    assert not (f.output / "manifest.json").exists()
    assert "vmap_synthetic_fs_error_do_not_emit" not in capsys.readouterr().out


def test_exclusive_writer_never_overwrites_and_serialization_is_bounded(tmp_path):
    path = tmp_path / "existing.json"
    path.write_bytes(b"retained")
    with pytest.raises(FileExistsError):
        manifests.write_exclusive(path, b"replacement")
    assert path.read_bytes() == b"retained"
    with pytest.raises(ValueError):
        manifests.encode_export_json({"v": "too large"}, maximum_bytes=1)
