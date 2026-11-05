"""Direct `run` commands validate options through the same typed configs as jobs."""

import datetime
import os
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import typer

from vardrrunner import journal as journal_module
from vardrrunner.commands import run as run_cmd
from vardrrunner.journal import Journal, Phase


def _common_patches(targets):
    """Patch auth/client/tool-check/resolution so only validation is exercised."""
    return (
        patch("vardrrunner.commands.run.runner.check_tool"),
        patch("vardrrunner.commands.run.config.require_auth", return_value=("https://a", "k")),
        patch("vardrrunner.commands.run.api.VardrMapClient", return_value=MagicMock()),
        patch("vardrrunner.commands.run._resolve_targets", return_value=targets),
    )


def test_run_nmap_rejects_invalid_timing():
    """`run nmap --timing 9` must be rejected (parity with jobs), not clamped."""
    p = _common_patches(["10.0.0.1"])
    with p[0], p[1], p[2], p[3], patch("vardrrunner.runner.run_nmap") as mock_nmap:
        with pytest.raises(typer.Exit):
            run_cmd.run_nmap("prog-1", target="10.0.0.1", timing=9, yes=True)
    mock_nmap.assert_not_called()  # rejected before any tool runs


def test_run_nuclei_rejects_invalid_severity():
    p = _common_patches(["https://app.example.com"])
    with p[0], p[1], p[2], p[3], patch("vardrrunner.runner.run_nuclei") as mock_nuclei:
        with pytest.raises(typer.Exit):
            run_cmd.run_nuclei(
                "prog-1", target="https://app.example.com", severity="bogus", yes=True
            )
    mock_nuclei.assert_not_called()


# ---------------------------------------------------------------------------
# Run directory pruning
# ---------------------------------------------------------------------------


def _pruning_supported():
    return (
        run_cmd.sys.version_info >= (3, 11)
        and run_cmd.shutil.rmtree.avoids_symlink_attacks
        and os.listdir in os.supports_fd
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
    )


@pytest.fixture
def confined_pruning_protocol(tmp_path, monkeypatch):
    """Portable descriptor protocol, not evidence of native OS confinement.

    Use real disposable directory contents behind an emulated held descriptor.
    Every relative operation is checked; native Linux tests exercise the kernel.
    """
    descriptor = 987654
    state = SimpleNamespace(
        root=tmp_path / "runs",
        held_root=tmp_path / "runs",
        identity=None,
        open_failure=None,
        on_open=None,
        on_enumerate=None,
        calls=[],
    )
    original_open, original_close = os.open, os.close
    original_fstat, original_stat = os.fstat, os.stat
    original_listdir, original_delete = os.listdir, run_cmd.shutil.rmtree

    def open_root(path, flags, *args, **kwargs):
        if Path(path) != state.root:
            return original_open(path, flags, *args, **kwargs)
        assert flags == os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        state.calls.append("open")
        if state.open_failure:
            raise state.open_failure
        if state.on_open:
            state.on_open()
        state.identity = original_stat(state.held_root, follow_symlinks=False)
        return descriptor

    def fstat(handle):
        if handle != descriptor:
            return original_fstat(handle)
        state.calls.append("identity")
        return state.identity

    def listdir(handle):
        if handle != descriptor:
            return original_listdir(handle)
        state.calls.append("enumerate")
        if state.on_enumerate:
            state.on_enumerate()
        return original_listdir(state.held_root)

    def relative_stat(path, *args, **kwargs):
        if kwargs.get("dir_fd") != descriptor:
            return original_stat(path, *args, **kwargs)
        assert Path(path).name == path and kwargs["follow_symlinks"] is False
        state.calls.append(("inspect", path))
        return original_stat(state.held_root / path, follow_symlinks=False)

    def relative_delete(path, *, dir_fd, ignore_errors):
        assert dir_fd == descriptor and Path(path).name == path
        state.calls.append(("delete", path))
        original_delete(state.held_root / path, ignore_errors=ignore_errors)

    relative_delete.avoids_symlink_attacks = True

    def close(handle):
        if handle != descriptor:
            return original_close(handle)
        state.calls.append("close")

    monkeypatch.setattr(run_cmd.sys, "version_info", (3, 11, 0))
    monkeypatch.setattr(os, "O_DIRECTORY", getattr(os, "O_DIRECTORY", 0x10000000), raising=False)
    monkeypatch.setattr(os, "O_NOFOLLOW", getattr(os, "O_NOFOLLOW", 0x20000000), raising=False)
    monkeypatch.setattr(os, "supports_fd", os.supports_fd | {listdir})
    monkeypatch.setattr(os, "open", open_root)
    monkeypatch.setattr(os, "fstat", fstat)
    monkeypatch.setattr(os, "listdir", listdir)
    monkeypatch.setattr(os, "stat", relative_stat)
    monkeypatch.setattr(os, "close", close)
    monkeypatch.setattr(run_cmd.shutil, "rmtree", relative_delete)
    return state


@pytest.fixture(params=["native", "protocol"])
def pruning_mode(request):
    if request.param == "protocol":
        return request.getfixturevalue("confined_pruning_protocol")
    return None


def _old_protocol_evidence(protocol):
    directory = protocol.root / "old"
    directory.mkdir(parents=True)
    evidence = directory / "evidence.json"
    evidence.write_bytes(b"old evidence")
    old = (datetime.datetime.now() - datetime.timedelta(days=10)).timestamp()
    os.utime(directory, (old, old))
    return evidence


def test_descriptor_protocol_rejects_root_replacement_before_inventory(
    tmp_path, confined_pruning_protocol
):
    protocol = confined_pruning_protocol
    evidence = _old_protocol_evidence(protocol)
    saved = tmp_path / "original"
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    (foreign / "unrelated.json").write_bytes(b"unrelated evidence")

    def replace_before_open():
        protocol.root.rename(saved)
        foreign.rename(protocol.root)

    protocol.on_open = replace_before_open
    with (
        patch.object(run_cmd.config, "runs_dir", return_value=protocol.root),
        patch.object(run_cmd, "journal_path_present") as inventory_probe,
    ):
        run_cmd._prune_run_dirs()
    inventory_probe.assert_not_called()
    assert protocol.calls == ["open", "identity", "close"]
    assert (saved / "old" / evidence.name).read_bytes() == b"old evidence"
    assert (protocol.root / "unrelated.json").read_bytes() == b"unrelated evidence"


def test_descriptor_protocol_open_failure_never_reaches_inventory(confined_pruning_protocol):
    protocol = confined_pruning_protocol
    evidence = _old_protocol_evidence(protocol)
    protocol.open_failure = PermissionError("synthetic denied directory")
    with (
        patch.object(run_cmd.config, "runs_dir", return_value=protocol.root),
        patch.object(run_cmd, "journal_path_present") as inventory_probe,
    ):
        run_cmd._prune_run_dirs()
    inventory_probe.assert_not_called()
    assert protocol.calls == ["open"]
    assert evidence.read_bytes() == b"old evidence"


def test_descriptor_protocol_bounded_inventory_failure_never_enumerates(
    confined_pruning_protocol, monkeypatch
):
    protocol = confined_pruning_protocol
    evidence = _old_protocol_evidence(protocol)
    store = Journal(run_cmd.config.journal_file())
    record = store.begin(
        job_id="retained-job",
        backend_url="https://map.example",
        engagement_id="engagement",
        job_type="httpx",
        tool="httpx",
        target_source="scope",
    )
    store.transition(record.run_id, Phase.DISCOVERED, run_dir=str(evidence.parent))
    monkeypatch.setattr(journal_module, "RETENTION_RECORD_LIMIT", 0)
    with patch.object(run_cmd.config, "runs_dir", return_value=protocol.root):
        run_cmd._prune_run_dirs()
    assert protocol.calls == ["open", "identity", "close"]
    assert evidence.read_bytes() == b"old evidence"


def test_descriptor_protocol_deletes_only_through_held_root_after_substitution(
    tmp_path, confined_pruning_protocol
):
    protocol = confined_pruning_protocol
    evidence = _old_protocol_evidence(protocol)
    saved = tmp_path / "original"
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    (foreign / "unrelated.json").write_bytes(b"unrelated evidence")

    def replace_after_open():
        protocol.root.rename(saved)
        foreign.rename(protocol.root)
        protocol.held_root = saved

    protocol.on_enumerate = replace_after_open
    with patch.object(run_cmd.config, "runs_dir", return_value=protocol.root):
        run_cmd._prune_run_dirs()
    assert protocol.calls == [
        "open",
        "identity",
        "enumerate",
        ("inspect", "old"),
        ("delete", "old"),
        "close",
    ]
    assert not (saved / "old" / evidence.name).exists()
    assert (protocol.root / "unrelated.json").read_bytes() == b"unrelated evidence"


def test_prune_run_dirs_removes_old_dirs(tmp_path, pruning_mode):
    runs = tmp_path / "runs"
    runs.mkdir()

    old_dir = runs / "20200101T000000"
    old_dir.mkdir()
    new_dir = runs / "20991231T235959"
    new_dir.mkdir()

    # Back-date old_dir so it's older than the prune threshold
    old_ts = (datetime.datetime.now() - datetime.timedelta(days=10)).timestamp()
    os.utime(old_dir, (old_ts, old_ts))

    with patch("vardrrunner.commands.run.config.runs_dir", return_value=runs):
        run_cmd._prune_run_dirs()

    assert old_dir.exists() is (not _pruning_supported())
    assert new_dir.exists()
    assert not run_cmd.config.journal_file().exists()


def test_prune_run_dirs_is_a_no_op_when_runs_dir_absent(tmp_path, pruning_mode):
    with patch("vardrrunner.commands.run.config.runs_dir", return_value=tmp_path / "no_runs"):
        run_cmd._prune_run_dirs()  # must not raise


@pytest.mark.parametrize(
    ("phase", "pid", "upload_state"),
    [
        (Phase.DISCOVERED, None, "not_started"),
        (Phase.FAILED, 123, "not_started"),
        (Phase.INTERRUPTED, None, "outcome_unknown"),
        (Phase.DONE, None, "succeeded"),
    ],
)
def test_prune_preserves_journal_evidence_and_removes_old_unjournaled_runs(
    tmp_path, phase, pid, upload_state, pruning_mode
):
    runs = tmp_path / "runs"
    retained = runs / "retained"
    direct = runs / "direct"
    retained.mkdir(parents=True)
    direct.mkdir()
    evidence = retained / "evidence.json"
    evidence.write_bytes(b"retained synthetic evidence")
    store = Journal(run_cmd.config.journal_file())
    record = store.begin(
        job_id="retained-job",
        backend_url="https://map.example",
        engagement_id="engagement",
        job_type="httpx",
        tool="httpx",
        target_source="scope",
    )
    store.transition(
        record.run_id, phase, run_dir=str(retained), pid=pid, upload_state=upload_state
    )
    old = (datetime.datetime.now() - datetime.timedelta(days=10)).timestamp()
    for directory in (retained, direct):
        os.utime(directory, (old, old))
    with patch.object(run_cmd.config, "runs_dir", return_value=runs):
        run_cmd._prune_run_dirs()
    assert evidence.read_bytes() == b"retained synthetic evidence"
    assert direct.exists() is (not _pruning_supported())


@pytest.mark.parametrize("field", ["artifact_path", "manifest_path"])
def test_prune_preserves_parent_of_journal_artifact_or_manifest(tmp_path, field, pruning_mode):
    runs = tmp_path / "runs"
    retained = runs / "retained"
    nested = retained / "nested"
    nested.mkdir(parents=True)
    evidence = nested / "evidence.json"
    evidence.write_bytes(b"retained evidence")
    store = Journal(run_cmd.config.journal_file())
    record = store.begin(
        job_id="retained-job",
        backend_url="https://map.example",
        engagement_id="engagement",
        job_type="httpx",
        tool="httpx",
        target_source="scope",
    )
    store.transition(record.run_id, Phase.FAILED, **{field: str(evidence)})
    old = (datetime.datetime.now() - datetime.timedelta(days=10)).timestamp()
    os.utime(retained, (old, old))
    with patch.object(run_cmd.config, "runs_dir", return_value=runs):
        run_cmd._prune_run_dirs()
    assert evidence.read_bytes() == b"retained evidence"


def test_prune_preserves_everything_when_journal_is_unreadable(tmp_path, pruning_mode):
    runs = tmp_path / "runs"
    old_run = runs / "old"
    old_run.mkdir(parents=True)
    evidence = old_run / "evidence.json"
    evidence.write_bytes(b"retained evidence")
    journal_path = run_cmd.config.journal_file()
    journal_path.write_bytes(b"invalid journal: preserve")
    old = (datetime.datetime.now() - datetime.timedelta(days=10)).timestamp()
    os.utime(old_run, (old, old))
    with patch.object(run_cmd.config, "runs_dir", return_value=runs):
        run_cmd._prune_run_dirs()
    assert evidence.read_bytes() == b"retained evidence"
    assert journal_path.read_bytes() == b"invalid journal: preserve"
    if pruning_mode:
        assert pruning_mode.calls == ["open", "identity", "close"]


@pytest.mark.parametrize("location", ["root", "child"])
@pytest.mark.parametrize("link_kind", ["symlink", "reparse"])
def test_prune_refuses_observed_directory_links(tmp_path, location, link_kind, pruning_mode):
    runs = tmp_path / "runs"
    old_run = runs / "old"
    old_run.mkdir(parents=True)
    evidence = old_run / "evidence.json"
    evidence.write_bytes(b"retained evidence")
    old = (datetime.datetime.now() - datetime.timedelta(days=10)).timestamp()
    os.utime(old_run, (old, old))
    selected = runs if location == "root" else old_run
    original = Path.lstat
    original_stat = os.stat

    def marker(info):
        return SimpleNamespace(
            st_mode=stat.S_IFLNK if link_kind == "symlink" else stat.S_IFDIR,
            st_mtime=info.st_mtime,
            st_file_attributes=0x400 if link_kind == "reparse" else 0,
        )

    def observe(path):
        info = original(path)
        return marker(info) if path == selected else info

    def observe_stat(path, *args, **kwargs):
        info = original_stat(path, *args, **kwargs)
        if location == "child" and path == old_run.name and kwargs.get("dir_fd") is not None:
            return marker(info)
        return info

    with (
        patch.object(run_cmd.config, "runs_dir", return_value=runs),
        patch.object(Path, "lstat", observe),
        patch.object(os, "stat", observe_stat),
    ):
        run_cmd._prune_run_dirs()
    assert evidence.read_bytes() == b"retained evidence"


def test_prune_preserves_everything_when_record_path_is_relative(tmp_path, pruning_mode):
    runs = tmp_path / "runs"
    old_run = runs / "old"
    old_run.mkdir(parents=True)
    evidence = old_run / "evidence.json"
    evidence.write_bytes(b"retained evidence")
    store = Journal(run_cmd.config.journal_file())
    record = store.begin(
        job_id="retained-job",
        backend_url="https://map.example",
        engagement_id="engagement",
        job_type="httpx",
        tool="httpx",
        target_source="scope",
    )
    store.transition(record.run_id, Phase.DISCOVERED, run_dir="runs/old")
    old = (datetime.datetime.now() - datetime.timedelta(days=10)).timestamp()
    os.utime(old_run, (old, old))
    with patch.object(run_cmd.config, "runs_dir", return_value=runs):
        run_cmd._prune_run_dirs()
    assert evidence.read_bytes() == b"retained evidence"


def test_prune_does_not_delete_foreign_evidence_after_run_root_substitution(tmp_path):
    runs = tmp_path / "runs"
    saved = tmp_path / "original-runs"
    external = tmp_path / "unrelated"
    direct = runs / "direct"
    foreign = external / "foreign"
    direct.mkdir(parents=True)
    foreign.mkdir(parents=True)
    (foreign / "evidence.json").write_bytes(b"unrelated evidence: preserve")
    old = (datetime.datetime.now() - datetime.timedelta(days=10)).timestamp()
    for directory in (direct, foreign):
        os.utime(directory, (old, old))
    replaced = False
    original_iterdir = Path.iterdir
    original_listdir = os.listdir
    supported = _pruning_supported()

    def substitute():
        nonlocal replaced
        if not replaced:
            runs.rename(saved)
            external.rename(runs)
            replaced = True

    def iterdir(path):
        if path == runs:
            substitute()
        return original_iterdir(path)

    def listdir(path):
        if isinstance(path, int):
            substitute()
        return original_listdir(path)

    with (
        patch.object(run_cmd.config, "runs_dir", return_value=runs),
        patch.object(Path, "iterdir", iterdir),
        patch.object(os, "listdir", listdir),
        patch.object(os, "supports_fd", os.supports_fd | {listdir}),
    ):
        run_cmd._prune_run_dirs()
    evidence_root = runs if replaced else external
    assert (evidence_root / "foreign" / "evidence.json").read_bytes() == (
        b"unrelated evidence: preserve"
    )
    assert replaced is supported


# ---------------------------------------------------------------------------
# _check_target_cap
# ---------------------------------------------------------------------------


def test_check_target_cap_aborts_when_exceeded():
    """_check_target_cap must exit even with --yes so automation can't bypass the guard."""
    with pytest.raises(typer.Exit):
        run_cmd._check_target_cap(["t"] * 600, max_targets=500)


def test_check_target_cap_passes_when_under_limit():
    run_cmd._check_target_cap(["t"] * 499, max_targets=500)  # must not raise


def test_check_target_cap_passes_at_exact_limit():
    run_cmd._check_target_cap(["t"] * 500, max_targets=500)  # must not raise


def test_check_target_cap_disabled_by_zero():
    run_cmd._check_target_cap(["t"] * 10_000, max_targets=0)  # must not raise


# A negative cap used to skip the check entirely, because every guard is written
# as `max_targets > 0`. Only 0 is documented as disabling the cap, so a stray
# minus sign must be an error rather than a silently disabled safety guard.
@pytest.mark.parametrize("bad", [-1, -500])
def test_validate_max_targets_rejects_negative(bad):
    with pytest.raises(typer.Exit):
        run_cmd.validate_max_targets(bad)


@pytest.mark.parametrize("ok", [0, 1, 500])
def test_validate_max_targets_accepts_zero_and_positive(ok):
    run_cmd.validate_max_targets(ok)  # must not raise


def test_check_target_cap_rejects_negative_before_counting():
    """Negative must abort even when the target count is under any sane limit."""
    with pytest.raises(typer.Exit):
        run_cmd._check_target_cap(["t"], max_targets=-1)


def test_run_httpx_respects_max_targets():
    p = _common_patches(["t"] * 600)
    with p[0], p[1], p[2], p[3], patch("vardrrunner.runner.run_httpx") as mock_httpx:
        with pytest.raises(typer.Exit):
            run_cmd.run_httpx("prog-1", target="x", yes=True, max_targets=500)
    mock_httpx.assert_not_called()


def test_run_httpx_disabled_cap_runs_all_targets():
    p = _common_patches(["t"] * 600)
    client_mock = MagicMock()
    client_mock.import_file.return_value = {"import_record": {"imported_count": 600}}
    run_dir = __import__("pathlib").Path("/tmp")
    with (
        p[0],
        p[1],
        patch("vardrrunner.commands.run.api.VardrMapClient", return_value=client_mock),
        p[3],
        patch("vardrrunner.runner.run_httpx"),
        patch("vardrrunner.commands.run._make_run_dir", return_value=run_dir),
        patch("vardrrunner.commands.run._finish"),
    ):
        run_cmd.run_httpx("prog-1", target="x", yes=True, max_targets=0)


# ---------------------------------------------------------------------------
# _make_run_dir
# ---------------------------------------------------------------------------


def test_make_run_dir_creates_unique_timestamped_dirs(tmp_path):
    with patch("vardrrunner.commands.run.config.runs_dir", return_value=tmp_path):
        first = run_cmd._make_run_dir()
        second = run_cmd._make_run_dir()
    assert first.exists() and second.exists()
    assert first.parent == tmp_path and second.parent == tmp_path
    assert first != second


# ---------------------------------------------------------------------------
# _execute helper
# ---------------------------------------------------------------------------


def test_execute_returns_callable_result():
    result = run_cmd._execute(lambda: "done")
    assert result == "done"


def test_execute_handles_tool_timeout(capsys):
    from vardrrunner.runner import ToolTimeout

    with pytest.raises(typer.Exit):
        run_cmd._execute(lambda: (_ for _ in ()).throw(ToolTimeout("timed out")))


# ---------------------------------------------------------------------------
# run_httpx — no targets path
# ---------------------------------------------------------------------------


def test_run_httpx_no_targets_exits():
    p = _common_patches([])
    with p[0], p[1], p[2], p[3]:
        with pytest.raises(typer.Exit):
            run_cmd.run_httpx("prog-1", target="x", yes=True)


# ---------------------------------------------------------------------------
# run_nuclei — no targets path and targets_file source
# ---------------------------------------------------------------------------


def test_run_nuclei_no_targets_exits():
    p = _common_patches([])
    with p[0], p[1], p[2], p[3]:
        with pytest.raises(typer.Exit):
            run_cmd.run_nuclei("prog-1", target="x", yes=True)


def test_run_nuclei_happy_path(tmp_path):
    p = _common_patches(["https://app.example.com"])
    with (
        p[0],
        p[1],
        p[2],
        p[3],
        patch("vardrrunner.commands.run._finish") as mock_finish,
        patch("vardrrunner.commands.run._make_run_dir", return_value=tmp_path),
    ):
        run_cmd.run_nuclei("prog-1", target="https://app.example.com", yes=True)
    mock_finish.assert_called_once()


# ---------------------------------------------------------------------------
# run_nmap — no targets after normalization
# ---------------------------------------------------------------------------


def test_run_nmap_no_targets_exits():
    p = _common_patches([])
    with p[0], p[1], p[2], p[3]:
        with pytest.raises(typer.Exit):
            run_cmd.run_nmap("prog-1", yes=True)


def test_run_nmap_happy_path(tmp_path):
    p = _common_patches(["https://app.example.com"])
    with (
        p[0],
        p[1],
        p[2],
        p[3],
        patch("vardrrunner.commands.run._finish") as mock_finish,
        patch("vardrrunner.commands.run._make_run_dir", return_value=tmp_path),
    ):
        run_cmd.run_nmap("prog-1", target="app.example.com", yes=True)
    mock_finish.assert_called_once()


# ---------------------------------------------------------------------------
# run_dnsx — no targets after host-strip normalization
# ---------------------------------------------------------------------------


def test_run_dnsx_no_targets_exits():
    p = _common_patches([])
    with p[0], p[1], p[2], p[3]:
        with pytest.raises(typer.Exit):
            run_cmd.run_dnsx("prog-1", yes=True)


def test_run_dnsx_happy_path(tmp_path):
    p = _common_patches(["app.example.com"])
    with (
        p[0],
        p[1],
        p[2],
        p[3],
        patch("vardrrunner.commands.run._finish") as mock_finish,
        patch("vardrrunner.commands.run._make_run_dir", return_value=tmp_path),
    ):
        run_cmd.run_dnsx("prog-1", target="app.example.com", yes=True)
    mock_finish.assert_called_once()


# ---------------------------------------------------------------------------
# run_naabu — all paths
# ---------------------------------------------------------------------------


def test_run_naabu_no_targets_exits():
    p = _common_patches([])
    with p[0], p[1], p[2], p[3]:
        with pytest.raises(typer.Exit):
            run_cmd.run_naabu("prog-1", yes=True)


def test_run_naabu_happy_path(tmp_path):
    p = _common_patches(["10.0.0.1"])
    with (
        p[0],
        p[1],
        p[2],
        p[3],
        patch("vardrrunner.commands.run._finish") as mock_finish,
        patch("vardrrunner.commands.run._make_run_dir", return_value=tmp_path),
    ):
        run_cmd.run_naabu("prog-1", target="10.0.0.1", yes=True)
    mock_finish.assert_called_once()


def test_run_naabu_max_targets_exceeded():
    # naabu deduplicates with dict.fromkeys; use distinct hosts so the cap triggers
    distinct_hosts = [f"host{i}.example.com" for i in range(600)]
    p = _common_patches(distinct_hosts)
    with p[0], p[1], p[2], p[3]:
        with pytest.raises(typer.Exit):
            run_cmd.run_naabu("prog-1", target="x", yes=True, max_targets=500)


@pytest.mark.parametrize("depth", [0, 11])
def test_run_katana_rejects_out_of_range_depth(depth):
    p = _common_patches(["https://a.example.com"])
    with p[0], p[1], p[2], p[3], patch("vardrrunner.runner.run_katana") as mock_katana:
        with pytest.raises(typer.Exit) as exc:
            run_cmd.run_katana("prog-1", target="https://a.example.com", depth=depth, yes=True)
    assert exc.value.exit_code == 1
    mock_katana.assert_not_called()


def test_run_katana_no_targets_exits():
    p = _common_patches([])
    with p[0], p[1], p[2], p[3]:
        with pytest.raises(typer.Exit) as exc:
            run_cmd.run_katana("prog-1", yes=True)
    assert exc.value.exit_code == 0


def test_run_katana_happy_path_dedupes_urls(tmp_path):
    p = _common_patches(["https://a.example.com", "https://a.example.com ", " "])
    with (
        p[0],
        p[1],
        p[2],
        p[3],
        patch("vardrrunner.commands.run._finish") as mock_finish,
        patch("vardrrunner.commands.run._make_run_dir", return_value=tmp_path),
    ):
        run_cmd.run_katana("prog-1", target="https://a.example.com", js_crawl=True, yes=True)
    tool, _client, _eng, urls, cfg, _ = mock_finish.call_args.args
    assert tool == "katana" and urls == ["https://a.example.com"] and cfg.js_crawl is True


def _gau_patches(scope_in):
    client = MagicMock()
    client.scope.return_value = {"in": scope_in}
    return (
        patch("vardrrunner.commands.run.runner.check_tool"),
        patch("vardrrunner.commands.run.config.require_auth", return_value=("https://a", "k")),
        patch("vardrrunner.commands.run.api.VardrMapClient", return_value=client),
    )


def test_run_gau_rejects_unknown_provider():
    p = _gau_patches([{"value": "*.example.com"}])
    with p[0], p[1], p[2], patch("vardrrunner.runner.run_gau") as mock_gau:
        with pytest.raises(typer.Exit) as exc:
            run_cmd.run_gau("prog-1", providers="otx,notaprovider", yes=True)
    assert exc.value.exit_code == 1
    mock_gau.assert_not_called()


def test_run_gau_without_wildcards_exits():
    p = _gau_patches([{"value": "example.com"}])
    with p[0], p[1], p[2]:
        with pytest.raises(typer.Exit) as exc:
            run_cmd.run_gau("prog-1", yes=True)
    assert exc.value.exit_code == 0


def test_run_gau_refuses_option_shaped_scope():
    p = _gau_patches([{"value": "*.-evil"}])
    with p[0], p[1], p[2], patch("vardrrunner.runner.run_gau") as mock_gau:
        with pytest.raises(typer.Exit) as exc:
            run_cmd.run_gau("prog-1", yes=True)
    assert exc.value.exit_code == 1
    mock_gau.assert_not_called()


def test_run_gau_happy_path(tmp_path):
    p = _gau_patches([{"value": "*.example.com"}])
    with (
        p[0],
        p[1],
        p[2],
        patch("vardrrunner.commands.run._finish") as mock_finish,
        patch("vardrrunner.commands.run._make_run_dir", return_value=tmp_path),
    ):
        run_cmd.run_gau("prog-1", subs=False, providers="otx", yes=True)
    tool, _client, _eng, domains, cfg, _ = mock_finish.call_args.args
    assert tool == "gau" and domains == ["example.com"]
    assert cfg.subs is False and cfg.providers == ("otx",)


def test_run_gau_max_targets_exceeded():
    p = _gau_patches([{"value": f"*.d{i}.example.com"} for i in range(5)])
    with p[0], p[1], p[2]:
        with pytest.raises(typer.Exit):
            run_cmd.run_gau("prog-1", yes=True, max_targets=3)


# ---------------------------------------------------------------------------
# _finish helper — no output and upload failure paths
# ---------------------------------------------------------------------------


def test_finish_no_output_exits(tmp_path):
    """_finish exits with code 0 when the tool produces no output file."""
    handler = MagicMock()
    handler.running_label.return_value = "httpx [1 target]"
    handler.execute.return_value = None

    with patch.dict("vardrrunner.handlers.REGISTRY", {"httpx": handler}):
        with pytest.raises(typer.Exit):
            run_cmd._finish("httpx", MagicMock(), "p1", ["x"], MagicMock(), tmp_path)


def test_finish_upload_failure_exits(tmp_path):
    """_finish exits with code 1 when the upload call raises."""
    output = tmp_path / "out.jsonl"
    output.write_text('{"url":"https://a.com"}\n')

    handler = MagicMock()
    handler.running_label.return_value = "httpx [1]"
    handler.execute.return_value = output
    handler.upload.side_effect = RuntimeError("upload failed")

    with patch.dict("vardrrunner.handlers.REGISTRY", {"httpx": handler}):
        with pytest.raises(typer.Exit):
            run_cmd._finish("httpx", MagicMock(), "p1", ["x"], MagicMock(), tmp_path)
