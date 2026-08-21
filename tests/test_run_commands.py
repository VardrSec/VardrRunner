"""Direct `run` commands validate options through the same typed configs as jobs."""

import datetime
import os
from unittest.mock import MagicMock, patch

import pytest
import typer

from vardrrunner.commands import run as run_cmd


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


def test_prune_run_dirs_removes_old_dirs(tmp_path):
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

    assert not old_dir.exists()
    assert new_dir.exists()


def test_prune_run_dirs_is_a_no_op_when_runs_dir_absent(tmp_path):
    with patch("vardrrunner.commands.run.config.runs_dir", return_value=tmp_path / "no_runs"):
        run_cmd._prune_run_dirs()  # must not raise


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
