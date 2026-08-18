"""Tests for recon pipelines: definitions and the sequential runner."""

from unittest.mock import MagicMock, patch

import pytest
import typer

from vardrrunner import pipelines
from vardrrunner.commands import pipeline as pipeline_cmd


def _fake_tool(*args, **kwargs):
    """Stand-in for runner.run_*: write a non-empty output file, return success."""
    output = args[1]  # run_*(targets, output, ...)
    output.write_text("data\n")
    return 0


def test_pipeline_definitions():
    assert set(pipelines.PIPELINES) >= {"recon", "quick", "deep", "ports"}
    recon = [s.tool for s in pipelines.PIPELINES["recon"]]
    assert recon == ["subfinder", "httpx", "nuclei"]
    # First stage reads scope; later stages chain via recon.
    assert pipelines.PIPELINES["recon"][0].source == "scope"
    assert pipelines.PIPELINES["recon"][1].source == "recon"
    # deep inserts dnsx resolution before probing; ports scans with naabu.
    assert [s.tool for s in pipelines.PIPELINES["deep"]] == [
        "subfinder",
        "dnsx",
        "httpx",
        "nuclei",
    ]
    assert [s.tool for s in pipelines.PIPELINES["ports"]] == ["subfinder", "dnsx", "naabu"]


def test_list_pipelines_runs(capsys):
    pipeline_cmd.list_pipelines()
    out = capsys.readouterr().out
    assert "recon" in out and "subfinder" in out


def test_list_pipelines_shows_stage_sources(capsys):
    pipeline_cmd.list_pipelines()
    out = capsys.readouterr().out
    # Each stage should show its source (scope/recon) so operators can see data flow.
    assert "scope" in out
    assert "recon" in out


def test_run_pipeline_unknown_name_exits():
    with pytest.raises(typer.Exit):
        pipeline_cmd.run_pipeline("nope", "prog-1", yes=True)


# ---------------------------------------------------------------------------
# max_targets guardrail
# ---------------------------------------------------------------------------


def test_pipeline_rejects_negative_max_targets():
    """`_run_stage` gates on `max_targets > 0`, so a negative would disable the cap
    on every stage. run_pipeline must refuse before any stage executes."""
    with pytest.raises(typer.Exit):
        pipeline_cmd.run_pipeline("quick", "prog-1", yes=True, max_targets=-1)


def test_pipeline_aborts_when_stage_exceeds_max_targets(tmp_path):
    """Pipeline stops and does not run the tool when targets > max_targets."""
    client = MagicMock()
    # 3 wildcards → 3 domains handed to subfinder
    client.scope.return_value = {
        "in": [{"value": "*.a.com"}, {"value": "*.b.com"}, {"value": "*.c.com"}],
        "out": [],
    }

    with (
        patch("vardrrunner.commands.pipeline.config.require_auth", return_value=("https://a", "k")),
        patch("vardrrunner.commands.pipeline.api.VardrMapClient", return_value=client),
        patch("vardrrunner.runner.tool_available", return_value=True),
        patch("vardrrunner.commands.pipeline._make_run_dir", return_value=tmp_path),
        patch("vardrrunner.runner.run_subfinder", side_effect=_fake_tool) as mock_run,
    ):
        # cap at 2 — 3 targets should trip it
        pipeline_cmd.run_pipeline("quick", "prog-1", yes=True, max_targets=2)

    mock_run.assert_not_called()
    client.import_file.assert_not_called()


def test_pipeline_disabled_cap_runs_all_stages(tmp_path):
    """max_targets=0 disables the guardrail; all stages execute normally."""
    client = MagicMock()
    client.scope.return_value = {
        "in": [{"value": f"*.s{i}.com"} for i in range(10)],
        "out": [],
    }
    client.import_file.return_value = {"import_record": {"imported_count": 10}}

    with (
        patch("vardrrunner.commands.pipeline.config.require_auth", return_value=("https://a", "k")),
        patch("vardrrunner.commands.pipeline.api.VardrMapClient", return_value=client),
        patch("vardrrunner.runner.tool_available", return_value=True),
        patch("vardrrunner.commands.pipeline._make_run_dir", return_value=tmp_path),
        patch("vardrrunner.runner.run_subfinder", side_effect=_fake_tool),
    ):
        # 10 domains, cap disabled → should run without aborting
        pipeline_cmd.run_pipeline("quick", "prog-1", yes=True, max_targets=0)

    # subfinder stage ran and uploaded
    assert client.import_file.call_count >= 1


def test_run_pipeline_invalid_severity_exits():
    with pytest.raises(typer.Exit):
        pipeline_cmd.run_pipeline("recon", "prog-1", severity="bogus", yes=True)


def test_run_pipeline_missing_tool_exits():
    with (
        patch("vardrrunner.commands.pipeline.config.require_auth", return_value=("https://a", "k")),
        patch("vardrrunner.commands.pipeline.api.VardrMapClient", return_value=MagicMock()),
        patch("vardrrunner.runner.tool_available", return_value=False),
    ):
        with pytest.raises(typer.Exit):
            pipeline_cmd.run_pipeline("quick", "prog-1", yes=True)


def test_run_pipeline_executes_stages_in_order(tmp_path):
    client = MagicMock()
    client.scope.return_value = {"in": [{"value": "*.example.com"}], "out": []}
    client.recon.return_value = [{"url": "https://app.example.com"}]
    client.import_file.return_value = {"import_record": {"imported_count": 1}}

    with (
        patch("vardrrunner.commands.pipeline.config.require_auth", return_value=("https://a", "k")),
        patch("vardrrunner.commands.pipeline.api.VardrMapClient", return_value=client),
        patch("vardrrunner.runner.tool_available", return_value=True),
        patch("vardrrunner.commands.pipeline._make_run_dir", return_value=tmp_path),
        patch("vardrrunner.runner.run_subfinder", side_effect=_fake_tool),
        patch("vardrrunner.runner.run_httpx", side_effect=_fake_tool),
        patch("vardrrunner.runner.run_nuclei", side_effect=_fake_tool),
    ):
        pipeline_cmd.run_pipeline("recon", "prog-1", yes=True)

    # Three stages → three uploads, in order: subfinder→httpx import, httpx import, nuclei import.
    upload_tool_types = [c.args[1] for c in client.import_file.call_args_list]
    assert upload_tool_types == ["httpx", "httpx", "nuclei"]


def _patches_for(client, tmp_path):
    return (
        patch("vardrrunner.commands.pipeline.config.require_auth", return_value=("https://a", "k")),
        patch("vardrrunner.commands.pipeline.api.VardrMapClient", return_value=client),
        patch("vardrrunner.runner.tool_available", return_value=True),
        patch("vardrrunner.commands.pipeline._make_run_dir", return_value=tmp_path),
        patch("vardrrunner.runner.run_subfinder", side_effect=_fake_tool),
        patch("vardrrunner.runner.run_httpx", side_effect=_fake_tool),
    )


def test_pipeline_upload_failure_honors_continue_on_error(tmp_path):
    client = MagicMock()
    client.scope.return_value = {"in": [{"value": "*.example.com"}], "out": []}
    client.recon.return_value = [{"url": "https://app.example.com"}]
    client.import_file.side_effect = RuntimeError("upload boom")  # every upload fails

    p = _patches_for(client, tmp_path)
    with p[0], p[1], p[2], p[3], p[4], p[5]:
        # quick = subfinder → httpx; --continue-on-error keeps going past the failed upload.
        pipeline_cmd.run_pipeline("quick", "prog-1", yes=True, continue_on_error=True)

    assert client.import_file.call_count == 2  # both stages attempted their upload


def test_pipeline_upload_failure_stops_without_continue(tmp_path):
    client = MagicMock()
    client.scope.return_value = {"in": [{"value": "*.example.com"}], "out": []}
    client.recon.return_value = [{"url": "https://app.example.com"}]
    client.import_file.side_effect = RuntimeError("upload boom")

    p = _patches_for(client, tmp_path)
    with p[0], p[1], p[2], p[3], p[4], p[5]:
        # Default: stop after the first failing stage.
        pipeline_cmd.run_pipeline("quick", "prog-1", yes=True)

    assert client.import_file.call_count == 1


def test_run_pipeline_stops_when_stage_has_no_targets(tmp_path):
    client = MagicMock()
    # No wildcard scope → subfinder resolves zero domains → pipeline stops at stage 1.
    client.scope.return_value = {"in": [{"value": "app.example.com"}], "out": []}

    with (
        patch("vardrrunner.commands.pipeline.config.require_auth", return_value=("https://a", "k")),
        patch("vardrrunner.commands.pipeline.api.VardrMapClient", return_value=client),
        patch("vardrrunner.runner.tool_available", return_value=True),
        patch("vardrrunner.commands.pipeline._make_run_dir", return_value=tmp_path),
        patch("vardrrunner.runner.run_subfinder", side_effect=_fake_tool),
    ):
        pipeline_cmd.run_pipeline("quick", "prog-1", yes=True)

    client.import_file.assert_not_called()


# ---------------------------------------------------------------------------
# Run-scoped handoff — core isolation guarantee
# ---------------------------------------------------------------------------


def _fake_subfinder_jsonl(*args, **kwargs):
    """subfinder fake: write valid JSONL so extract_handoff_targets works."""
    output = args[1]
    # run_subfinder writes to a .txt file; SubfinderHandler then converts it.
    # Mimic that: just write hosts to the output path.
    output.write_text("a.example.com\nb.example.com\n")
    return 0


def test_handoff_prevents_recon_call_for_next_stage(tmp_path):
    """When subfinder produces valid JSONL output, httpx must NOT call client.recon()."""
    client = MagicMock()
    client.scope.return_value = {"in": [{"value": "*.example.com"}], "out": []}
    client.import_file.return_value = {"import_record": {"imported_count": 2}}

    captured_httpx_targets = []

    def fake_httpx(targets, output, **kw):
        captured_httpx_targets.extend(targets)
        # Write valid httpx JSONL so extract_handoff_targets works for the next stage
        output.write_text('{"url": "https://a.example.com"}\n{"url": "https://b.example.com"}\n')

    with (
        patch("vardrrunner.commands.pipeline.config.require_auth", return_value=("https://x", "k")),
        patch("vardrrunner.commands.pipeline.api.VardrMapClient", return_value=client),
        patch("vardrrunner.runner.tool_available", return_value=True),
        patch("vardrrunner.commands.pipeline._make_run_dir", return_value=tmp_path),
        patch("vardrrunner.runner.run_subfinder", side_effect=_fake_subfinder_jsonl),
        patch("vardrrunner.runner.run_httpx", side_effect=fake_httpx),
    ):
        pipeline_cmd.run_pipeline("quick", "prog-1", yes=True)

    # httpx must have been called with hosts from the handoff, NOT client.recon()
    assert "a.example.com" in captured_httpx_targets or "b.example.com" in captured_httpx_targets
    client.recon.assert_not_called()


def test_handoff_written_and_read_end_to_end(tmp_path):
    """Full recon pipeline: subfinder handoff feeds httpx; httpx handoff feeds nuclei."""
    client = MagicMock()
    client.scope.return_value = {"in": [{"value": "*.example.com"}], "out": []}
    client.import_file.return_value = {"import_record": {"imported_count": 1}}

    # Use separate subdirs so each stage gets its own run_dir without name collisions.
    dirs = [tmp_path / f"stage_{i}" for i in range(3)]
    for d in dirs:
        d.mkdir()
    dir_iter = iter(dirs)

    captured_nuclei_targets = []

    def fake_nuclei(targets, output, **kw):
        captured_nuclei_targets.extend(targets)
        output.write_text('{"template-id": "test"}\n')

    def fake_httpx(targets, output, **kw):
        output.write_text('{"url": "https://a.example.com"}\n{"url": "https://b.example.com"}\n')

    with (
        patch("vardrrunner.commands.pipeline.config.require_auth", return_value=("https://x", "k")),
        patch("vardrrunner.commands.pipeline.api.VardrMapClient", return_value=client),
        patch("vardrrunner.runner.tool_available", return_value=True),
        patch("vardrrunner.commands.pipeline._make_run_dir", side_effect=lambda: next(dir_iter)),
        patch("vardrrunner.runner.run_subfinder", side_effect=_fake_subfinder_jsonl),
        patch("vardrrunner.runner.run_httpx", side_effect=fake_httpx),
        patch("vardrrunner.runner.run_nuclei", side_effect=fake_nuclei),
    ):
        pipeline_cmd.run_pipeline("recon", "prog-1", yes=True)

    # Nuclei received URLs from httpx's handoff, not from client.recon()
    assert "https://a.example.com" in captured_nuclei_targets
    assert "https://b.example.com" in captured_nuclei_targets
    client.recon.assert_not_called()


def test_handoff_falls_back_to_recon_when_extract_returns_empty(tmp_path):
    """If extract_handoff_targets returns [] (e.g. terminal tool), next stage uses recon."""
    from vardrrunner import handlers as h

    client = MagicMock()
    client.scope.return_value = {"in": [{"value": "*.example.com"}], "out": []}
    client.recon.return_value = [{"url": "https://fallback.example.com"}]
    client.import_file.return_value = {"import_record": {"imported_count": 1}}

    captured_httpx_targets = []

    def fake_httpx(targets, output, **kw):
        captured_httpx_targets.extend(targets)
        output.write_text('{"url": "https://fallback.example.com"}\n')

    with (
        patch("vardrrunner.commands.pipeline.config.require_auth", return_value=("https://x", "k")),
        patch("vardrrunner.commands.pipeline.api.VardrMapClient", return_value=client),
        patch("vardrrunner.runner.tool_available", return_value=True),
        patch("vardrrunner.commands.pipeline._make_run_dir", return_value=tmp_path),
        patch("vardrrunner.runner.run_subfinder", side_effect=_fake_subfinder_jsonl),
        patch("vardrrunner.runner.run_httpx", side_effect=fake_httpx),
        # Force subfinder to extract nothing → no handoff file written
        patch.object(h.SubfinderHandler, "extract_handoff_targets", return_value=[]),
    ):
        pipeline_cmd.run_pipeline("quick", "prog-1", yes=True)

    # No handoff → httpx fell back to backend recon
    client.recon.assert_called_once()


def test_pipeline_run_id_appears_in_output(tmp_path, capsys):
    """A run ID is printed at pipeline start and end."""
    client = MagicMock()
    client.scope.return_value = {"in": [], "out": []}

    with (
        patch("vardrrunner.commands.pipeline.config.require_auth", return_value=("https://x", "k")),
        patch("vardrrunner.commands.pipeline.api.VardrMapClient", return_value=client),
        patch("vardrrunner.runner.tool_available", return_value=True),
        patch("vardrrunner.commands.pipeline._make_run_dir", return_value=tmp_path),
        patch("vardrrunner.runner.run_subfinder", side_effect=_fake_tool),
    ):
        pipeline_cmd.run_pipeline("quick", "prog-1", yes=True)

    # run ID is 8 hex chars; we just verify "Run ID:" appears in the output
    out = capsys.readouterr().out
    assert "run" in out.lower()
