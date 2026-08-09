"""
Pipeline commands — run a chain of tools as one recon workflow.

Each pipeline run gets a short UUID run ID printed at the start and end so
operators can cross-reference logs. Targets flow locally between stages via a
handoff file: after each stage completes, its discovered targets (hosts or URLs)
are written to a plain-text file in the stage's run directory. The next stage
reads from that file instead of the shared backend recon store, so no stale recon
from prior runs can contaminate the pipeline.

Fallback: if a stage produces no parseable handoff targets (e.g. nuclei, nmap)
the next stage falls back to the backend recon store as before — preserving the
original behaviour for terminal tools and for the direct `run` commands.
"""

import json
import time
import types
import uuid
from dataclasses import dataclass
from pathlib import Path

import typer
from rich import box
from rich.console import Console
from rich.live import Live
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from vardrrunner import api, config, configs, handlers, pipelines, runner
from vardrrunner.commands.run import MAX_TARGETS_DEFAULT, _make_run_dir

console = Console()


# ---------------------------------------------------------------------------
# Pipeline TUI
# ---------------------------------------------------------------------------


@dataclass
class _StageState:
    tool: str
    status: str = "pending"  # pending | running | done | failed | no_targets | aborted
    targets: int = 0
    summary: str = ""
    elapsed: float = 0.0


class _PipelineTUI:
    """Rich Live table that updates one row per stage in place."""

    _ICONS: dict[str, Text] = {
        "pending": Text("○", style="dim"),
        "done": Text("✓", style="bold green"),
        "failed": Text("✗", style="bold red"),
        "no_targets": Text("⊘", style="yellow"),
        "aborted": Text("—", style="dim"),
    }

    def __init__(self, stages: list[pipelines.Stage]) -> None:
        self._rows = [_StageState(tool=s.tool) for s in stages]
        self._spinner = Spinner("dots")
        self._live = Live(self._render(), refresh_per_second=8, auto_refresh=True)

    def __enter__(self) -> "_PipelineTUI":
        self._live.__enter__()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        self._live.__exit__(exc_type, exc_val, exc_tb)

    def start(self, i: int) -> None:
        self._rows[i].status = "running"
        self._live.update(self._render())

    def finish(
        self,
        i: int,
        *,
        status: str,
        targets: int = 0,
        summary: str = "",
        elapsed: float = 0.0,
    ) -> None:
        r = self._rows[i]
        r.status = status
        r.targets = targets
        r.summary = summary
        r.elapsed = elapsed
        self._live.update(self._render())

    def _render(self) -> Table:
        table = Table(box=box.SIMPLE_HEAD, show_footer=False, padding=(0, 1), expand=False)
        table.add_column("#", style="dim", width=3)
        table.add_column("Tool", style="bold", min_width=10)
        table.add_column("", width=2)
        table.add_column("Targets", justify="right", min_width=7)
        table.add_column("Results", min_width=30)
        table.add_column("Time", justify="right", style="dim", min_width=5)

        for idx, row in enumerate(self._rows, 1):
            icon: Text | Spinner = (
                self._spinner
                if row.status == "running"
                else self._ICONS.get(row.status, Text(row.status))
            )
            targets_cell = str(row.targets) if row.targets else "—"
            time_cell = f"{row.elapsed:.0f}s" if row.elapsed else ""

            if row.status == "failed":
                summary_cell: Text = Text(row.summary or "failed", style="red")
            elif row.status == "no_targets":
                summary_cell = Text("no targets", style="yellow")
            elif row.status == "aborted":
                summary_cell = Text("aborted", style="dim")
            else:
                summary_cell = Text(row.summary)

            table.add_row(str(idx), row.tool, icon, targets_cell, summary_cell, time_cell)

        return table


# ---------------------------------------------------------------------------
# Stage execution
# ---------------------------------------------------------------------------


@dataclass
class _StageResult:
    status: str  # done | failed | no_targets | aborted
    should_continue: bool
    targets: int = 0
    summary: str = ""
    elapsed: float = 0.0
    handoff: Path | None = None


def _run_stage(
    client: api.VardrMapClient,
    stage: pipelines.Stage,
    engagement_id: str,
    severity: str | None,
    continue_on_error: bool,
    handoff_path: Path | None = None,
    max_targets: int = MAX_TARGETS_DEFAULT,
) -> _StageResult:
    """Run one pipeline stage and return a structured result. Never prints."""
    t0 = time.monotonic()
    handler = handlers.REGISTRY[stage.tool]
    cfg = {"severity": severity} if (stage.tool == "nuclei" and severity) else {}
    config_obj = handler.parse_config(cfg)

    # Local handoff takes priority over the backend recon store so prior pipeline
    # runs can't contaminate this one with stale data.
    if handoff_path is not None and stage.source == "recon" and handoff_path.exists():
        raw = [t for t in handoff_path.read_text().splitlines() if t.strip()]
        targets = handler.normalize_handoff_targets(raw)
    else:
        try:
            targets = handler.resolve_targets(client, engagement_id, stage.source, config_obj)
        except Exception as e:
            return _StageResult(
                status="failed",
                should_continue=continue_on_error,
                summary=f"target resolution: {e}",
                elapsed=time.monotonic() - t0,
            )

    if not targets:
        return _StageResult(
            status="no_targets",
            should_continue=False,
            elapsed=time.monotonic() - t0,
        )

    if max_targets > 0 and len(targets) > max_targets:
        return _StageResult(
            status="aborted",
            should_continue=continue_on_error,
            targets=len(targets),
            summary=f"{len(targets)} targets exceeds --max-targets {max_targets}",
            elapsed=time.monotonic() - t0,
        )

    run_dir = _make_run_dir()
    try:
        output = handler.execute(targets, run_dir, config_obj)
    except Exception as e:
        return _StageResult(
            status="failed",
            should_continue=continue_on_error,
            targets=len(targets),
            summary=str(e),
            elapsed=time.monotonic() - t0,
        )

    if output is None or not output.exists() or output.stat().st_size == 0:
        return _StageResult(
            status="no_targets",
            should_continue=False,
            targets=len(targets),
            elapsed=time.monotonic() - t0,
        )

    try:
        summary = handler.upload(client, engagement_id, output)
    except Exception as e:
        return _StageResult(
            status="failed",
            should_continue=continue_on_error,
            targets=len(targets),
            summary=f"upload: {e}",
            elapsed=time.monotonic() - t0,
        )

    extracted = handler.extract_handoff_targets(output)
    next_handoff: Path | None = None
    if extracted:
        next_handoff = run_dir / "handoff.txt"
        next_handoff.write_text("\n".join(extracted))

    return _StageResult(
        status="done",
        should_continue=True,
        targets=len(targets),
        summary=summary,
        elapsed=time.monotonic() - t0,
        handoff=next_handoff,
    )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def list_pipelines() -> None:
    """Print the available pipelines and their tool chains."""
    console.print("[bold]Available pipelines[/bold]")
    for name, stages in pipelines.PIPELINES.items():
        chain = " → ".join(f"{s.tool}[dim]({s.source})[/dim]" for s in stages)
        console.print(f"  [bold]{name}[/bold]: {chain}")


def run_pipeline(
    name: str,
    engagement_id: str,
    severity: str | None = None,
    yes: bool = False,
    continue_on_error: bool = False,
    max_targets: int = MAX_TARGETS_DEFAULT,
    dry_run: bool = False,
    as_json: bool = False,
) -> None:
    """Run every stage of a pipeline in order against an engagement."""
    stages = pipelines.PIPELINES.get(name)
    if stages is None:
        available = ", ".join(pipelines.PIPELINES)
        console.print(f"[red]Unknown pipeline {name!r}.[/red] Available: {available}")
        raise typer.Exit(1)

    if severity:
        try:
            configs.NucleiConfig.from_dict({"severity": severity})
        except configs.ConfigError as e:
            console.print(f"[red]Invalid --severity:[/red] {e}")
            raise typer.Exit(1) from e

    url, key = config.require_auth()
    client = api.VardrMapClient(url, key)

    missing = sorted({s.tool for s in stages if not runner.tool_available(s.tool)})
    if missing:
        console.print(f"[red]Missing tools:[/red] {', '.join(missing)} — install them and retry.")
        raise typer.Exit(1)

    run_id = uuid.uuid4().hex[:8]
    chain = " → ".join(s.tool for s in stages)
    if not as_json:
        console.print(
            f"\n[bold]Pipeline '{name}'[/bold]: {chain}  "
            f"(engagement {engagement_id}  run [dim]{run_id}[/dim])"
        )

    if dry_run:
        _run_pipeline_dry(client, stages, engagement_id, severity, max_targets)
        return

    if not yes and not typer.confirm("Run this pipeline?", default=False):
        console.print("[dim]Aborted.[/dim]")
        raise typer.Exit(0)

    t_total = time.monotonic()
    stopped_at: int | None = None
    handoff_path: Path | None = None
    stage_results: list[dict] = []

    if as_json:
        # JSON mode: no TUI — stdout must be pure JSON for machine consumers.
        for i, stage in enumerate(stages):
            result = _run_stage(
                client, stage, engagement_id, severity, continue_on_error, handoff_path, max_targets
            )
            stage_results.append(
                {
                    "stage": i + 1,
                    "tool": stage.tool,
                    "source": stage.source,
                    "status": result.status,
                    "targets": result.targets,
                    "summary": result.summary,
                    "elapsed": round(result.elapsed, 2),
                }
            )
            handoff_path = result.handoff
            if not result.should_continue:
                stopped_at = i
                for j in range(i + 1, len(stages)):
                    stage_results.append(
                        {
                            "stage": j + 1,
                            "tool": stages[j].tool,
                            "source": stages[j].source,
                            "status": "aborted",
                            "targets": 0,
                            "summary": "",
                            "elapsed": 0.0,
                        }
                    )
                break
        total_elapsed = time.monotonic() - t_total
        console.print_json(
            json.dumps(
                {
                    "run_id": run_id,
                    "pipeline": name,
                    "engagement_id": engagement_id,
                    "success": stopped_at is None,
                    "total_elapsed": round(total_elapsed, 2),
                    "stages": stage_results,
                }
            )
        )
        return

    with _PipelineTUI(stages) as tui:
        for i, stage in enumerate(stages):
            tui.start(i)
            result = _run_stage(
                client, stage, engagement_id, severity, continue_on_error, handoff_path, max_targets
            )
            tui.finish(
                i,
                status=result.status,
                targets=result.targets,
                summary=result.summary,
                elapsed=result.elapsed,
            )
            handoff_path = result.handoff
            if not result.should_continue:
                stopped_at = i
                for j in range(i + 1, len(stages)):
                    tui.finish(j, status="aborted")
                break

    total_elapsed = time.monotonic() - t_total
    if stopped_at is None:
        console.print(
            f"\n[green]Pipeline complete[/green] in {total_elapsed:.0f}s.  Run [dim]{run_id}[/dim]"
        )
    else:
        console.print(
            f"\n[yellow]Pipeline stopped[/yellow] at stage {stopped_at + 1} "
            f"({stages[stopped_at].tool}) in {total_elapsed:.0f}s.  "
            f"Run [dim]{run_id}[/dim]"
        )


def _run_pipeline_dry(
    client: api.VardrMapClient,
    stages: list[pipelines.Stage],
    engagement_id: str,
    severity: str | None,
    max_targets: int,
) -> None:
    """Resolve first-stage targets and print what would run without executing."""
    console.print("[dim]Dry run — no tools will execute.[/dim]\n")
    first = stages[0]
    handler = handlers.REGISTRY[first.tool]
    cfg_dict = {"severity": severity} if (first.tool == "nuclei" and severity) else {}
    config_obj = handler.parse_config(cfg_dict)
    try:
        targets = handler.resolve_targets(client, engagement_id, first.source, config_obj)
    except Exception as e:
        console.print(f"[red]Could not resolve stage-1 targets:[/red] {e}")
        raise typer.Exit(1) from e

    n = len(targets)
    cap = (
        f"  [yellow](exceeds --max-targets {max_targets})[/yellow]"
        if max_targets > 0 and n > max_targets
        else ""
    )
    console.print(f"  [bold]Stage 1[/bold] {first.tool}({first.source}): {n} target(s){cap}")
    for i, stage in enumerate(stages[1:], 2):
        console.print(
            f"  [bold]Stage {i}[/bold] {stage.tool}({stage.source}): targets from stage {i - 1}"
        )
    console.print("\n[dim]Pass --yes (and omit --dry-run) to execute.[/dim]")
