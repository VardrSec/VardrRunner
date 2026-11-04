"""Inspect and export the sanitized local execution journal."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from contextlib import ExitStack
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from vardrrunner import config, manifests, redaction, resources
from vardrrunner.journal import TERMINAL_PHASES, Journal, JournalError, RunRecord
from vardrrunner.windows_export import WindowsExport, WindowsExportError

console = Console()

EXPORT_ARTIFACT_LIMIT = 8 * 1024**2
EXPORT_METADATA_LIMIT = 1024**2
EXPORT_JSON_DEPTH = 12


class ExportError(RuntimeError):
    """Internal fixed error codes only; never input, filesystem or parser messages."""


def _require_export(condition: bool, code: str) -> None:
    if not condition:
        raise ExportError(code)


def _plain_components(path: Path) -> None:
    _require_export(".." not in path.parts, "unsafe_path")
    for component in (path, *path.parents):
        info = component.lstat()
        _require_export(
            not stat.S_ISLNK(info.st_mode)
            and not getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400),
            "linked_path_unsupported",
        )


def _artifact_document(
    record: RunRecord, maximum: int, windows: WindowsExport | None = None
) -> dict:
    _require_export(bool(record.run_dir and record.artifact_path), "artifact_unavailable")
    root, source = (
        Path(record.run_dir or "").absolute(),
        Path(record.artifact_path or "").absolute(),
    )
    _require_export(
        type(record.artifact_size) is int and 0 < record.artifact_size <= maximum,
        "artifact_size_unsupported",
    )
    _require_export(
        isinstance(record.artifact_sha256, str)
        and re.fullmatch(r"[0-9a-f]{64}", record.artifact_sha256) is not None,
        "artifact_digest_unavailable",
    )
    if windows is not None:
        raw = windows.read_source(root, source, maximum)
    else:
        _plain_components(root)
        _plain_components(source)
        _require_export(
            root.is_dir() and source.parent == root and source.suffix.lower() == ".json",
            "artifact_path_unsupported",
        )
        before = source.lstat()
        _require_export(
            stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_ino != 0,
            "artifact_file_unsupported",
        )
        descriptor = os.open(
            source, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            _require_export(
                stat.S_ISREG(opened.st_mode)
                and opened.st_nlink == 1
                and (opened.st_dev, opened.st_ino, opened.st_size)
                == (before.st_dev, before.st_ino, record.artifact_size),
                "artifact_changed",
            )
            raw = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
            _require_export(
                (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_nlink)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_nlink),
                "artifact_changed",
            )
    _require_export(
        len(raw) == record.artifact_size
        and hashlib.sha256(raw).hexdigest() == record.artifact_sha256,
        "artifact_integrity_mismatch",
    )

    def pairs(items):
        result = {}
        for key, value in items:
            _require_export(key not in result, "ambiguous_json")
            result[key] = value
        return result

    def finite(value):
        parsed = float(value)
        _require_export(math.isfinite(parsed), "nonfinite_json")
        return parsed

    def constant(_):
        raise ExportError("nonfinite_json")

    document = json.loads(
        raw.decode("utf-8"), object_pairs_hook=pairs, parse_float=finite, parse_constant=constant
    )
    _require_export(isinstance(document, dict), "artifact_shape_unsupported")

    def bounded(value, depth=0):
        _require_export(depth <= EXPORT_JSON_DEPTH, "json_depth_exceeded")
        for child in (
            value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
        ):
            bounded(child, depth + 1)

    bounded(document)
    return document


def _private_directories_supported() -> bool:
    return (
        os.name == "posix"
        and os.open in os.supports_dir_fd
        and hasattr(os, "O_DIRECTORY")
        and bool(getattr(os, "O_NOFOLLOW", 0))
    )


def _protected_parent(path: Path) -> None:
    _plain_components(path)
    for component in (path, *path.parents):
        info = component.stat()
        mode = stat.S_IMODE(info.st_mode)
        _require_export(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid in {0, _effective_uid()}
            and (not mode & 0o022 or bool(mode & stat.S_ISVTX)),
            "unprotected_output_parent",
        )


def _effective_uid() -> int:
    getter = getattr(os, "geteuid", None)
    if getter is None:
        raise ExportError("private_directory_unsupported")
    return int(getter())


def export_run(run_id: str, output: Path) -> None:
    """Export one recorded terminal run as a redacted derivative, never executable authority."""
    try:
        with ExitStack() as stack:
            windows = stack.enter_context(WindowsExport()) if os.name == "nt" else None
            _require_export(
                windows is not None or _private_directories_supported(),
                "private_directory_unsupported",
            )
            path = config.journal_file()
            record = Journal.read_existing(path, run_id)
            _require_export(record is not None, "run_unavailable")
            assert record is not None
            _require_export(
                record.phase in TERMINAL_PHASES and record.pid is None, "run_not_quiescent"
            )
            limits = resources.load_limits()
            maximum = min(EXPORT_ARTIFACT_LIMIT, limits.max_artifact_bytes)
            document = _artifact_document(record, maximum, windows)
            artifact = manifests.encode_export_json(document, maximum_bytes=maximum)
            derivative_hash = hashlib.sha256(artifact).hexdigest()
            portable = replace(
                record,
                run_dir=".",
                artifact_path="artifact.json",
                manifest_path="manifest.json",
                artifact_sha256=derivative_hash,
                artifact_size=len(artifact),
                warnings=[
                    *record.warnings,
                    {
                        "code": "redacted_export",
                        "source_artifact_sha256": record.artifact_sha256 or "",
                        "message": "Redacted derivative; original recorded provenance is in audit.json.",
                    },
                ],
            )
            audit = manifests.encode_export_json(
                {"audit_schema_version": 1, "run_count": 1, "runs": [_payload(record)]},
                maximum_bytes=EXPORT_METADATA_LIMIT,
            )
            manifest = manifests.encode_export_json(
                {
                    "manifest_schema_version": manifests.MANIFEST_SCHEMA_VERSION,
                    **portable.manifest_payload(),
                },
                maximum_bytes=EXPORT_METADATA_LIMIT,
            )
            output = output.absolute()
            if windows is None:
                _protected_parent(output.parent)
            _require_export(
                not output.exists() and not output.is_symlink(), "exclusive_output_required"
            )
            root = Path(record.run_dir or "").absolute()
            _require_export(output != root and root not in output.parents, "output_inside_source")
            resources.ensure_free_space(
                output.parent,
                limits.min_free_disk_bytes + len(artifact) + len(audit) + len(manifest),
            )
            _require_export(Journal.read_existing(path, run_id) == record, "record_changed")
            if windows is not None:

                def fresh() -> None:
                    _require_export(Journal.read_existing(path, run_id) == record, "record_changed")

                windows.publish(output, (artifact, audit, manifest), fresh)
            else:
                output.mkdir(mode=0o700)
                _plain_components(output)
                directory = os.open(
                    output,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                )
                try:
                    info = os.fstat(directory)
                    _require_export(
                        info.st_ino != 0
                        and info.st_uid == _effective_uid()
                        and not stat.S_IMODE(info.st_mode) & 0o077,
                        "private_directory_unavailable",
                    )
                    manifests.write_exclusive(
                        Path("artifact.json"), artifact, directory_fd=directory
                    )
                    _require_export(
                        manifests.artifact_digest(Path("artifact.json"), directory_fd=directory)
                        == (derivative_hash, len(artifact)),
                        "export_integrity_mismatch",
                    )
                    manifests.write_exclusive(Path("audit.json"), audit, directory_fd=directory)
                    _require_export(Journal.read_existing(path, run_id) == record, "record_changed")
                    _plain_components(output)
                    current = output.lstat()
                    _require_export(
                        (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino),
                        "output_directory_changed",
                    )
                    manifests.write_exclusive(
                        Path(manifests.MANIFEST_NAME), manifest, directory_fd=directory
                    )
                finally:
                    os.close(directory)
    except (ExportError, WindowsExportError) as exc:
        console.print(
            f"[red]Portable export refused or incomplete ({exc}); retain any new output.[/red]"
        )
        raise typer.Exit(1) from None
    except Exception:
        console.print("[red]Portable export refused or incomplete; retain any new output.[/red]")
        raise typer.Exit(1) from None
    console.print(
        "[green]Exported a redacted evidence copy; original run status is preserved.[/green]"
    )


def _payload(record: RunRecord) -> dict[str, Any]:
    data = asdict(record)
    data["phase"] = record.phase.value
    return redaction.redact(data)


def _store() -> Journal:
    try:
        return Journal(config.journal_file())
    except (OSError, JournalError) as exc:
        console.print(
            f"[red]Cannot open execution journal:[/red] {redaction.redact_rich_exception(exc)}"
        )
        raise typer.Exit(1) from exc


def list_runs(
    since: str | None = None,
    limit: int = 100,
    as_json: bool = False,
    engagement_id: str | None = None,
) -> None:
    records = _store().list(since=since, limit=limit, engagement_id=engagement_id)
    if as_json:
        console.print_json(json.dumps([_payload(record) for record in records]))
        return
    if not records:
        console.print("[dim]No journaled runs.[/dim]")
        return
    table = Table(title="Execution Audit")
    table.add_column("Run")
    table.add_column("Job")
    table.add_column("Tool")
    table.add_column("Phase")
    table.add_column("Started")
    table.add_column("Status")
    for record in records:
        table.add_row(
            record.run_id[:10],
            redaction.redact_text(record.job_id)[:10],
            record.tool,
            record.phase.value,
            record.started_at[:19],
            record.status,
        )
    console.print(table)


def show_run(run_id: str) -> None:
    record = _store().get(run_id)
    if record is None:
        console.print(f"[red]Run not found:[/red] {redaction.redact_rich_text(run_id)}")
        raise typer.Exit(1)
    console.print_json(json.dumps(_payload(record), indent=2, sort_keys=True))


def export_runs(
    output: Path,
    since: str | None = None,
    limit: int = 10_000,
    engagement_id: str | None = None,
) -> None:
    records = _store().list(since=since, limit=limit, engagement_id=engagement_id)
    document = {
        "audit_schema_version": 1,
        "run_count": len(records),
        "runs": [_payload(record) for record in records],
    }
    try:
        manifests.write_atomic_json(output, document)
    except OSError as exc:
        console.print(f"[red]Could not export audit:[/red] {redaction.redact_rich_exception(exc)}")
        raise typer.Exit(1) from exc
    console.print(f"[green]Exported {len(records)} run(s)[/green] to {output}")
