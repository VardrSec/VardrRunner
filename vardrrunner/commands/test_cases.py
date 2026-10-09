"""Reviewable authorization-case artifacts; credentials remain runner references."""

import json
from pathlib import Path
from typing import Any

import requests
import typer
from rich.console import Console

from vardrrunner import api, config, redaction

console = Console()
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024


def _read(path: Path) -> Any:
    if path.stat().st_size > MAX_DOCUMENT_BYTES:
        raise ValueError("JSON input exceeds 2 MiB")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _safe_draft(value: Any) -> Any:
    # These are editable specs, not audit logs: preserve reference field names
    # and values (the generic log redactor masks the entire credential object).
    if isinstance(value, dict):
        credential = value.get("credential")
        if isinstance(credential, dict) and credential.get("value"):
            raise ValueError("Draft contains a literal credential")
        return {k: _safe_draft(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_safe_draft(v) for v in value]
    return redaction.redact_text(value) if isinstance(value, str) else value


def _fail(exc: Exception) -> None:
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        try:
            detail = exc.response.json().get("detail", "Request failed")
        except (ValueError, AttributeError):
            detail = "Request failed"
        console.print(
            f"[red]Case authoring failed:[/red] {redaction.redact_rich_text(str(detail))}"
        )
    else:
        console.print(f"[red]Case authoring failed:[/red] {redaction.redact_rich_exception(exc)}")
    raise typer.Exit(1) from exc


def draft_cases(
    engagement_id: str,
    openapi: Path | None,
    endpoint_ids: list[str],
    output: Path,
    base_url: str = "",
    offset: int = 0,
    limit: int = 50,
) -> None:
    try:
        if bool(openapi) == bool(endpoint_ids):
            raise ValueError("Choose --openapi or one or more --endpoint options")
        if output.exists():
            raise ValueError("Output already exists; choose a new path to preserve your review")
        body = {"base_url": base_url, "offset": offset, "limit": limit}
        if openapi:
            body["openapi"] = _read(openapi)
        else:
            body["endpoint_ids"] = endpoint_ids
        url, key = config.require_auth()
        result = api.VardrMapClient(url, key).post(
            f"/engagements/{engagement_id}/test-cases/preview", json=body
        )
        cases = _safe_draft(result["drafts"])
        artifact = {
            "cases": cases,
            "total": result["total"],
            "offset": result["offset"],
            "next_offset": result["next_offset"],
        }
        with output.open("x", encoding="utf-8") as stream:
            json.dump(artifact, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        console.print(
            f"Saved {len(cases)} draft(s). Total: {result['total']}; next offset: {result['next_offset']}. No cases stored or queued.",
            markup=False,
        )
    except (OSError, ValueError, KeyError, requests.RequestException) as exc:
        _fail(exc)


def save_cases(engagement_id: str, file: Path, reviewed: bool) -> None:
    try:
        if not reviewed:
            raise ValueError(
                "Review targets, identities, and access decisions, then pass --reviewed"
            )
        artifact = _read(file)
        cases = artifact.get("cases") if isinstance(artifact, dict) else artifact
        if not isinstance(cases, list) or not cases:
            raise ValueError("Provide a non-empty cases array")
        url, key = config.require_auth()
        result = api.VardrMapClient(url, key).post(
            f"/engagements/{engagement_id}/test-cases/reviewed",
            json={"reviewed": True, "cases": cases},
        )
        for case in result["test_cases"]:
            console.print(f"Saved case {redaction.redact_text(str(case['id']))}", markup=False)
        console.print(
            "No jobs queued. Select a saved case in VardrMap to execute it.", markup=False
        )
    except (OSError, ValueError, KeyError, requests.RequestException) as exc:
        _fail(exc)
