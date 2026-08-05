from pathlib import Path

import typer
from rich.console import Console

from vardrrunner import api, config

console = Console()

# Tools whose output the backend's file-import endpoint can ingest directly.
# subfinder/dnsx convert to httpx-format JSONL before uploading (not raw files).
# nmap/naabu use create_services (a structured payload), not the file-import path.
SUPPORTED_TOOLS = ["httpx", "nuclei"]


def import_file(tool: str, engagement_id: str, file: Path):
    """Upload a tool output file directly to VardrMap without running the tool."""
    if tool not in SUPPORTED_TOOLS:
        console.print(
            f"[red]Unsupported tool:[/red] {tool}. Supported: {', '.join(SUPPORTED_TOOLS)}"
        )
        raise typer.Exit(1)

    if not file.exists():
        console.print(f"[red]File not found:[/red] {file}")
        raise typer.Exit(1)

    url, key = config.require_auth()
    try:
        client = api.VardrMapClient(url, key)
        result = client.import_file(engagement_id, tool, str(file))
    except Exception as e:
        console.print(f"[red]Import failed:[/red] {e}")
        raise typer.Exit(1) from e

    record = result.get("import_record", {})
    count = record.get("imported_count", "?")
    console.print(
        f"[green]Imported[/green] {count} {tool} result(s) into engagement [bold]{engagement_id}[/bold]"
    )
