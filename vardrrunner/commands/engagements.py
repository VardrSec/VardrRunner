import typer
from rich.console import Console
from rich.table import Table

from vardrrunner import api, config, redaction

console = Console()


def list_engagements():
    """List all engagements in your VardrMap."""
    url, key = config.require_auth()
    try:
        client = api.VardrMapClient(url, key)
        engagements = client.engagements()
    except Exception as e:
        console.print(f"[red]Error:[/red] {redaction.redact_rich_exception(e)}")
        raise typer.Exit(1) from e

    if not engagements:
        console.print("[dim]No engagements found.[/dim]")
        return

    table = Table(show_header=True, header_style="bold dim")
    table.add_column("ID", style="dim", no_wrap=True)
    table.add_column("Name", style="bold")
    table.add_column("Platform")
    table.add_column("Findings", justify="right")
    table.add_column("Scans", justify="right")

    for p in engagements:
        table.add_row(
            redaction.redact_text(str(p["id"])),
            redaction.redact_text(str(p["name"])),
            redaction.redact_text(str(p.get("platform") or "—")),
            str(p.get("findings_count", 0)),
            str(p.get("scans_count", 0)),
        )
    console.print(table)


def show_scope(engagement_id: str):
    """Show in-scope and out-of-scope items for an engagement."""
    url, key = config.require_auth()
    try:
        client = api.VardrMapClient(url, key)
        scope = client.scope(engagement_id)
    except Exception as e:
        console.print(f"[red]Error:[/red] {redaction.redact_rich_exception(e)}")
        raise typer.Exit(1) from e

    in_scope = scope.get("in", [])
    out_scope = scope.get("out", [])

    if not in_scope and not out_scope:
        console.print("[dim]No scope items defined.[/dim]")
        return

    if in_scope:
        console.print("[bold green]In scope:[/bold green]")
        for item in in_scope:
            value = redaction.redact_rich_text(str(item.get("value", "")))
            kind = redaction.redact_rich_text(str(item.get("kind", "")))
            console.print(f"  [green]+[/green] {value}  [dim]{kind}[/dim]")

    if out_scope:
        console.print("[bold red]Out of scope:[/bold red]")
        for item in out_scope:
            value = redaction.redact_rich_text(str(item.get("value", "")))
            kind = redaction.redact_rich_text(str(item.get("kind", "")))
            console.print(f"  [red]-[/red] {value}  [dim]{kind}[/dim]")
