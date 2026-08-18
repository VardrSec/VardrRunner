"""`vardrrunner credentials` — report credential posture without revealing it.

Answers the questions an operator actually has before an unattended run: where
is my key coming from, is it encrypted at rest, and can anyone else on this box
read it? Every value shown is a fact *about* the credential; the credential
itself is never printed.
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from vardrrunner import credentials

console = Console()

_SOURCE_NOTES = {
    "environment": "VARDRMAP_API_KEY — nothing written to disk by the runner",
    "keychain": "OS keychain — encrypted at rest",
    "config file": "cleartext in the config file",
}


def show_credentials() -> None:
    """Print credential source, storage posture and file permissions."""
    s = credentials.inspect()

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_row("[dim]Backend URL[/dim]", s.api_url or "[red]not configured[/red]")

    if s.source:
        table.add_row("[dim]Key source[/dim]", f"{s.source} — {_SOURCE_NOTES.get(s.source, '')}")
    else:
        table.add_row("[dim]Key source[/dim]", "[red]none — run `vardrrunner login vardrmap`[/red]")

    table.add_row(
        "[dim]Encrypted at rest[/dim]",
        "[green]yes[/green]" if s.at_rest_encrypted else "[yellow]no[/yellow]",
    )
    table.add_row(
        "[dim]OS keychain[/dim]",
        "[green]available[/green]" if s.keychain_available else "[yellow]unavailable[/yellow]",
    )
    table.add_row(
        "[dim]Plaintext in config[/dim]",
        "[yellow]yes[/yellow]" if s.plaintext_in_config else "[green]no[/green]",
    )
    table.add_row("[dim]Config file[/dim]", str(s.config_file))
    if s.config_mode:
        table.add_row("[dim]Config permissions[/dim]", s.config_mode)

    console.print(table)

    if s.world_readable:
        console.print(
            f"\n[red]Warning:[/red] {s.config_file} holds a cleartext key and is readable "
            f"by group/other ({s.config_mode}). Run `chmod 600 {s.config_file}`."
        )
    elif s.plaintext_in_config:
        console.print(
            "\n[yellow]Note:[/yellow] the key is stored in cleartext. Prefer "
            "VARDRMAP_API_KEY on servers, or install a keyring backend and re-run login."
        )

    if not s.is_authenticated:
        raise typer.Exit(1)
