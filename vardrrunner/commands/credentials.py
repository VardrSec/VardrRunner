"""`vardrrunner credentials` — credential posture and approved Gate references.

Answers the questions an operator actually has before an unattended run: where
is my key coming from, is it encrypted at rest, and can anyone else on this box
read it? Every value shown is a fact *about* the credential; the credential
itself is never printed.
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from vardrrunner import config, credential_grants, credentials

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
        table.add_row("[dim]Key source[/dim]", "[red]none — run `vardrrunner init`[/red]")

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


def _reference(env: str | None, keychain: str | None) -> tuple[str, str]:
    if bool(env) == bool(keychain):
        console.print("[red]Name exactly one reference: --env NAME or --keychain ACCOUNT.[/red]")
        raise typer.Exit(2)
    return ("env", str(env)) if env else ("keychain", str(keychain))


def approve(
    engagement_id: str,
    origin: str,
    env: str | None,
    keychain: str | None,
    *,
    issuer: str | None = None,
    expires_in: int | None = None,
) -> None:
    """Allow queued VardrGate cases to use one credential reference (ADR 0023)."""
    source, name = _reference(env, keychain)
    if issuer is not None or expires_in is not None:
        if issuer is None or expires_in is None:
            console.print("[red]An expiring grant requires both --issuer and --expires-in.[/red]")
            raise typer.Exit(2)
        try:
            grant = credential_grants.Store().approve(
                issuer, engagement_id, origin, source, name, expires_in
            )
        except credential_grants.GrantError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(2) from exc
        console.print(
            f"Expiring reference grant approved: {grant['id']}; expires {grant['expires_at']}. Names only; legacy approvals unchanged."
        )
        return
    try:
        entry = config.approve_credential(engagement_id, origin, source, name)
    except config.InvalidApproval as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(2) from e
    console.print(
        f"Approved {entry['source']} reference [bold]{entry['name']}[/bold] for engagement "
        f"{entry['engagement_id']} at {entry['origin']}. Only the name is stored."
    )


def revoke(
    engagement_id: str,
    origin: str,
    env: str | None,
    keychain: str | None,
    *,
    issuer: str | None = None,
) -> None:
    """Withdraw an approval."""
    source, name = _reference(env, keychain)
    if issuer is not None:
        try:
            removed = credential_grants.Store().revoke(issuer, engagement_id, origin, source, name)
        except credential_grants.GrantError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(2) from exc
        console.print(
            "Expiring grant revoked; running tools and provider credentials are unchanged."
            if removed
            else "No active matching expiring grant."
        )
        if not removed:
            raise typer.Exit(1)
        return
    try:
        removed = config.revoke_credential(engagement_id, origin, source, name)
    except config.InvalidApproval as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(2) from e
    if not removed:
        console.print("[yellow]No matching approval.[/yellow]")
        raise typer.Exit(1)
    console.print("Approval removed.")


def list_approvals(*, issuer: str | None = None) -> None:
    """Print every approved reference. Names only; no secret is read."""
    if issuer is not None:
        try:
            normalized = credential_grants.issuer(issuer)
            grants = [g for g in credential_grants.Store().entries() if g["issuer"] == normalized]
        except credential_grants.GrantError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(2) from exc
        table = Table("Grant", "Engagement", "Origin", "Source", "Name", "Expires", "State")
        for grant in grants:
            state = grant["status"]
            if (
                state == "active"
                and credential_grants.timestamp(grant["expires_at"]) <= credential_grants.now()
            ):
                state = "expired"
            table.add_row(
                grant["id"],
                grant["engagement_id"],
                grant["origin"],
                grant["source"],
                grant["name"],
                grant["expires_at"],
                state,
            )
        console.print(table)
        return
    entries = config.credential_approvals()
    if not entries:
        console.print(
            "No approved credential references. VardrGate jobs that reference a credential "
            "will fail until one is approved with `vardrrunner credentials approve`."
        )
        return
    table = Table("Engagement", "Origin", "Source", "Name")
    for e in entries:
        table.add_row(
            str(e.get("engagement_id", "")),
            str(e.get("origin", "")),
            str(e.get("source", "")),
            str(e.get("name", "")),
        )
    console.print(table)
