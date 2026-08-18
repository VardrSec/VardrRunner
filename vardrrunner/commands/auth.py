import os

import typer
from rich.console import Console
from rich.table import Table

from vardrrunner import api, config, credentials, keychain, redaction

console = Console()
app = typer.Typer(help="Authentication commands.")


@app.command("vardrmap")
def login_vardrmap(
    api_url: str | None = typer.Option(None, "--url", help="VardrMap API base URL"),
    api_key: str | None = typer.Option(None, "--key", help="vmap_ API key"),
    allow_plaintext: bool = typer.Option(
        False,
        "--allow-plaintext-credentials",
        help="Permit storing the key in cleartext when no OS keychain exists",
    ),
):
    """Authenticate vardrrunner with your VardrMap instance.

    The key goes to the OS keychain when one is available. When one is not,
    login **refuses** rather than silently writing cleartext to disk — pass
    ``--allow-plaintext-credentials`` to accept that, or use the
    ``VARDRMAP_API_KEY`` environment variable, which writes nothing at all.

    Note that omitting ``--key`` protects your *shell history*; it has no
    bearing on how the key is then stored.
    """
    # A Typer-decorated function called directly receives OptionInfo as its Python default.
    # Only the literal boolean True is an explicit plaintext opt-in.
    allow_plaintext = allow_plaintext is True
    if not api_url:
        api_url = typer.prompt("VardrMap API URL").strip().rstrip("/")
    if not api_key:
        api_key = typer.prompt("API key (vmap_...)", hide_input=True).strip()

    if not api_key.startswith("vmap_"):
        console.print("[red]Error:[/red] API key must start with vmap_")
        raise typer.Exit(1)

    try:
        config.validate_api_url(api_url)
    except config.InvalidApiUrl as e:
        console.print(f"[red]Error:[/red] {redaction.redact_rich_exception(e)}")
        raise typer.Exit(1) from e

    # Verify the key works before saving
    console.print("Verifying credentials…")
    try:
        client = api.VardrMapClient(api_url, api_key)
        user = client.whoami()
    except Exception as e:
        console.print(f"[red]Authentication failed:[/red] {redaction.redact_rich_exception(e)}")
        raise typer.Exit(1) from e

    who = redaction.redact_rich_text(
        str(user.get("username") or user.get("github_id") or "unknown")
    )
    console.print(f"[green]Logged in[/green] as [bold]{who}[/bold]")

    # Prefer the OS keychain; the config file (URL only) makes the key resolvable.
    if keychain.available() and keychain.set_key(api_url, api_key):
        try:
            config.save_url(api_url)
        except Exception as e:
            keychain.delete_key(api_url)
            console.print(
                f"[red]Not saved:[/red] could not persist the backend URL: "
                f"{redaction.redact_rich_exception(e)}"
            )
            raise typer.Exit(1) from e
        console.print("API key stored in your OS keychain.")
        return

    # No keychain. Storing the key means cleartext on disk, so that has to be a
    # decision the operator made on purpose — failing closed is the whole point.
    if not allow_plaintext:
        console.print(
            f"[red]Not saved.[/red] {credentials.plaintext_refusal_message(config.CONFIG_FILE)}"
        )
        raise typer.Exit(1)

    try:
        config.save({"api_url": api_url, "api_key": api_key})
    except Exception as e:
        console.print(
            f"[red]Not saved:[/red] could not write the credential file: "
            f"{redaction.redact_rich_exception(e)}"
        )
        raise typer.Exit(1) from e
    console.print(
        f"[yellow]Stored the key in cleartext at {config.CONFIG_FILE}[/yellow] "
        "as requested. Anyone who can read that file has your key; prefer "
        "VARDRMAP_API_KEY on servers."
    )


def logout():
    """Remove the stored API key (keychain + config file); leave the API URL in place."""
    url = config.get_api_url()
    removed = []
    if url and keychain.delete_key(url):
        removed.append("keychain")
    if config.clear_file_key():
        removed.append("config file")

    if removed:
        console.print(f"[green]Logged out.[/green] Removed API key from: {', '.join(removed)}.")
    else:
        console.print("[dim]No stored API key found.[/dim]")

    if os.environ.get(config.ENV_API_KEY):
        console.print(
            f"[yellow]Note:[/yellow] {config.ENV_API_KEY} is still set in your environment — "
            "unset it to fully log out."
        )
    if url:
        console.print(
            f"API URL [dim]{url}[/dim] left in place. Re-authenticate with "
            "[bold]vardrrunner login vardrmap[/bold]."
        )


def whoami():
    """Show the identity associated with the configured API key."""
    url, key = config.require_auth()
    try:
        client = api.VardrMapClient(url, key)
        user = client.whoami()
    except Exception as e:
        console.print(f"[red]Error:[/red] {redaction.redact_rich_exception(e)}")
        raise typer.Exit(1) from e

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_row("[dim]GitHub ID[/dim]", redaction.redact_text(str(user.get("github_id", "—"))))
    table.add_row("[dim]Username[/dim]", redaction.redact_text(str(user.get("username", "—"))))
    table.add_row("[dim]Email[/dim]", redaction.redact_text(str(user.get("email", "—"))))
    table.add_row("[dim]API URL[/dim]", redaction.redact_url(url))
    console.print(table)
