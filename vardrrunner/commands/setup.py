"""Guided first-run setup without weakening credential or service safeguards."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from vardrrunner import config, identity, redaction
from vardrrunner.commands import auth, doctor
from vardrrunner.commands import identity as identity_command
from vardrrunner.commands import service as service_command
from vardrrunner.journal import Journal

console = Console()


def _fail(message: str, exc: Exception | None = None) -> None:
    console.print(f"[red]Setup stopped:[/red] {redaction.redact_rich_text(message)}")
    if exc is None:
        raise typer.Exit(1)
    raise typer.Exit(1) from exc


def _ensure_auth(
    *,
    api_url: str | None,
    api_key: str | None,
    allow_plaintext: bool,
    non_interactive: bool,
) -> None:
    supplied = api_url is not None or api_key is not None
    if supplied and non_interactive and (not api_url or not api_key):
        _fail("--non-interactive requires both --url and --key when either is supplied")

    authenticated = False
    if not supplied:
        try:
            config.require_auth()
            authenticated = True
        except Exception:
            authenticated = False

    if not authenticated:
        if non_interactive and not supplied:
            _fail(
                "no credentials configured; set VARDRMAP_URL and VARDRMAP_API_KEY or "
                "provide --url and --key"
            )
        auth.login_vardrmap(
            api_url=api_url,
            api_key=api_key,
            allow_plaintext=allow_plaintext,
        )

    try:
        config.require_auth()
        source = config.credential_source() or "unknown"
    except Exception as exc:
        _fail(f"authentication is not usable: {redaction.redact_exception(exc)}", exc)
    console.print(f"[green]✓ Authentication configured[/green] · {source}")


def _ensure_identity(name: str | None, non_interactive: bool) -> None:
    try:
        current = identity.load_or_create()
    except identity.IdentityError as exc:
        _fail(f"runner identity is unavailable: {redaction.redact_exception(exc)}", exc)

    chosen = name
    if chosen is None and not non_interactive:
        chosen = typer.prompt("Runner name", default=current.name).strip()
    if chosen is not None and chosen != current.name:
        identity_command.set_name(chosen)
        current = identity.load_or_create()
    console.print(
        "[green]✓ Runner identity ready[/green] · "
        f"{redaction.redact_rich_text(current.name)} · {current.runner_id}"
    )


def _ensure_journal() -> None:
    try:
        Journal(config.journal_file())
    except Exception as exc:
        _fail(f"execution journal is unavailable: {redaction.redact_exception(exc)}", exc)
    console.print(
        f"[green]✓ Execution journal ready[/green] · "
        f"{redaction.redact_rich_text(str(config.journal_file()))}"
    )


def initialize(
    *,
    api_url: str | None = None,
    api_key: str | None = None,
    name: str | None = None,
    production: bool = False,
    install_service: bool = False,
    start_service: bool = True,
    env_file: Path | None = None,
    allow_plaintext: bool = False,
    non_interactive: bool = False,
) -> None:
    """Configure auth, identity, durable state, optional service, and health checks."""
    console.print("\n[bold]VardrRunner guided setup[/bold]")
    _ensure_auth(
        api_url=api_url,
        api_key=api_key,
        allow_plaintext=allow_plaintext,
        non_interactive=non_interactive,
    )
    _ensure_identity(name, non_interactive)
    _ensure_journal()

    should_install = install_service or env_file is not None
    if not non_interactive and not should_install:
        should_install = typer.confirm(
            "Install the native per-user background service?", default=production
        )
    if should_install:
        service_command.install(env_file=env_file, start=start_service, dry_run=False)

    console.print("\n[bold]Final health check[/bold]")
    try:
        doctor.run_doctor(as_json=False, production=production)
    except typer.Exit as exc:
        if exc.exit_code != 0:
            _fail("health checks did not pass; follow the remediation above", exc)

    console.print("\n[bold green]VardrRunner setup complete.[/bold green]")
    if not should_install:
        console.print("Start work with `vardrrunner jobs run` or `vardrrunner daemon start`.")
