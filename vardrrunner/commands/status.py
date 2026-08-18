"""
vardrrunner status — show whether the local runner is ready to work.

Checks config, API connectivity, and local tool availability without
crashing on missing config or network errors.
"""

import requests
from rich.console import Console
from rich.table import Table

from vardrrunner import api, config, redaction, runner

console = Console()

_OK = "[green]  OK  [/green]"
_FAIL = "[red]  FAIL[/red]"
_WARN = "[yellow]  WARN[/yellow]"


def _row(table: Table, ok: bool, message: str) -> None:
    table.add_row(_OK if ok else _FAIL, message)


def run_status() -> None:
    # Resolve via the same precedence the rest of the CLI uses: env over file.
    api_url = config.get_api_url()
    api_key = config.get_api_key()
    config_exists = config.CONFIG_FILE.exists()

    console.print()
    console.print("[bold]VardrRunner Status[/bold]")

    # ------------------------------------------------------------------
    # Config
    # ------------------------------------------------------------------
    config_table = Table(show_header=False, box=None, padding=(0, 1))
    _row(config_table, config_exists, "Config file found")
    _row(config_table, bool(api_url), "API URL configured")
    _row(config_table, bool(api_key), "API key configured")
    console.print()
    console.print("[bold]Config[/bold]")
    console.print(config_table)

    if not api_url or not api_key:
        console.print()
        console.print("[dim]Run:[/dim] [bold]vardrrunner login vardrmap[/bold]")
        console.print()
        return

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------
    conn_table = Table(show_header=False, box=None, padding=(0, 1))
    authed = False
    username = None
    engagement_count = None

    try:
        client = api.VardrMapClient(api_url, api_key)
        user = client.whoami()
        username = user.get("username") or user.get("github_id") or "unknown"
        authed = True
        _row(
            conn_table,
            True,
            f"Authenticated as [bold]{redaction.redact_rich_text(str(username))}[/bold]",
        )
    except requests.HTTPError as e:
        status_code = e.response.status_code if e.response is not None else "?"
        _row(conn_table, False, f"Authentication failed (HTTP {status_code})")
    except requests.RequestException as e:
        _row(conn_table, False, f"API unreachable — {redaction.redact_rich_exception(e)}")

    if authed:
        try:
            engagements = client.engagements()
            engagement_count = len(engagements)
            _row(
                conn_table,
                True,
                f"{engagement_count} engagement{'s' if engagement_count != 1 else ''} available",
            )
        except requests.HTTPError as e:
            status_code = e.response.status_code if e.response is not None else "?"
            _row(conn_table, False, f"Could not fetch engagements (HTTP {status_code})")
        except requests.RequestException as e:
            _row(
                conn_table,
                False,
                f"Could not fetch engagements — {redaction.redact_rich_exception(e)}",
            )

    console.print()
    console.print("[bold]Connection[/bold]")
    console.print(conn_table)

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------
    tools_table = Table(show_header=False, box=None, padding=(0, 1))
    # Iterate the allowlist directly so status never drifts from what the runner supports.
    for tool in runner.ALLOWED_TOOLS:
        found = runner.tool_available(tool)
        _row(tools_table, found, f"{tool} {'found' if found else 'not found on PATH'}")

    console.print()
    console.print("[bold]Tools[/bold]")
    console.print(tools_table)

    # ------------------------------------------------------------------
    # Next steps
    # ------------------------------------------------------------------
    if authed:
        console.print()
        console.print("[dim]Next steps:[/dim]")
        console.print("  vardrrunner engagements")
        console.print("  vardrrunner jobs list")
        console.print("  vardrrunner jobs run")

    console.print()
