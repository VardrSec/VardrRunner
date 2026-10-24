"""
vardrrunner status — show whether the local runner is ready to work.

Checks the installed version, config, API connectivity, and local tool
availability without crashing on missing config or network errors.
"""

import requests
from rich.console import Console
from rich.table import Table

from vardrrunner import __version__, api, config, redaction, runner, toolchain, updates

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
    # Version
    # ------------------------------------------------------------------
    # Asking for status is an explicit request, so it may run the cached release check
    # (one registry request a day at most, ADR 0012). It never installs, and an unreachable
    # registry is a warning: release discovery must not fail a health check.
    version_table = Table(show_header=False, box=None, padding=(0, 1))
    try:
        release = updates.check()
    except updates.UpdateCheckError:
        version_table.add_row(
            _WARN,
            f"VardrRunner {__version__} (could not check for releases; "
            "run `vardrrunner update check`)",
        )
    else:
        if release.update_available:
            version_table.add_row(_WARN, f"VardrRunner {__version__}")
            version_table.add_row("", updates.notice(release))
        else:
            _row(version_table, True, f"VardrRunner {__version__} (latest)")
    console.print()
    console.print("[bold]Version[/bold]")
    console.print(version_table)

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
        console.print("[dim]Run:[/dim] [bold]vardrrunner init[/bold]")
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
    for tool, binary in runner.ALLOWED_TOOLS.items():
        st = toolchain.status(tool, binary)
        found = st.source in ("managed", "path") or (st.source == "system" and bool(st.path))
        described = {
            "managed": f"managed {st.installed_version}, verified",
            "tampered": "FAILED VERIFICATION, will not run",
            "path": "found on PATH (unverified)",
        }.get(st.source, "found" if found else "not installed")
        _row(tools_table, found, f"{tool} {described}")

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
