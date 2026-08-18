"""
Send a heartbeat to VardrMap with local runner status: hostname, version, OS,
and tool availability. Called explicitly via `vardrrunner heartbeat` and
automatically at the start of `vardrrunner jobs run`.
"""

import logging
import platform
import socket

from rich.console import Console

from vardrrunner import __version__, api, config, redaction, runner

console = Console()


def send_heartbeat(quiet: bool = False) -> None:
    """Post runner status to /runner/heartbeat. Failures are non-fatal."""
    try:
        url, key = config.require_auth()
    except Exception:
        if not quiet:
            console.print("[yellow]Heartbeat skipped — not authenticated.[/yellow]")
        return

    tools: dict = {}
    for name in runner.ALLOWED_TOOLS:
        ok = runner.tool_available(name)
        ver = runner.tool_version(name) if ok else None
        tools[name] = {"ok": ok, "version": ver}

    payload = {
        "hostname": socket.gethostname(),
        "version": __version__,
        "os": f"{platform.system()} {platform.release()}",
        "tools": tools,
    }

    try:
        client = api.VardrMapClient(url, key)
        client.send_heartbeat(payload)
        if not quiet:
            console.print("[green]Heartbeat sent.[/green]")
            for name, info in tools.items():
                status = (
                    f"[green]{info['version'] or '✓'}[/green]"
                    if info["ok"]
                    else "[dim]not found[/dim]"
                )
                console.print(f"  {name}: {status}")
    except Exception as e:
        if not quiet:
            console.print(
                f"[yellow]Heartbeat failed:[/yellow] {redaction.redact_rich_exception(e)}"
            )
        else:
            logging.warning("Heartbeat failed: %s", redaction.redact_exception(e))
