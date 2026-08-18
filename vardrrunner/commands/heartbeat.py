"""
Send a heartbeat to VardrMap with local runner status: hostname, version, OS,
and tool availability. Called explicitly via `vardrrunner heartbeat` and
automatically at the start of `vardrrunner jobs run`.
"""

import logging
import platform
import socket

from rich.console import Console

from vardrrunner import __version__, api, compatibility, config, identity, redaction, runner

console = Console()


def send_heartbeat(quiet: bool = False) -> compatibility.CompatibilityReport | None:
    """Post runner status and return optional backend compatibility guidance.

    Transport and authentication failures remain non-fatal and return ``None``.
    A caller that claims queue work must treat a ``BLOCK`` report as a hard gate.
    """
    try:
        url, key = config.require_auth()
    except Exception:
        if not quiet:
            console.print("[yellow]Heartbeat skipped — not authenticated.[/yellow]")
        return None

    tools: dict = {}
    for name in runner.ALLOWED_TOOLS:
        ok = runner.tool_available(name)
        ver = runner.tool_version(name) if ok else None
        tools[name] = {"ok": ok, "version": ver}

    try:
        runner_identity = identity.load_or_create()
    except identity.IdentityError as e:
        if not quiet:
            console.print(
                f"[yellow]Heartbeat skipped — identity unavailable:[/yellow] "
                f"{redaction.redact_rich_exception(e)}"
            )
        else:
            logging.warning("Heartbeat identity unavailable: %s", redaction.redact_exception(e))
        return None

    payload = {
        "hostname": socket.gethostname(),
        "runner_id": runner_identity.runner_id,
        "name": runner_identity.name,
        "version": __version__,
        "os": f"{platform.system()} {platform.release()}",
        "tools": tools,
        "compatibility": compatibility.advertisement(),
    }

    try:
        client = api.VardrMapClient(url, key)
        response = client.send_heartbeat(payload)
        report = compatibility.evaluate(response)
        if not quiet:
            console.print("[green]Heartbeat sent.[/green]")
            for name, info in tools.items():
                status = (
                    f"[green]{info['version'] or '✓'}[/green]"
                    if info["ok"]
                    else "[dim]not found[/dim]"
                )
                console.print(f"  {name}: {status}")
        if report.level is compatibility.CompatibilityLevel.WARN:
            message = "; ".join(report.messages)
            if quiet:
                logging.warning("Backend compatibility warning: %s", message)
            else:
                console.print(
                    f"[yellow]Compatibility warning:[/yellow] {redaction.redact_rich_text(message)}"
                )
        elif report.level is compatibility.CompatibilityLevel.BLOCK:
            message = "; ".join(report.messages)
            if quiet:
                logging.error("Backend compatibility block: %s", message)
            else:
                console.print(
                    f"[red]Backend compatibility block:[/red] {redaction.redact_rich_text(message)}"
                )
        return report
    except Exception as e:
        if not quiet:
            console.print(
                f"[yellow]Heartbeat failed:[/yellow] {redaction.redact_rich_exception(e)}"
            )
        else:
            logging.warning("Heartbeat failed: %s", redaction.redact_exception(e))
        return None
