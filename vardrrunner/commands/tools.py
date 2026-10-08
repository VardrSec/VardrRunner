"""Install, inspect, verify, and remove the tools VardrRunner executes."""

from __future__ import annotations

import ctypes.util
import os
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from vardrrunner import config, redaction, runner, toolchain

console = Console()

_SOURCE_STYLE = {
    "managed": "[green]managed[/green]",
    "tampered": "[red]FAILED VERIFY[/red]",
    "path": "[yellow]PATH (unverified)[/yellow]",
    "missing": "[dim]missing[/dim]",
    "system": "[dim]system[/dim]",
}


def pcap_available() -> bool:
    """naabu's SYN scans need libpcap (Linux/macOS) or Npcap (Windows)."""
    if os.name == "nt":
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        return (Path(system_root) / "System32" / "Npcap" / "wpcap.dll").exists()
    return ctypes.util.find_library("pcap") is not None


def pcap_hint() -> str:
    if os.name == "nt":
        return "naabu needs Npcap for port scans: install it from https://npcap.com"
    return "naabu needs libpcap: e.g. `sudo apt install libpcap0.8` or `brew install libpcap`"


def install(names: list[str], all_tools: bool, force: bool) -> None:
    if all_tools:
        names = toolchain.manageable_tools()
    if not names:
        console.print("[red]Name the tools to install, or pass --all.[/red]")
        raise typer.Exit(1)

    failed = 0
    console.print(f"Installing into {redaction.redact_rich_text(str(config.tools_dir()))}")
    for name in names:
        try:
            result = toolchain.install(name, force=force)
        except toolchain.ToolchainError as exc:
            failed += 1
            console.print(f"[red]FAIL {name}:[/red] {redaction.redact_rich_exception(exc)}")
            continue
        verb = "already installed" if result.already_installed else "installed and verified"
        console.print(f"[green]OK {name} {result.version}[/green] {verb}")
        if name == "naabu" and not pcap_available():
            console.print(f"  [yellow]WARN[/yellow] {pcap_hint()}")
    if failed:
        raise typer.Exit(1)


def list_tools() -> None:
    console.print(f"Managed tools: {redaction.redact_rich_text(str(config.tools_dir()))}")
    table = Table(box=None, padding=(0, 2))
    table.add_column("tool", no_wrap=True)
    table.add_column("source", no_wrap=True)
    table.add_column("version", no_wrap=True)
    # Paths wrap rather than truncate: a cut-off location is useless for auditing.
    table.add_column("location", overflow="fold")
    table.add_column("detail", overflow="fold")
    for name, binary in runner.ALLOWED_TOOLS.items():
        st = toolchain.status(name, binary)
        version = st.installed_version or (
            f"pinned {st.pinned_version}" if st.pinned_version else ""
        )
        table.add_row(
            name,
            _SOURCE_STYLE.get(st.source, st.source),
            version,
            redaction.redact_rich_text(st.path or ""),
            redaction.redact_rich_text(st.detail),
        )
    console.print(table)


def verify() -> None:
    failed = 0
    checked = 0
    for name, binary in runner.ALLOWED_TOOLS.items():
        st = toolchain.status(name, binary)
        if st.source == "managed":
            checked += 1
            console.print(
                f"[green]OK {name} {st.installed_version}[/green] matches its install receipt"
            )
        elif st.source == "tampered":
            checked += 1
            failed += 1
            console.print(f"[red]FAIL {name}:[/red] {redaction.redact_rich_text(st.detail)}")
    if not checked:
        console.print("No managed tools installed. Run `vardrrunner tools install --all`.")
    if failed:
        raise typer.Exit(1)


def remove(name: str) -> None:
    try:
        removed = toolchain.remove(name)
    except toolchain.ToolchainError as exc:
        console.print(f"[red]FAIL {name}:[/red] {redaction.redact_rich_exception(exc)}")
        raise typer.Exit(1) from exc
    if not removed:
        console.print(f"{name} is not installed by VardrRunner.")
        return
    console.print(f"[green]Removed {name}.[/green]")


def purge(yes: bool) -> None:
    targets = f"{config.tools_dir()} and {config.data_dir()}"
    if not yes and not typer.confirm(f"Delete every managed tool and its data ({targets})?"):
        raise typer.Exit(1)
    try:
        toolchain.purge()
    except OSError as exc:
        console.print(
            f"[red]Could not delete managed tools:[/red] {redaction.redact_rich_exception(exc)}"
        )
        raise typer.Exit(1) from exc
    console.print("[green]All managed tools and tool data removed.[/green]")
