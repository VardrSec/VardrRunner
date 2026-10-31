"""
vardrrunner — local automation runner for the VardrSec product family.

Runs security tooling on the operator's machine and syncs results to a VardrSec
backend (today: VardrMap) over HTTP. See https://github.com/VardrSec/VardrRunner.
"""

import importlib
import sys
from pathlib import Path

import typer
from rich.console import Console

from vardrrunner import __version__, configs, shell, updates
from vardrrunner import runner as process_runner
from vardrrunner.commands import audit, auth, engagements, identity, imports, jobs, run, tools
from vardrrunner.commands import credentials as credentials_cmd
from vardrrunner.commands import doctor as doctor_cmd
from vardrrunner.commands import heartbeat as heartbeat_cmd
from vardrrunner.commands import pipeline as pipeline_cmd
from vardrrunner.commands import setup as setup_cmd
from vardrrunner.commands import status as status_cmd
from vardrrunner.commands import test_cases as test_cases_cmd
from vardrrunner.commands import updates as updates_cmd

# Characters the CLI's output uses that legacy code pages (Windows cp1252 when
# output is piped or redirected) cannot encode.
_OUTPUT_PROBE = "✓✗→—…·"


def _harden_output_streams() -> None:
    """Never crash because a character can't be encoded on stdout/stderr.

    On Windows, output that goes to a pipe or file uses the legacy code page, so
    printing "✓" raised UnicodeEncodeError and aborted the command mid-way. For
    any stream that can't encode the characters we print, unencodable characters
    are replaced instead. Real consoles and UTF-8 streams are left untouched.
    Runs at import, before Typer renders `--help`.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        encoding = getattr(stream, "encoding", None)
        if reconfigure is None or not encoding:
            continue
        try:
            _OUTPUT_PROBE.encode(encoding)
        except UnicodeEncodeError:
            reconfigure(errors="replace")
        except LookupError:
            continue


_harden_output_streams()

console = Console()

# Shared across every command that resolves targets, so the cap is described
# identically in `run --help` and `pipeline run --help`.
_MAX_TARGETS_HELP = "Abort if resolved targets exceed this count (0 disables the cap)"

app = typer.Typer(
    name="vardrrunner",
    help="Local runner for VardrMap. Runs tools locally, uploads results to your VardrMap instance.",
    # A bare `vardrrunner` opens the console in a terminal and prints help elsewhere;
    # `_startup_cleanup` decides which, so Typer must not answer it first.
    no_args_is_help=False,
)


def _print_version(value: bool) -> None:
    # Offline by design (ADR 0012): only a release an explicit check already cached is named.
    if not value:
        return
    console.print(f"vardrrunner {__version__}")
    status = updates.cached()
    if status is not None and status.update_available:
        console.print(updates.notice(status))
    raise typer.Exit()


def _interactive() -> bool:
    """Only a person at a terminal gets the console: a script or pipe calling a bare
    `vardrrunner` keeps the help text and exit code 2 rather than waiting for input."""
    return sys.stdin.isatty() and sys.stdout.isatty()


@app.callback(invoke_without_command=True)
def _startup_cleanup(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_print_version,
        is_eager=True,
        help="Show the installed version and exit.",
    ),
) -> None:
    """Remove sensitive temp state left by a previously interrupted process."""
    process_runner.cleanup_sensitive_temp_dirs()
    if ctx.invoked_subcommand is not None:
        return
    if _interactive() and not shell.is_running():
        shell.run(app)
        raise typer.Exit()
    console.print(ctx.get_help())
    raise typer.Exit(2)


@app.command("mcp")
def mcp() -> None:
    """Run the MCP server so an AI agent (Claude Code, Claude Desktop) can drive VardrMap.

    Serves over stdio. Requires the optional extra: `pip install vardrrunner[mcp]`.
    """
    try:
        # mcp_server defers its SDK imports to build_server(), so importing it alone succeeds
        # without the extra. Import the SDK here so a missing extra reaches the hint below.
        importlib.import_module("mcp.server")
        from vardrrunner import mcp_server
    except ImportError as exc:  # the mcp package (and its deps) are opt-in
        # Escape the [mcp] bracket so Rich prints it literally instead of as a tag.
        console.print(
            "[red]The MCP server needs the optional 'mcp' extra.[/red]\n"
            "Install it with:  [bold]pip install 'vardrrunner\\[mcp]'[/bold]"
        )
        raise typer.Exit(1) from exc
    mcp_server.run()


@app.command("init")
def initialize(
    api_url: str | None = typer.Option(None, "--url", help="VardrMap API base URL"),
    api_key: str | None = typer.Option(
        None, "--key", help="vmap_ API key (prefer the hidden prompt or environment)"
    ),
    name: str | None = typer.Option(None, "--name", help="Human label for this runner"),
    production: bool = typer.Option(
        False, "--production", help="Require strict credential, disk, and durable-state checks"
    ),
    allow_plaintext: bool = typer.Option(
        False,
        "--allow-plaintext-credentials",
        help="Explicitly permit cleartext key storage when no keychain is available",
    ),
    non_interactive: bool = typer.Option(
        False, "--non-interactive", help="Never prompt; fail if required input is missing"
    ),
    install_tools: bool | None = typer.Option(
        None,
        "--install-tools/--no-install-tools",
        help="Install pinned, verified tools (asked interactively; off when unattended)",
    ),
):
    """Set up a runner for manual use; never install or start background services."""
    setup_cmd.initialize(
        api_url=api_url,
        api_key=api_key,
        name=name,
        production=production,
        allow_plaintext=allow_plaintext,
        non_interactive=non_interactive,
        install_tools=install_tools,
    )


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #

app.command("login")(auth.login)


@app.command()
def status():
    """Show config, API connectivity, and local tool availability."""
    status_cmd.run_status()


@app.command()
def doctor(
    as_json: bool = typer.Option(False, "--json", help="Emit a machine-readable JSON report"),
    production: bool = typer.Option(
        False,
        "--production",
        help="Require durable state, secure credentials, and disk headroom",
    ),
    platform: bool = typer.Option(
        False,
        "--platform",
        help="Require Map database and migration readiness (v1 /ready contract)",
    ),
    offline: bool = typer.Option(
        False,
        "--offline",
        help="Skip release-registry requests; still check the configured backend",
    ),
):
    """Deep preflight before running scans — exits non-zero on actionable failures."""
    doctor_cmd.run_doctor(
        as_json=as_json, production=production, platform=platform, offline=offline
    )


@app.command()
def heartbeat():
    """Send a heartbeat to VardrMap — reports hostname, version, and tool status."""
    heartbeat_cmd.send_heartbeat(quiet=False)


@app.command()
def logout():
    """Remove stored credentials (keychain + config file); keep the API URL."""
    auth.logout()


credentials_app = typer.Typer(
    help="Credential posture, and the credential references VardrGate jobs may use."
)
app.add_typer(credentials_app, name="credentials")

_APPROVAL_ENGAGEMENT = typer.Option(..., "--engagement", "-e", help="Engagement UUID")
_APPROVAL_ORIGIN = typer.Option(
    ..., "--origin", help="Target origin the case contacts, e.g. https://api.example.com"
)
_APPROVAL_ENV = typer.Option(None, "--env", help="Environment variable name (value_env)")
_APPROVAL_KEYCHAIN = typer.Option(None, "--keychain", help="OS keychain account (value_keychain)")


@credentials_app.callback(invoke_without_command=True)
def credentials(ctx: typer.Context):
    """Show where the API key comes from and how exposed it is (never shows the key)."""
    if ctx.invoked_subcommand is None:
        credentials_cmd.show_credentials()


@credentials_app.command("approve")
def credentials_approve(
    engagement_id: str = _APPROVAL_ENGAGEMENT,
    origin: str = _APPROVAL_ORIGIN,
    env: str | None = _APPROVAL_ENV,
    keychain: str | None = _APPROVAL_KEYCHAIN,
):
    """Let VardrGate jobs for one engagement and origin use a credential reference."""
    credentials_cmd.approve(engagement_id, origin, env, keychain)


@credentials_app.command("approvals")
def credentials_approvals():
    """List approved credential references (names only)."""
    credentials_cmd.list_approvals()


@credentials_app.command("revoke")
def credentials_revoke(
    engagement_id: str = _APPROVAL_ENGAGEMENT,
    origin: str = _APPROVAL_ORIGIN,
    env: str | None = _APPROVAL_ENV,
    keychain: str | None = _APPROVAL_KEYCHAIN,
):
    """Withdraw an approved credential reference."""
    credentials_cmd.revoke(engagement_id, origin, env, keychain)


audit_app = typer.Typer(
    help="Inspect and export the sanitized local execution journal.", no_args_is_help=True
)
app.add_typer(audit_app, name="audit")


@audit_app.command("list")
def audit_list(
    since: str | None = typer.Option(None, "--since", help="ISO timestamp lower bound"),
    limit: int = typer.Option(100, "--limit", min=1, max=10_000),
    as_json: bool = typer.Option(False, "--json", help="Emit machine-readable JSON"),
):
    """List recent journaled job runs."""
    audit.list_runs(since=since, limit=limit, as_json=as_json)


@audit_app.command("show")
def audit_show(run_id: str = typer.Argument(..., help="Full journal run ID")):
    """Show one journaled run as sanitized JSON."""
    audit.show_run(run_id)


@audit_app.command("export")
def audit_export(
    output: Path = typer.Option(..., "--output", "-o", help="Destination JSON file"),
    since: str | None = typer.Option(None, "--since", help="ISO timestamp lower bound"),
    limit: int = typer.Option(10_000, "--limit", min=1, max=10_000),
):
    """Atomically export sanitized journal records."""
    audit.export_runs(output=output, since=since, limit=limit)


@app.command()
def whoami():
    """Show the identity tied to the configured API key."""
    auth.whoami()


identity_app = typer.Typer(help="Inspect or label this runner installation.", no_args_is_help=True)
app.add_typer(identity_app, name="identity")


@identity_app.command("show")
def identity_show():
    """Show the stable runner ID, name, and hostname."""
    identity.show()


@identity_app.command("set-name")
def identity_set_name(name: str = typer.Argument(..., help="Human label, up to 128 characters")):
    """Persist a human-readable runner name."""
    identity.set_name(name)


tools_app = typer.Typer(
    help="Install and verify the pinned tools VardrRunner runs (~/.vardrmap/tools).",
    no_args_is_help=True,
)
app.add_typer(tools_app, name="tools")


@tools_app.command("install")
def tools_install(
    names: list[str] = typer.Argument(None, help="Tools to install, e.g. httpx nuclei"),
    all_tools: bool = typer.Option(False, "--all", help="Install every tool VardrRunner pins"),
    force: bool = typer.Option(False, "--force", help="Reinstall even if already verified"),
):
    """Install, update, or repair pinned tools; skip ones already up to date."""
    tools.install(names or [], all_tools=all_tools, force=force)


@tools_app.command("list")
def tools_list():
    """Show every tool, where it comes from, and whether it is verified."""
    tools.list_tools()


@tools_app.command("verify")
def tools_verify():
    """Re-hash managed tools against their install receipt."""
    tools.verify()


@tools_app.command("remove")
def tools_remove(name: str = typer.Argument(..., help="Tool to remove")):
    """Delete one managed tool."""
    tools.remove(name)


@tools_app.command("purge")
def tools_purge(yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation")):
    """Delete every managed tool and managed tool data."""
    tools.purge(yes=yes)


update_app = typer.Typer(help="Update VardrRunner to the newest release, or check for one.")
app.add_typer(update_app, name="update")


@update_app.callback(invoke_without_command=True)
def update(ctx: typer.Context):
    """Install the newest release now (pipx installs; other installers get the command)."""
    # The callback also runs before `update check`; only a bare `update` installs.
    if ctx.invoked_subcommand is None:
        updates_cmd.upgrade()


@update_app.command("check")
def update_check(
    as_json: bool = typer.Option(False, "--json", help="Emit machine-readable JSON"),
):
    """Check PyPI for a newer release without installing it."""
    updates_cmd.check(as_json=as_json)


# --------------------------------------------------------------------------- #
# Engagements
# --------------------------------------------------------------------------- #


@app.command(name="engagements")
def engagement_list():
    """List all engagements in VardrMap."""
    engagements.list_engagements()


@app.command()
def scope(engagement_id: str = typer.Argument(..., help="Engagement UUID")):
    """Show in-scope and out-of-scope items for an engagement."""
    engagements.show_scope(engagement_id)


# --------------------------------------------------------------------------- #
# Import
# --------------------------------------------------------------------------- #

import_app = typer.Typer(help="Import tool output files into VardrMap.", no_args_is_help=True)
app.add_typer(import_app, name="import")


@import_app.command("nuclei")
def import_nuclei(
    engagement_id: str = typer.Option(..., "--engagement", "-e", help="Engagement UUID"),
    file: Path = typer.Option(..., "--file", "-f", help="Path to nuclei JSONL output"),
):
    """Import a nuclei output file."""
    imports.import_file("nuclei", engagement_id, file)


@import_app.command("httpx")
def import_httpx(
    engagement_id: str = typer.Option(..., "--engagement", "-e", help="Engagement UUID"),
    file: Path = typer.Option(..., "--file", "-f", help="Path to httpx JSON/JSONL output"),
):
    """Import an httpx output file."""
    imports.import_file("httpx", engagement_id, file)


# --------------------------------------------------------------------------- #
# Jobs
# --------------------------------------------------------------------------- #

jobs_app = typer.Typer(help="Manage and execute scan job queue.", no_args_is_help=True)
app.add_typer(jobs_app, name="jobs")


@jobs_app.command("list")
def jobs_list():
    """List pending scan jobs."""
    jobs.list_jobs()


@jobs_app.command("run")
def jobs_run(
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompts"),
):
    """Claim and execute all pending scan jobs."""
    jobs.run_jobs(yes=yes)


# --------------------------------------------------------------------------- #
# Run
# --------------------------------------------------------------------------- #

run_app = typer.Typer(
    help="Run a tool locally and upload results to VardrMap.", no_args_is_help=True
)
app.add_typer(run_app, name="run")


@run_app.command("httpx")
def run_httpx(
    engagement_id: str = typer.Option(..., "--engagement", "-e", help="Engagement UUID"),
    scope: bool = typer.Option(False, "--scope", help="Use in-scope assets from VardrMap"),
    from_recon: bool = typer.Option(
        False, "--from-recon", help="Use live recon items from VardrMap"
    ),
    target: str | None = typer.Option(None, "--target", help="Single inline target"),
    targets_file: Path | None = typer.Option(None, "--targets", help="Path to a targets .txt file"),
    limit: int = typer.Option(100, "--limit", help="Max recon items to use (--from-recon only)"),
    status_code: int | None = typer.Option(
        None, "--status-code", help="Filter recon by HTTP status code"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
    max_targets: int = typer.Option(
        run.MAX_TARGETS_DEFAULT, "--max-targets", min=0, help=_MAX_TARGETS_HELP
    ),
):
    """Run httpx locally and upload results to VardrMap."""
    run.run_httpx(
        engagement_id=engagement_id,
        scope=scope,
        from_recon=from_recon,
        target=target,
        targets_file=targets_file,
        limit=limit,
        status_code=status_code,
        yes=yes,
        max_targets=max_targets,
    )


@run_app.command("subfinder")
def run_subfinder(
    engagement_id: str = typer.Option(..., "--engagement", "-e", help="Engagement UUID"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
    max_targets: int = typer.Option(
        run.MAX_TARGETS_DEFAULT, "--max-targets", min=0, help=_MAX_TARGETS_HELP
    ),
):
    """Run subfinder against wildcard scope entries and import discovered hosts."""
    run.run_subfinder(engagement_id=engagement_id, yes=yes, max_targets=max_targets)


@run_app.command("nuclei")
def run_nuclei(
    engagement_id: str = typer.Option(..., "--engagement", "-e", help="Engagement UUID"),
    scope: bool = typer.Option(False, "--scope", help="Use in-scope assets from VardrMap"),
    from_recon: bool = typer.Option(
        False, "--from-recon", help="Use live recon items from VardrMap"
    ),
    target: str | None = typer.Option(None, "--target", help="Single inline target"),
    targets_file: Path | None = typer.Option(None, "--targets", help="Path to a targets .txt file"),
    limit: int = typer.Option(100, "--limit", help="Max recon items to use (--from-recon only)"),
    status_code: int | None = typer.Option(
        None, "--status-code", help="Filter recon by HTTP status code"
    ),
    severity: str | None = typer.Option(
        None, "--severity", help="Comma-separated severities, e.g. high,critical"
    ),
    templates: str | None = typer.Option(
        None, "--templates", "-t", help="Nuclei template path or tag"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
    max_targets: int = typer.Option(
        run.MAX_TARGETS_DEFAULT, "--max-targets", min=0, help=_MAX_TARGETS_HELP
    ),
):
    """Run nuclei locally and upload results to VardrMap."""
    run.run_nuclei(
        engagement_id=engagement_id,
        scope=scope,
        from_recon=from_recon,
        target=target,
        targets_file=targets_file,
        limit=limit,
        status_code=status_code,
        severity=severity,
        templates=templates,
        yes=yes,
        max_targets=max_targets,
    )


@run_app.command("nmap")
def run_nmap(
    engagement_id: str = typer.Option(..., "--engagement", "-e", help="Engagement UUID"),
    scope: bool = typer.Option(False, "--scope", help="Use in-scope assets from VardrMap"),
    from_recon: bool = typer.Option(
        False, "--from-recon", help="Use live recon items from VardrMap"
    ),
    target: str | None = typer.Option(None, "--target", help="Single inline target"),
    targets_file: Path | None = typer.Option(None, "--targets", help="Path to a targets .txt file"),
    limit: int = typer.Option(500, "--limit", help="Max recon items to use (--from-recon only)"),
    top_ports: int = typer.Option(100, "--top-ports", help="Number of most-common ports to scan"),
    timing: int = typer.Option(
        3, "--timing", help="nmap timing template (0-4; 5 is never allowed)"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
    max_targets: int = typer.Option(
        run.MAX_TARGETS_DEFAULT, "--max-targets", min=0, help=_MAX_TARGETS_HELP
    ),
):
    """Run nmap service discovery locally and upload open ports to VardrMap.

    Optional and unsupported: refused unless VARDRRUNNER_ENABLE_NMAP=1 and nmap is
    installed by you. Use `run naabu` for supported port discovery.
    """
    run.run_nmap(
        engagement_id=engagement_id,
        scope=scope,
        from_recon=from_recon,
        target=target,
        targets_file=targets_file,
        limit=limit,
        top_ports=top_ports,
        timing=timing,
        yes=yes,
        max_targets=max_targets,
    )


@run_app.command("dnsx")
def run_dnsx(
    engagement_id: str = typer.Option(..., "--engagement", "-e", help="Engagement UUID"),
    scope: bool = typer.Option(False, "--scope", help="Use in-scope assets from VardrMap"),
    from_recon: bool = typer.Option(
        False, "--from-recon", help="Use live recon items from VardrMap"
    ),
    target: str | None = typer.Option(None, "--target", help="Single inline target"),
    targets_file: Path | None = typer.Option(None, "--targets", help="Path to a targets .txt file"),
    limit: int = typer.Option(500, "--limit", help="Max recon items to use (--from-recon only)"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
    max_targets: int = typer.Option(
        run.MAX_TARGETS_DEFAULT, "--max-targets", min=0, help=_MAX_TARGETS_HELP
    ),
):
    """Resolve hosts with dnsx and upload the resolvable ones as recon targets."""
    run.run_dnsx(
        engagement_id=engagement_id,
        scope=scope,
        from_recon=from_recon,
        target=target,
        targets_file=targets_file,
        limit=limit,
        yes=yes,
        max_targets=max_targets,
    )


@run_app.command("naabu")
def run_naabu(
    engagement_id: str = typer.Option(..., "--engagement", "-e", help="Engagement UUID"),
    scope: bool = typer.Option(False, "--scope", help="Use in-scope assets from VardrMap"),
    from_recon: bool = typer.Option(
        False, "--from-recon", help="Use live recon items from VardrMap"
    ),
    target: str | None = typer.Option(None, "--target", help="Single inline target"),
    targets_file: Path | None = typer.Option(None, "--targets", help="Path to a targets .txt file"),
    limit: int = typer.Option(500, "--limit", help="Max recon items to use (--from-recon only)"),
    top_ports: int = typer.Option(100, "--top-ports", help="Number of most-common ports to scan"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
    max_targets: int = typer.Option(
        run.MAX_TARGETS_DEFAULT, "--max-targets", min=0, help=_MAX_TARGETS_HELP
    ),
):
    """Port-scan hosts with naabu locally and upload open ports to VardrMap."""
    run.run_naabu(
        engagement_id=engagement_id,
        scope=scope,
        from_recon=from_recon,
        target=target,
        targets_file=targets_file,
        limit=limit,
        top_ports=top_ports,
        yes=yes,
        max_targets=max_targets,
    )


@run_app.command("katana")
def run_katana(
    engagement_id: str = typer.Option(..., "--engagement", "-e", help="Engagement UUID"),
    scope: bool = typer.Option(False, "--scope", help="Use in-scope assets from VardrMap"),
    from_recon: bool = typer.Option(
        False, "--from-recon", help="Use live recon items from VardrMap"
    ),
    target: str | None = typer.Option(None, "--target", help="Single inline target URL"),
    targets_file: Path | None = typer.Option(None, "--targets", help="Path to a targets .txt file"),
    limit: int = typer.Option(100, "--limit", help="Max recon items to use (--from-recon only)"),
    depth: int = typer.Option(3, "--depth", help="Maximum crawl depth (1-10)"),
    js_crawl: bool = typer.Option(
        False, "--js-crawl", help="Also parse JavaScript files for endpoints"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
    max_targets: int = typer.Option(
        run.MAX_TARGETS_DEFAULT, "--max-targets", min=0, help=_MAX_TARGETS_HELP
    ),
):
    """Crawl URLs with katana locally and upload discovered endpoints to VardrMap."""
    run.run_katana(
        engagement_id=engagement_id,
        scope=scope,
        from_recon=from_recon,
        target=target,
        targets_file=targets_file,
        limit=limit,
        depth=depth,
        js_crawl=js_crawl,
        yes=yes,
        max_targets=max_targets,
    )


@run_app.command("gau")
def run_gau(
    engagement_id: str = typer.Option(..., "--engagement", "-e", help="Engagement UUID"),
    subs: bool = typer.Option(
        True, "--subs/--no-subs", help="Include subdomains of each wildcard domain"
    ),
    providers: str | None = typer.Option(
        None, "--providers", help="Comma list of wayback,commoncrawl,otx,urlscan (default: all)"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
    max_targets: int = typer.Option(
        run.MAX_TARGETS_DEFAULT, "--max-targets", min=0, help=_MAX_TARGETS_HELP
    ),
):
    """Fetch archived URLs for wildcard scope domains with gau and upload them to VardrMap."""
    run.run_gau(
        engagement_id=engagement_id,
        subs=subs,
        providers=providers,
        yes=yes,
        max_targets=max_targets,
    )


@run_app.command("ffuf")
def run_ffuf(
    engagement_id: str = typer.Option(..., "--engagement", "-e", help="Engagement UUID"),
    scope: bool = typer.Option(False, "--scope", help="Use in-scope assets from VardrMap"),
    from_recon: bool = typer.Option(
        False, "--from-recon", help="Use live recon items from VardrMap"
    ),
    target: str | None = typer.Option(None, "--target", help="Single inline target URL"),
    targets_file: Path | None = typer.Option(None, "--targets", help="Path to a targets .txt file"),
    limit: int = typer.Option(100, "--limit", help="Max recon items to use (--from-recon only)"),
    wordlist: str = typer.Option(
        "common", "--wordlist", help="Wordlist name in ~/.vardrmap/wordlists (not a path)"
    ),
    extensions: str | None = typer.Option(
        None, "--extensions", help="Comma list of extensions to append, e.g. .php,.bak"
    ),
    match_codes: str | None = typer.Option(
        None, "--match-codes", help="Statuses to keep, e.g. 200,301,403 (default: ffuf's own)"
    ),
    rate: int = typer.Option(
        configs.FFUF_DEFAULT_RATE,
        "--rate",
        min=1,
        max=configs.FFUF_MAX_RATE,
        help="Requests per second, per target",
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
    max_targets: int = typer.Option(
        run.MAX_TARGETS_DEFAULT, "--max-targets", min=0, help=_MAX_TARGETS_HELP
    ),
):
    """Fuzz site roots for hidden content with ffuf and upload what it finds to VardrMap."""
    run.run_ffuf(
        engagement_id=engagement_id,
        scope=scope,
        from_recon=from_recon,
        target=target,
        targets_file=targets_file,
        limit=limit,
        wordlist=wordlist,
        extensions=extensions,
        match_codes=match_codes,
        rate=rate,
        yes=yes,
        max_targets=max_targets,
    )


@run_app.command("dalfox")
def run_dalfox(
    engagement_id: str = typer.Option(..., "--engagement", "-e", help="Engagement UUID"),
    scope: bool = typer.Option(False, "--scope", help="Use in-scope assets from VardrMap"),
    from_recon: bool = typer.Option(
        False, "--from-recon", help="Use live recon items from VardrMap"
    ),
    target: str | None = typer.Option(None, "--target", help="Single inline target URL"),
    targets_file: Path | None = typer.Option(None, "--targets", help="Path to a targets .txt file"),
    limit: int = typer.Option(100, "--limit", help="Max recon items to use (--from-recon only)"),
    worker: int = typer.Option(
        10, "--worker", min=1, max=100, help="Concurrent workers per target"
    ),
    delay: int = typer.Option(
        0, "--delay", min=0, max=10_000, help="Milliseconds between requests, per worker"
    ),
    mining: bool = typer.Option(
        True, "--mining/--no-mining", help="Discover extra parameters to test"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
    max_targets: int = typer.Option(
        run.MAX_TARGETS_DEFAULT, "--max-targets", min=0, help=_MAX_TARGETS_HELP
    ),
):
    """Scan URLs for XSS with dalfox and upload the candidates to VardrMap."""
    run.run_dalfox(
        engagement_id=engagement_id,
        scope=scope,
        from_recon=from_recon,
        target=target,
        targets_file=targets_file,
        limit=limit,
        worker=worker,
        delay=delay,
        mining=mining,
        yes=yes,
        max_targets=max_targets,
    )


# --------------------------------------------------------------------------- #
# Pipeline
# --------------------------------------------------------------------------- #

pipeline_app = typer.Typer(help="Run a chain of tools as one recon pipeline.", no_args_is_help=True)
app.add_typer(pipeline_app, name="pipeline")


@pipeline_app.command("list")
def pipeline_list():
    """List the available pipelines and their tool chains."""
    pipeline_cmd.list_pipelines()


@pipeline_app.command("run")
def pipeline_run(
    name: str = typer.Argument(..., help="Pipeline name (see `pipeline list`)"),
    engagement_id: str = typer.Option(..., "--engagement", "-e", help="Engagement UUID"),
    severity: str | None = typer.Option(
        None, "--severity", help="nuclei severity filter for the scan stage"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
    continue_on_error: bool = typer.Option(
        False, "--continue-on-error", help="Keep going if a stage fails"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Resolve first-stage targets and print the plan without executing"
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit a machine-readable JSON result"),
    max_targets: int = typer.Option(
        run.MAX_TARGETS_DEFAULT, "--max-targets", min=0, help=_MAX_TARGETS_HELP
    ),
):
    """Run every stage of a pipeline in order against an engagement."""
    pipeline_cmd.run_pipeline(
        name,
        engagement_id,
        severity=severity,
        yes=yes,
        continue_on_error=continue_on_error,
        dry_run=dry_run,
        as_json=as_json,
        max_targets=max_targets,
    )


cases_app = typer.Typer(
    help="Draft and save reviewed VardrGate authorization cases.", no_args_is_help=True
)
app.add_typer(cases_app, name="test-cases")


@cases_app.command("draft")
def draft_cases(
    engagement_id: str = typer.Argument(..., help="Engagement ID"),
    output: Path = typer.Option(..., "--output", help="New JSON file for operator review"),
    openapi: Path | None = typer.Option(None, "--openapi", help="OpenAPI 3.x JSON file"),
    endpoint_ids: list[str] = typer.Option(
        [], "--endpoint", help="Observed endpoint ID; repeat to select more"
    ),
    base_url: str = typer.Option("", "--base-url", help="Override the API server URL"),
    offset: int = typer.Option(0, "--offset", min=0),
    limit: int = typer.Option(50, "--limit", min=1, max=100),
) -> None:
    """Draft VardrGate cases from an OpenAPI file or observed operations into a review file."""
    test_cases_cmd.draft_cases(
        engagement_id, openapi, endpoint_ids, output, base_url, offset, limit
    )


@cases_app.command("save")
def save_cases(
    engagement_id: str = typer.Argument(..., help="Engagement ID"),
    file: Path = typer.Option(..., "--file", help="Reviewed JSON cases file"),
    reviewed: bool = typer.Option(
        False, "--reviewed", help="Confirm review of targets, identities and access decisions"
    ),
) -> None:
    """Save reviewed cases to VardrMap (requires --reviewed)."""
    test_cases_cmd.save_cases(engagement_id, file, reviewed)
