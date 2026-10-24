"""
Interactive console: a bare `vardrrunner` in a terminal opens a prompt where commands are
typed without the program name (`heartbeat`, `jobs list`, `doctor`).

Every line goes through the same Typer app a one-shot invocation uses, so commands, flags
and `--help` cannot drift between the two. The loop only waits for the operator's next
line: nothing runs between commands and nothing outlives `exit` (ADR 0016, ADR 0017).
"""

from __future__ import annotations

import random
import shlex
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from importlib import metadata
from typing import Any
from urllib.parse import urlparse

import typer
from rich.console import Console, Group
from rich.table import Table
from rich.text import Text

from vardrrunner import __version__, config, handlers, pipelines, redaction, runner, updates

console = Console()

WEBSITE = "https://www.vardrsec.com"
PROMPT = "vardrrunner"
# `mcp` serves over stdin/stdout, which the console is reading from.
BLOCKED = frozenset({"mcp"})
EXIT_WORDS = frozenset({"exit", "quit"})
HELP_WORDS = frozenset({"help", "?"})
BUILTINS = ("help", "use", "back", "banner", "exit", "quit")
# Below this width the shield and the text beside it would wrap, so only the text shows.
SHIELD_MIN_WIDTH = 84

SHIELD = (
    " .::::::::::::::::::::::.",
    " ::                    ::",
    " ::         /\\         ::",
    " ::        /  \\        ::",
    " ::       / /\\ \\       ::",
    " ::      / /__\\ \\      ::",
    " ::     /________\\     ::",
    " ::   \\            /   ::",
    "  ::    \\        /    ::",
    "   ::     \\    /     ::",
    "    ::      \\/      ::",
    "     ::     /\\     ::",
    "      ::  /    \\  ::",
    "        o'::::::'o",
    "           '::'",
)
# Rows 2-6 hold the triangle; the swords cross below it.
_EMBLEM_ROWS = range(2, 7)


@dataclass(frozen=True)
class Quote:
    text: str
    author: str
    # False when no primary source was found: shown as "attributed to", never as fact.
    sourced: bool

    def credit(self) -> str:
        return f"— {self.author}" if self.sourced else f"— attributed to {self.author}"


QUOTES = (
    Quote(
        "There are only two forces in the world, the sword and the spirit. "
        "In the long run the sword will always be conquered by the spirit.",
        "Napoleon Bonaparte",
        True,
    ),
    Quote("In war, the moral is to the physical as three is to one.", "Napoleon Bonaparte", True),
    Quote(
        "Never do what the enemy wishes you to do, for this reason alone, that he desires it.",
        "Napoleon Bonaparte",
        True,
    ),
    Quote("The first qualification in a general is a cool head.", "Napoleon Bonaparte", True),
    Quote("Victory belongs to the most persevering.", "Napoleon Bonaparte", False),
    Quote(
        "A good plan violently executed now is better than a perfect plan executed next week.",
        "George S. Patton",
        True,
    ),
    Quote(
        "Never tell people how to do things. Tell them what to do "
        "and they will surprise you with their ingenuity.",
        "George S. Patton",
        True,
    ),
    Quote(
        "Untutored courage is useless in the face of educated bullets.", "George S. Patton", True
    ),
    Quote("Success is how high you bounce when you hit bottom.", "George S. Patton", False),
    Quote(
        "Accept the challenges so that you can feel the exhilaration of victory.",
        "George S. Patton",
        False,
    ),
    Quote(
        "In a man-to-man fight, the winner is he who has one more round in his magazine.",
        "Erwin Rommel",
        True,
    ),
    Quote(
        "The best form of welfare for the troops is first-class training.", "Erwin Rommel", False
    ),
    Quote("Sweat saves blood, blood saves lives, and brains save both.", "Erwin Rommel", False),
    Quote(
        "Be an example to your men, in your duty and in private life. Never spare yourself.",
        "Erwin Rommel",
        False,
    ),
    Quote("Don't fight a battle if you don't gain anything by winning.", "Erwin Rommel", False),
    Quote("Klotzen, nicht kleckern! (Strike concentrated, don't scatter.)", "Heinz Guderian", True),
    Quote("When the situation is obscure, attack.", "Heinz Guderian", False),
    Quote("New weapons require new tactics.", "Heinz Guderian", False),
    Quote(
        "There are no desperate situations, there are only desperate people.",
        "Heinz Guderian",
        False,
    ),
    Quote("The engine of the Panzer is a weapon just as the main gun.", "Heinz Guderian", False),
)

TIPS = (
    "`use <engagement-id>` fills in --engagement for every command until `back`.",
    "`jobs run` claims and runs the pending jobs once, then returns to this prompt.",
    "`doctor` checks credentials, disk, identity, journal and tools before a run.",
    "`status` shows the installed version and names an available upgrade.",
    "`<command> --help` works here exactly as it does on the command line.",
    "`pipeline list` shows each pipeline's stages before you run one.",
)

# The exit status a command interrupted by Ctrl+C returns (128 + SIGINT).
_INTERRUPTED = 130
_running = False


def is_running() -> bool:
    """True while the console is open, so a bare invocation inside it cannot nest another."""
    return _running


# --------------------------------------------------------------------------- #
# Banner
# --------------------------------------------------------------------------- #


def _shield() -> Text:
    text = Text()
    for row, line in enumerate(SHIELD):
        for char in line:
            if char in "/\\_":
                style = "bold white" if row in _EMBLEM_ROWS else "grey70"
            elif char == "o":
                style = "grey70"
            else:
                style = "steel_blue1"
            text.append(char, style=style)
        text.append("\n")
    text.rstrip()
    return text


def _author() -> str | None:
    try:
        authors = metadata.metadata("vardrrunner").get_all("Author") or []
    except metadata.PackageNotFoundError:
        return None
    return authors[0] if authors else None


def _vardrmap_line() -> str:
    url = config.get_api_url()
    host = urlparse(url).hostname if url else None
    if not host:
        return "Not logged in. Run `login vardrmap`."
    return f"VardrMap: {host}"


def _info() -> Text:
    lines = Text()
    lines.append(f"VardrRunner {__version__}\n", style="bold")
    lines.append(f"A product of VardrSec · {WEBSITE}\n")
    author = _author()
    if author:
        lines.append(f"Author: {author}\n")
    lines.append("\n")
    lines.append(
        f"{len(runner.ALLOWED_TOOLS)} tools · {len(pipelines.PIPELINES)} pipelines · "
        f"{len(handlers.REGISTRY)} job types\n",
        style="dim",
    )
    lines.append(_vardrmap_line(), style="dim")
    # Cached only: opening the console never touches the network (ADR 0012).
    status = updates.cached()
    if status is not None and status.update_available:
        lines.append("\n")
        lines.append_text(Text.from_markup(updates.notice(status)))
    return lines


def banner(choose: Callable[[Sequence[Any]], Any] = random.choice) -> Group:
    """The shield, product information, a quote and a tip."""
    info = _info()
    if console.width >= SHIELD_MIN_WIDTH:
        top: Any = Table.grid(padding=(0, 4))
        top.add_row(_shield(), info)
    else:
        top = info
    quote: Quote = choose(QUOTES)
    quote_text = Text(f'"{quote.text}"', style="italic")
    quote_text.append(f"\n  {quote.credit()}", style="dim")
    footer = Text()
    footer.append("Tip: ", style="bold")
    footer.append(choose(TIPS))
    footer.append("\nType `help` for commands, `exit` to leave.", style="dim")
    return Group(Text(), top, Text(), quote_text, Text(), footer, Text())


# --------------------------------------------------------------------------- #
# Lines and commands
# --------------------------------------------------------------------------- #


def split(line: str) -> list[str]:
    """Split a line like a shell would, but keep backslashes and `#`.

    `C:\\scans\\out.jsonl` is a Windows path, not a run of escapes, and `#` appears in URLs.
    """
    lexer = shlex.shlex(line, posix=True)
    lexer.whitespace_split = True
    lexer.escape = ""
    lexer.commenters = ""
    return list(lexer)


def engagement_defaults(command: Any, engagement: str) -> dict[str, Any]:
    """A Click `default_map` that supplies `engagement` to every command taking one.

    Defaults rather than rewritten argv: a value typed on the line still wins, and the
    positional engagement of `scope` is filled the same way as `--engagement`.
    """
    defaults: dict[str, Any] = {}
    for name, sub in getattr(command, "commands", {}).items():
        if hasattr(sub, "commands"):
            nested = engagement_defaults(sub, engagement)
            if nested:
                defaults[name] = nested
        elif any(param.name == "engagement_id" for param in sub.params):
            defaults[name] = {"engagement_id": engagement}
    return defaults


def completion_tree(command: Any) -> dict[str, Any]:
    """Command names, subcommands and long options, in prompt_toolkit's nested-dict form."""
    tree: dict[str, Any] = {}
    for name, sub in getattr(command, "commands", {}).items():
        if getattr(sub, "hidden", False) or name in BLOCKED:
            continue
        if hasattr(sub, "commands"):
            tree[name] = completion_tree(sub)
        else:
            options = {opt for param in sub.params for opt in param.opts if opt.startswith("--")}
            tree[name] = options or None
    return tree


@dataclass
class Session:
    """One open console: the Click command built from the app, and the chosen engagement."""

    command: Any
    engagement: str | None = None

    def prompt(self) -> str:
        if self.engagement:
            return f"{PROMPT}({self.engagement[:8]}) > "
        return f"{PROMPT} > "

    def handle(self, line: str) -> bool:
        """Run one line. Returns False when the operator asked to leave."""
        try:
            args = split(line)
        except ValueError as exc:
            console.print(f"[red]Could not read that line:[/red] {exc}")
            return True
        if args and args[0] == PROMPT:
            args = args[1:]
        if not args:
            return True
        word = args[0].lower()
        if word in EXIT_WORDS:
            return False
        if word in HELP_WORDS:
            self._help()
        elif word == "use":
            self._use(args[1:])
        elif word == "back":
            self.engagement = None
        elif word == "banner":
            console.print(banner())
        elif word in BLOCKED:
            console.print(
                f"[yellow]`{word}` can't run inside the console.[/yellow] "
                f"Run `vardrrunner {word}` from your shell."
            )
        else:
            self._invoke(args)
            if args[0] == "update" and len(args) == 1 and self._upgraded():
                return False
        return True

    def _help(self) -> None:
        table = Table.grid(padding=(0, 2))
        table.add_row("use <engagement-id>", "Fill in --engagement for every command")
        table.add_row("back", "Clear the engagement")
        table.add_row("banner", "Show the banner again")
        table.add_row("exit, quit", "Leave the console (Ctrl+D also works)")
        console.print()
        console.print("[bold]Console commands[/bold]")
        console.print(table)
        self._invoke(["--help"])

    def _use(self, args: list[str]) -> None:
        if len(args) != 1:
            console.print("Usage: use <engagement-id>")
            return
        try:
            self.engagement = str(uuid.UUID(args[0]))
        except ValueError:
            console.print(f"[red]Not an engagement ID:[/red] {redaction.redact_rich_text(args[0])}")

    def _invoke(self, args: list[str]) -> None:
        defaults = engagement_defaults(self.command, self.engagement) if self.engagement else None
        try:
            code = self.command.main(
                args=args, prog_name=PROMPT, standalone_mode=False, default_map=defaults
            )
        # With standalone_mode off, an Exit comes back as a return code, and Ctrl+C as
        # Abort (Click) or a return of 130 (Typer 0.26+), so neither is caught here.
        except typer.Abort:
            console.print("[yellow]Aborted.[/yellow]")
        except SystemExit:
            pass
        except Exception as exc:
            # Typer 0.26 vendors Click, so `click.ClickException` is not the class raised
            # here. Usage errors and missing-argument help carry their own `show()`.
            show = getattr(exc, "show", None)
            if callable(show):
                show()
            else:
                console.print(f"[red]Error:[/red] {redaction.redact_rich_exception(exc)}")
        else:
            # Typer turns Ctrl+C inside a command into a silent return of 130.
            if code == _INTERRUPTED:
                console.print("[yellow]Interrupted.[/yellow]")

    def _upgraded(self) -> bool:
        """True when `update` installed a different version, so the console closes: this
        process still holds the old modules, and staying open would run them."""
        installed = updates.installed_version()
        if not installed or installed == __version__:
            return False
        console.print(
            f"[green]VardrRunner {installed} is installed.[/green] Closing the console; "
            "run `vardrrunner` to reopen it."
        )
        return True


def _reader(session: Session) -> tuple[Callable[[str], str], bool]:
    """The line reader, and whether it completes commands."""
    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.completion import NestedCompleter
        from prompt_toolkit.history import InMemoryHistory
    except ImportError:
        return input, False
    tree = completion_tree(session.command)
    tree.update(dict.fromkeys(BUILTINS))
    # In memory only: a line can carry a secret (`login vardrmap --key ...`), and a history
    # file would write it to disk.
    prompt_session: Any = PromptSession(
        history=InMemoryHistory(), completer=NestedCompleter.from_nested_dict(tree)
    )
    return prompt_session.prompt, True


def run(app: typer.Typer) -> None:
    """Show the banner and read commands until the operator leaves."""
    global _running
    session = Session(typer.main.get_command(app))
    read, completes = _reader(session)
    console.print(banner())
    if not completes:
        console.print(
            "[dim]Install `vardrrunner\\[shell]` for tab completion and command history.[/dim]\n"
        )
    _running = True
    try:
        while True:
            try:
                line = read(session.prompt())
            except KeyboardInterrupt:
                continue
            except EOFError:
                console.print()
                break
            if not session.handle(line):
                break
    finally:
        _running = False
