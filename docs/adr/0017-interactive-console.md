# ADR 0017 — Interactive console

- **Status:** Accepted
- **Date:** 2026-10-24

## Context

An operator working an engagement types many short commands in a row (`heartbeat`,
`jobs list`, `scope`, `jobs run`), each prefixed with `vardrrunner` and most repeating
the same `--engagement <uuid>`. Tools such as msfconsole solve this with a console: typing
the program name alone opens a prompt where commands are typed without it.

ADR 0016 forbids startup services, detached workers and polling loops. A console must not
become a way back to any of them.

## Decision

A bare `vardrrunner` opens an interactive console when stdin and stdout are both
terminals. Without a terminal, such as in a script, pipe or CI job, it keeps the old
behavior (help text, exit code 2) so nothing waits for input that never comes.

- **One command tree.** Each line is split shell-style (backslashes kept for Windows paths)
  and passed to the same Typer app a one-shot invocation uses, with
  `standalone_mode=False`. Commands, flags and `--help` cannot drift between the two.
- **`use <engagement-id>`** validates a UUID and supplies it through Click's `default_map`
  to every parameter named `engagement_id`, both `--engagement` and the positional
  argument of `scope`. A value typed on the line still wins. `back` clears it.
- **Errors never end the session.** Usage errors print Click's message. Unexpected
  exceptions are shown only through `redaction.py`. Ctrl+C cancels the running command
  and is reported as "Interrupted."
- **`mcp` is refused** inside the console, because it serves over the stdin and stdout
  the console reads from.
- **After `update`,** the console checks the installed version from a fresh interpreter. If
  it changed, the console says so and closes, because staying open would keep running the
  old modules. The operator reopens it with `vardrrunner`.
- **Completion is optional.** The `shell` extra adds `prompt_toolkit` for tab completion
  and up-arrow history. Without it, `input()` gives a plain prompt with the same features.
- **History is in memory only.** A line can carry a secret (`login vardrmap --key …`), so
  nothing typed is ever written to disk.
- **The banner is offline.** It shows the version, counts read from the code, the VardrMap
  host (never the key), a cached update notice, a quote and a tip. It makes no network
  request and does not read the keychain. Quotes without a primary source are credited
  "attributed to".

### Relationship to ADR 0016

The console is a foreground loop that blocks on the operator's next line. Nothing runs
between commands, no job is polled or claimed unless the operator types `jobs run`, and
nothing survives `exit`. This is an interactive shell, not a background worker, so ADR 0016
stands unchanged.

## Consequences

- Repetitive sessions are shorter, and the engagement no longer has to be pasted into
  every command.
- Bare `vardrrunner` behaves differently at a terminal than before (console instead of
  help). Scripts are unaffected because they have no terminal.
- One more optional dependency (`prompt_toolkit`) that the core never imports eagerly.
- Inside the console, Click writes usage errors to stderr, as it does for one-shot calls.

## Alternatives considered

- **A `vardrrunner shell` subcommand.** Rejected: an extra word for the most common way
  in, and unlike msfconsole, which opens on its own name.
- **`click-repl`.** Rejected: an extra dependency with its own parsing, and it can't fill
  the engagement through `default_map` or refuse `mcp` without patching it.
- **Persistent history file.** Rejected: it would write secrets typed on the line to disk.
