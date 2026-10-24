# Unreleased — interactive console

Requires Python 3.10 or newer. No VardrMap change is required.

## Type commands without `vardrrunner`

```text
PS> vardrrunner
 .::::::::::::::::::::::.    VardrRunner 0.50.0
 ::                    ::    A product of VardrSec · https://www.vardrsec.com
 ...
vardrrunner > heartbeat
vardrrunner > use 3f2a9c1e-…
vardrrunner(3f2a9c1e) > scope
vardrrunner(3f2a9c1e) > jobs run
vardrrunner(3f2a9c1e) > exit
```

- **Bare `vardrrunner` at a terminal** opens the console. Every command and flag works as
  it does on the command line. Bare `vardrrunner` in a script or pipe still prints help and
  exits 2.
- **`use <engagement-id>`** fills in `--engagement` (and the ID `scope` takes) for every
  command until `back`. An engagement typed on the line still wins.
- **Console commands:** `help` or `?`, `use`, `back`, `banner`, and `exit`, `quit` or
  Ctrl+D.
- **Errors keep the console open.** Ctrl+C cancels the running command, not the console.
- **`mcp` can't run inside the console.** Run `vardrrunner mcp` from your shell.
- **After `update`,** the console tells you to restart it if a newer version was installed.

## Banner

The VardrSec shield, the version, tool, pipeline and job-type counts, the VardrMap host,
a cached update notice, a quote and a tip. Opening the console makes no network request
and never reads the API key. Quotes without a primary source are credited "attributed to".

## Tab completion (optional)

```text
pipx install --force 'vardrrunner[shell]'
# or, on an existing pipx install:
pipx inject vardrrunner prompt_toolkit
```

This adds completion for commands, subcommands and options, plus up-arrow history. History
is kept in memory only, so a key typed on the line is never written to disk.

See [ADR 0017](../docs/adr/0017-interactive-console.md).
