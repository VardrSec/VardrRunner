# Unreleased — rename leftovers removed (breaking)

No VardrMap change is required.

| Before | Now |
|---|---|
| `--program <id>`, `-p <id>` | `--engagement <id>` or `-e <id>` |
| `vardrrunner programs` | `vardrrunner engagements` |
| `vardrrunner login vardrmap` | `vardrrunner login` |
| `vardrrunner update check --force` | `vardrrunner update check` |

The old forms fail with Typer's usage error (exit 2) and run nothing.

## `init` or `login`

- **`init`** is first-time setup: the key, the runner's name, tools and a `doctor` check.
- **`login`** only saves or replaces the key, for example after rotating it. It checks the
  key against VardrMap and doesn't re-run setup. Its URL prompt defaults to the saved
  backend.

Messages follow the same split. When nothing is configured they say `vardrrunner init`; when
a key is rejected or the config file is broken they say `vardrrunner login`.

## Console

`use <engagement-id>` in the interactive console is unchanged: it fills `--engagement`
itself, so nothing typed there used the removed names.
