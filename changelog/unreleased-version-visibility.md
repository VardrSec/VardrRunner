# Installed version and update notices

Before this change, the installed version only appeared as a side effect of
`update check` ("Up to date. VardrRunner 0.48.0"). There was no `--version`, and `status`
did not show it, although its documentation said it did.

```bash
vardrrunner --version
# vardrrunner 0.47.0
# Update available: 0.47.0 → 0.48.0. Run `pipx upgrade vardrrunner`.

vardrrunner status
# Version
#    WARN  VardrRunner 0.47.0
#          Update available: 0.47.0 → 0.48.0. Run `pipx upgrade vardrrunner`.
```

## Where the notice comes from

- **`--version`** is offline. It reads the 24-hour release cache that `update check` and
  `status` write. With no cache or a stale one, it prints only the version.
- **`status`** runs the cached release check, so it makes at most one PyPI request a day.
  An unreachable registry shows a warning and the rest of `status` runs as before.
- **No other command** contacts the registry, and nothing checks in the background
  (ADR 0012 amendment, ADR 0016).

## The upgrade command

The command is chosen from where the running interpreter lives:

| Install | Command shown |
|---|---|
| pipx (`…/pipx/venvs/vardrrunner`) | `pipx upgrade vardrrunner` |
| uv (`…/uv/tools/vardrrunner`) | `uv tool upgrade vardrrunner` |
| another virtualenv | `python -m pip install --upgrade vardrrunner` |
| unrecognized | `pipx upgrade vardrrunner` or `uv tool upgrade vardrrunner` |

VardrRunner never runs it. `pipx upgrade` keeps packages added with `pipx inject`, such as
the `mcp` extra.
