# VardrRunner — Claude Instructions

Local automation runner for VardrSec. Python CLI (Typer + Rich) that runs security tooling locally and syncs results to VardrMap **over HTTP only**. Polls `GET /jobs/pending`, claims atomically (`POST /jobs/{id}/claim`), executes locally, streams lifecycle events back, uploads results, heartbeats. Zero code coupling to the backend — JSON over wire only. Extracted from VardrMap monorepo 2026-06-14 (see `docs/adr/0001-extract-vardrrunner-from-vardrmap.md`).

## Where things live
- `vardrrunner/` — Python package
  - `cli.py` — Typer app; wires every sub-command
  - `api.py` — thin HTTP client (`requests.Session`); **only** thing that talks to backend
  - `config.py` — resolves credentials (env > keychain > `~/.vardrmap/config.json`); enforces HTTPS
  - `keychain.py` — OS keychain wrapper (`keyring`); degrades gracefully
  - `configs.py` — typed, validated tool configs + `JobEnvelope`; bad payload → `ConfigError`
  - `targets.py` — target resolution (scope/recon/inline/file)
  - `handlers.py` — one `ToolHandler` per job type + `REGISTRY`; add new tools here (see ADR 0002)
  - `pipelines.py` — named recon pipelines (ordered `Stage(tool, source)` chains)
  - `runner.py` — subprocess execution (timeouts, allowlist), output capture, run directory management
  - `commands/` — one module per group: `auth`, `daemon`, `doctor`, `heartbeat`, `imports`, `jobs`, `pipeline`, `engagements`, `run`, `status`
- `tests/` — pytest suite (421 tests, 95% coverage); all subprocess and HTTP calls mocked — no network or real tool calls
- `docs/` — architecture, development setup, CLI reference, ADRs
- `changelog/` — per-version notes; `CHANGELOG.md` at root is the index
- `.github/workflows/` — CI (lint + tests on every push)
- `scratch/` — gitignored; throwaway experiments only

## Hard rules
- No "Co-Authored-By: Claude" in commits
- Run full test suite + linter before every commit
- Every behavior-changing change updates docs **and** `CHANGELOG.md` in the same commit
- All backend communication through `api.py` — no scattered HTTP calls
- Never log, print, or commit the API key; it lives in the OS keychain
- Never build shell strings from unsanitized server data — always pass argv lists

## Security
- API key: OS keychain by default (env `VARDRMAP_API_KEY` > keychain > plaintext config fallback). Never echo it.
- Backend URL must be HTTPS (except localhost); `config.validate_api_url` enforces this on login and every authenticated call
- Treat all backend data as untrusted: validate job payloads, normalize targets before passing to subprocess
- Never use `shell=True` with interpolated server data
- Every tool run bounded by a timeout; missing/failed/timed-out tool → job marked **failed** with reason — never silent skip, never hang

## Documentation rules
Behavior-changing = adds, removes, or modifies a command, flag, config key, backend endpoint called, or operator-visible behavior.

- New/changed command/flag → `docs/cli.md`
- New module, data flow, or backend interaction → `docs/architecture.md`
- New setup step, env var, or dependency → `docs/development.md`
- Non-trivial design decision → ADR in `docs/adr/`
- Any feature/fix/behavior change → `CHANGELOG.md` + `changelog/vX.Y.Z.md`

Docs-only, test-only, pure-refactor commits may note "No user-facing docs change needed."

## Verification
```
ruff check vardrrunner tests
ruff format --check vardrrunner tests
mypy vardrrunner
pytest tests --cov=vardrrunner --cov-fail-under=95
```
Autofix: `ruff check --fix vardrrunner tests && ruff format vardrrunner tests`

## Running locally
```
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -e ".[dev]"
vardrrunner login vardrmap
vardrrunner heartbeat
vardrrunner daemon start
```

## Commands
- `login vardrmap` — authenticate; store key in OS keychain
- `logout` — remove credentials, keep URL
- `run httpx|subfinder|nuclei|nmap` — run tool locally, upload results
- `pipeline list|run <name>` — chain tools (subfinder → httpx → nuclei)
- `import nuclei|httpx` — import existing output file
- `jobs list|run` — inspect and execute backend job queue (one-shot)
- `daemon start|stop|status` — long-running background worker (poll + heartbeat)
- `heartbeat` — send single heartbeat
- `status` — local config, version, tool availability
- `doctor` — deep preflight for unattended use; exits non-zero on failures (`--json`)
