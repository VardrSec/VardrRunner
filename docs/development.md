# VardrRunner — Development

## Prerequisites
- Python **3.10+**
- `git`
- (Optional, for real runs) the external tools on your `PATH`: `httpx`, `subfinder`,
  `nuclei`, `nmap`, `dnsx`, `naabu`, and `vardrgate` (only for `vardrgate_api_test`
  jobs). They are **not** needed to run the test suite — every subprocess call is mocked.

## Setup
```bash
git clone https://github.com/jorge-aquino/VardrRunner.git
cd VardrRunner
python -m venv venv

# Windows (PowerShell)
.\venv\Scripts\Activate.ps1
# macOS / Linux
source venv/bin/activate

pip install -e ".[dev]"  # editable install + dev tools (pytest, ruff, mypy)
```

## Running the test suite
```bash
pytest tests                                          # quick run
pytest tests --cov=vardrrunner --cov-report=term-missing   # with coverage (as CI runs it)
```
- **222 tests**, all hermetic: no network, no real subprocesses, no real filesystem state
  outside temp dirs.
- The suite must be **green before every commit** (Engineering Charter §3).
- Add tests in the **same commit** as any behavior change.

### What the tests cover
| File | Area |
|------|------|
| `tests/test_config.py` | credential resolution, HTTPS validation, auth |
| `tests/test_credentials.py` | keychain resolution (env > keychain > file), login/logout, fallback |
| `tests/test_configs.py` | typed tool configs + `JobEnvelope` validation |
| `tests/test_handlers.py` | per-tool handlers + the registry |
| `tests/test_jobs.py` | job lifecycle, malformed envelope, claim race, execution core |
| `tests/test_pipelines.py` | pipeline definitions + sequential runner (incl. continue-on-error) |
| `tests/test_run_commands.py` | direct `run` commands validate options like jobs do |
| `tests/test_api.py` | API client headers + retry configuration |
| `tests/test_daemon.py` | daemon start/stop/status, PID file, liveness probe |
| `tests/test_heartbeat.py` | heartbeat payload + posting |
| `tests/test_job_events.py` | lifecycle event emission |
| `tests/test_runner.py` | subprocess execution, timeouts, output capture, failures |
| `tests/test_nmap.py` | nmap target normalization + profile + `run nmap` command |
| `tests/test_status.py` | tool detection + status output |
| `tests/test_doctor.py` | preflight checks, exit codes, and `--json` report |

## Lint, format, and types
CI enforces all three on every push; run them locally before committing:
```bash
ruff check vardrrunner tests           # lint
ruff format --check vardrrunner tests  # formatting
mypy vardrrunner                       # type check
```
Autofix most issues with:
```bash
ruff check --fix vardrrunner tests && ruff format vardrrunner tests
```
Config lives in `pyproject.toml` (`[tool.ruff]`, `[tool.mypy]`).

## Branch & commit workflow
1. Branch off `main` for any non-trivial change.
2. Implement **with tests**; keep the suite green.
3. Update docs and `CHANGELOG.md` in the **same commit** (Charter §2).
4. For a non-trivial design decision, add an ADR in `docs/adr/`.
5. Never add "Co-Authored-By: Claude" to commits.
6. Open a PR; CI must pass before merge.

## Releasing
Releases are **tag-driven** — pushing a `vX.Y.Z` tag runs `release.yml` (build → SBOM →
provenance attestation → GitHub Release, with opt-in PyPI). See
[ADR 0003](adr/0003-distribution-and-release.md).

1. In a PR: bump `__version__` in `vardrrunner/__init__.py` — the **single source of truth**
   (`pyproject.toml` reads it dynamically; the heartbeat reports it to the backend).
2. Roll `Unreleased` into a dated `## [X.Y.Z]` section in `CHANGELOG.md`; add a
   `changelog/vX.Y.Z.md` rollup note.
3. Merge the PR, then tag `main` and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.
4. The release workflow publishes a GitHub Release with the wheel, sdist, and SBOM.
   **PyPI** is opt-in: configure a [trusted publisher](https://docs.pypi.org/trusted-publishers/)
   for this repo's `release.yml` and set the repo variable `PYPI_PUBLISH=true`.

## Configuration during development
The CLI reads/writes `~/.vardrmap/config.json`. To point at a local backend:
```bash
vardrrunner login vardrmap     # enter http://localhost:8000 and a dev API key
```
`http://localhost` is accepted; any other host must be `https://` (the runner refuses to
send the key over plain HTTP). Delete `~/.vardrmap/config.json` to reset auth.

Or skip the file entirely with environment variables (handy for tests/containers):
```bash
export VARDRMAP_URL=http://localhost:8000
export VARDRMAP_API_KEY=vmap_devkey
export VARDRRUNNER_TOOL_TIMEOUT=300        # optional: per-tool run ceiling, seconds
```
Env values take precedence over the config file.
