# VardrRunner

**The local automation runner for the VardrSec product family.**

VardrRunner runs your security tooling on *your* machine and syncs the results to a
VardrSec backend (today: [VardrMap](https://github.com/jorge-aquino/VardrMap)) over HTTP.
It is a thin, fast, dependency-light client: it polls the backend for queued scan jobs,
claims them atomically, executes the tool locally, streams live progress back, uploads
results, and heartbeats so the backend always knows which machines are online.

> **Why local?** Recon and scanning tools belong on the operator's box — their bandwidth,
> their IP, their tool versions. The backend orchestrates and stores; the runner does the
> work. The two are fully decoupled and only ever exchange JSON.

---

## Features
- **Job queue worker** — poll, atomically claim, execute, and report scan jobs
- **Daemon mode** — `daemon start` runs a continuous background worker (poll every 5 s,
  heartbeat every 60 s) with detached mode, PID file, and graceful shutdown
- **Tool runners** — `httpx`, `subfinder`, `nuclei`, `nmap`, `dnsx`, `naabu` (more coming),
  each capturing output into a timestamped run directory, every run bounded by a timeout
- **Recon pipelines** — chain tools in one command: `recon` (subfinder → httpx → nuclei),
  `deep` (adds dnsx resolution), `ports` (subfinder → dnsx → naabu), `quick`
- **Importers** — pull existing `nuclei` / `httpx` output files into the backend
- **Real heartbeat** — reports hostname, version, OS, and per-tool availability so the
  backend's Bridge shows live machine status
- **Live job events** — emits `started → targets_resolved → running → uploaded → done/failed`
  so the backend Terminal shows real-time logs
- **Preflight (`doctor`)** — one command validates the whole machine (creds, URL, perms,
  auth, daemon, disk, tools, pipelines) and exits non-zero on actionable failures, for
  scripting unattended/VPS provisioning
- **Safe by default** — missing tools fail the job loudly, targets are normalized before
  use, and the API key is stored locally with restrictive permissions

## Requirements
- Python **3.10+**
- The external tools you intend to run, on your `PATH` (e.g. `httpx`, `subfinder`, `nuclei`, `nmap`, `dnsx`, `naabu`)
- A VardrSec backend URL and an API key (`vmap_…` for VardrMap)

## Install

**From PyPI** (once published) — recommended via [pipx](https://pipx.pypa.io) for an isolated CLI:
```bash
pipx install vardrrunner      # or: pip install vardrrunner
```

**From a GitHub Release** (works today, before PyPI) — grab the wheel from the
[latest release](https://github.com/jorge-aquino/VardrRunner/releases) (each is built in CI
with a CycloneDX SBOM and a build-provenance attestation):
```bash
pipx install ./vardrrunner-<version>-py3-none-any.whl
```

**From source** (development):
```bash
git clone https://github.com/jorge-aquino/VardrRunner.git
cd VardrRunner
python -m venv venv
.\venv\Scripts\Activate.ps1     # Windows  (macOS/Linux: source venv/bin/activate)
pip install -e ".[dev]"
```
All three install the `vardrrunner` command.

> Homebrew / Scoop formulae are planned once there's demand; until then use pipx or the release wheel.

## Quick start
```bash
vardrrunner login vardrmap     # prompts for backend URL + API key; key goes to your OS keychain
vardrrunner status             # show config, version, and which tools are detected
vardrrunner heartbeat          # confirm the backend can see this machine
vardrrunner daemon start       # run the continuous worker (poll jobs + heartbeat)
```

### One-shot usage
```bash
vardrrunner jobs list                          # show the backend queue
vardrrunner jobs run                            # claim + execute all pending jobs once
vardrrunner run subfinder --engagement 12 ...       # run a single tool and upload results
vardrrunner import nuclei --engagement 12 -f out.jsonl
```

See **[docs/cli.md](docs/cli.md)** for the full command reference.

## Configuration

**Desktop / dev:** `vardrrunner login` stores your API key in the **OS keychain** (macOS
Keychain, Windows Credential Locker, Linux Secret Service) — no plaintext key on disk. The
backend URL is kept in `~/.vardrmap/config.json`. Run `vardrrunner logout` to remove it.

**CI / servers / containers:** set credentials via environment variables (no keychain
needed). The key resolves in this order — **`VARDRMAP_API_KEY` env → OS keychain → config
file**:

| Variable | Purpose |
|----------|---------|
| `VARDRMAP_URL` | Backend base URL (must be `https://`, except `localhost`) |
| `VARDRMAP_API_KEY` | Your `vmap_` API key |
| `VARDRRUNNER_TOOL_TIMEOUT` | Per-tool run timeout in seconds (default 1800); a hung tool is killed and the job marked failed |
| `VARDRRUNNER_ALLOW_INSECURE` | Set to `1` to permit a plain-HTTP backend URL (not recommended) |

The runner refuses to send your API key over plain HTTP to a non-local host, so a mistyped
`http://` URL can't leak your key.

## Documentation
- [docs/architecture.md](docs/architecture.md) — how the runner is structured and how it talks to the backend
- [docs/development.md](docs/development.md) — local setup, testing, and contribution workflow
- [docs/cli.md](docs/cli.md) — complete command and flag reference
- [docs/adr/](docs/adr/) — Architecture Decision Records
- [CHANGELOG.md](CHANGELOG.md) — version history

## Development & testing
```bash
pip install -e ".[dev]"   # editable install + dev tools (pytest, ruff, mypy)
ruff check vardrrunner tests           # lint
ruff format --check vardrrunner tests  # formatting
mypy vardrrunner                       # type check
pytest tests              # 384 tests; all subprocess + HTTP calls are mocked
```
CI runs lint, types, bandit security scan, and tests at 95% coverage on Python 3.10–3.12 for every push.
Contributions follow the **Engineering Charter** in [CLAUDE.md](CLAUDE.md): clean code,
tests in the same commit, docs updated, and the suite always green.

## License
[MIT](LICENSE) © 2026 Jorge Aquino.

---
*Part of the VardrSec product family — [VardrMap](https://github.com/jorge-aquino/VardrMap) · VardrRunner · VardrVault.*
