# VardrRunner — CLI Reference

All commands are sub-commands of `vardrrunner`. Run any command with `--help` for its
exact flags. Commands that talk to the backend require a prior `login` (they exit with a
helpful message otherwise).

```
vardrrunner [COMMAND] [SUBCOMMAND] [OPTIONS]
```

---

## `login`
Authenticate to a Vardr product. Prompts for the backend URL and API key, verifies the key,
then stores it in the **OS keychain** (macOS Keychain / Windows Credential Locker / Linux
Secret Service). The backend URL is kept in `~/.vardrmap/config.json`. On a machine with no
keyring backend, it falls back to the plaintext config file with a warning.

```bash
vardrrunner login vardrmap
```

Key resolution order at runtime: **`VARDRMAP_API_KEY` env → keychain → config file**.

## `logout`
Remove the stored API key from the keychain and config file. The backend URL is left in
place (re-authenticate with `login`); warns if `VARDRMAP_API_KEY` is still set.

```bash
vardrrunner logout
```

---

## `status`
Show local configuration, runner version, and which external tools are detected on `PATH`
(with versions where available). Does not require auth for the local parts. This is the
quick human glance — *"show me where I stand."*

```bash
vardrrunner status
```

---

## `doctor`
Deep preflight before unattended use — *"validate this machine."* Unlike `status`, `doctor`
is built for scripts: it **exits 0 only when the runner is healthy enough to work**, exits
non-zero on any actionable failure, and prints a remediation hint per problem.

```bash
vardrrunner doctor && vardrrunner daemon start --detach   # gate provisioning on health
vardrrunner doctor --json                                  # machine-readable report
```

Checks: credential source (env vs file), backend URL validity (HTTPS), config-file
permissions, API auth, daemon PID health (running / stale), run-dir writability, free disk,
tool versions, and per-pipeline readiness. **Failures** (no creds, bad URL, auth failure,
unwritable run dir, critically low disk, zero tools) set a non-zero exit; missing individual
tools and low-ish disk are **warnings** that don't block.

---

## `heartbeat`
Send a single heartbeat to the backend (hostname, version, OS, tool availability). Useful
to confirm connectivity and that the backend's Bridge sees this machine.

```bash
vardrrunner heartbeat
```

---

## `run` — run a tool locally and upload results
```bash
vardrrunner run httpx     --engagement <id> [options]
vardrrunner run subfinder --engagement <id> [options]
vardrrunner run nuclei    --engagement <id> [options]
vardrrunner run nmap      --engagement <id> [--top-ports N] [--timing 0-4] [options]
vardrrunner run dnsx      --engagement <id> [options]
vardrrunner run naabu     --engagement <id> [--top-ports N] [options]
```
Executes the named tool against the engagement's scope, captures output into a timestamped
run directory under `~/.vardrmap/runs`, and uploads parsed results to the backend.
- `run nmap` — safe-profile service discovery (normalizes URLs to hosts, never uses
  `-A`/`-O`/`-p-`/`--script`/`-T5`) → services API.
- `run dnsx` — DNS resolution; uploads the **resolvable** hosts as recon targets, so a later
  httpx/nuclei pass only probes hosts that exist.
- `run naabu` — fast top-ports scan → open ports to the services API.

Every tool run is bounded by a timeout (default 1800 s; set `VARDRRUNNER_TOOL_TIMEOUT`); a
hung tool is killed rather than blocking.

---

## `import` — import an existing output file
```bash
vardrrunner import nuclei --engagement <id> --file <path>
vardrrunner import httpx  --engagement <id> --file <path>
```
Pushes results from a tool output file (JSONL) you already have, without running the
tool. `-f` is shorthand for `--file`. Supported tools: `httpx`, `nuclei`.

---

## `pipeline` — chain tools into one recon workflow
```bash
vardrrunner pipeline list                              # show available pipelines
vardrrunner pipeline run recon --engagement <id> [options]
```
A pipeline runs an ordered chain of tools. Each stage writes its discovered targets to a
local handoff file; the next stage reads from that file instead of pulling from the backend
recon store. This keeps the pipeline fast and consistent even when the backend is slow.
Built-in pipelines:

| Name | Chain |
|------|-------|
| `recon` | subfinder (enumerate subdomains from wildcard scope) → httpx (probe) → nuclei (scan) |
| `quick` | subfinder → httpx |
| `deep` | subfinder → **dnsx** (keep only resolvable) → httpx → nuclei |
| `ports` | subfinder → dnsx → **naabu** (fast port scan → services) |

Options for `pipeline run`:
- `--severity high,critical` — nuclei severity filter for the scan stage
- `--yes` / `-y` — skip the confirmation prompt
- `--continue-on-error` — keep going if a stage fails (default: stop)
- `--dry-run` — resolve first-stage targets and print the plan without executing any tool
- `--json` — emit a machine-readable JSON result (run ID, per-stage status/targets/elapsed)

The pipeline preflights that every tool in the chain is installed, and stops early if a
stage produces no targets (e.g. no subdomains discovered).

---

## `jobs` — one-shot queue operations
```bash
vardrrunner jobs list     # show pending/running jobs for your account
vardrrunner jobs run      # claim and execute all currently pending jobs, then exit
```
`jobs run` auto-sends a heartbeat first, then for each pending job: claims it
(`POST /jobs/{id}/claim`, skipping on `409`), resolves targets, executes, and reports
lifecycle events. This is the same execution core the daemon uses.

Recognized job types are the recon tools (`httpx`, `subfinder`, `nuclei`, `nmap`,
`dnsx`, `naabu`) plus `vardrgate_api_test`, which runs a VardrGate API authorization
test via the local `vardrgate` binary and uploads the result to the job. See
[ADR 0006](adr/0006-vardrgate-api-test-handler.md).

For `vardrgate_api_test`, an identity credential may reference a secret instead of
embedding it — `value_env` (an environment variable on the runner) or
`value_keychain` (an OS-keychain account) — resolved locally at execution so the
secret never reaches the backend. A missing referenced secret fails the job. See
[ADR 0007](adr/0007-local-secret-resolution.md).

---

## `daemon` — continuous background worker
```bash
vardrrunner daemon start [--detach]   # poll jobs (5 s) + heartbeat (60 s) continuously
vardrrunner daemon stop               # cooperative graceful shutdown (removes PID file)
vardrrunner daemon status             # report whether the daemon is running
```
- `--detach` runs the daemon as a detached background process and writes a PID file.
- A double-start guard prevents two daemons from running at once.
- Shutdown is cooperative: `stop` removes the PID file; the daemon notices and exits
  cleanly (graceful SIGTERM handling on Unix, ctypes liveness probe on Windows).

---

## Exit behavior
- Commands requiring auth exit with a clear "Not logged in. Run: `vardrrunner login vardrmap`"
  message when no config is present.
- A missing or failing tool marks the corresponding job **failed** with a reason — the
  runner never silently skips work.
