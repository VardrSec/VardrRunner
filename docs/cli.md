# VardrRunner — CLI Reference

All commands are sub-commands of `vardrrunner`. Run any command with `--help` for its
exact flags. Commands that talk to the backend require a prior `login` (they exit with a
helpful message otherwise).

```
vardrrunner [COMMAND] [SUBCOMMAND] [OPTIONS]
```

Every command that acts on an engagement takes `--engagement <uuid>`. `--program` and
`-p` are accepted as aliases on the same flag, so scripts written before the v0.27.0
rename keep working.

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

## `whoami`
Show the identity tied to the configured API key (`GET /me`). Confirms *which* account a
key belongs to without printing the key itself.

```bash
vardrrunner whoami
```

---

## `engagements`
List every engagement visible to the configured key.

```bash
vardrrunner engagements          # alias of `engagement-list`
```

`vardrrunner programs` still runs as a retired alias; it is hidden from `--help`.

## `scope`
Show the in-scope and out-of-scope items for one engagement — useful before a run to
confirm what the `--scope` target source will expand to.

```bash
vardrrunner scope <engagement-id>
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
Executes the named tool, captures output into a timestamped run directory under
`~/.vardrmap/runs`, and uploads parsed results to the backend.
- `run nmap` — safe-profile service discovery (normalizes URLs to hosts, never uses
  `-A`/`-O`/`-p-`/`--script`/`-T5`) → services API.
- `run dnsx` — DNS resolution; uploads the **resolvable** hosts as recon targets, so a later
  httpx/nuclei pass only probes hosts that exist.
- `run naabu` — fast top-ports scan → open ports to the services API.

### Choosing targets
Every `run` command except `subfinder` takes one target source (`subfinder` always reads
wildcard entries from the engagement's scope):

| Flag | Source |
|------|--------|
| `--scope` | In-scope assets from the engagement |
| `--from-recon` | Live recon items from the backend recon store |
| `--target <value>` | A single inline target |
| `--targets <path>` | A targets `.txt` file, one per line |

With `--from-recon`, `--limit` caps how many recon items are pulled (default 100 for
httpx/nuclei, 500 for nmap/dnsx/naabu) and `--status-code` filters them by HTTP status
(httpx and nuclei only).

### Per-tool options
| Command | Options |
|---------|---------|
| `run nuclei` | `--severity high,critical` · `--templates`/`-t <path-or-tag>` |
| `run nmap` | `--top-ports N` (default 100) · `--timing 0-4` (default 3; 5 is never allowed) |
| `run naabu` | `--top-ports N` (default 100) |

`--yes`/`-y` skips the confirmation prompt on any of them.

### Target cap
A run aborts before executing anything if the resolved target count exceeds
`--max-targets` (default **500**), so a broad scope can't turn into a several-thousand-host
scan by accident. Pass `--max-targets 0` to disable the cap, or a higher number to raise
it. The cap applies to `run` and `pipeline run` alike, and it applies even with `--yes` —
`--yes` means "skip the confirmation prompt", not "ignore safety guards".

```bash
vardrrunner run httpx --engagement <id> --scope --max-targets 2000
vardrrunner run httpx --engagement <id> --scope --max-targets 0     # no cap
```

Every tool run is bounded by a timeout (default 1800 s; set `VARDRRUNNER_TOOL_TIMEOUT`); a
hung tool is killed rather than blocking.

---

## `import` — import an existing output file
```bash
vardrrunner import nuclei --engagement <id> --file <path>
vardrrunner import httpx  --engagement <id> --file <path>
```
Pushes results from a tool output file (JSONL) you already have, without running the
tool. `-f` is shorthand for `--file`. Supported tools: `httpx`, `nuclei` — the two
formats the backend's file-import endpoint accepts. `subfinder`/`dnsx` are excluded
because they convert to httpx-format JSONL before uploading; `nmap`/`naabu` upload via
the services API rather than file import.

`import ffuf` was removed in v0.28.0; it had lingered in `--help` since v0.21.1 despite
always failing.

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
- `--max-targets N` — per-stage target cap (default 500; `0` disables)

Each run prints an 8-hex run ID at start and end. Progress renders as a live table — one
row per stage, with a spinner while running and a final status icon (`✓` done, `✗` failed,
`⊘` no targets, `—` aborted) plus target count, result summary, and elapsed time. When a
stage stops the pipeline, the remaining stages are marked aborted immediately.

The pipeline preflights that every tool in the chain is installed, stops early if a stage
produces no targets (e.g. no subdomains discovered), and applies the same 500-target cap
per stage as the `run` commands.

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

Options for `daemon start`:

| Option | Default | Purpose |
|--------|---------|---------|
| `--detach` / `-d` | off | Run in the background and write the PID file |
| `--poll-interval N` | 5 | Seconds between job polls |
| `--heartbeat-interval N` | 60 | Seconds between heartbeats |
| `--log-file <path>` | none | Append output to a rotating log file |

- The PID file is `~/.vardrrunner.pid`. A double-start guard prevents two daemons from
  running at once, and `daemon status` cleans up a stale PID file.
- `--log-file` writes through a rotating handler — **5 MB per file, 3 backups** — so a
  long-lived VPS daemon can't fill the disk. Every line is prefixed with an ISO 8601
  timestamp, and Rich markup is rendered to plain text rather than written literally.
- Poll failures back off exponentially (5 s → 10 s → 20 s …, capped at 5 min) and reset on
  the next successful poll, so a downed backend isn't hammered.
- Shutdown is cooperative: `stop` removes the PID file; the daemon notices and exits
  cleanly (graceful SIGTERM handling on Unix, ctypes liveness probe on Windows).

---

## Exit behavior
- Commands requiring auth exit with a clear "Not logged in. Run: `vardrrunner login vardrmap`"
  message when no config is present.
- A missing or failing tool marks the corresponding job **failed** with a reason — the
  runner never silently skips work.
