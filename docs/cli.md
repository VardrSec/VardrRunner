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
Authenticate to a Vardr product. Verifies the key against `GET /me` before saving anything,
then stores it in the **OS keychain** (macOS Keychain / Windows Credential Locker / Linux
Secret Service). The backend URL is kept in `~/.vardrmap/config.json`. On a machine with no
keyring backend, login fails closed unless cleartext storage is explicitly accepted.

```bash
vardrrunner login vardrmap
```

| Option | Purpose |
|--------|---------|
| `--url` | Backend base URL; prompted for if omitted |
| `--key` | The `vmap_` API key; prompted for (with hidden input) if omitted |
| `--allow-plaintext-credentials` | Permit cleartext storage when no OS keychain exists |

**Login fails closed.** With no OS keychain available — or when a keychain write fails —
`login` verifies your key, **saves nothing**, and exits 1 rather than quietly writing
cleartext to `~/.vardrmap/config.json`. It prints three routes: use `VARDRMAP_API_KEY`
(recommended for servers; nothing touches disk), install a keyring backend, or pass
`--allow-plaintext-credentials` to accept it deliberately. See
[ADR 0009](adr/0009-fail-closed-credential-storage.md).

**Prefer the prompt for the key.** Passing `--key` puts a live credential into your shell
history — on PowerShell it persists to `(Get-PSReadlineOption).HistorySavePath`, and on
POSIX shells to `~/.bash_history` or equivalent. Omitting `--key` reads it with echo
disabled, so it never reaches your history.

That is the only thing the prompt protects. **Where the key is then stored does not depend
on how you supplied it:** if an OS keychain is available it goes there; otherwise login
refuses unless `--allow-plaintext-credentials` was supplied. `vardrrunner credentials` and
`doctor` both report which source is in use. On a headless box or a container, where a
keyring backend usually is not present, set
`VARDRMAP_API_KEY` in the environment instead of logging in at all; nothing is written to
disk on that path.

Key resolution order at runtime: **`VARDRMAP_API_KEY` env → keychain → config file**.

## `logout`
Remove the stored API key from the keychain and config file. The backend URL is left in
place (re-authenticate with `login`); warns if `VARDRMAP_API_KEY` is still set.

```bash
vardrrunner logout
```

## `credentials`
Report how this machine is authenticated, without ever displaying the key: source
(`environment` / `keychain` / `config file`), whether it is encrypted at rest, keychain
availability, whether the config file holds cleartext, and file permissions. Exits
non-zero when no credential is configured, so it composes into provisioning scripts.

```bash
vardrrunner credentials
```

Only the OS keychain counts as **encrypted at rest**. `VARDRMAP_API_KEY` is not written
to disk by the runner — a real improvement — but any process running as your user can
read it, so it is reported as unencrypted rather than safe.

## `whoami`
Show the identity tied to the configured API key (`GET /me`). Confirms *which* account a
key belongs to without printing the key itself.

```bash
vardrrunner whoami
```

---

## `identity`

Each installation has a stable UUID independent of hostname and a human-readable label:

```bash
vardrrunner identity show
vardrrunner identity set-name chicago-runner-1
```

The first identity is created at `~/.vardrmap/runner-identity.json` with owner-only
permissions. Corrupt state fails closed; it is never silently replaced with a new UUID.
Set `VARDRUNNER_NAME` for a deployment-time label override without rewriting the file.

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
vardrrunner doctor --production                            # strict unattended profile
```

Checks: credential source (env vs file), backend URL validity (HTTPS), config-file
permissions, API auth, daemon PID health (running / stale), run-dir writability, free disk,
tool versions, and per-pipeline readiness. **Failures** (no creds, bad URL, auth failure,
unwritable run dir, critically low disk, zero tools) set a non-zero exit; missing individual
tools and low-ish disk are **warnings** that don't block.

`--production` additionally treats plaintext credentials as a failure, raises disk
thresholds to 1 GiB minimum / 5 GiB warning, verifies the execution journal and stable
identity, and requires either a live daemon or active native service. JSON output includes
`"profile": "standard" | "production"`.

---

## `heartbeat`
Send a single heartbeat to the backend (hostname, version, OS, tool availability). Useful
to confirm connectivity and that the backend's Bridge sees this machine.

```bash
vardrrunner heartbeat
```

---

## `audit` — local execution evidence

Queue-driven jobs are recorded in `~/.vardrmap/runner-journal.sqlite3`. Audit commands are
local and never contact the backend:

```bash
vardrrunner audit list [--since <iso-timestamp>] [--limit 100] [--json]
vardrrunner audit show <run-id>
vardrrunner audit export --output audit.json [--since <iso-timestamp>] [--limit 10000]
```

`list` shows recent lifecycle outcomes, `show` prints one full sanitized record, and
`export` atomically writes a versioned JSON document suitable for incident review or
retention. Records include target counts, sanitized tool settings, lifecycle timestamps,
failure categories, policy warnings, and artifact SHA-256/size. They exclude raw targets,
credentials, request bodies, and headers.

Completed runs write the same evidence to `manifest.json` beside the artifact. The SQLite
journal remains the recovery source of truth; manifests are portable run evidence.

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
(`POST /jobs/{id}/claim`), resolves targets, executes, and reports lifecycle events.
This is the same execution core the daemon uses.

### How claim outcomes are reported

| Outcome | Behaviour |
|---|---|
| **Stop-work** (`403`) | Prints `STOP-WORK — not running this job.`, emits a `blocked` event, runs nothing. That engagement is suppressed for 60 seconds, then rechecked automatically. |
| **Claim race** (`409`) | Another runner won. Skipped quietly, **not** marked failed — the job is theirs to finish. |
| **Auth** (`401`) | Reported as `auth`. Re-run `vardrrunner login vardrmap`. |
| **Rate limited** (`429`) | Reported as `rate_limited`; the daemon backs off. |
| **Backend down** (`5xx`) | Reported as `backend_unavailable`; the daemon backs off and retries. |
| **Anything else** | Reported as `unknown` and logged. The job is left pending and the worker stays alive. |

### Advisory policy warnings

The backend evaluates authorization, testing window and scope on claim. Findings come back
as warnings and are printed **before any tool runs**, so you see them while you can still
intervene:

```
⚠ Target is not in the recorded scope: a.com not in scope
⚠ Outside the agreed testing window
```

They do **not** block execution — that is deliberate, and staying in scope remains your
responsibility. They are also emitted as a `policy_warning` job event so the backend
Terminal records them. Stop-work is the only policy condition that halts.

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
| `--log-format text|json` | `text` | Human text or redacted JSON Lines |

- The PID file is `~/.vardrrunner.pid`. A double-start guard prevents two daemons from
  running at once, and `daemon status` cleans up a stale PID file.
- `--log-file` writes through a rotating handler — **5 MB per file, 3 backups** — so a
  long-lived VPS daemon can't fill the disk. Every line is prefixed with an ISO 8601
  timestamp, and Rich markup is rendered to plain text rather than written literally.
- Poll failures back off exponentially (5 s → 10 s → 20 s …, capped at 5 min) and reset on
  the next successful poll, so a downed backend isn't hammered.
- The daemon opens the SQLite execution journal before writing its PID or claiming work.
  Journal failure is a startup failure, preventing unaccounted execution.
- Every poll first reconciles interrupted runs. Complete artifacts can resume upload and a
  confirmed upload can resume finalization. An upload with an unknown outcome is never
  duplicated automatically; it is retained as an `upload_failed` audit record.
- Shutdown is cooperative: `stop` removes the PID file; the daemon notices and exits
  cleanly (graceful SIGTERM handling on Unix, ctypes liveness probe on Windows).

JSON log records contain `log_schema_version`, UTC `timestamp`, `level`, `event`, stable
`runner_id`, `pid`, and redacted `message`. Rotation remains 5 MiB × four files total.

---

## `service` — native unattended startup

```bash
vardrrunner service install [--no-start] [--dry-run]
vardrrunner service status
vardrrunner service uninstall
```

The command installs a systemd **user** unit on Linux, LaunchAgent on macOS, or per-user
ONLOGON Scheduled Task on Windows. It runs the foreground daemon with rotating JSON logs;
no separate worker implementation is introduced. `--dry-run` prints paths and manager
commands without changing the host.

Actual installation first verifies local authentication, the execution journal, and stable
identity so a broken configuration does not enter a native supervisor restart loop.

On Linux only, `--env-file <path>` adds a systemd `EnvironmentFile` reference. The file is
never copied or displayed, and no secret is embedded in the unit. macOS and Windows should
use the OS keychain or config-based credential resolution. Windows hosts that must start
before user logon should use their existing enterprise supervisor rather than the per-user
task.

A systemd user unit starts at boot only when user lingering is enabled. The installer does
not change that host policy; it prints the administrator command
`loginctl enable-linger <user>` after installation.

---

## Exit behavior
- Commands requiring auth exit with a clear "Not logged in. Run: `vardrrunner login vardrmap`"
  message when no config is present.
- A missing or failing tool marks the corresponding job **failed** with a reason — the
  runner never silently skips work.
