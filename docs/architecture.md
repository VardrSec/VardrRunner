# VardrRunner — Architecture

## Role in the VardrSec system
VardrRunner is a **durable local execution client**. A VardrSec backend (VardrMap today) owns the
queue, the database, and the UI. The runner owns *execution*: it runs tools on the
operator's machine and reports back. The two are fully decoupled and communicate only via
JSON over HTTP — there is no shared code, no shared database, and no import dependency in
either direction.

```
┌──────────────────────────┐        HTTP (JSON)        ┌──────────────────────────┐
│         VardrMap         │ <──── poll / claim ─────  │       VardrRunner        │
│   (backend + DB + UI)    │ <──── events / upload ──  │  (this repo, local CLI)  │
│                          │ <──── heartbeat ────────  │  runs httpx/subfinder/   │
│                          │                           │  nuclei/nmap/dnsx/naabu/ │
│                          │  ──── jobs / scope ─────> │  vardrgate locally       │
└──────────────────────────┘                           └──────────────────────────┘
```

The runner never listens — every exchange is outbound. The full set of endpoints it
calls, all through `api.py`:

| Endpoint | Used for |
|----------|----------|
| `GET /me` | `whoami`, and the auth check in `doctor` |
| `GET /engagements` · `GET /engagements/{id}` | engagement list and scope lookup |
| `GET /engagements/{id}/recon` | `--from-recon` target resolution (paginated, 500/page) |
| `POST /engagements/{id}/imports` | httpx/nuclei/subfinder/dnsx result upload |
| `POST /engagements/{id}/services` | nmap/naabu open-port upload |
| `GET /jobs/pending` | poll the queue |
| `POST /jobs/{id}/claim` | atomic claim |
| `PATCH /jobs/{id}` | mark a job `done` / `failed` |
| `POST /jobs/{id}/events` | lifecycle events for the backend Terminal |
| `POST /jobs/{id}/upload` | `vardrgate_api_test` result attached to the job |
| `POST /runner/heartbeat` | machine status for the backend Bridge |

Requests to `/programs/*` are no longer sent; VardrMap's legacy path middleware still
accepts them, but the runner has called `/engagements/*` since v0.27.0 and therefore
requires VardrMap ≥ v0.22.0.

## Package layout
| Path | Responsibility |
|------|----------------|
| `vardrrunner/cli.py` | Typer application; defines command groups and wires them together. Thin — delegates to `commands/`. |
| `vardrrunner/api.py` | The **only** module that performs HTTP. A `requests.Session` wrapper exposing typed methods; raises `requests.HTTPError` on non-2xx. Retries transient failures (connection errors, 429/5xx) with exponential backoff on idempotent methods only (never POST/PATCH); sends a `User-Agent: vardrrunner/<version>` header. |
| `vardrrunner/config.py` | Resolve credentials (key: env > keychain > config file; URL: env > file); atomically persist config; identify whether auth survives a fresh service process; enforce HTTPS. |
| `vardrrunner/keychain.py` | OS keychain wrapper (`keyring`) for the API key. Degrades gracefully (returns None/False) when no backend is present, so servers fall back to env/file. |
| `vardrrunner/configs.py` | Typed, validated tool configs (`HttpxConfig`, `NucleiConfig`, `NmapConfig`, `SubfinderConfig`, `VardrGateConfig`). Raw backend dicts are parsed into frozen dataclasses up front; invalid values raise `ConfigError` and fail the job fast. |
| `vardrrunner/errors.py` | The failure taxonomy (`FailureCategory`) and `RunnerError` hierarchy, plus `classify_status()` — the single place an HTTP status becomes a domain meaning. Imports nothing from the package or outside stdlib, so it is the bottom of the dependency graph (see ADR 0008). |
| `vardrrunner/credentials.py` | Describes credential posture — source, encryption at rest, keychain availability, cleartext state, file permissions — without ever returning the key. Shared by `doctor` and `credentials` so they cannot disagree about the same machine (ADR 0009). |
| `vardrrunner/redaction.py` | The single sanitization layer. Everything the runner emits — job events, failure reasons, log lines, errors — passes through here first. Masks by key name and by value pattern; deterministic, idempotent, depth-bounded, and never raises. |
| `vardrrunner/journal.py` | Transactional SQLite execution journal and explicit run state machine. WAL mode supports concurrent audit readers; a partial unique index permits only one unfinished attempt per backend job. |
| `vardrrunner/recovery.py` | Startup reconciliation for interrupted jobs. Resumes known-safe artifact uploads, retries finalization, and refuses automatic replay when an upload outcome is ambiguous. |
| `vardrrunner/manifests.py` | Streaming SHA-256 artifact hashes and atomic, permission-restricted JSON manifests/exports. |
| `vardrrunner/identity.py` | Stable per-installation UUID + human label. Uses exclusive first creation, fails closed on corruption, and supports a `VARDRRUNNER_NAME` deployment override. |
| `vardrrunner/service.py` | Pure service-plan generation plus argv-only native manager execution for systemd, launchd, and Windows Scheduled Tasks. Definitions never contain credentials. |
| `vardrrunner/compatibility.py` | Version/capability advertisement and total evaluation of optional backend constraints. Legacy responses remain compatible; definite mismatches block queue claims. |
| `vardrrunner/resources.py` | Bounded environment-driven target, artifact, concurrency, and free-disk policy shared by direct, pipeline, and queue execution. |
| `vardrrunner/updates.py` | Explicit release-check orchestration and 24-hour atomic cache. Network access remains isolated in `api.py`. |
| `vardrrunner/policy.py` | All parsing and presentation of the backend's advisory `warnings` array. Isolated so a backend shape change touches one file; parsing is total and never raises. |
| `vardrrunner/targets.py` | Target resolution (scope/recon/inline/file → list of targets). Shared by the `run` commands and the handlers — lives here to avoid an import cycle. |
| `vardrrunner/handlers.py` | One `ToolHandler` per job type (`parse_config`/`resolve_targets`/`execute`/`upload`) plus the `REGISTRY`. Adding a tool is a one-file change here (see ADR 0002). Includes `vardrgate_api_test`, which drives VardrGate over a binary/JSON contract — no shared code (see ADR 0006) — and resolves identity credential references (`value_env`/`value_keychain`) to real secrets locally before execution (see ADR 0007). |
| `vardrrunner/pipelines.py` | Named recon pipelines — ordered lists of `Stage(tool, source)`. Stages reference handlers; each stage writes its discovered targets to a local handoff file, which the next stage reads directly instead of querying the backend recon store. |
| `vardrrunner/runner.py` | Subprocess execution, stdout/stderr capture, timestamped run directories under `~/.vardrmap/runs`. |
| `vardrrunner/commands/auth.py` | `login` / `logout` / `whoami` — prompt for and persist backend URL + API key, remove stored credentials, and report the identity behind the key. |
| `vardrrunner/commands/run.py` | `run httpx|subfinder|nuclei|nmap|dnsx|naabu` — execute one tool, upload results (shares the typed-config + handler path). |
| `vardrrunner/commands/imports.py` | `import nuclei|httpx` — push an existing output file. |
| `vardrrunner/commands/jobs.py` | `jobs list|run` — owns the uniform job *lifecycle* (`_execute_one`): capability → config → targets → claim → events → upload → done/fail, delegating specifics to a `handlers` registry entry. |
| `vardrrunner/commands/audit.py` | `audit list|show|export` — read-only views and atomic exports of sanitized journal state. |
| `vardrrunner/commands/identity.py` | `identity show|set-name` — inspect or label this installation without exposing credentials. |
| `vardrrunner/commands/service.py` | `service install|status|uninstall` — preview and manage native per-user supervision. |
| `vardrrunner/commands/updates.py` | `update check` — inspect public release metadata; never installs automatically. |
| `vardrrunner/commands/setup.py` | `init` — compose auth, identity, journal, optional service installation, and doctor into one idempotent guided/provisioning workflow. |
| `vardrrunner/commands/pipeline.py` | `pipeline list|run` — runs a `pipelines` chain stage by stage (resolve → execute → upload), each stage writing a local handoff file so the next stage reads from it directly rather than the backend recon store. |
| `vardrrunner/commands/daemon.py` | `daemon start|stop|status` — continuous worker (poll + heartbeat) with PID file and graceful shutdown. |
| `vardrrunner/commands/heartbeat.py` | `heartbeat` — send a single heartbeat. |
| `vardrrunner/commands/status.py` | `status` — local config, version, detected tool availability (quick glance). |
| `vardrrunner/commands/doctor.py` | `doctor` — deep preflight; runs health checks and exits non-zero on actionable failures (`--json` report). Reuses `daemon` PID helpers and `config` validation. |
| `vardrrunner/commands/engagements.py` | `engagements` (list) and `scope` (show in/out-of-scope items) — renamed from `commands/programs.py` in v0.27.0. |

## Job execution lifecycle
1. **Poll and journal** — `GET /jobs/pending` returns queued jobs for this operator. The
   runner opens a local run record before any claim; if durable state is unavailable it
   fails closed and claims nothing.
2. **Validate and resolve targets** — validate the envelope/schema/config, verify the tool,
   then expand scope/recon targets. Target shape and the local count ceiling are enforced;
   only a count and sanitized command profile enter the journal. Target values and
   credentials do not.
3. **Claim** — `POST /jobs/{id}/claim` atomically transitions `pending → running`. The
   response is classified (ADR 0008): `409` is a lost race and the runner skips the job
   without marking it failed; `403` is **stop-work** and halts; `401`/`429`/`5xx` are
   reported with their category. Advisory policy warnings on the response are printed
   before any tool runs and emitted as a `policy_warning` event.
4. **Execute** — after verifying the configured free-disk reserve, `runner.py` spawns the
   tool as an argv list (never `shell=True` with server data), records its PID, and captures
   output to a run directory. Emits `running`.
5. **Hash and upload** — enforce the local artifact-size ceiling, then stream a SHA-256
   digest and size into the journal before POSTing results. Emits `uploaded` after a
   confirmed response.
6. **Finalize** — mark the backend job done/failed, close the journal record, and atomically
   write `manifest.json` beside the artifact.

Events are posted via `POST /jobs/{id}/events` so the backend Terminal can render live logs.

## Heartbeat
On daemon start and every 60 s thereafter, the runner sends `POST /runner/heartbeat` with
stable runner UUID/name, hostname, runner version, OS, and per-tool availability + versions.
Identity fields are additive; older backends may ignore them and retain hostname identity.
The payload also advertises supported job schemas and named capabilities. An optional
compatibility response can require runner versions/capabilities/schemas; definite mismatches
pause claims while heartbeats continue, and absent metadata means legacy-compatible.
The backend marks a
runner **online** if `last_seen` is within 5 minutes. Heartbeats are upserted per
`(owner, hostname)`, so multiple machines show up independently in the backend's Bridge.

## Daemon model
`daemon start` launches a dedicated worker thread that interleaves job polling (5 s) and
heartbeats (60 s). `--detach` spawns a `DETACHED_PROCESS` and writes a PID file; `stop`
removes the PID file as a cooperative shutdown signal and the daemon exits gracefully.
Windows liveness is checked via a ctypes probe (plain `os.kill` on Windows is
`TerminateProcess` and would kill the daemon it was meant to check).

PID ownership is claimed with exclusive file creation and a durable write. Concurrent
starts cannot both pass; malformed/non-positive/dead state is replaced once as stale.
Poll and heartbeat ranges are checked in both CLI parsing and the daemon command boundary.

Daemon logs rotate at 5 MiB with three backups. Text remains the interactive default;
`--log-format json` emits one redacted JSON object per line with schema version, UTC
timestamp, level, event, runner ID, process ID, and message.

Queue concurrency defaults to one and may be raised to eight. Pending work is grouped by
engagement: groups may run in parallel, but jobs inside one group are sequential. Each
worker receives an isolated API session; the backend's atomic claim remains the authority
across multiple runner processes or hosts.

For unattended startup, `service.py` generates a per-user systemd unit (Linux), LaunchAgent
(macOS), or Scheduled Task (Windows). The generated command is the same foreground daemon,
so there is one lifecycle implementation. Service files contain executable/log paths only,
never credentials, and native manager commands are executed as argv lists without a shell.
Installation preflight also verifies credentials survive a fresh process. Shell-only auth
requires an explicitly referenced Linux systemd env file; the runner never copies or reads
that file's contents.

Before each poll, reconciliation inspects unfinished records for the configured backend:

- work interrupted before claim is closed locally;
- a dead claimed/executing job with no complete artifact is failed on the backend;
- an existing, complete artifact is hashed, uploaded, and finalized;
- a confirmed upload awaiting only the final PATCH is finalized without re-uploading;
- an upload whose response was lost is **not replayed automatically**, because the current
  backend import contract has no idempotency key. It is closed as `upload_failed` while the
  local artifact and audit record remain available.

## Configuration & secrets
Local state lives under `~/.vardrmap/`:
- `config.json` — the backend `api_url` (normally **no secret**; only holds a plaintext
  `api_key` in the explicit no-keychain fallback); replacements are atomic
- `runs/` — timestamped tool output directories, pruned after 7 days
- `runner-journal.sqlite3` — sanitized execution state and recovery metadata (SQLite/WAL)
- `runner-identity.json` — stable installation UUID, name, and original hostname
- `daemon.jsonl` — default structured service log (rotated; service installs only)
- `update-check.json` — public release metadata cache (24-hour TTL; no credentials)

Completed job run directories also contain `manifest.json` with provenance, lifecycle
timestamps, artifact SHA-256/size, warnings, and failure category. Manifests and audit
exports pass through the same redaction layer as terminal and backend output. Raw targets,
API keys, identity credentials, request bodies, and headers are never journaled.

The one exception is the daemon PID file, `~/.vardrrunner.pid`, which is deliberately
outside `~/.vardrmap/` — it belongs to the runner process, not to a backend's config.

`login` **fails closed**: with no OS keychain it refuses to write a cleartext key unless
`--allow-plaintext-credentials` is passed, because the machines without a keyring backend
are the ones most likely to run unattended (ADR 0009).

The **API key** resolves from `VARDRMAP_API_KEY` env > **OS keychain** (`keyring`) > config
file. `vardrrunner login` stores it in the keychain by default; `logout` removes it. On a
headless box with no keyring backend, login fails closed unless the operator explicitly
passes `--allow-plaintext-credentials` (servers should use the env var). The backend URL must be HTTPS (except `localhost`,
or with `VARDRRUNNER_ALLOW_INSECURE=1`) so the key is never sent in cleartext. The API key is
the runner's only credential; it is never logged or printed.

## Policy and trust boundaries

The backend evaluates authorization, testing window and scope for every job.
**Findings are advisory**: they ride back as a `warnings` array and the work
still runs, because staying in scope is the operator's responsibility — the same
as it is with any other tool in the kit. VardrRunner's job is to make findings
impossible to miss, not to enforce them.

**Stop-work is the one exception.** It arrives as HTTP `403` and halts
execution. It is the operator's own emergency brake, not the platform
second-guessing them, and it is never presented as a generic claim failure. The
daemon remembers which engagements refused and stops re-claiming their jobs every
cycle. It rechecks after 60 seconds, so lifting stop-work restores availability without a
daemon restart or special command.

`403` carries this single meaning because VardrMap answers cross-account access
with `404` rather than `403`, so object existence is never disclosed. That
assumption is recorded in ADR 0008 and is what would need revisiting if the
backend contract changed.

### Redaction

Every value leaving the process is sanitized by `redaction.py` first: job events
(written to the backend and rendered in its Terminal), failure reasons (printed
*and* stored as `error_message`), log lines, and daemon poll errors. It defends
on two axes — by key name (`api_key`, `authorization`, `cookie`, `value_env`, …,
normalised so `X-API-KEY` matches) and by value pattern (`vmap_` keys, `Bearer`
headers, secret query parameters, `key=value` in free text) — because either
alone leaves a gap.

It is deliberately **not** a guarantee that secrets never touch disk: a tool
writes its own artifacts and the runner does not rewrite them. It governs what
the runner *says* about them.

Everything in a policy payload is **untrusted remote data**. It is redacted and Rich-escaped
before display or recording, and is never interpolated into a command line. Findings remain
advisory except `stop_work_active`, which blocks whether represented as HTTP 403 or—defence
in depth—in a successful response's warning array.

## Design invariants
- **All HTTP goes through `api.py`.** No ad-hoc requests elsewhere.
- **All backend data is untrusted.** Validate and normalize before it reaches a subprocess.
- **Every tool run is time-bounded.** A hung tool is killed and the job marked failed — the
  daemon never blocks forever.
- **Failures are loud, and classified.** A missing/failed tool fails the job; it is never
  skipped silently. Every reported failure carries a `FailureCategory`.
- **No unjournaled claims.** Queue work is not claimed unless local durable state is writable.
- **Ambiguous uploads are not replayed.** Recovery favors duplicate prevention when the
  backend cannot prove idempotency; artifacts remain available for operator review.
- **Advisory stays advisory.** Only stop-work and explicitly configured local deny rules
  may block; scope and window findings warn.
- **Blast radius is capped.** A run aborts before executing anything if the resolved target
  count exceeds 500 (`commands/run.py: MAX_TARGETS_DEFAULT`), including under `--yes`.
- **Compatibility precedes claims.** Definite runner/backend version, capability, or schema
  mismatches pause queue claims while heartbeat recovery remains available.
- **Same-engagement work is serialized.** Optional concurrency applies only across groups;
  one runner process never executes two jobs from the same engagement simultaneously.
- **Installed means restartable.** Native service preflight rejects authentication that
  exists only in the launching shell unless a Linux environment file is attached.
- **One local daemon owns the PID.** Exclusive creation closes the concurrent-start race;
  the backend claim remains the cross-host ownership authority.
- **No backend coupling.** The runner must build, test, and run without the backend present
  (tests mock every HTTP and subprocess call).
