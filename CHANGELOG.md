# Changelog

All notable changes to VardrRunner are documented here.
This project follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Per-version detail notes live in [`changelog/`](changelog/).

## [Unreleased]

## [0.33.0] — 2026-08-18

Phase 3 of the enterprise-grade roadmap: stable runner identity, structured daemon logs,
native user-service management, and production readiness checks. See
[`changelog/v0.33.0.md`](changelog/v0.33.0.md) and
[ADR 0011](docs/adr/0011-runner-identity-and-service-management.md).

### Added

- Stable per-installation UUID and human label in `runner-identity.json`, with
  race-safe first creation, `VARDRRUNNER_NAME`, and `identity show|set-name`.
- Heartbeat `runner_id` and `name` fields, additive for compatibility with older backends.
- `daemon start --log-format json` for rotating, redacted JSON Lines logs carrying schema,
  UTC timestamp, level, event, runner ID, PID, and message.
- `service install|status|uninstall` for systemd user services, macOS launchd agents, and
  Windows Scheduled Tasks, including `--dry-run` and Linux `--env-file` support.
- `doctor --production`, which requires secure credential storage, durable identity/journal,
  stronger disk headroom, and active supervision.

### Security and reliability

- Service definitions never embed API keys and are written atomically with owner-only
  permissions. Commands use argv execution without a shell.
- Identity corruption fails closed and is never silently replaced; concurrent first use
  converges on one UUID.
- Structured log messages pass through centralized redaction before serialization.

## [0.32.0] — 2026-08-18

Phase 2 of the enterprise-grade roadmap: durable execution, crash reconciliation, run
manifests, and local audit export. See [`changelog/v0.32.0.md`](changelog/v0.32.0.md) and
[ADR 0010](docs/adr/0010-durable-execution-journal.md).

### Added

- Transactional SQLite/WAL execution journal with an explicit lifecycle state machine and
  one-active-attempt-per-job invariant.
- Startup reconciliation that resumes complete artifacts and pending finalization while
  conservatively refusing ambiguous upload replay.
- Child-process PID recording, streaming artifact SHA-256/size, and atomic per-run
  `manifest.json` files.
- `vardrrunner audit list|show|export` for sanitized local execution evidence.

### Security

- Queue work now fails closed before claim if the journal is unavailable or incompatible.
- Journal profiles exclude raw targets, VardrGate test cases, credentials, headers, and
  request bodies; manifests and exports are redacted again at write time.
- Automatic recovery never repeats a non-idempotent upload whose outcome is unknown.

### Reliability

- Dead or restarted workers no longer leave recoverable jobs silently stuck in `running`.
- SQLite handles are short-lived and always explicitly closed; WAL permits concurrent
  read-only audit inspection while the daemon runs.

## [0.31.1] — 2026-08-18

Phase 1 completion and integration hardening. See
[`changelog/v0.31.1.md`](changelog/v0.31.1.md).

### Fixed

- A `stop_work_active` finding returned in a successful claim response now blocks execution;
  the helper that detected it previously existed only in unit tests and was not connected to
  the job lifecycle.
- Stop-work suppression now expires after 60 seconds and rechecks the backend. Lifting the
  halt restores work without requiring a daemon restart, while repeated refusals remain
  bounded to one per minute rather than every poll.
- Credential posture inspection now genuinely survives corrupt or unreadable configuration;
  it no longer catches one parse and then calls helpers that parse the same file again.
- Redaction is applied across CLI errors, policy findings, job listings/configuration,
  heartbeat and keychain logs, pipeline summaries, status/doctor output, engagement/scope
  display, and direct run output. Untrusted Rich markup is escaped after secret masking.

### Security

- Job configurations displayed by `jobs list` are recursively sanitized, including literal
  VardrGate identity credentials.
- Backend-controlled warning text, engagement metadata, scope values, usernames and result
  summaries can no longer inject Rich markup into the operator terminal.

## [0.31.0] — 2026-08-17

Phase 1c of the enterprise-grade roadmap: credential storage fails closed. See
[`changelog/v0.31.0.md`](changelog/v0.31.0.md) and
[ADR 0009](docs/adr/0009-fail-closed-credential-storage.md).

### Changed

- **BREAKING — `login` no longer writes a cleartext key silently.** When no OS keychain is
  available (or a keychain write fails), `vardrrunner login vardrmap` now verifies the key,
  **saves nothing**, and exits 1 with three routes forward: `VARDRMAP_API_KEY`, install a
  keyring backend, or pass the new `--allow-plaintext-credentials`. The machines without a
  keyring backend are exactly the ones that run unattended, so "the command succeeded" was
  the wrong thing to optimise for. Every other login path is unchanged.

### Added

- **`vardrrunner credentials`** — reports key source, whether it is encrypted at rest,
  keychain availability, whether the config file holds cleartext, and file permissions.
  Never displays the key. Exits non-zero when unauthenticated, so it composes into
  provisioning scripts.
- **`--allow-plaintext-credentials`** on `login vardrmap`, the explicit opt-in.
- **`doctor` reports credential storage posture** — encrypted at rest, environment
  variable, or cleartext — plus a warning when no keyring backend exists.
- **`vardrrunner/credentials.py`** — one module describing credential posture, shared by
  `doctor` and `credentials` so they cannot describe the same machine differently.

### Security

- A present-but-broken keyring is treated as absent rather than silently downgraded to
  cleartext.
- Nothing is persisted before the refusal, so a failed login cannot leave a half-configured
  machine.
- The environment variable is deliberately **not** reported as "encrypted at rest": it is
  not written to disk by the runner, but any process running as that user can read it.


## [0.30.0] — 2026-08-17

Phase 1b of the enterprise-grade roadmap: one sanitization layer in front of
every trust boundary. See [`changelog/v0.30.0.md`](changelog/v0.30.0.md).

### Added

- **`vardrrunner/redaction.py` — centralized sanitization.** A single, deterministic
  redactor applied before data crosses a trust boundary. Masks by **key name**
  (`api_key`, `authorization`, `cookie`, `token`, `value_env`, `value_keychain`, …,
  normalising `X-API-KEY` and `Auth-Token` to the same forms) *and* by **value pattern**
  (`vmap_` keys, `Bearer`/`Basic` headers, cookies, secret query parameters, `key=value`
  assignments in free text), plus `redact_url()` for `https://user:pass@host` userinfo and
  `redact_exception()` for messages that quote the failing request.

### Security

- **Job events, failure reasons and daemon poll errors are now sanitized.** Event text is
  written to the backend and rendered in its Terminal; failure reasons routinely quote the
  command, URL or payload that failed, which is exactly where a credential ends up. All
  three went out unredacted before this release.
- Redaction is **depth-bounded** (12 levels): an untrusted payload cannot turn
  sanitization into a denial of service, and a subtree beyond the bound is replaced with a
  marker rather than emitted unchecked.
- Redaction **never raises**. Sanitizing must not be the reason a job dies, so an
  unparseable value is returned unchanged — but the recursive walker masks by key name as
  well as value pattern, so an unrecognised *shape* still cannot become an exfiltration
  path.


## [0.29.0] — 2026-08-17

Phase 1a of the enterprise-grade roadmap: the runner can now tell a halt order
from a lost race. See [`changelog/v0.29.0.md`](changelog/v0.29.0.md) and
[ADR 0008](docs/adr/0008-error-classification-and-policy-handling.md).

### Fixed

- **Stop-work was indistinguishable from a claim race, and retried forever.** The
  job-claim path caught every exception in one handler whose comment anticipated only a
  `409`, so a stop-work refusal (`403`), an expired key (`401`), a backend outage (`5xx`)
  and a genuine race all printed the same line and left the job pending — and the daemon
  re-claimed the halted job every `poll_interval` seconds with no explanation. Each is now
  reported distinctly, and a stop-work engagement is skipped for the life of the daemon
  rather than re-attempted every cycle. Restarting re-checks it.

### Added

- **`vardrrunner/errors.py` — one failure taxonomy.** `FailureCategory` plus a
  `RunnerError` hierarchy, and `classify_status()` as the single place an HTTP status
  becomes a domain meaning. Category values are stable identifiers written to durable
  records from the execution journal onward.
- **`vardrrunner/policy.py` — advisory policy findings are now surfaced.** The backend's
  `warnings` array (authorization, testing window, scope) was previously never read. It is
  now printed **before any tool runs**, while the operator can still intervene, and emitted
  as a `policy_warning` job event. Warnings remain advisory and do not block — only
  stop-work halts.

### Changed

- `claim_job()` and `complete_job()` raise classified `RunnerError` subclasses, chained
  from the original `HTTPError`. The generic `get`/`post`/`patch` still raise
  `requests.HTTPError`, so `doctor` and `status` are unaffected.
- `execute_pending_jobs()` accepts an optional `blocked_engagements` set for stop-work
  suppression. Existing callers are unaffected.

### Security

- Policy payloads are treated as untrusted display data: rendered and recorded, never used
  for control flow beyond display, never interpolated into a command line. Parsing is total
  — a malformed payload yields no warnings rather than raising, so a display failure cannot
  abort a job the backend already permitted.


## [0.28.1] — 2026-08-17

### Fixed

- **A negative `--max-targets` silently disabled the target cap.** Every guard is written
  as `max_targets > 0`, so `--max-targets -1` skipped the check entirely and let an
  unbounded target list through — on a tool that runs nmap and nuclei. Only `0` was ever
  documented as disabling the cap. Negative values are now rejected at parse time
  (`min=0`), and `validate_max_targets()` rejects them again inside `_check_target_cap()`
  and at the top of `run_pipeline()` so programmatic callers cannot skip the guard either.
  Introduced in v0.28.0, when the option was first exposed to the command line.

### Documentation

- **Corrected an overstated claim about API key storage.** `docs/cli.md` said that using
  the hidden-input prompt "never writes it to disk in cleartext", and the README said
  logging in means "no plaintext key on disk". Neither is true without an OS keychain: on a
  machine with no keyring backend, `login` falls back to writing the key in cleartext to
  `~/.vardrmap/config.json` (with a warning) regardless of how it was supplied. The prompt
  protects shell history, nothing more. Both files now say so and point headless users at
  `VARDRMAP_API_KEY`.
- **Install instructions rewritten around PyPI.** `pipx install vardrrunner` is now the
  headline path rather than a "once published" placeholder, with the GitHub Release wheel
  demoted to the verify-before-installing case and source install marked as development.
- **`uv` documented for machines with no Python.** `pipx` presumes a Python installation,
  which a fresh VPS or clean Windows box may not have; `uv` bootstraps its own CPython.
  Also notes `uvx vardrrunner` for one-shot use without installing.
- **README states plainly that cloning alone does not provide the command** — it must be
  installed into an environment on `PATH`.
- **`login --url` / `--key` documented** in `docs/cli.md`, with a warning that passing
  `--key` writes a live credential into shell history and that the hidden-input prompt or
  `VARDRMAP_API_KEY` should be preferred.
- **ADR 0003 amended** to record that PyPI publishing went live in v0.28.0, and that the
  original ADR did not account for operators without Python.

## [0.28.0] — 2026-08-17

First release published to PyPI. See [`changelog/v0.28.0.md`](changelog/v0.28.0.md).

### Fixed

- **`--max-targets` is now an actual option.** The guardrail shipped in v0.22.1 and the
  500-target cap has been enforced ever since, but the option was never added to the Typer
  commands — so the abort message named a flag that did not parse, and the cap could
  neither be raised nor disabled. `--max-targets N` (`0` disables) is now on all six
  `run <tool>` commands and on `pipeline run`.
- **`import ffuf` removed.** v0.21.1 dropped `ffuf` from `SUPPORTED_TOOLS` but left the
  command registered in `cli.py`, so it stayed visible in `--help` and always exited with
  "Unsupported tool: ffuf".

### Changed

- **Wiring tests assert kwargs, not just call counts.** Both defects above survived because
  `tests/test_cli.py` only asserted `mock.assert_called_once()`, which passes whether or not
  an option reaches the command module. `--max-targets` is now asserted on every command
  that takes it, and a regression test proves `import ffuf` is no longer routable.

### Documentation

- **Docs resynced to the shipped v0.27.0 surface.** `whoami`, `engagements`, and `scope`
  are documented for the first time; `run` target-source and per-tool flags, the daemon's
  `--poll-interval` / `--heartbeat-interval` / `--log-file`, and the 500-target cap are
  now in [`docs/cli.md`](docs/cli.md). `docs/architecture.md` gains the full endpoint
  table the runner calls and corrects the claim that all local state lives under
  `~/.vardrmap/` (the daemon PID file is `~/.vardrrunner.pid`).
- **Stale figures corrected.** Test count was recorded as 222, 384, and 421 in three
  different files; it is 439 at ~96% coverage. Repository URLs moved from
  `jorge-aquino/*` to `VardrSec/*` (ADR 0001 keeps its original path as a historical
  record).
- **Missing per-version notes added** for v0.22.2, v0.23.0, and v0.24.0, and ADRs
  0005–0007 added to the ADR index.
- **Two shipped-vs-documented mismatches recorded** rather than papered over: the
  `--max-targets` option (v0.22.1) was never wired into `cli.py`, and `import ffuf`
  (v0.21.1) is still a registered command. Both are noted in `CLAUDE.md`, `docs/cli.md`,
  and the affected changelog entries.

## [0.27.0] — 2026-08-04

### Changed

- **Programs are now Engagements**, following VardrMap's rename. `api.py` calls
  `/engagements/*`; `VardrMapClient.programs()` → `engagements()`;
  `commands/programs.py` → `commands/engagements.py`. See
  [`changelog/v0.27.0.md`](changelog/v0.27.0.md).
- **Requires VardrMap ≥ v0.22.0.** Deploy the backend before upgrading the runner.

### Compatibility

- `--program` and `-p` still accepted on every command that takes `--engagement`.
- `vardrrunner programs` still runs; hidden from `--help`.

## [0.26.0] — 2026-07-09

### Added
- **Local secret resolution for VardrGate identities.**  A `vardrgate_api_test` job credential may reference a secret instead of embedding it: `value_env` (an environment variable read on the runner) or `value_keychain` (an OS-keychain account). The handler resolves references to real values locally, just before execution, so secrets never travel through — or persist in — the backend. A referenced-but-missing secret fails the job rather than running with a blank credential. Literal `value` and anonymous credentials are untouched. Adds `keychain.get_secret()`.

## [0.25.0] — 2026-07-08

### Added
- **`vardrgate_api_test` job handler.**  VardrRunner can now run VardrGate API authorization tests as jobs. The handler shells out to the `vardrgate run --job … --out …` binary (added to the tool allowlist as `vardrgate`), captures the sanitized result JSON, and uploads it to the job via `POST /jobs/{id}/upload`. The job is self-contained — the test case travels in the job config, so there are no scope/recon targets to resolve. VardrRunner imports no VardrGate internals; the coupling is the CLI/JSON contract only. See [ADR 0006](docs/adr/0006-vardrgate-api-test-handler.md).
- **`VardrGateConfig`.**  Typed, validated config for the new job type (`test_case`, `execution`, optional `policy_id`).

### Changed
- **`ToolHandler.upload()` gained an optional `job_id` parameter.**  Recon handlers import results to a program and ignore it; the VardrGate handler uses it to attach the result to the originating job. Existing call sites and handlers are unaffected (defaults to `""`).

## [0.24.0] — 2026-06-26

### Added
- **`pipeline run --dry-run`.**  Resolves first-stage targets and prints the planned tool chain without executing any tool. Useful for validating scope and target counts before committing to a long pipeline run.
- **`pipeline run --json`.**  Emits a machine-readable JSON result after the pipeline completes — run ID, per-stage status/targets/summary/elapsed, and an overall `success` flag. Designed for CI scripts that need to inspect pipeline results programmatically.

### Fixed
- **Daemon log files no longer contain Rich markup brackets.** The file-mode `Console` was created with `markup=False`, which caused `[green]`, `[dim]`, and similar tags to appear literally in log files. Removing that flag lets Rich render markup to plain text automatically since the log file is not a terminal. `_RotatingLogFile` now also implements `isatty() → False` explicitly.
- **Daemon poll backs off exponentially on consecutive errors.** A downed backend was previously retried every `poll_interval` seconds regardless of failure count. The daemon now backs off exponentially (5 s → 10 s → 20 s … capped at 5 min) and resets on the next successful poll. The error message now includes the retry delay.
- **`_extract_jsonl_field` OSError now logged as a warning** instead of silently swallowed. Disk-full or permissions failures are now visible in log aggregation.
- **Collapsed redundant exception handlers in `_run_stage`.** `ToolTimeout` is a subclass of `Exception`; both handlers returned the same result shape, so the separate branch was dead code.

### Changed
- **Subfinder and Dnsx `execute()` use a shared `_write_host_import_jsonl()` helper.** Both handlers duplicated the same JSONL conversion loop. Extracted to a module-level helper in `handlers.py`.

## [0.23.0] — 2026-06-23

### Added
- **Live TUI for `pipeline run`.** Each stage is now a live-updating table row
  (Rich `Live` + `Table`) with a spinner while running and final status icons
  (✓ done, ✗ failed, ⊘ no targets, — aborted) plus target count, result summary,
  and elapsed time per stage. Remaining stages are marked aborted immediately when
  a stage stops the pipeline.

### Changed
- `_run_stage` now returns a structured `_StageResult` dataclass instead of
  printing directly, keeping all display logic in `_PipelineTUI`.

## [0.22.2] — 2026-06-20

### Changed
- **Operational logging in silent paths.** `_emit()` in `jobs.py`, `heartbeat.py`
  quiet mode, and the daemon all now emit `logging.warning()` on failures instead of
  silently swallowing errors, making issues visible in log aggregation without breaking
  quiet operation.
- **VARDRRUNNER_TOOL_TIMEOUT validation.** Invalid values now log a warning and fall
  back to the default instead of silently being ignored.
- **Keychain failures logged at DEBUG level.** `available()`, `get_key()`, `set_key()`,
  and `delete_key()` all emit structured debug logs on exception so operators can
  diagnose keyring backend issues.
- **Handler method signatures.** All `ToolHandler` concrete methods are now annotated
  with their specific config types (e.g. `configs.HttpxConfig`) instead of `Any`,
  catching config/handler mismatches at type-check time.
- **JSONL parsing deduplicated.** Shared `_extract_jsonl_field()` utility replaces three
  identical implementations across `HttpxHandler`, `SubfinderHandler`, and `DnsxHandler`.

### Added
- **`bandit` security scan in CI.** `bandit -r vardrrunner -ll -q` runs in the lint job
  on every push, blocking merges on high/medium severity findings.
- **Coverage threshold raised to 95%.** `pytest --cov-fail-under=95`; new test files
  cover `api.py` HTTP methods, `keychain.py`, `commands/auth.py`, `commands/programs.py`,
  `commands/heartbeat.py`, `cli.py` (via `typer.testing.CliRunner`), and the full
  job lifecycle edge cases (malformed job, unknown tool, config error, target resolution
  failure, claim race, no output, `ToolTimeout`, generic exception).

## [0.22.1] — 2026-06-20

### Added
- **Target-count guardrail on `pipeline run` and all `run <tool>` commands.**
  If the resolved target count exceeds the limit the command aborts before running
  any tool, printing the count and telling the operator how to raise or disable the
  cap. Default is 500. The check applies even with `--yes` so automation pipelines
  can't accidentally scan thousands of hosts.
  **Correction (2026-08-16):** the accompanying `--max-targets` option was never wired
  into `cli.py`, so the cap was fixed at 500 and could not be changed from the command
  line. Fixed in v0.28.0. See [`changelog/v0.22.1.md`](changelog/v0.22.1.md).

## [0.22.0] — 2026-06-20

### Added
- **Daemon log rotation.** When `--log-file` is specified, log output is now written
  through a `RotatingFileHandler` (5 MB per file, 3 backup files) instead of an
  unbounded append-only file. Prevents runaway disk use on long-lived VPS daemons.
- **Daemon log timestamps.** Every line written to the log file is prefixed with an
  ISO 8601 timestamp (`YYYY-MM-DDTHH:MM:SS`) so operators can correlate events and
  grep logs by time without relying on filesystem metadata.

## [0.21.1] — 2026-06-20

### Fixed
- **`import` command no longer lists `ffuf` as supported.** `ffuf` has no handler,
  no backend importer, and would fail at runtime. `SUPPORTED_TOOLS` is now `["httpx",
  "nuclei"]` — the two formats the backend's file-import endpoint actually accepts.
  `subfinder`/`dnsx` are excluded because they convert to httpx-format JSONL before
  uploading; `nmap`/`naabu` use `create_services`, not file import.
  **Correction (2026-08-16):** the `import ffuf` command itself remained registered in
  `cli.py` and kept appearing in `--help`; only the `SUPPORTED_TOOLS` entry was removed
  here. The command was removed in v0.28.0.
- **Run directories are pruned automatically.** `_make_run_dir()` now deletes run
  directories older than 7 days before creating a new one, so pipeline artifacts don't
  accumulate indefinitely on long-running VPS daemons.

### Changed
- **`pipeline list` now shows each stage's data source.** Output is now
  `subfinder(scope) → httpx(recon) → nuclei(recon)` so operators can see data flow
  at a glance without reading the source code.

## [0.21.0] — 2026-06-20
Run-scoped pipeline isolation. See [changelog/v0.21.0.md](changelog/v0.21.0.md) for details.

### Added
- **Run-scoped pipeline isolation.** Each `pipeline run` now generates a short run ID
  (`8-hex`) printed at the start and end. After every stage completes, its discovered
  targets are extracted from the output and written to a local **handoff file**; the next
  stage reads from that file instead of the shared backend recon store. This prevents stale
  recon from earlier runs contaminating later stages.
- **`ToolHandler.extract_handoff_targets(output)`** — new method on every handler, returns
  the targets that stage produced for the next stage. `HttpxHandler` extracts URLs/hosts
  from its JSONL; `SubfinderHandler` and `DnsxHandler` extract hostnames. Terminal handlers
  (nuclei, nmap, naabu) return `[]` and fall back to backend resolution.
- **`ToolHandler.normalize_handoff_targets(targets)`** — new method that strips URL
  scheme/path for host-only tools (nmap, dnsx, naabu), matching what their
  `resolve_targets()` does for backend recon. Default is identity.
- **ADR 0005** documents the design decision. See `docs/adr/0005-run-scoped-pipelines.md`.

### Changed
- `commands/pipeline._run_stage()` return type changed from `bool` to
  `tuple[bool, Path | None]`. No public API change — `_run_stage` is internal.

## [0.20.1] — 2026-06-20
Reliability hardening. See [changelog/v0.20.1.md](changelog/v0.20.1.md) for details.

### Fixed
- **Recon pagination.** `api.recon()` now paginates in chunks of 500 instead of issuing one
  request with the caller's `limit`. Eliminates the live 422 seen at `limit=736` and makes
  large recon sets reliable for httpx, nuclei, naabu, and pipelines.
- **Tool failures are now fatal.** `runner._run_tool()` raises `ToolError` on any non-zero exit
  code; every `run_*` function signature changed from `-> int` to `-> None`. A failed httpx,
  nuclei, subfinder, dnsx, nmap, or naabu run marks the job **failed** with the exit code
  rather than silently drifting into "done".
- **`doctor` skips auth after an invalid backend URL.** `_check_auth()` now validates the URL
  before making any network call, returning a WARN instead of a noisy follow-up failure.
- **Corrupt config file is handled gracefully.** `config.load()` raises `InvalidConfigFile`
  (not a raw `JSONDecodeError`) on malformed JSON. `doctor._collect()` catches it, emits one
  clear FAIL check with a remediation hint, and continues running tool/disk/daemon checks.
- **`nmap` version detection fixed.** `tool_version()` now uses `--version` for nmap (was
  `-version`) and falls back to a `X.Y.Z`-style regex in addition to `vX.Y.Z`, so nmap,
  dnsx, and naabu report actual version numbers instead of "unknown".

## [0.20.0] — 2026-06-17
Secure credentials + broader recon coverage. See
[changelog/v0.20.0.md](changelog/v0.20.0.md) for the rollup.

### Added
- **dnsx + naabu tools.** Two new recon tools via the handler registry:
  - `dnsx` (`vardrrunner run dnsx`) resolves hosts and uploads only the **resolvable** ones as
    recon targets, so later httpx/nuclei passes don't waste time on dead names.
  - `naabu` (`vardrrunner run naabu`) does a fast top-ports scan and uploads open ports to the
    services API (`source: "naabu"`).
  - Two new pipelines: `deep` (subfinder → dnsx → httpx → nuclei) and `ports`
    (subfinder → dnsx → naabu). `doctor`/`status`/heartbeat pick up both tools automatically.
- **OS keychain credential storage.** `vardrrunner login` now stores your API key in the OS
  keychain (macOS Keychain, Windows Credential Locker, Linux Secret Service) by default, with
  the backend URL kept in `config.json`. Key resolution is `VARDRMAP_API_KEY` env > keychain >
  legacy config file. On a headless box with no keyring backend it falls back to the plaintext
  config file with a warning, so servers keep working. See
  [docs/adr/0004-credential-storage.md](docs/adr/0004-credential-storage.md).
- **`vardrrunner logout`** — removes the stored key from the keychain and config file, leaves
  the API URL in place, and warns if `VARDRMAP_API_KEY` is still set in the environment.
### Changed
- `doctor` reports the **credential source** (`environment` / `keychain` / `config file`)
  without exposing the secret, and only warns about config-file permissions when the file
  actually holds a plaintext key.

## [0.19.0] — 2026-06-17
First feature release from the standalone repo. See
[changelog/v0.19.0.md](changelog/v0.19.0.md) for the rollup.

### Added
- **`vardrrunner doctor`.** A deep preflight for unattended/VPS use, distinct from `status`'s
  quick glance: it exits 0 only when the runner is healthy enough to work, exits non-zero on
  actionable failures, and prints remediation per problem (so `doctor && daemon start` gates
  provisioning). Checks credential source, backend URL validity, config-file permissions, API
  auth, daemon PID health, run-dir writability, free disk, tool versions, and pipeline
  readiness. `--json` emits a machine-readable report.
- **Recon pipelines.** `vardrrunner pipeline run recon --program <id>` chains tools in one
  command — `recon` = subfinder → httpx → nuclei, `quick` = subfinder → httpx. Each stage
  uploads its results so the next pulls them from the recon store; the run preflights tool
  availability, validates the nuclei `--severity` filter up front, stops early on an empty
  stage, and supports `--continue-on-error`. `vardrrunner pipeline list` shows the chains.
  Built on the handler registry — a pipeline is just an ordered list of `Stage(tool, source)`.
- **Typed, validated job configs.** Tool configs (`limit`, `status_code`, `severity`,
  `templates`, `top_ports`, `timing`, `timeout`) are parsed into frozen dataclasses
  (`configs.py`) and validated up front. A malformed or drifted backend payload now fails
  the job fast with a clear message (e.g. out-of-range nmap timing, unknown nuclei severity)
  instead of blowing up mid-execution. A `JobEnvelope` likewise validates the job wrapper
  (`id`/`tool_type`/`target_source`/`program_id`).
- **`vardrrunner run nmap`.** Direct service-discovery command (safe profile only), matching
  the existing nmap *job* support. `status` now lists every allowlisted tool (incl. nmap),
  so it can't drift from what the runner actually supports.
- **Environment-variable config.** `VARDRMAP_URL` and `VARDRMAP_API_KEY` override the
  config file (precedence: env > file), so containers, CI, and headless VPS daemons don't
  need a config file. `status` reflects the resolved source.
- **Per-tool run timeout.** Every tool subprocess now runs under a wall-clock limit
  (default 1800 s; override per job via `config.timeout`, or globally via
  `VARDRRUNNER_TOOL_TIMEOUT`). A hung tool is killed and the job marked **failed** instead
  of freezing the daemon forever.

### Changed
- **Tool-handler registry.** `execute_pending_jobs` (~290 lines of per-tool `if` branches)
  is refactored into a `ToolHandler` per job type (`handlers.py`) driven by one uniform
  lifecycle (`_execute_one`): capability check → config → targets → claim → events → upload
  → done/fail. Every tool now gets identical claim/event/failure handling, and adding a tool
  is a one-file change. See
  [docs/adr/0002-tool-handler-registry.md](docs/adr/0002-tool-handler-registry.md).
- **Direct `run` commands share the typed-config/handler path.** `run httpx|subfinder|nuclei|nmap`
  now validate their options through the same configs and reuse the same handlers as jobs and
  pipelines, so `run nmap --timing 9` is rejected (not silently clamped) and `run nuclei
  --severity bogus` fails before any work. Target resolution moved to `targets.py`.
- **Resilient API client.** The HTTP session now retries transient failures
  (connection errors and 429/500/502/503/504) with exponential backoff, so a
  long-running daemon survives network blips and brief backend restarts. Retries
  are limited to idempotent methods — POST/PATCH are never auto-retried, so a
  dropped response can't cause a double-claim, double-import, or duplicate event.
  Retry count and backoff are constructor-configurable. Requests also send a
  `User-Agent: vardrrunner/<version> (<os>)` header for backend attribution.

### Fixed
- **Pipeline `--continue-on-error` is now complete** — it also covers tool-execution and
  upload failures, not just target resolution and timeouts.
- **Malformed job envelopes fail cleanly.** A job missing a required field is marked failed
  (or skipped if it has no id) via `JobEnvelope`, instead of risking a `KeyError` mid-loop.

### Security
- **HTTPS enforced for the backend URL.** The runner refuses to send your `vmap_` API key
  over plain HTTP to a non-local host (allowed for `localhost`, or with
  `VARDRRUNNER_ALLOW_INSECURE=1`). Validated at login and on every authenticated call.

## [0.18.0] — 2026-06-14
First release from the standalone repository. See
[changelog/v0.18.0.md](changelog/v0.18.0.md) for detail.

### Changed
- Extracted VardrRunner into its own repository from the VardrMap monorepo, preserving
  full commit history via `git subtree split`. See
  [docs/adr/0001-extract-vardrrunner-from-vardrmap.md](docs/adr/0001-extract-vardrrunner-from-vardrmap.md).
- **Corrected the package version** from a misleading `0.1.0` to `0.18.0` (the package
  already carried v0.17.x of features). Version is now single-sourced from
  `vardrrunner/__init__.py` and read dynamically by `pyproject.toml`; the heartbeat reports it.
- Replaced `pyflakes` with **ruff** (lint + format) and added **mypy** type checking; all
  three plus coverage now run in CI on Python 3.10–3.12.

### Added
- Standalone repo scaffolding: `CLAUDE.md` (with the shared VardrSec Engineering Charter),
  `README.md`, `docs/` (architecture, development, CLI reference, ADRs), `changelog/`,
  CI workflow, and `.gitignore`.
- `LICENSE` (MIT).
- `[project.optional-dependencies] dev` extra in `pyproject.toml` — `pip install -e ".[dev]"`.

---

## History before extraction
The features below shipped while VardrRunner lived inside the VardrMap repo. They are
recorded here for continuity; their commits are present in this repo's history.

### v0.17.1 — Daemon Windows fixes
- ctypes liveness probe (Windows `os.kill` was terminating the daemon)
- PID-file-removal graceful stop protocol; `DETACHED_PROCESS` detach; double-start guard

### v0.17.0 — Daemon
- `daemon start/stop/status`; polls jobs every 5 s, heartbeats every 60 s on a dedicated
  thread; `--detach` background mode with PID file; graceful SIGTERM shutdown
- Extracted `execute_pending_jobs()` so one-shot and daemon share one execution path

### v0.15.0 — Radar, AI triage, normalization
- nmap job type; `strip_url_to_host()` target normalization

### v0.14.0 — Service discovery
- Atomic job claim via `POST /jobs/{id}/claim`; nmap job type (safe profile);
  per-tool config validation

### v0.13.0 — Job events
- Emits `started/targets_resolved/running/uploaded/done/failed` lifecycle events

### v0.12.0 — Real heartbeat
- `POST /runner/heartbeat`; reports hostname, version, OS, per-tool availability;
  explicit `heartbeat` command + auto-heartbeat on `jobs run`

### v0.11.0 — Job dispatch
- subfinder job dispatch (wildcard extraction → subfinder → JSONL → httpx import)

### v0.9.0 — VardrRunner v1
- subfinder support for wildcard scope; `jobs list` / `jobs run`; missing tool marks job
  failed instead of silently skipping; `status` command
