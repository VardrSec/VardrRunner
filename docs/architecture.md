# VardrRunner — Architecture

The [explicit managed-worker candidate](managed-worker.md) composes the existing
managed claim/Gate/result protocols with the separate
[Linux lifecycle owner](worker-lifecycle.md). Actual verified owner context alone
enables Linux controlled execution. Native Windows Job Objects and ordinary CLI
behavior remain unchanged. Host-observed retirement is authenticated metadata;
it does not recreate a native execution handle or consumption acknowledgement.
Runtime acceptance remains open and default startup remains inert.

The inactive persistent-v3 candidate retains signed-64-bit decimal sequences and
immutable admission snapshots in additive tables of the same journal. Exact
original-key observation `/4` may record physical retirement; it never supplies a
missing claim, consume, DONE or idle-release acknowledgment. Full startup audits
validate retained history; normal idle checks select unresolved rows.

Persistent selections are provisional metadata until the claim transport returns.
Preparing one does not advance the issued history head or native sequence. An
unknown reply retains its original association and hold. A source-proven local
no-send denial can close only that selection; it cannot reset an issued attempt
or delete the generic claim tombstone.

V3 reusability records every refresh-loop callback failure, including local
stop-journal reads. Exact thread quiescence alone cannot erase that failure.
Native idle-channel EOF has its own immutable cleanup deadline; an open healthy
idle channel retains persistent availability without job authority.

An optional finite v3 idle policy closes claims at the conservative pre-ACK
cutoff. Closure is sticky: after a full hold audit and empty-lineage check,
Runner keeps the channel open in a nonspawning, no-RPC wait. Its checked post-ACK
idle bound includes a fixed five-second shutdown-only reserve; no claim, native
or job deadline moves. Native exit 124 identifies an unambiguous optional-idle
branch only, not a successful job or physical-stop receipt. The separate native
EOF cleanup deadline and all unresolved holds remain unchanged.
Python's separate discovery window stops new requests but never selects physical
idle termination. If it closes before the owner cutoff is observed, Runner
rechecks readiness and full holds with bounded sleeps while keeping fd3 open.
Count exhaustion still returns through its existing completed-session path.

The worker's pre-send runtime/enrollment/root association commits in the same
journal transaction as its send marker. Optional authenticated observation v2
can retire an untouched unknown intent only after Map has irreversibly fenced
that exact unbound runtime against late claims. Legacy unlinked records retain
v1 and their conservative holds. Neither receipt nor local retirement reconstructs
an execution capability or resets a tombstone or spent allowance.

Runner remains the single execution engine, with standalone workspaces and
optional Map coordination. The native standalone Gate consumer is a development
capability. Recon remains validation-only, rejected before reservation callbacks
or execution; managed Docker execution remains gated.
Canonical journal/WAL identity and Windows database/ancestor replacement pins are
implemented; POSIX pathname replacement and SQLite snapshot non-mutation remain
open safety gates. Read-only SQLite access is not a strict filesystem non-mutation guarantee.
Full/Mapless, Docker and cross-platform acceptance remain required. Earlier test
evidence applies only to its recorded source revision.

The additive `workspace gate` consumer reuses the existing standalone contract,
ledger, fixed-Gate runtime, native Windows control, journal and audit/export. It
does not issue approval, bootstrap trust or use Map. Unsupported execution platforms
refuse before consumption; unfinished local records never enter Map recovery.
See [ADR 0039](adr/0039-standalone-workspace-gate.md). Existing legacy commands,
queue and MCP remain independent of this explicit consumer.


The DNSx adapter explicitly disables the pinned tool's automatic version check.
This removes that auxiliary version request; it is not DNS destination, proxy,
redirect, scope or aggregate-budget enforcement for a standalone recon profile.

The reconciled export read also uses the existing observed-file guard before its
SQLite connection; read-only mode, fresh reads and live WAL visibility remain.

Workspace metadata listing reuses `local_workspaces` and the same row validation
as known-ID lookup. A bounded SQLite read-only query checks current journal/table
schemas and orders before limiting; it constructs no Journal and performs no
initialization/migration. No active selection, new state, authority or execution
path is introduced. Existing application startup maintenance remains unchanged.

Every journal connection uses one canonical database pathname, including grant
transactions and workspace inventory. Ordinary symlinks resolve to that database,
so Windows readers see its committed WAL rather than a separate alias WAL name.
On Windows, each canonical ancestor and the database are opened as non-reparse
objects and retained without delete sharing until SQLite closes. Ancestor handles
also deny write sharing; database handles allow legitimate concurrent SQLite writes.
Hardlinked Windows databases refuse because alternate names can split WAL state.
The adapter uses existing Windows APIs and adds no minimum Windows version.
Missing journals retain their existing creation/read-only semantics. POSIX retains
the observed-file check; its pathname replacement race is not closed. The Windows
pins cover database/ancestor replacement, not authority authenticity, database-content
tampering, sidecar replacement, strict inspection non-mutation or bounded metadata I/O.
See [ADR 0042](adr/0042-canonical-journal-name-pins.md).

Age cleanup preserves every journal-linked directory, including terminal and
uncertain runs. Bounded path-only inventory must be complete before deletion.
On supported runtimes, cleanup verifies and holds the run-root descriptor and
performs later operations relative to it. Windows, Python 3.10 and runtimes
without that confinement skip automatic cleanup; direct execution remains usable.
Journal evidence has no new automatic deletion policy.

The partial NM-3 single-run evidence exporter reuses journal/schema-1 audit and
manifest formats. It reads a current-schema journal in SQLite read-only mode,
binds source JSON to the recorded digest/size and regular-file descriptor, then
serializes a centrally redacted derivative. Original provenance stays in audit;
the portable manifest describes the derivative and links the original hash.
Fixed filenames are created exclusively through a pinned private POSIX directory
descriptor. Fresh journal rechecks detect changed records without pinning one
stale database snapshot. No database, grants, config or executable authority is
copied. Windows now has an isolated handle-adapter candidate using verified private
ACLs and no-redirect creation. Native security acceptance remains open. See
[ADR 0040](adr/0040-portable-run-export.md).

Path conversion can normalize input spellings before validation. The security
boundary binds the resulting path through actual no-redirect handle operations;
it does not promise raw CLI-token rejection for every spelling alias.

Audit history and schema-1 metadata export optionally select an exact engagement
or local workspace ID through the existing journal query. Bound SQL parameters
apply that filter together with the time bound before ordering and limiting.
Only `None` means unscoped; explicit blank/whitespace values remain literal
historical IDs. No workspace lookup, Map transport, authorization, schema change
or artifact-copy system is involved. Existing callers remain unscoped by default.

The opt-in authorization ledger records trusted observed time in a short separate
transaction, independent of permission changes. Denied issuance/consumption cannot
forget expiry, and permission transactions recheck time after writer-lock waits
and before reservation. Monotonic elapsed time composes with the runtime clock;
unknown ordinals/fences remain spent. See [ADR 0031](adr/0031-ledger-clock-denials.md).

Opt-in duration allocations use an immutable claim-start monotonic deadline,
composed through existing launch checks and native supervision. Map accounts
nonrefundable allocated seconds; Runner measures and enforces the permission
window. Claim and monitor entry are atomically single-use per owned facade,
including unknown responses and failed monitor setup. See
[ADR 0030](adr/0030-allocated-duration-permission.md) for exclusions.

Opt-in cumulative target accounting uses Map's owned claim receipt and Runner's
existing fixed Gate compiler/request guard, including auxiliary origins. Default
execution remains unchanged. See [ADR 0029](adr/0029-cumulative-target-attempts.md).

Explicit owned engagement capacity uses Map reservations via
`jobs run --controlled --concurrency-budget`. Map accounts; Runner executes and
requires the receipt. This does not count unregistered manual work or enable a
worker. See [ADR 0028](adr/0028-engagement-capacity.md).

Opt-in expiring Gate reference grants are described in
[ADR 0027](adr/0027-expiring-reference-grants.md). A separate config catalog uses
the existing journal for writer serialization, digest anchoring and observed-time
fencing. Checks cover claim, provider resolution and actual process creation,
including auxiliary origins. Signed execution deadlines compose with grant/control
checks after lock waiting. Post-creation failures preserve process ownership and
partial-artifact fences. Default approval and execution behavior is unchanged;
reference permission is distinct from human execution approval.

Opt-in manual execution control and cancellation are described in
[ADR 0026](adr/0026-controlled-cancellation.md). Map control is authenticated and
attempt-bound, with bounded leases, conservative uncertainty and local emergency
requests in the existing journal. It does not grant execution approval or enable
a worker; legacy paths and Gate evidence semantics remain unchanged.

The first Compose distribution uses a one-shot, non-root Runner container; native execution remains supported. See [ADR 0019](adr/0019-container-packaging.md).

The toolkit's existing Katana, DNSx, Naabu, httpx, Subfinder, FFUF and Nuclei use recorded source builds with dependency patches
and the same runtime hash verification; see [ADR 0020](adr/0020-container-source-katana.md).
Gau has four explicitly recorded source fixes for provider TLS/errors and extensionless JSON output;
its modified main module is not presented as unchanged upstream source. See
[ADR 0021](adr/0021-gau-patched-source.md). Backend contracts are unchanged.

## Identity/session preflight

The optional reviewed Gate identity `preflight` remains in the unresolved case and
its hash. Credentials resolve locally as before. Runner requires the Gate CLI flag
before execution so a legacy binary cannot silently ignore the check. A preflight
failure (exit 3) is accepted only with a consistent safe report; artifacts upload
before failed finalization. The journal records the failure intent, so recovery
cannot convert a failed prerequisite into `done`. Map computes session completeness
against its claim snapshot and retains probe evidence with unknown resource
decisions. Cases without preflight retain the existing binary contract.

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
│                          │  ──── jobs / scope ─────> │  katana/gau/vardrgate    │
└──────────────────────────┘                           └──────────────────────────┘
```

The runner never listens — every exchange is outbound. The full set of endpoints it
calls, all through `api.py`:

| Endpoint | Used for |
|----------|----------|
| `GET /me` | `whoami`, and the auth check in `doctor` |
| `GET /ready` | opt-in `doctor --platform`: value-free v1 Map database/migration readiness |
| `GET /engagements` · `GET /engagements/{id}` | engagement list and scope lookup |
| `GET /engagements/{id}/recon` | `--from-recon` target resolution (paginated, 500/page) |
| `POST /engagements/{id}/imports` | httpx/nuclei/subfinder/dnsx/katana/gau/ffuf/dalfox result upload, with the producing `job_id` |
| `POST /engagements/{id}/services` | nmap/naabu open-port upload, with the producing `job_id` |
| `POST /engagements/{id}/test-cases/preview` · `.../reviewed` | `test-cases draft` / `save` |
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
| `vardrrunner/api.py` | The **only** module that performs HTTP. A `requests.Session` wrapper exposing typed methods; raises `requests.HTTPError` on non-2xx. Retries transient failures (connection errors, 429/5xx) with exponential backoff on idempotent methods only (never POST/PATCH); sends a `User-Agent: vardrrunner/<version>` header. Also performs the two public, unauthenticated fetches: release metadata for `update check` and `status`, and pinned tool archives for `tools install` (HTTPS-only, size-capped; integrity is checked by `toolchain.py`). |
| `vardrrunner/config.py` | Resolve credentials (key: env > keychain > config file; URL: env > file); atomically persist config; identify whether auth survives a fresh service process; enforce HTTPS; store approved VardrGate credential references (ADR 0023) and the tool-process environment allowlist (ADR 0022). |
| `vardrrunner/keychain.py` | OS keychain wrapper (`keyring`) for the API key. Degrades gracefully (returns None/False) when no backend is present, so servers fall back to env/file. |
| `vardrrunner/configs.py` | Typed, validated tool configs (`HttpxConfig`, `NucleiConfig`, `NmapConfig`, `SubfinderConfig`, `DnsxConfig`, `NaabuConfig`, `KatanaConfig`, `GauConfig`, `FfufConfig`, `DalfoxConfig`, `VardrGateConfig`). Raw backend dicts are parsed into frozen dataclasses up front; invalid values raise `ConfigError` and fail the job fast. `FfufConfig` is where a wordlist *name* is validated — never a path, so the backend cannot point ffuf at an arbitrary local file (`runner.resolve_wordlist` re-checks it against `~/.vardrmap/wordlists`). |
| `vardrrunner/errors.py` | The failure taxonomy (`FailureCategory`) and `RunnerError` hierarchy, plus `classify_status()` — the single place an HTTP status becomes a domain meaning. Imports nothing from the package or outside stdlib, so it is the bottom of the dependency graph (see ADR 0008). |
| `vardrrunner/credentials.py` | Describes credential posture — source, encryption at rest, keychain availability, cleartext state, file permissions — without ever returning the key. Shared by `doctor` and `credentials` so they cannot disagree about the same machine (ADR 0009). |
| `vardrrunner/redaction.py` | The single sanitization layer. Everything the runner emits — job events, failure reasons, log lines, errors — passes through here first. Masks by key name and by value pattern; deterministic, idempotent, depth-bounded, and never raises. |
| `vardrrunner/journal.py` | Transactional SQLite execution journal and explicit run state machine. WAL mode supports concurrent audit readers; a partial unique index permits only one unfinished attempt per backend job. |
| `vardrrunner/recovery.py` | Reconciliation of interrupted jobs during explicit queue execution. Resumes known-safe artifact uploads, retries finalization, and refuses automatic replay when an upload outcome is ambiguous. |
| `vardrrunner/manifests.py` | Streaming SHA-256 artifact hashes and atomic, permission-restricted JSON manifests/exports. |
| `vardrrunner/identity.py` | Stable per-installation UUID + human label. Uses exclusive first creation, fails closed on corruption, and supports a `VARDRRUNNER_NAME` deployment override. |
| `vardrrunner/compatibility.py` | Version/capability advertisement and total evaluation of optional backend constraints. Legacy responses remain compatible; definite mismatches block queue claims. |
| `vardrrunner/resources.py` | Bounded environment-driven target, artifact, concurrency, and free-disk policy shared by direct, pipeline, and queue execution. |
| `vardrrunner/shell.py` | Interactive console for a bare `vardrrunner` at a terminal: banner, line splitting, `use`/`back` engagement defaults (Click `default_map`), optional `prompt_toolkit` completion with in-memory history. Every line runs through the same Typer app as a one-shot call; nothing runs between lines (ADR 0017). |
| `vardrrunner/updates.py` | Explicit release-check orchestration and 24-hour atomic cache. Network access remains isolated in `api.py`. |
| `vardrrunner/policy.py` | All parsing and presentation of the backend's advisory `warnings` array. Isolated so a backend shape change touches one file; parsing is total and never raises. |
| `vardrrunner/target_safety.py` | Classifies resolved targets (public / private / loopback / link-local / cloud metadata) and evaluates locally-configured deny rules. Classification is lexical — no DNS — so it stays fast, offline-safe, and free of a TOCTOU gap against the tool's own resolution. |
| `vardrrunner/targets.py` | Target resolution (scope/recon/inline/file → list of targets). Shared by the `run` commands and the handlers — lives here to avoid an import cycle. |
| `vardrrunner/handlers.py` | One `ToolHandler` per job type (`parse_config`/`resolve_targets`/`execute`/`upload`) plus the `REGISTRY`. Adding a tool is a one-file change here (see ADR 0002). Includes `vardrgate_api_test`, which drives VardrGate over a binary/JSON contract — no shared code (see ADR 0006) — and resolves identity credential references (`value_env`/`value_keychain`) to real secrets locally before execution (see ADR 0007), only when the operator approved each reference for the job's engagement and every origin the case contacts (`check_gate_case`, ADR 0023). |
| `vardrrunner/pipelines.py` | Named recon pipelines — ordered lists of `Stage(tool, source)`. Stages reference handlers; each stage writes its discovered targets to a local handoff file, which the next stage reads directly instead of querying the backend recon store. |
| `vardrrunner/mcp_server.py` | Optional MCP server (`vardrrunner mcp`): adapts VardrMap's API to Model Context Protocol tools so an AI agent can read an engagement and queue jobs. Read tools page server-side with `offset`/`next_offset` (VardrMap v0.39.0+) plus guarded writes (queue job/pipeline, draft finding, draft per-finding report); no scope/auth/delete tools. Also reads authorizations, finding activity and client deliverables, and drafts VardrGate cases via `test-cases/preview`. Two writes are withheld as assertions only a person can make: saving a test case (declares human review) and writing a client deliverable revision (immutable, client-facing). Also serves the shipped methodology checklists (`list_methodologies`, `get_methodology`), which make no API call. Six prompts (`brief`, `triage`, `untested`, `methodology`, `retest`, `api_playbook`) package the repeated workflows; they are instruction text only and fetch nothing at expansion, so no target-controlled data reaches the trusted prompt position. Imports `mcp` lazily; the core never depends on it (ADR 0015). |
| `vardrrunner/runner.py` | Allowlisted process-group execution, process-tree timeouts, stdout/stderr capture, private VardrGate job files, and atomically unique run directories under `~/.vardrmap/runs`. Every command's program comes from `program()`, which asks `toolchain.py` for a verified managed path before falling back to `PATH`. |
| `vardrrunner/methodologies.py` | Versioned methodology checklists from `methodologies.json` (shipped in the package): OWASP API Security Top 10 2023 and WSTG 4.2. Validated at load; an item's `method` (`tooling` or `manual`) says how it is tested, **not** whether it has been — recorded manual work evidences a `manual` item as well as a job does. Every `suggests` entry must name a real job type; a `status`/`covered`/`done`/`coverage` key is **refused**, as is the field's former name `evidence`, which invited conflating method with evidence. Coverage comes from an engagement's own jobs and findings, never from this data. The WSTG entry is category-level, with OWASP's scenario identifiers (`WSTG-v42-INFO-02`) deferred; each methodology states this in a `scope` field. |
| `vardrrunner/toolchain.py` | Pinned, verified tool installs (ADR 0014). An asset may record a `member` — where the binary sits inside the archive, for a tool that nests it (dalfox) — validated to be relative, non-climbing and to end in the binary the entry installs, so extraction stays "copy exactly this one named entry". Loads `tool_manifest.json` (shipped in the package: version, per-platform archive URL, SHA-256), installs into `~/.vardrmap/tools` fail-closed (hash → single-member extract → version check → one rename → receipt), and re-hashes managed binaries before first use; a mismatch is never executed. |
| `vardrrunner/commands/auth.py` | `login` / `logout` / `whoami` — prompt for and persist backend URL + API key, remove stored credentials, and report the identity behind the key. |
| `vardrrunner/commands/run.py` | `run httpx|subfinder|nuclei|nmap|dnsx|naabu|katana|gau|ffuf|dalfox` — execute one tool, upload results (shares the typed-config + handler path). |
| `vardrrunner/commands/imports.py` | `import nuclei|httpx` — push an existing output file. |
| `vardrrunner/commands/jobs.py` | `jobs list|run` — owns the uniform job *lifecycle* (`_execute_one`): capability → config → targets → claim → events → upload → done/fail, delegating specifics to a `handlers` registry entry. |
| `vardrrunner/commands/audit.py` | `audit list|show|export` — read-only views and atomic exports of sanitized journal state. |
| `vardrrunner/workspaces.py`, `commands/workspace.py` | Explicit `workspace create|show` metadata in an additive table of the existing SQLite journal. No Map client, credential provider, approval, active-context selection or execution path. Existing run identities and journal schema version remain unchanged. This is the first metadata-only NM-3 slice, not complete Mapless operation. |
| `vardrrunner/commands/identity.py` | `identity show|set-name` — inspect or label this installation without exposing credentials. |
| `vardrrunner/commands/updates.py` | `update` — install the newest release in the foreground with pipx (`updates.upgrade_argv`/`run_upgrade`), confirm it from an isolated interpreter, or name the installer's command for uv/virtualenv installs; `update check` — report only. Both always ask the registry. Nothing installs unless the operator runs `update`. |
| `vardrrunner/commands/setup.py` | `init` — compose auth, identity, journal, tool installation, and doctor into one idempotent guided/provisioning workflow. |
| `vardrrunner/commands/pipeline.py` | `pipeline list|run` — runs a `pipelines` chain stage by stage (resolve → execute → upload), each stage writing a local handoff file so the next stage reads from it directly rather than the backend recon store. |
| `vardrrunner/commands/heartbeat.py` | `heartbeat` — send a single heartbeat. |
| `vardrrunner/commands/status.py` | `status` — local config, version, and each tool's source (managed / PATH / missing) (quick glance). |
| `vardrrunner/commands/test_cases.py` | `test-cases draft|save` - draft VardrGate cases from observed operations or OpenAPI into a never-overwritten review file, refuse literal credentials, and save only with `--reviewed`. |
| `vardrrunner/commands/tools.py` | `tools install|list|verify|remove|purge` — manage pinned tool installs; also naabu's capture-library check shared with `doctor`. |
| `vardrrunner/commands/doctor.py` | `doctor` — deep preflight; runs health checks and exits non-zero on actionable failures (`--json` report). Reuses `daemon` PID helpers and `config` validation. |
| `vardrrunner/commands/engagements.py` | `engagements` (list) and `scope` (show in/out-of-scope items) — renamed from `commands/programs.py` in v0.27.0. |

## Job execution lifecycle
1. **Poll and journal** — `GET /jobs/pending` returns queued jobs for this operator. The
   runner opens a local run record before any claim; if durable state is unavailable it
   fails closed and claims nothing.
2. **Validate and resolve targets** — validate the envelope/schema/config, verify the tool,
   then expand scope/recon targets. The journal-aware lifecycle validates shape, records
   input statistics, applies local findings/deny rules exactly once, and enforces the local
   count ceiling. Only counts and a sanitized command profile enter the journal; target
   values and credentials do not.
3. **Claim** — `POST /jobs/{id}/claim` atomically transitions `pending → running`. The
   response is classified (ADR 0008): `409` is a lost race and the runner skips the job
   without marking it failed; `403` is **stop-work** and halts; `401`/`429`/`5xx` are
   reported with their category. Advisory policy warnings on the response are printed
   before any tool runs and emitted as a `policy_warning` event.
4. **Execute** — after verifying the configured free-disk reserve, `runner.py` atomically
   allocates a unique run directory, resolves the tool (a managed install must pass hash verification or the job fails; otherwise `PATH`), and spawns it as an argv list with an empty stdin and an allowlisted environment (ADR 0022) in a dedicated
   process group/session (never `shell=True` with server data). It records the PID and
   captures output; a timeout terminates the complete process tree. Emits `running`.
5. **Hash and upload** — enforce the local artifact-size ceiling, then stream a SHA-256
   digest and size into the journal before POSTing results. Emits `uploaded` after a
   confirmed response.
6. **Finalize** — mark the backend job done/failed, close the journal record, and atomically
   write `manifest.json` beside the artifact.

Events are posted via `POST /jobs/{id}/events` so the backend Terminal can render live logs.

## Heartbeat
Explicit `heartbeat` and `jobs run` commands send `POST /runner/heartbeat` with
stable runner UUID/name, hostname, runner version, OS, and per-tool availability + versions.
Identity fields are additive; older backends may ignore them and retain hostname identity.
The payload also advertises supported job schemas and named capabilities. An optional
compatibility response can require runner versions/capabilities/schemas; definite mismatches
prevent claims, and absent metadata means legacy-compatible.
The backend marks a
runner **online** if `last_seen` is within 5 minutes. Heartbeats are upserted per
`(owner, hostname)`, so multiple machines show up independently in the backend's Bridge.

## Manual execution
`run`, `pipeline run`, and `jobs run` execute in the foreground only when invoked.
No command registers startup, creates a detached worker, or polls continuously. The
`daemon` and `service` commands were removed in v0.51.0 (ADR 0016 amendment); leftover
registrations from 0.47.0 or earlier are removed by hand (see `docs/cli.md`).

A stop-work refusal skips the engagement's remaining jobs for the rest of that run; the
next `jobs run` asks the backend again.

Queue concurrency defaults to one and may be raised to eight. Pending work is grouped by
engagement: groups may run in parallel, but jobs inside one group are sequential. Each
worker receives an isolated API session; the backend's atomic claim remains the authority
across multiple runner processes or hosts. Atomic run-directory allocation prevents
same-second workers from sharing an output path.

During an explicit `jobs run` invocation, reconciliation inspects unfinished records for the configured backend:

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
- `runs/` — atomically unique timestamp-prefixed tool output directories, pruned after 7 days
- `runner-journal.sqlite3` — sanitized execution state and recovery metadata (SQLite/WAL)
- `runner-identity.json` — stable installation UUID, name, and original hostname
- `update-check.json` — public release metadata cache (24-hour TTL; no credentials)

Completed job run directories also contain `manifest.json` with provenance, lifecycle
timestamps, artifact SHA-256/size, warnings, and failure category. Manifests and audit
exports pass through the same redaction layer as terminal and backend output. Raw targets,
API keys, identity credentials, request bodies, and headers are never journaled.

`login` **fails closed**: with no OS keychain it refuses to write a cleartext key unless
`--allow-plaintext-credentials` is passed, because the machines without a keyring backend
are the ones most likely to run unattended (ADR 0009).

The **API key** resolves from `VARDRMAP_API_KEY` env > **OS keychain** (`keyring`) > config
file. `vardrrunner login` stores it in the keychain by default; `logout` removes it. On a
headless box with no keyring backend, login fails closed unless the operator explicitly
passes `--allow-plaintext-credentials` (servers should use the env var). The backend URL must be HTTPS (except `localhost`,
or with `VARDRRUNNER_ALLOW_INSECURE=1`) so the key is never sent in cleartext. The API key is
the runner's only credential; it is never logged or printed.

Resolved VardrGate identity secrets briefly exist in a private runner-owned temporary
directory because the external CLI accepts a job file. On POSIX the directory is mode
`0700` and the exclusively created file is `0600`. Cleanup covers executable resolution,
preflight inspection, and execution failures as well as success. A setup or execution
exception remains the primary error if cleanup also fails; that cleanup failure logs a
fixed message without credential values. Cleanup failure after success fails the run.
Every CLI startup also removes abandoned, correctly named directories whose owner PID is
no longer alive, while refusing to traverse symlinks, junctions, or active directories.

## Policy and trust boundaries

The backend evaluates authorization, testing window and scope for every job.
**Findings are advisory**: they ride back as a `warnings` array and the work
still runs, because staying in scope is the operator's responsibility — the same
as it is with any other tool in the kit. VardrRunner's job is to make findings
impossible to miss, not to enforce them.

**Stop-work is the one exception.** It arrives as HTTP `403` and halts
execution. It is the operator's own emergency brake, not the platform
second-guessing them, and it is never presented as a generic claim failure. The
queue executor remembers refused engagements during the current invocation and suppresses
further claims during the cooldown. It does not start a background retry loop.

`403` carries this single meaning because VardrMap answers cross-account access
with `404` rather than `403`, so object existence is never disclosed. That
assumption is recorded in ADR 0008 and is what would need revisiting if the
backend contract changed.

### Redaction

Every value leaving the process is sanitized by `redaction.py` first: job events
(written to the backend and rendered in its Terminal), failure reasons (printed
*and* stored as `error_message`), log lines, and queue errors. It defends
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
- **Every tool run is time-bounded.** A hung tool's complete process tree is killed and the
  job marked failed — the runner never blocks forever or leaves scanner children running.
- **Failures are loud, and classified.** A missing/failed tool fails the job; it is never
  skipped silently. Every reported failure carries a `FailureCategory`.
- **A managed tool runs only if it still matches its receipt.** A binary in
  `~/.vardrmap/tools` that fails hash verification fails the job and never falls back to a
  `PATH` copy. Pins come from the package, never from the download site (ADR 0014).
- **No unjournaled claims.** Queue work is not claimed unless local durable state is writable.
- **Ambiguous uploads are not replayed.** Recovery favors duplicate prevention when the
  backend cannot prove idempotency; artifacts remain available for operator review.
- **Advisory stays advisory.** Only stop-work and explicitly configured local deny rules
  may block; scope, window, and target-classification findings warn. Nothing is denied
  by default, and every override is recorded as a job event.
- **Blast radius is capped.** A run aborts before executing anything if the resolved target
  count exceeds 500 (`commands/run.py: MAX_TARGETS_DEFAULT`), including under `--yes`.
- **Compatibility precedes claims.** Definite runner/backend version, capability, or schema
  mismatches pause queue claims while heartbeat recovery remains available.
- **Same-engagement work is serialized.** Optional concurrency applies only across groups;
  one runner process never executes two jobs from the same engagement simultaneously.
- **Run outputs are isolated.** Directory allocation is atomic, so concurrent starts cannot
  collide even when their wall-clock timestamp is identical.
- **Manual invocation only.** Installation and setup cannot register startup or launch a
  background worker. Only explicit execution commands claim, run, or recover queued jobs.
- **No backend coupling.** The runner must build, test, and run without the backend present
  (tests mock every HTTP and subprocess call).

## API playbooks and result binding (v0.47.0)

Map is the single source for original versioned API playbooks. MCP reads its
engagement-scoped catalog and individual guide over `api.py`, plus filtered
redacted evidence. The api_playbook prompt expands to instructions only and makes
no API call; fetched guidance and target-controlled content stay in tool results.
Human review, evidence linking/retest recording and client deliverable commits
remain operator actions. No methodology coverage is inferred from a guide.

Map captures the unresolved spec at claim. Runner compares it with the spec it
validated, resolved and showed before claim, failing before execution if changed.
The Gate handler adds SHA-256 of sorted compact JSON (default ensure_ascii=True,
UTF-8) of the unresolved spec to its result artifact after binary execution.
Credential resolution does not affect the binding; the hash survives recovery
without storing resolved secrets. This is correlation, not a signed attestation.
Old artifacts remain uploadable, but Map treats an absent binding as inconclusive.

## Independent Gate verifier identity

The Gate handler resolves `write_verification.identity` credential references
locally alongside caller references, leaving the reviewed case/hash unresolved.
Its optional principal preflight participates in the existing capability guard
and complete-diagnostics validation. Result artifacts preserve additive semantic
assessment/readback metadata for Map's companion upload handler, without treating
scanner conclusions as operator-confirmed findings. Failed checks retain safe
evidence and fail the job. Deploy the matching Map support before this feature.

## NM-1 opt-in authorization foundation

The unregistered `authorization.claim.ManagedEntry` adds a one-shot pre-claim
boundary and same-journal durable intent fence around that managed composition.
It preserves pre-RPC clock/grant identity through local artifact creation;
recovery holds uncertainty without replay or legacy finalization. See
[ADR 0033](adr/0033-managed-preclaim-entry.md).

The later unregistered `authorization.managed.ManagedGate` prototype composes the
same handler with current-control verification, durable consumption, expiring grants
and native Windows containment. It is not a CLI/queue adapter and does not finalize
managed Map success. See [ADR 0032](adr/0032-unregistered-managed-native-gate.md).

The independent `authorization` package adds signed bounded approvals, single-use
execution contracts and additive journal state. It reuses the Gate handler with a
request projection for the explicitly supported `gate-fixed-http/1` profile.
Legacy commands, queue and MCP paths do not advertise this capability. The
separate native Windows `workspace gate` consumer uses it explicitly with
existing signed permission; issuer-side key/trust provisioning and context
preparation are not yet a supported first-run workflow.
See [ADR 0025](adr/0025-authorization-contract-v1.md) and the
[conformance specification](contracts/README.md) for trust boundaries and limits.

`authorization.runtime.execute_gate` is an explicit standalone library adapter:
check current time/binary/local grants, consume durably, then call the existing
handler with a private request projection and approved timeout. It records known
completion only after the handler returns. Managed live execution is refused.
The deadline is the earliest execution-contract expiry, approval expiry or testing
window end, capped by approved duration. The existing subprocess adapter rechecks
it after credential and private-file preparation; elapsed setup time cannot restore
permission. This is the existing timeout boundary, not managed cancellation.

### Unregistered managed consumption barrier

The preclaim handle reserves local consumption, journals its one-shot send,
requires Map's exact current owned-contract ACK, and journals that observation
before native dispatch. Neither an ACK nor a locally retained artifact completes
Map work or releases capacity. Recovery defers all such attempts without network
replay. Separate send/ACK markers survive later held states. See
[ADR 0034](adr/0034-managed-consumption-barrier.md); this remains a local prototype.

### Managed result and terminal receipts

The unregistered preclaim handle now exposes explicit finalization after known
native return. Result retention and completion have separate durable sends and
exact acknowledgements; evidence receipt alone releases nothing. Explicit
reconciliation observes a trusted authenticated receipt and closes local state
only for the exact terminal outcome. Ordinary recovery still defers managed rows.
See [ADR 0035](adr/0035-managed-result-finalization.md).

### Managed known-stop receipts

A managed native `ExecutionStopped` can establish a report right only with literal
confirmed containment and a fixed known cause. Observer PIDs remain metadata, not
a permission or liveness source. The explicit one-shot stop lane requires consumed
owned binding and an exact remote receipt before local terminal state. Missing or
uncertain receipt state stays held. See [ADR 0036](adr/0036-managed-known-stop-receipts.md).

### Managed claim observation after restart

An explicit unregistered observation authenticates the original enrolled principal
and plan/case/association fingerprints without returning a control capability.
It records metadata only; absence never authorizes a retry. Reconciliation closes
only an existing exact durable result/stop intent, preserving native proof and
uncertainty fences. Ordinary recovery remains deferred. See
[ADR 0037](adr/0037-managed-claim-observation.md).

### Explicit managed JSON transport

`api.VardrMapClient.managed_post` is a library-only one-shot HTTPS primitive with
strict finite JSON and request/response size limits, no retries or redirects,
fresh header-authenticated sessions and inherited proxy/CA configuration. It does
not register managed Map routes or enable execution. Read-idle waits are not a
total transfer deadline; existing signed/monotonic ceilings remain mandatory.
See [ADR 0038](adr/0038-explicit-managed-json-transport.md) and the
[canonical NM-2 exit status](nm2-canonical-exit-status.md).

Managed transport also preserves a trusted configured API base prefix such as
Full's `/backend`; it does not strip or rewrite the signed origin/association
identity. Only simple path segments are accepted. Prefix compatibility supplies
no new route activation or execution right.

### Dormant finite recon projection (NM-3)

`authorization.recon_plan` is a pure, opt-in contract projection, with no CLI,
MCP, default capability or recon executor. The initial slice accepts canonical
finite ASCII hostnames, explicit HTTPS/443 GET-root tuples, IPv4 destination
CIDRs and numeric IPv4 resolver endpoints. A-only DNSx and the exact reviewed
Linux release binary hashes are required; Windows and A+AAAA remain unsupported.
Existing Gate behavior and default capabilities are preserved.

The signed full-plan digest binds both tools, all original candidates, resolvers,
destination networks, fixed options/environment, a shared deadline and evidence
byte ceiling. The existing human approval and ledger allocate one whole journey
ordinal before any future execution. No stage refund, smaller post-DNS reservation
or additional budget store is introduced. The conditional Linux source model
reserves `4M` HTTP application requests and `2N + 50M` DNS application questions for
N original DNS inputs and M original URL inputs. DNS authority is explicit in the
human-reviewed plan digest; this is neither an independent DNS quota nor a global
cross-plan token pool. These numbers do not bound packets, connections or bytes.
Evidence byte limits are declarations for future enforcement, not disk quotas.

Pure DNS handoff can select only original URL tuples; ambiguous, empty or mixed
out-of-CIDR address sets fail closed. It cannot establish destination enforcement
at connect time. No tool runs through this module. Even trusted explicit profile
validation cannot pass the Gate runtime's first-line profile guard. No common
platform currently has both the Linux tool proof and accepted native cancellation.
The Docker managed worker remains disabled/unsupported, with its watchdog-hang
security gate open. No execution adoption or full portability is claimed.

Dormant recon follow-up: distinguish `vardr.finite-recon-plan/1` from the unchanged
Gate schema; recheck the shared recon deadline at final ledger issuance/consumption.
No execution path is enabled.

### Existing-worker inspection snapshot

The explicit top-level `worker-state` facade reads an operator-selected existing
identity and journal. It uses the pure identity validator and noncreating bounded
reader, `journal_connection(readonly=True)`, and one `BEGIN` read snapshot. The
existing full local-holds engine and unfinished RunRecord validation accept that
same connection; ordinary callers delegate with unchanged predicates and no
inspection budget. Optional checkpoints cover history loops and nested scans only
when the inspection supplies them. No Store/Journal constructor or migration runs.

Inspection validates current schema, exact admission/runtime/Runner binding,
original association joins and canonical retirement provenance. Genuine parent0
without any per-runtime association is `empty_unissued`, never fabricated local
retirement. A retired nonempty runtime keeps earlier released rows unchanged.
If the next claim committed remotely but its reply was lost, the exact original
observation can anchor retirement at server sequence N+1 while the local cursor
stays N, including N=0. The preceding full audit validates existing released
history. Inspection requires the exact next retired selection, no local attempt
at N+1, no consumption, and the original validated snapshot; it creates no claim
acknowledgement or history entry and preserves all earlier released rows.
Closed preclaim tombstones remain unchanged and do not count as issued attempts.
Incomplete facts are held with null counts; valid unretired state or nonzero
global holds may report complete facts while remaining held. The closed public
schema contains no raw rows, tokens, token hashes, identity labels or response
values. Logical read-only WAL semantics do not promise zero filesystem writes.
See [ADR0043](adr/0043-proposed-linux-worker-lifecycle-owner.md#offline-existing-state-inspection-amendment)
and [the CLI contract](cli.md#offline-worker-state-inspection-nm-2-candidate).

### Original worker reconciliation selector

`authorization/worker_reconciliation.py` and the top-level `worker-reconcile`
command reuse the same six-selection validators, complete read snapshot and closed
`worker-state/1` audit builder. The audit contract is unchanged. A unique pending
selection takes priority over the exact issued history head; ambiguity and absent
original associations are held rather than guessed from a generic bounded list.
No job/history count limit is added.

Only a validated actionable original association reaches credential resolution and
the existing original-key managed observation route. One response is retained for
existing result/stop/retirement reconciliation; it cannot authorize another RPC or
execution. Optional exact-association guards apply before observation and receipt
metadata writes, including result/stop ACK/close transactions. Legacy callers keep
the original default predicates and behavior. A final fresh audit must establish
original-key-linked retirement and zero global holds before success is reported.

The explicit writer uses `Journal.open_existing` without the ordinary constructor.
It binds every `mode=rw` connection to the DB dev/inode observed at original
selection and refuses missing/replaced/current-schema mismatches. It reuses the
same transaction and existing SQL methods, including ordinary evidence-table
creation during authenticated observation, not a second SQL recovery engine.
Normal WAL sidecars remain supported. Existing Windows path pins and POSIX
observed-file limitations remain; this is not an OS sandbox or content freeze.

Already-retired state and truly empty parent0 return offline without credentials.
A fully certified closed-preclaim parent0 cohort has a separate parent-only
retirement branch. It preserves the existing early-return and physical selection
ancestry paths. Reuse the original observation RECORD transaction, which validates
its exact source and stores only evidence. Then a new full same-connection audit
and retained original-key claimNone/unbound last0 snapshot permit updating only
the exact parent. No tombstone, issued attempt, ACK or grant is created/rewritten.
The full private cohort UUID tuple detects membership drift without a count cap.
Inspection recognizes that original-key snapshot on its unchanged tombstone;
actual nonzero associations remain visible. Global-holds engines are unchanged,
and another runtime/run hold is never cleared or concealed by parent retirement. Distribution still owns physical stop and any
future next-enable lifecycle; this component adds no service, Map endpoint,
automatic reconciliation or activation.


The separate `worker-bootstrap-state` reader shares the current journal schema,
identity and bounded read-only snapshot with `worker-state`. It audits all
existing local holds and fixed worker history tables without pretending there
is an admitted worker parent. Absence of a journal is incomplete, not a zero
ledger or fresh-installation assertion. Distribution still owns first and
successor container lifecycle decisions; this helper grants no authority.
