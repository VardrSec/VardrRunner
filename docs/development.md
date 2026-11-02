# VardrRunner — Development

`tests/test_managed_claim.py` covers the unregistered pre-claim entry, independent
journal connections, preparation/grant/clock failures and conservative recovery.
Map's explicit `tests/test_managed_entry.py` adds real verified loopback TLS and
native Windows Gate execution; it additionally requires `NM2_PRECLAIM_ENTRY=1`
and the existing native fixture opt-ins. Use disposable profiles/databases, an
explicit child environment allowlist and dotenv disabled. No production route,
enrollment or completion is enabled. See [ADR 0033](adr/0033-managed-preclaim-entry.md).

Authorization-ledger checks include denial followed by clock rollback, reload,
contended writer locks and validation delayed beyond signed expiry. Historical
reference-vector tests explicitly freeze injected monotonic clocks; runtime uses
real elapsed time and managed adapters must also supply their trusted UTC clock.
No signed payload timestamp may supply that clock. Cross-repository managed wire
vectors are conformance evidence only, not authenticated online-control proof.

Duration tests distinguish allocation from measured preparation, process runtime
and cleanup. Include native cooperative/refusing trees, late claim responses,
grant-lock/environment/permit delays, clock changes and receipt/library-entry
failures. PostgreSQL verifies accounting and policy races; the combined loopback
fixture checks real Gate with all controls. No test may use retained state.
Competing claim/monitor tests must hold setup open to verify the single-use entry
is reserved before callbacks can race; failed setup cannot restart permission.

Target-budget checks cover exact receipt binding, conservative auxiliary origins,
unsupported fixed profiles and actual handler guard wiring. Map PostgreSQL fixtures
verify cumulative atomicity and enable/disable races; real guarded Gate loopback
must also pass. See [ADR 0029](adr/0029-cumulative-target-attempts.md).

Concurrency-budget regressions cover CLI opt-in, required controlled mode and
refusal of absent/false reservation receipts. Map's production-dialect tests
verify atomic accounting; Runner unit tests do not certify database locking.
See [ADR 0028](adr/0028-engagement-capacity.md) before integration testing.

## Local expiring-grant checks

The normal suite includes `test_expiring_grants.py` and
`test_expiring_grant_jobs.py`: synthetic bindings, TTL/revocation, all auxiliary
origins, clock rollback, stale state, claim/provider/preparation races and audit
privacy. Windows tests launch disposable Python processes for guard-exit failures,
lock-delayed signed deadlines and confirmed termination. Recovery tests preserve
the grant marker and ambiguous PID fence even without controlled execution.
Suite-wide fixtures redirect config/journal/tool state; never point these tests at
an installed workspace, retained database, real keychain or external target.

After grant/launch changes, also run VardrSec's explicit real guarded Gate fixture
with expiring standalone grants and a temporary grant journal. Use only its
ephemeral loopback target, public test signing key and synthetic environment values.
Require all 14 requests across five phases, preserved case hash and no additional
replay requests. The fixture's legacy config patch alone is insufficient: the
grant journal must also be redirected. No provider values belong in receipts.
See [ADR 0027](adr/0027-expiring-reference-grants.md) for atomicity, rollback and
unsupported-platform limits. This does not certify managed signed authorization,
Linux/Docker containment, budgets or a future worker.

NM-2 cancellation checks: `tests/test_execution_control.py` uses real bounded
synthetic process trees; `tests/test_controlled_jobs.py` covers late cancellation,
durable PID and upload state. On Windows, hidden private consoles verify actual
graceful signalling and owner-crash cleanup. No scanner/external target is used.
The explicit `tests/nm2_control_acceptance.py --map-source <checkout> --out <new-dir>`
harness needs Map's test dependencies and exercises real loopback HTTP with a new
SQLite database. Production-dialect races live in Map's `postgres_tests` and must
pass separately. Never point these checks at retained installations or databases.

`tests/nm2_native_fault_acceptance.py --map-source <checkout> --out <new-dir>`
adds real HTTP proxy loss/delay and ambiguous owned-finalization coverage. Run
with Map's existing Windows test Python and Runner's existing `.venv` available;
redirect `TEMP`/`TMP` to disposable scratch. It creates its own SQLite database,
synthetic authentication, grant catalog and three-process trees. It is explicitly
opt-in, outside normal pytest discovery. See [native fault coverage](nm2-native-faults.md)
for the case matrix, transport-timeout injection and evidence limits.

Container development: see [the container guide](container.md) for build, persistent state, credentials and trust configuration.

The container CI generates disposable Gau TLS fixtures on its host with the
existing `cryptography` dev dependency and mounts them read-only for the real
producing-handler regression. Synthetic private keys are neither committed nor
included in the product image; no host CA enrollment or real provider traffic is
needed. See [ADR 0021](adr/0021-gau-patched-source.md).

Identity preflight requires the matching Gate/Map feature builds before use.
Run `tests/test_identity_preflight.py` during edits, then the normal full suite and
the Map three-repository acceptance harness against disposable loopback fixtures.
No new dependency, setup secret or environment variable is required.

## Prerequisites
- Python **3.10+**
- `git`
- (Optional, for real runs) the external tools. `vardrrunner tools install --all` installs
  pinned, verified builds of `httpx`, `subfinder`, `nuclei`, `dnsx`, `naabu`, `katana`,
  `ffuf` and `dalfox` into
  `~/.vardrmap/tools`; `vardrgate` (only for `vardrgate_api_test` jobs) still
  comes from your OS or `PATH`, and `nmap` is an unsupported opt-in
  (`VARDRRUNNER_ENABLE_NMAP=1`, your own installation). None are needed for the default tests; real scanners
  are used only by the explicitly enabled smoke tests below. Native Gau is excluded
  from installation/execution; use the reviewed [container toolkit](container.md)
  for Gau. The exclusion ships in 0.54.0; earlier releases still install the archive.
- (Optional, for real `ffuf` runs) at least one wordlist in `~/.vardrmap/wordlists`, named
  without the extension — `common.txt` backs `--wordlist common`. A symlink to an existing
  list (SecLists, dirb) is fine. None ship with VardrRunner, and a job names a wordlist
  rather than giving a path, so the file has to exist on the machine running the scan.

## Setup
```bash
git clone https://github.com/VardrSec/VardrRunner.git
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
- Default tests mock backend/scanner calls and isolate filesystem state in temporary
  directories. The CI coverage floor is 95%; test counts live in CI output, not this guide.
- Code changes require green relevant suites, lint and type checks before review.
  Docs-only changes require a diff and Markdown-link check.
- Add tests in the **same commit** as any behavior change.

### Smoke tests against the real binaries (opt-in)
Mocked subprocesses cannot show that a flag is
accepted or what a tool's exit code means — dalfox exits `1` when it *finds* something, which
mocked tests could never have revealed — so `tests/test_smoke_*.py` run the actual pinned
binaries through the real handlers.

```bash
VARDRRUNNER_SMOKE=1 pytest tests -m smoke -v
VARDRRUNNER_SMOKE=1 VARDRRUNNER_SMOKE_BIN_DIR=/path/to/bins pytest tests -m smoke -v
```
- **Opt-in.** Without `VARDRRUNNER_SMOKE=1` they skip, so a default `pytest` never launches a
  scanner and CI is unaffected.
- **Binary resolution.** The normal managed install or `PATH`, or a directory given by
  `VARDRRUNNER_SMOKE_BIN_DIR`. If a tool cannot be found the test skips and says how to
  install it; it does not fail.
- **No external targets.** The only target is a fixture server the test starts on
  `127.0.0.1`. Each test asserts that every request it caused came from loopback and stayed
  under a request ceiling, and every run has a 60-second timeout.
- They assert the real **argv** (the tool accepts every flag we pass), the real **exit
  behaviour** (clean, findings, unreachable) and the real **output parsing**.
- Run the smoke test whenever a tool's argv, exit-code handling or output parsing changes.
  dalfox's exit code `1` once shipped as a job failure through 1165 green mocked tests. A
  tool's exit code is documentation until you have seen it from the real binary, and **a
  report file existing is never evidence a run succeeded** — dalfox writes a valid empty
  report on an unreachable target.

### Wiring and guard tests
`tests/test_cli.py` is the only thing that checks Typer wiring, and
`mock.assert_called_once()` is not enough: it passes whether or not an option reaches the
command module. Two v0.28.0 fixes existed because nothing asserted kwargs — `--max-targets`
was implemented but never exposed, and `import ffuf` stayed registered after leaving
`SUPPORTED_TOOLS`. **When adding a flag, assert the kwarg it produces.**

Assert its range too. v0.28.1 fixed `--max-targets -1` silently disabling the target cap,
because every guard read `max_targets > 0`. For any option that gates a safety check, test
the out-of-range values, not only the happy path: a guard a stray minus sign can switch off
is worse than none, because the operator believes it is on.

### Combined platform acceptance

VardrMap's [three-repository harness](https://github.com/VardrSec/VardrMap/blob/main/scripts/integration/README.md)
builds the actual Gate binary, starts a disposable Map backend, and executes the real
Runner worker against bounded loopback fixtures. It supports SQLite or a freshly
migrated disposable PostgreSQL database. It checks assessment completeness, case
binding, evidence provenance and reporting; it does not verify hosted GitHub OAuth.
Use matching companion commits and deploy Map's assessment migration/endpoints before
publishing Runner's corresponding features. No new Runner environment variable is
required for shared playbook reads or case binding.

### What the tests cover
| File | Area |
|------|------|
| `tests/test_redaction.py` | the sanitization layer, adversarially: secret shapes, key spellings, hostile nesting, and whether it is actually wired into each boundary |
| `tests/test_errors.py` | failure taxonomy, status classification, stable wire values |
| `tests/test_policy.py` | advisory-warning parsing, incl. payloads that must not raise |
| `tests/test_job_policy.py` | stop-work, claim race, auth/backend failures, advisory display |
| `tests/test_config.py` | credential resolution, HTTPS validation, auth |
| `tests/test_credentials.py` | keychain resolution (env > keychain > file), login/logout, fallback |
| `tests/test_credentials_posture.py` | fail-closed login, the plaintext opt-in, and credential posture reporting |
| `tests/test_keychain.py` | the `keyring` wrapper itself, incl. graceful degradation |
| `tests/test_auth_commands.py` | `login_vardrmap`, `logout`, `whoami` |
| `tests/test_configs.py` | typed tool configs + `JobEnvelope` validation |
| `tests/test_handlers.py` | per-tool handlers + the registry |
| `tests/test_jobs.py` | job lifecycle, malformed envelope, claim race, execution core |
| `tests/test_pipelines.py` | pipeline definitions + the sequential runner (incl. continue-on-error, target cap) |
| `tests/test_pipeline.py` | `pipeline` command internals — `_run_stage`, `_StageResult`, the live TUI |
| `tests/test_run_commands.py` | direct `run` commands validate options like jobs do |
| `tests/test_imports.py` | `SUPPORTED_TOOLS` gating and file import |
| `tests/test_engagements.py` | `engagements` list + `scope` display |
| `tests/test_cli.py` | Typer wiring — every command route reaches its command module |
| `tests/test_api.py` | API client headers, HTTP methods + retry configuration |
| `tests/test_heartbeat.py` | heartbeat payload + posting |
| `tests/test_job_events.py` | lifecycle event emission |
| `tests/test_runner.py` | subprocess execution, process-tree timeouts, private temporary data, output capture, failures |
| `tests/test_journal.py` | SQLite schema/state-machine invariants, concurrency, hashing, manifests, and job integration |
| `tests/test_recovery.py` | interruption reconciliation, safe resume, ambiguous-upload refusal, backend isolation |
| `tests/test_audit.py` | sanitized list/show/export behavior and atomic export failures |
| `tests/test_identity.py` | stable UUID creation, concurrent first use, labels, corruption and IO failures |
| `tests/test_compatibility.py` | version parsing, capability/schema negotiation, legacy and malformed responses |
| `tests/test_resources.py` | bounded environment policy, disk reserve, and artifact ceilings |
| `tests/test_updates.py` | cached release checks and human/JSON command output |
| `tests/test_phase4_safety.py` | target shape, queue ceilings, compatibility gate, and engagement-safe concurrency |
| `tests/test_target_safety.py` | lexical target classification, local deny rules, single-pass queue auditing, and terminal escaping |
| `tests/test_setup.py` | interactive/non-interactive onboarding, option forwarding, idempotent state, and doctor gating |
| `tests/test_nmap.py` | nmap target normalization + profile + `run nmap` command (the suite opts in to the optional integration) |
| `tests/test_nmap_optional.py` | nmap is off by default in fresh interpreters, opt-in only, never installed in the image, and naabu never calls it |
| `tests/test_status.py` | tool detection + status output |
| `tests/test_doctor.py` | preflight checks, exit codes, and `--json` report |
| `tests/test_toolchain.py` | pinned installs: manifest validation, hash mismatch, single-member extraction, hostile archives, version checks, antivirus quarantine, receipts, tamper detection, PATH fallback |
| `tests/test_upload_provenance.py` | every tool's upload carries the producing `job_id` (files, services, and each katana/gau chunk) and sends none when there is no job |
| `tests/test_test_cases_command.py` | `test-cases draft|save`: never overwrites the review file, refuses literal credentials, needs `--reviewed`, accepts a BOM and a bare list, forwards server refusals |
| `tests/test_shell.py` | the interactive console: line splitting, `use`/`back` engagement defaults, error and Ctrl+C handling, refused `mcp`, restart notice after `update`, banner content (no key, offline, attributed quotes), completion tree, in-memory history |
| `tests/test_mcp_server.py` | the MCP server: tool surface and read/write hints, that no scope/auth/delete tool exists, output capping, severity/source/status filters, writes posting the right body, and 404/400/connection error mapping (skipped if the `mcp` extra is absent) |
| `tests/test_katana_gau.py` | katana/gau configs, argv construction (incl. `--` before gau domains), katana body stripping, tar.gz installs refusing links and directories, and that every installable tool is runnable |
| `tests/test_tools_commands.py` | `tools` commands, runner resolution of managed binaries, `doctor` tool checks, HTTPS-only size-capped asset download |

## Lint, format, and types
CI enforces all of these on every push and PR to `main`; run them locally before committing:
```bash
ruff check vardrrunner tests           # lint
ruff format --check vardrrunner tests  # formatting
mypy vardrrunner                       # type check
bandit -r vardrrunner -ll -q           # security scan (blocks on high/medium)
```
Autofix most issues with:
```bash
ruff check --fix vardrrunner tests && ruff format vardrrunner tests
```
Config lives in `pyproject.toml` (`[tool.ruff]`, `[tool.mypy]`).

### What CI runs
| Job | Contents |
|-----|----------|
| **Lint + types** | ruff check, ruff format --check, mypy, bandit — on Python 3.12 |
| **Tests** | pytest with `--cov-fail-under=95` on Ubuntu 3.10–3.14, plus Python 3.14 on Windows and macOS (tool installs, the OS keychain and file paths differ per OS) |
| **Dependency audit** | `pip-audit` against the installed dependency set |

Tests only run if the lint job passes (`needs: lint`).

## Branch & commit workflow
1. Branch off `main` for any non-trivial change.
2. Implement **with tests**; keep the suite green.
3. Update docs and `CHANGELOG.md` in the **same commit** (see `AGENTS.md`).
4. For a non-trivial design decision, add an ADR in `docs/adr/`.
5. Never add AI attribution (`Co-Authored-By` trailers or "Generated with" lines).
6. Open a PR; CI must pass before merge.

## Releasing
Releases are **tag-driven** — pushing a `vX.Y.Z` tag runs `release.yml` (verify tag and
source → build + SBOM → provenance attestation → GitHub Release, with opt-in PyPI). The
jobs are split by privilege and all third-party actions are pinned to commit SHAs. See
[ADR 0003](adr/0003-distribution-and-release.md).

1. In a PR: bump `__version__` in `vardrrunner/__init__.py` — the **single source of truth**
   (`pyproject.toml` reads it dynamically; the heartbeat reports it to the backend).
2. Roll `Unreleased` into a dated `## [X.Y.Z]` section in `CHANGELOG.md`; add a
   `changelog/vX.Y.Z.md` rollup note.
3. Merge the PR, then tag `main` and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.
4. The release workflow refuses a tag that does not exactly match `__version__`, then
   publishes a GitHub Release with the wheel, sdist, and SBOM.
   **PyPI** is opt-in: configure a [trusted publisher](https://docs.pypi.org/trusted-publishers/)
   for this repo's `release.yml` and set the repo variable `PYPI_PUBLISH=true`.

## Updating tool pins
Tool versions and hashes live in `vardrrunner/tool_manifest.json` and change **only**
through `scripts/pin_tools.py` and review (ADR 0014). Never hand-edit a hash.

```bash
export GITHUB_TOKEN=$(gh auth token)            # avoids GitHub API rate limits
python scripts/pin_tools.py --set httpx=1.13.0   # move one tool; omit --set to re-pin all
python scripts/pin_tools.py --check              # re-download every pin; exit 1 on drift
```

Pinning downloads every platform archive, hashes it locally, and only writes a pin when
that hash matches the tool's own published checksums file and the archive contains the
expected binary. The `Tool pin drift` workflow runs `--check` weekly and on any PR that
touches the manifest; a drifted hash means an upstream release changed after pinning and
must be investigated, not re-pinned. This is the only place the project downloads real
tool archives — the test suite never does.

## Configuration during development
The CLI reads/writes `~/.vardrmap/config.json`. To point at a local backend:
```bash
vardrrunner login              # enter http://localhost:8000 and a dev API key
```
`http://localhost` is accepted; any other host must be `https://` (the runner refuses to
send the key over plain HTTP). Delete `~/.vardrmap/config.json` to reset auth.

Or skip the file entirely with environment variables (handy for tests/containers):
```bash
export VARDRMAP_URL=http://localhost:8000
export VARDRMAP_API_KEY=vmap_devkey
export VARDRRUNNER_TOOL_TIMEOUT=300        # optional: per-tool run ceiling, seconds
export VARDRRUNNER_DENY_TARGETS=cloud_metadata,loopback   # optional: local deny rules
export VARDRRUNNER_ALLOW_DENIED_TARGETS=1  # optional: explicit, audited override
export VARDRUNNER_NAME=chicago-runner-1   # optional: heartbeat/display label override
export VARDRRUNNER_MAX_TARGETS=500          # queue target ceiling (1..100000)
export VARDRRUNNER_MAX_ARTIFACT_MB=100      # output ceiling before upload (1..10240)
export VARDRRUNNER_MAX_CONCURRENT_JOBS=1    # parallel engagement groups (1..8)
export VARDRRUNNER_MIN_FREE_DISK_MB=512     # required reserve before claim/execute
```
Env values take precedence over the config file.

VardrRunner runs only when invoked; `init` installs no startup service. Use `run`,
`pipeline run`, or one-shot `jobs run` explicitly, and `heartbeat` for a single
connectivity check. Environment credentials apply to the invoked command. A startup
service left by 0.47.0 or earlier is removed by hand; see `docs/cli.md`.

`VARDRRUNNER_TOOLS_DIR` optionally overrides only the managed binary/receipt directory; the container toolkit target uses `/opt/vardrtools`. See [container operations](container.md).

## NM-1 conformance

The later `tests/managed_tls_transport.py` reuses the existing API client for
Map's `tests/test_managed_tls.py` fixture. In addition to `NM2_RUNNER_SOURCE`,
that suite requires explicit `NM2_TLS_LOOPBACK=1` in the isolated child. It opens
only fixture-owned loopback listeners and verifies a disposable named certificate
against an explicit CA file. It changes no machine trust or runtime client defaults.
Fixture sessions use zero retries/redirects and bounded timeouts; certificate,
redirect, truncated-response, timeout and fixed-expiry failures remain fail-closed.
Neither the TLS fixture nor the inert probe starts Gate or proves deployed support,
real enrollment, public/VPN/fresh-host networking or distributed consumption/ACK.

The later NM-2 `tests/managed_http_probe.py` is a test-only probe for Map's opt-in
`tests/test_managed_http.py` harness. That ASGI harness transports JSON through
real synthetic JWT/local-cookie/CSRF authentication, managed issuance and current
control, then uses Runner's existing compiler, validator, durable ledger and launch
guard. Its final callback is inert: it starts no process and contacts no targets.
No product module imports the other application or loads this test helper.

The matching Map fixture selects this checkout with `NM2_RUNNER_SOURCE`. Run only
with a disposable profile/database, explicit child environment allowlist and dotenv
disabled. ASGI HTTPS and tool digests are synthetic; this is not TLS deployment,
tool provenance or Gate execution evidence. The test does not enable managed CLI,
MCP, production routes, trust provisioning or queue execution. Map consumption and
Runner consumption are not a distributed acknowledgement/exactly-once protocol.

`tests/test_authorization_contract.py`, `test_authorization_cli.py` and
`test_authorization_runtime.py` exercise synthetic signing vectors, negative
permission cases, transactional replay/fencing and the explicit standalone adapter.
They run in the normal regression suite without assessment traffic. The synthetic
fixture signing seed is public and must never be trusted outside tests.
VardrSec's explicit `tests/nm1_contract_acceptance.py` checks Map/standalone issuance;
`tests/nm1_guarded_execution.py` runs a separately built guarded Gate against an
ephemeral loopback fixture. Neither script modifies an installed Runner workspace.
Run that real guarded fixture whenever the projection argv or Gate handler changes;
the existing ffuf/dalfox smoke tests cover different adapters.
Runtime regressions include a valid shorter-lived contract and permission expiring
during private-file preparation, covering both preflight and ordinary Gate launches.
