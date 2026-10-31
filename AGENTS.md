# VardrRunner — agent instructions

Shared rules for every coding agent (Claude Code imports this file from `CLAUDE.md`;
Codex reads it directly). They must hold even when this repository is cloned on its own.

VardrRunner is the local execution engine of the VardrSec platform: a Python CLI
(Typer + Rich) that runs security tooling **only when invoked** and syncs results to
VardrMap **over HTTP only** (JSON on the wire, no code coupling). `jobs run` polls once,
claims atomically, executes locally, streams events, uploads and heartbeats.

Runner owns explicit tool execution, orchestration, credentials, `doctor` diagnostics
and result transport. It does **not** own installation or lifecycle (Compose, HTTPS,
backup, updates — the VardrSec repo), the UI or engagement data (VardrMap), or
authorization-assessment logic (VardrGate, invoked as a subprocess). Do not add those here.

Where to look: [`docs/architecture.md`](docs/architecture.md) (package layout, job
lifecycle, trust boundaries, design invariants), [`docs/cli.md`](docs/cli.md)
(every command and flag), [`docs/development.md`](docs/development.md) (setup, tests,
smoke tests, CI, releases, tool pins), [`docs/container.md`](docs/container.md),
[`docs/adr/`](docs/adr/). Current release priorities: `docs/community-alpha.md` in the
VardrSec repository.

## Safety floor
- Execute tools only on explicit operator invocation, against authorized targets.
  Tests use mocks or bounded loopback fixtures.
- Never log, print, commit or report the API key, identity tokens or credentials.
- No force-push, history rewrite, release tag, package/image publication or
  deployment without explicit authorization.
- `git fetch && git status -sb` and `gh run list --limit 1` before starting work.
- No AI attribution: no `Co-Authored-By` trailers or "Generated with" lines.

## Execution boundaries
- **Never reintroduce startup or background execution** (ADR 0016): no service
  install, sign-in task, detached worker or polling loop, opt-in or not. Queued jobs
  run only from an explicit `jobs run`; starting a container never starts a scan.
- **Subprocesses:** argv lists only, never `shell=True` or shell strings built from
  server data. `runner.program()` is the only way a command gets its executable.
  Every tool runs with an empty stdin, a timeout that kills the whole process tree,
  and `config.tool_environment()` — an allowlist, never the full environment, which
  holds `VARDRMAP_API_KEY` and identity tokens (ADR 0022). A missing, failed or
  timed-out tool fails the job with a reason; never skip silently or hang.
- **All backend data is untrusted:** validate job payloads into typed configs
  (`configs.py`, `ConfigError`) and normalize targets before they reach a subprocess.
  A wordlist is a **name**, never a path (`runner.resolve_wordlist` confines it to
  `~/.vardrmap/wordlists`), so the backend cannot make ffuf read a local file.
- **Advisory stays advisory:** scope, window and target-classification findings warn;
  only stop-work and explicitly configured local deny rules block. The target cap
  applies even under `--yes`; test out-of-range values of any safety option.
- `doctor --platform` (ADR 0018) reads Map's value-free `GET /ready`; it runs no
  scans, applies no migrations, repairs nothing and never prints the key. Do not
  duplicate this logic in the distribution or Map.
- `update` installs only when the operator runs it; nothing else installs software
  (ADR 0012 amendment). `init` never installs a startup service.
- `test-cases draft|save`: the review file is created exclusively (never
  overwritten), literal credentials are refused, and `save` requires `--reviewed`.
- **Containerized Runner** (ADR 0019): UID/GID 10001, no added capabilities, no
  Docker socket, no published ports. Raw-packet modes are unsupported — never "fix"
  that with `--privileged`.

## Credentials and transport
- Key sources, in order: `VARDRMAP_API_KEY`, OS keychain, then
  `~/.vardrmap/config.json` only with explicit `--allow-plaintext-credentials`.
  `login` fails closed without a keychain (ADR 0009). Add no insecure fallback;
  never bake keys into images or Compose files.
- Backend URL must be HTTPS (except localhost); `config.validate_api_url` enforces it
  on login and every authenticated call.
- `api.py` is the **only** module that talks HTTP.
- **Everything crossing a trust boundary goes through `redaction.py`** — job events,
  failure reasons, logs, errors. Never format a raw exception or payload into output;
  use `redact_text`/`redact_exception`/`redact`/`redact_url` (ADR 0008).
- The interactive shell keeps history in memory only (a typed key must never reach
  disk), refuses `mcp`, and its banner never reads the keychain (ADR 0017).

## Tool integrity
- **Never execute a managed tool that fails hash verification**, and never fall back
  to a `PATH` copy when one does. Hashes come from the packaged `tool_manifest.json`,
  never the download site, and change only via `scripts/pin_tools.py` (ADR 0014).
- Native Gau install/execution is refused; `--all` skips it with no `PATH` fallback
  (ADR 0021). Container source-build substitutions (Katana ADR 0020; DNSx, Naabu)
  record source and build provenance; a source-build receipt is development
  provenance, not authenticated release provenance.

## MCP server (ADR 0015)
- Read tools plus guarded writes. No scope, authorization or delete tool.
- **Never add a tool that saves a VardrGate case or writes a client deliverable** —
  those are assertions only the operator can make. `propose_*` tools are allowed
  because a proposal is inert; there is deliberately **no approve tool**.
- Prompts are instruction text only: never pre-fetch engagement data into one
  (target-controlled strings would land in the trusted prompt position). A prompt may
  only name tools that exist; a test enforces it.
- Methodology checklists cannot represent coverage: `status`/`covered`/`done`/
  `coverage` keys and the old `evidence` field are refused. `method` says how an item
  is tested, never whether it has been.
- Scanner output is a candidate: handlers upload it as the tool wrote it and never
  re-grade a match, rename a tier or decide what is confirmed.

## Contracts with Map and Gate
- Runner calls a separately deployed VardrMap. Changing an endpoint or response key
  it reads requires checking which Map version serves it and recording the
  requirement in the changelog. Deploy the matching Map migration/endpoints before
  publishing the dependent Runner feature.
- Playbook and evidence reads (`list_api_playbooks`, `get_api_playbook`,
  `list_evidence`) need full-scope credentials; malformed reads raise, never render
  as an empty inventory. Keep case-sensitive identity filters and bounded pagination;
  associate proof by job/case/identity metadata, not similar titles.
- **Gate credential references** resolve only when the operator approved them with
  `credentials approve` for the engagement and every origin the case contacts; a case
  containing `${` is refused; both checks run before claim. Never add a path that
  resolves an unapproved reference. Always invoke Gate with `--literal-job` (ADR 0023).
- Compare the polled spec with the spec returned by claim; a changed case fails for
  operator review (older backends may omit the claim spec).
- `case_hash` = SHA-256 of the unresolved reviewed spec as sorted compact Python JSON
  with default ASCII escaping. Never include resolved credentials; preserve it during
  recovery. Case binding is correlation, not signed attestation.
- Declared identity preflight requires Gate's `--require-identity-preflight`. Inspect
  exit 3 only with complete consistent diagnostics and no resource executions or
  findings; upload the safe artifact, then fail the job, and preserve that
  finalization intent across crash recovery. Probes are not authorization evidence.
- Job completion and Map's assessment completeness are separate; legacy unbound
  results stay inconclusive, and conclusive results establish neither independent
  verification nor full coverage.
- ffuf probes each target first (an unreachable target can yield an exit-0 empty
  report). dalfox needs a valid report and a consistent exit code: 0 without
  findings, 1 with findings; anything else fails.
- Recovery never replays an ambiguous upload, and no queue work is claimed unless
  local durable state is writable.

## Development rules
- Behavior changes ship tests (95% coverage floor) and update the relevant docs
  (`docs/cli.md`, `docs/architecture.md`, `docs/development.md`) **and**
  `CHANGELOG.md` plus a note in `changelog/` in the same commit. Use an unreleased
  note until a version is assigned; never invent or renumber releases.
- When adding a flag, assert the kwarg it produces in `tests/test_cli.py`. When
  changing a tool's argv, exit handling or parsing, run its opt-in smoke test
  (`VARDRRUNNER_SMOKE=1`); see `docs/development.md`.
- Code changes: `ruff check vardrrunner tests`, `ruff format --check vardrrunner tests`,
  `mypy vardrrunner`, `pytest tests --cov=vardrrunner --cov-fail-under=95`.
  Docs-only changes: review the diff, check Markdown links and `git diff --check`.
- Non-trivial design decisions get an ADR in `docs/adr/`.
