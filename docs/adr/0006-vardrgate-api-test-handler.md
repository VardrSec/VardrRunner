# ADR 0006 — VardrGate as a job type, executed via binary contract

- **Status:** Accepted
- **Date:** 2026-07-08

## Context
VardrGate is a VardrSec API authorization test engine. Its enterprise plan calls
for VardrRunner to be its execution plane rather than building a second agent:
VardrRunner already polls a backend, claims jobs atomically, streams events,
uploads results, and heartbeats. VardrGate now exposes a runner-compatible job
queue (`GET /jobs/pending`, `POST /jobs/{id}/claim`, `PATCH /jobs/{id}`,
`POST /jobs/{id}/events`, `POST /jobs/{id}/upload`, `POST /runner/heartbeat`)
whose shapes match this runner's existing `api.py` client.

Two things about a VardrGate job differ from the recon tools the handler registry
was built for (ADR 0002):

1. It is **self-contained** — the test case and execution settings arrive inside
   the job config; there is nothing to resolve from program scope or recon.
2. Its **result belongs to the job**, not to a program's import store.

## Decision
Add a `vardrgate_api_test` handler to the existing registry rather than a new
execution path.

- **Binary contract, not shared code.** The handler shells out to
  `vardrgate run --job <file> --out <result>`. VardrRunner imports no VardrGate
  internals; the coupling is the CLI plus JSON on disk. `vardrgate` is added to
  the subprocess allowlist (`ALLOWED_TOOLS["vardrgate_api_test"] = "vardrgate"`),
  keeping the "never run un-allowlisted executables" guarantee.
- **Fit the lifecycle.** `resolve_targets` returns the endpoint URL from the test
  case as a single synthetic target so the uniform lifecycle (claim → events →
  upload → done/fail) proceeds unchanged. `execute` writes the job envelope and
  runs the binary; `upload` posts the sanitized result to
  `POST /jobs/{id}/upload`.
- **`upload()` gains an optional `job_id`.** Recon handlers attach results to a
  program and ignore it; VardrGate needs the job id to attach the result to the
  originating job. The parameter defaults to `""`, so existing handlers and call
  sites are untouched.

## Consequences
- Adding VardrGate stayed a one-file-per-concern change (config, handler,
  runner helper) on top of the existing registry — no new lifecycle.
- The `vardrgate` binary is an optional runtime requirement, needed only for this
  job type; `status`/`doctor` report its availability like any other tool.
- Credential redaction and SSRF protection remain VardrGate's responsibility; the
  runner only transports the sanitized result.

## Alternatives considered
- **A separate VardrGate agent / execution path** — rejected; duplicates the
  poll/claim/event/upload machinery the registry already provides.
- **Importing VardrGate as a library** — rejected; it is a Go program, and the
  binary/JSON contract keeps the two products decoupled and independently
  releasable.

## Amendment: identity preflight (v0.47.0, decided 2026-10-12)

Cases may declare reviewed identity preflight checks. Runner resolves credential
references locally as before and passes `--require-identity-preflight` so an older
Gate binary rejects the flag before sending target traffic. Gate's safe report
contains one bounded diagnostic per configured identity; it contains no session
response body, headers, matched values or raw network errors. Runner validates
the diagnostics and exit code together before binding the artifact to the
unresolved case hash.

Exit 3 with failed preflight and empty executions/findings is retained and
uploaded, then the job is marked failed. It must not become a successful empty
scan. The handler exposes a completion error for this prerequisite failure;
the execution journal persists that failure during finalization, and recovery
retries failed finalization rather than converting it to done. Missing or
contradictory reports fail without treating the prerequisite as satisfied.

Cases without preflight retain the existing binary contract. This feature
checks a session at one moment; it adds no login, refresh or automatic retries.
The matching Map backend and both companion binaries must be deployed/upgraded
before operators author these cases. See [CLI reference](../cli.md).
