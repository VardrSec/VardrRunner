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
