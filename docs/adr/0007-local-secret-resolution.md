# ADR 0007 — Local secret resolution for VardrGate identities

- **Status:** Accepted
- **Date:** 2026-07-09

## Context
VardrGate API authorization tests must call an endpoint as several real
identities, which means real bearer tokens / API keys. If those secrets are
embedded in the job the backend creates, they end up in the control-plane
database, in job payloads on the wire, and in any logs of the queue — exactly
what an API-security product must not do. The enterprise plan is explicit:
"Resolve secrets locally from approved vaults" and "keep credentials out of code
and logs."

## Decision
A `vardrgate_api_test` job carries a **reference** to each secret, not the secret
itself. Each identity credential may specify at most one of:

- `value` — a literal (kept for local runs and tests)
- `value_env` — an environment variable name, read on the runner
- `value_keychain` — an account looked up in the OS keychain

The handler resolves references to real values **locally, in `execute`, just
before invoking the `vardrgate` binary** — on a deep copy, so the original job is
never mutated. A referenced-but-missing secret raises `ConfigError`, which the
lifecycle turns into a failed job (never a silent run with a blank credential).
Specifying more than one source is also a `ConfigError`.

The resolved value lives only in the private temp job file for the duration of the run;
VardrGate redacts credential values from its result by construction, so the uploaded
artifact contains no secret.

> **Amendment (2026-08-21, v0.36.1).** The VardrGate CLI still requires a path, so the
> boundary cannot be memory-only without changing that external contract. VardrRunner now
> writes the envelope exclusively inside a private temporary directory (`0700` directory
> and `0600` file on POSIX), removes the directory after execution, and treats cleanup
> failure after an otherwise successful run as a job failure. CLI startup removes abandoned
> runner-owned directories after hard crashes. Cleanup validates the exact name, owner PID,
> path boundary, and file type and never traverses symlinks or junctions.

## Consequences
- The backend stores only references — no plaintext identity secrets in the
  database, job payloads, or logs.
- Operators provision secrets on the runner via environment or the OS keychain,
  the same trust boundary already used for the backend API key.
- Vault / cloud secret-manager providers can be added later as additional
  reference kinds (`value_vault`, …) behind the same resolution seam without
  changing the job schema.
- Literal `value` remains supported for local development and CI, so the change
  is backward compatible.
- A hard crash may leave encrypted-in-transit but plaintext-at-rest job data until the next
  VardrRunner invocation; private permissions minimize exposure and startup cleanup bounds
  persistence without deleting an active process's data.
