# ADR 0010: Durable execution journal and conservative reconciliation

- **Status:** Accepted
- **Date:** 2026-08-18

## Context

A backend claim moves a job to `running`, but before this change the runner retained its
execution state only in memory. Process termination, host restart, or a lost response could
leave work stuck with no durable explanation. Blindly rerunning on startup is unsafe: POST
imports and job uploads do not currently accept an idempotency key, so a lost upload
response creates an unknowable outcome.

Small security teams need useful auditability and recovery without deploying another
database or operations stack.

## Decision

Use a local SQLite database in WAL mode as the execution source of truth. Insert a sanitized
run before backend claim and move it through an explicit forward-only state machine. A
partial unique index allows only one unfinished attempt for a job. Each operation uses a
short transaction and closes its connection.

Record operational provenance only: backend identity, job/engagement IDs, tool, sanitized
profile, target count, lifecycle timestamps, child PID, warnings, stable failure category,
and artifact metadata. Never record target values, credentials, VardrGate test cases,
headers, or request bodies.

At startup and before each daemon poll:

1. close pre-claim interruptions locally;
2. fail dead claimed executions that have no complete artifact;
3. upload a complete artifact when upload definitely never began;
4. retry the idempotent final status PATCH after a confirmed upload;
5. refuse to repeat an upload with an unknown outcome and close it as `upload_failed`.

Terminal runs write a second, atomic manifest beside their artifact. The journal remains
authoritative; the manifest is portable evidence. Audit exports are also atomic and pass
through centralized redaction.

## Consequences

- The runner fails closed if it cannot create or migrate the journal; it will not claim
  unaccounted work.
- Recovery can restore availability after common crashes without duplicating known
  non-idempotent requests.
- An ambiguous upload requires operator/backend-side review rather than automatic replay.
- SQLite adds no package dependency and is appropriate for one small-team worker host, but
  it is not a cross-host coordinator; backend claim remains the distributed lock.
