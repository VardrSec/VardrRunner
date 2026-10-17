# ADR 0016 — Require explicit daemon scan execution opt-in

Status: accepted

## Context

The native sign-in service previously launched `daemon start`, which immediately
reconciled interrupted jobs and consumed the pending queue. Old queued jobs could
therefore start scans when an operator signed in. Changing only setup defaults would
leave existing service definitions executing scans after upgrades.

## Decision

`daemon start` sends heartbeats by default. Queue polling, claims, execution, and recovery
require `--run-jobs`. The flag applies to the current invocation and propagates to a
detached child. `service install --run-jobs` explicitly records it in the native service
definition; service installation and guided setup otherwise produce heartbeat-only
services. The setup service prompt defaults to No, including in production mode.

The guard precedes all queue/recovery access, because `/jobs/pending` can materialize
scheduled jobs. Existing manual execution commands retain their behavior. No backend
contract or persisted configuration key changes.

## Consequences

Legacy service commands become heartbeat-only when launched with the upgraded executable.
An already-running old process must be stopped. Intentional unattended operators must
explicitly reinstall their service with `--run-jobs`, retaining any Linux environment-file
argument. Heartbeats still report runner availability, not permission to execute jobs.
Queued jobs and interrupted evidence remain available for deliberate execution or review.
