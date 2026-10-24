# ADR 0016: Manual invocation and removal of startup workers

- **Status:** Accepted
- **Date:** 2026-10-17

## Context

A native sign-in service launched the runner daemon, which polled pending jobs and
reconciled interrupted execution. Installing or setting up a scanning tool could thus
lead to scans at the next sign-in without a new operator action. An opt-in service
command still permits this accident when mistaken for program/dependency installation.

## Decision

VardrRunner runs only when invoked, like an ordinary command-line scanning program.
Remove native service creation, detached worker creation, and the continuous queue loop.
`service install` and `daemon start` remain as compatibility errors, with no opt-in flag
or configuration escape hatch. Old options are hidden but accepted for migration errors.
`init` rejects legacy service options before authentication or local state changes.
Production health checks no longer require a daemon or service.

Keep manual `run`, `pipeline run`, and one-shot `jobs run`, including recovery during
explicit queue execution. Keep single `heartbeat`, legacy `daemon stop|status`, and
`service uninstall|status`. Service plans can only inspect or remove old registrations.

This supersedes the service-management portions of ADR 0011 and the service-setup and
background-health requirements of ADR 0013. Their identity and secure setup decisions
remain in effect.

## Consequences

Neither downloading, setup, nor a former service command can enable startup or background
scans. Queue jobs may still exist on the backend; the runner processes them only when
explicitly invoked. This intentionally removes unattended worker support.

An upgrade does not stop already-running old code or remove OS registrations. Operators
must stop legacy daemons and uninstall their services. Old registrations that call the
updated daemon entry point receive an error and cannot launch a worker.

Tests verify rejected commands have no execution side effects and preserve cleanup and
manual queue behavior across platforms.

## Amendment (2026-10-24): cleanup commands removed

The compatibility errors and cleanup commands kept above served one release cycle. v0.51.0
removes them: `daemon` and `service` are unknown commands, and the hidden `init` options
`--install-service`, `--start-service`/`--no-start-service` and `--env-file` are unknown
options. Nothing changes in behavior, because none of them could start work. `doctor` no
longer checks for a daemon PID file. A one-shot `jobs run` no longer carries the daemon's
60-second stop-work recheck: a halted engagement's remaining jobs are skipped for the rest of
the run, and the next run asks again. Leftover registrations are removed by hand, as
documented in `docs/cli.md`.
