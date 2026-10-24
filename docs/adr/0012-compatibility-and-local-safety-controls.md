# ADR 0012: Compatibility negotiation and local execution safety controls

- **Status:** Accepted
- **Date:** 2026-08-18

## Context

An unattended runner must not claim work it cannot interpret or safely accommodate. Small
teams also need bounded parallelism without deploying a scheduler, while backend upgrades
must not force lockstep runner releases. Scope enforcement is deliberately advisory and
must remain separate from local input/resource safety.

## Decision

Advertise runner version, supported job-schema versions, and named capabilities in every
heartbeat. Treat absent compatibility metadata as a legacy backend. An optional response
may set minimum/maximum runner versions, required capabilities, and accepted job schemas.
Malformed metadata warns; a definite mismatch blocks queue claims while heartbeats continue.

Require each parsed queue envelope to use a supported integer schema version, defaulting an
absent field to v1 for compatibility. Validate target shape at every source boundary,
including backend collections and local pipeline handoffs.

Enforce bounded local limits before claim/upload: target count, free-disk reserve, and
artifact size. Make queue concurrency opt-in, cap it at eight, group work by engagement,
and allocate one API client per worker. This guarantees sequential execution within one
engagement without introducing a distributed lock.

Keep release discovery explicit and read-only: `update check` fetches public package
metadata through `api.py`, writes a 24-hour atomic cache, and never installs software.

> **Amendment (2026-08-21, v0.36.1).** Queue target resolution supplies raw collected
> values to the lifecycle, which performs shape validation, statistics, classification,
> warnings, and local deny evaluation exactly once. Statistics describe shape-valid input
> before deny filtering; tool-specific normalization may then de-duplicate equivalent hosts.
> Concurrent output directories are allocated atomically. Cooperative shutdown finishes
> active work but checks the stop signal before every later job, preventing new claims from
> an already-fetched group.

> **Amendment (2026-10-24, unreleased).** `status` also runs the cached release check,
> because an operator asking for status is an explicit request and an outdated runner is
> part of where they stand. It shares `update check`'s 24-hour cache, so it makes at most one
> registry request a day. A failed check is a warning that never fails the command.
> `--version` stays offline and only reports a newer release already cached. Both name the
> upgrade command for the detected installer (pipx, uv, or pip in a virtualenv) and never
> run it. Release discovery is still never automatic: no other command contacts the
> registry, and nothing checks in the background.

> **Amendment (2026-10-24, v0.50.0) — operator-run update.** A day-old cache told an
> operator "Up to date" hours after a release, and naming a command they then had to retype
> added nothing. So:
>
> - **`vardrrunner update`** (bare) installs the newest release in the foreground. It runs
>   only `pipx upgrade vardrrunner`, resolved with `shutil.which` and passed as an argv
>   (no shell), and only for a pipx install: upgrading from inside the running pipx
>   executable is verified on Windows. A plain-virtualenv pip upgrade would have to replace
>   the running `vardrrunner.exe`, and uv is unverified, so those installs get the command
>   printed and exit 1. It reports success only when a fresh, isolated (`-I`) interpreter
>   reads the release it was upgrading to; anything else is reported with the installer's
>   output and a non-zero exit.
> - **`update`, `update check` and `doctor` always ask the registry** (and refresh the cache).
>   `update check --force` is accepted and does nothing extra. `doctor` reports a newer
>   release as a `version` WARN naming `vardrrunner update` (5-second timeout); an unreachable
>   registry is an OK line saying the check could not run, so it never makes a machine look
>   unhealthy. `status` keeps the 24-hour cache and `--version` stays offline.
> - Update notices everywhere now say `Run vardrrunner update`.
>
> This does not reverse the rejection of *automatic* self-update below: nothing installs
> unless the operator types `vardrrunner update`, and nothing runs in the background.

## Consequences

- Old backends remain usable and can adopt compatibility constraints incrementally.
- A hard mismatch preserves availability signals but intentionally sacrifices queue
  throughput until either side becomes compatible.
- Concurrency improves throughput across engagements but remains process-local; multiple
  runner installations still rely on the backend's atomic claim operation.
- Local shape/resource failures are safety controls, not scope decisions. Authorization,
  scope, and testing-window findings remain advisory; stop-work remains the sole backend
  policy block.
- Artifacts rejected for size remain local and are not uploaded automatically.

## Alternatives considered

- Lockstep runner/backend releases were rejected because they make small-team operations
  brittle and turn ordinary backend deploys into coordinated fleet events.
- Global parallel execution was rejected because simultaneous scans within one engagement
  increase operational risk and make evidence harder to interpret.
- Automatic self-update was rejected because unattended code installation changes the
  host without an operator-controlled package-management or rollback decision.
