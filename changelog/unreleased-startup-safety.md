# Unreleased — explicit automatic scan opt-in

Previously, a service installed at sign-in immediately polled the backend, reconciled
interrupted work, and executed pending jobs. A backlog could therefore produce unexpected
scans each time the operator signed in.

`daemon start` now sends heartbeats only. `daemon start --run-jobs` explicitly enables
queue polling, execution, and recovery for that process. Detached startup preserves the
choice. `service install` creates a heartbeat-only service; `service install --run-jobs`
persists the opt-in in the native service command on Windows, macOS, and Linux.

`init` never opts in to scan execution. Its interactive service prompt defaults to No,
including under `--production`. Package installation does not register a startup service.
Explicit manual commands such as `jobs run`, `run`, and `pipeline run` remain unchanged.

## Upgrade

- Stop existing daemons before upgrading and restart with the updated executable.
- Legacy services without `--run-jobs` then send heartbeats only. Already-running old
  processes retain their old behavior until stopped.
- For intentional unattended scanning, stop the daemon and reinstall the service with
  `--run-jobs`; retain the Linux `--env-file` argument if one was configured.
- To revoke a previously configured opt-in, stop the daemon and reinstall without the
  flag. To remove sign-in startup entirely, use `service uninstall`.
- Queued jobs, interrupted journal entries, and scan artifacts are preserved.

No backend endpoint, request, or response contract changes. Heartbeat-only mode avoids
`/jobs/pending` entirely because that endpoint can materialize due schedules. Existing
manual queue commands retain their behavior.
