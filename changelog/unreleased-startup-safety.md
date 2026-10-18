# Unreleased — manual setup and explicit background execution opt-in

Previously, a service installed at sign-in immediately polled the backend, reconciled
interrupted work, and executed pending jobs. A backlog could therefore produce unexpected
scans each time the operator signed in.

`daemon start` now sends heartbeats only. `daemon start --run-jobs` explicitly enables
queue polling, execution, and recovery for that process. Detached startup preserves the
choice. `service install` creates a heartbeat-only service; `service install --run-jobs`
persists the opt-in in the native service command on Windows, macOS, and Linux.

`init` never offers or installs background startup unless `--install-service` is explicitly
passed. Accepting every setup prompt or using `--production` cannot install a service.
`--env-file` now requires `--install-service` and fails before setup changes if omitted.
Package installation does not register a startup service. Explicit service installation
prints that it enables background startup and explains how to remove it.
Explicit manual commands such as `jobs run`, `run`, and `pipeline run` remain unchanged.

## Upgrade

- For manual-only operation, remove an older startup service with `service uninstall`.
  Package upgrades and normal setup do not remove existing service registrations.
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
