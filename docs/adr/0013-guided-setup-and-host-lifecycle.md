# ADR 0013: Guided setup and verified host lifecycle

- **Status:** Accepted
- **Date:** 2026-08-18

## Context

The runner had secure individual commands, but successful small-team deployment still
required knowing their correct order. In particular, a service could be installed while
authentication existed only in the current shell, then restart without credentials. Two
simultaneous daemon starts could also race while replacing the PID file.

## Decision

Provide one orchestration command, `vardrrunner init`, that composes existing auth,
identity, journal, service, and doctor behavior. Keep the underlying modules authoritative;
the setup command does not implement alternate credential storage or a weaker health check.
Interactive mode prompts for human decisions. Non-interactive mode never prompts and fails
on missing input.

Treat setup as incomplete until `doctor` succeeds. The production profile requires native
supervision and the existing strict credential/disk/durable-state checks.

Before service installation, require either authentication persisted in the keychain/config
or an explicit Linux systemd environment file. Never inspect, copy, or display that file's
secret contents.

Write config atomically. Claim daemon PID ownership with exclusive creation, durable flush,
and stale-state replacement; bound poll and heartbeat intervals at both CLI and command
boundaries. Roll back a newly stored keychain key when URL persistence fails.

## Consequences

- A new host has one documented path from installation to a verified worker.
- Provisioning systems get deterministic behavior without hidden prompts.
- Environment-only service deployments must provide an operator-managed systemd env file;
  macOS/Windows services need a keychain or explicitly accepted config credential.
- `init` may stop after partially completing safe steps (for example identity creation)
  when doctor finds a missing tool. Re-running is idempotent and resumes from existing state.
- PID ownership remains process-local coordination. Cross-host job ownership continues to
  rely on the backend's atomic claim endpoint.

## Alternatives considered

- A second setup-specific credential store was rejected because it would duplicate and
  weaken the existing resolution policy.
- Automatically writing an env file was rejected because it would create a new plaintext
  secret artifact and force the runner to own its lifecycle.
- Treating doctor failures as warnings was rejected because setup would report success for
  a host that cannot perform or survive its intended workload.
