# ADR 0018: Opt-in platform readiness and offline diagnostics

Status: Accepted, 2026-10-25

## Decision

Reuse Runner's existing doctor instead of creating a diagnostics engine in the
future VardrSec Compose distribution. Keep local execution, credentials, jobs and
result transport in Runner; Map exposes readiness and will display reported
status, and Gate remains the authorization-testing engine.

Add `doctor --platform`, which requests Map's value-free v1 `/ready` contract
through `api.py`. Check its component/schema, allowed database/migration states,
and agreement between HTTP status and reported readiness. Read 503 as unready;
never turn missing, redirected, unsupported or inconsistent proof into health.
Use no retries or redirect following for this probe, and bounded HTTP waits.
Only declared status enums enter the report; ignore free-form server data.

The flag is opt-in. Ordinary doctor calls keep their older-Map compatibility.
Keep API authentication as a separate existing check; public readiness does not
establish a valid runner credential or access to any engagement.

Add `doctor --offline` to skip release discovery while still contacting the
configured backend. Preserve normal release checks by default. Make the limited
meaning explicit in help and documentation; it does not promise zero networking.

## Consequences

Platform checks require Map ADR 0003; missing support fails only when requested.
The existing JSON report and nonzero failure exit are reused. No setup service,
polling loop, scan, automatic repair, installation, schema migration, database
coupling or Docker socket access is introduced. Schema-marker readiness is not
a complete installation, UI, privacy, release-compatibility or workflow audit.

Compose packaging, local authentication, component-version manifests and Map's
new status display remain later slices with their own acceptance criteria.
