# 0044: Explicit one-shot local worker

Status: implemented; installed journey verification remains separate.

## Decision

The owner-authorized CE delivery uses the existing toolkit image and the
ADR 0043 native owner for one explicitly invoked standalone Gate job. Ordinary
Runner stays UID/GID 10001, capability-free, inert at startup. Its toolkit contains
the owner as a non-setuid executable and the existing authorization dependency.
Only an explicit distribution overlay starts PID 1 as UID 0 with SETUID, SETGID
and SETPCAP. The owner drops every capability before execution, retains UID 10000,
and starts the fixed local entrypoint at UID 10001 with the existing private fd3.
`--local` selects that entrypoint; arbitrary commands and persistent local mode
are refused. No service, Map daemon, signer or execution engine is introduced.

LocalAdmission is separate from Map Admission. The same credentialed PID-1
channel authenticates its fresh READY nonce directly; Map continues to match its
host-correlated admission nonce. The local object binds one runtime and one
validated signed plan. The native incarnation is bounded by the signed outer
permission/window/grants and existing reporting reserve. Its per-job LEASE still
ends at the earliest signed permission, grant or plan timeout; native DONE
retains only the existing finite idle/report interval. Reporting supplies no
extra execution authority.

The worker reads exactly six documents from read-only `/run/vardr-local`. The
private issuer volume is never mounted. The provisioned authority hash binds
the actual public signing key, workspace, runner and issuer identity. Existing
ledger state, signatures, grants, scope, time and consume-once checks govern the
job. The first native lease follows durable consumption; renewals and launch
revalidation cannot extend the original hard end. Existing local stop state and
grant revocation remain effective.

Healthy completion requires child drain, control-thread quiescence and the
native DONE acknowledgement before ledger completion and journal DONE. Unknown
completion keeps consumption and evidence for inspection. Runner and tools still
share UID 10001 under ADR 0043's trusted-host, immutable-image and closed-lineage
assumptions; this adds no full credential-isolation claim.

An optional writable `/exports` volume receives the existing redacted directory
export at `/exports/result` after terminal DONE. Export refusal returns status
`done`, `export_status: held` and Python exit 2; the unchanged native parent
maps any nonzero child exit to container exit 125. The successful journal run is
preserved and must never be replayed to retry delivery.
Root filesystem read-only `/exports` means no export was requested. Distribution
owns copying and retaining its one-off container and export volume.

## Limits

This activates only the fixed Gate profile. Dormant finite recon remains a
projection without an executor. Source and inert tests do not establish physical
containment or installed packaging acceptance. Existing native/Docker and
cross-platform delivery obligations remain unchanged.
