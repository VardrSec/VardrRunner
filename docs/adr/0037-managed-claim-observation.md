# ADR 0037 — Explicit claim observation after capability loss

Status: local unregistered prototype; independent review and Windows gates open.

A crash can lose the in-memory control capability while retaining a claim intent
or a one-shot result/stop intent. Capability-bound inspection alone cannot resolve
this case. Add an explicit read-only observation using the original enrolled API
principal, Runner identity and plan/case/association fingerprints. No token,
signed envelope, artifact, lease or credential reference is returned.

Map authenticates the actual currently authorized enrolled key and membership,
then reads under the existing engagement/job/execution/contract/approval lock order.
Approval expiry or revocation does not erase historical receipts. Revoked
enrollment or a different key does not authorize observation. The operation changes
no business state, counters, fees, reservation or lease. Existing clock/authentication
telemetry retains its established behavior. No database migration is added.

Runner validates the exact bounded response and atomically records a separate
observation snapshot after checking the source journal has not changed. A known
claim or immutable receipt cannot disappear or change in a later snapshot.
Absence is only a snapshot: an earlier request could still commit after it. It
never permits another claim, resend, native execution or capacity release.

Generic server terminal metadata cannot establish local native proof. Explicit
reconciliation can close only an existing exact durable result/stop intent using
its existing receipt checks. It never reconstructs a report right from a PID or
partial file, probes or signals a PID, submits evidence or retries a finish. PIDs
remain audit metadata. Ordinary recovery continues to defer managed work.

This remains library-only, with fixture-only HTTP adapters. No production route,
CLI command, worker, enrollment, credential provisioning or runtime activation is
added. Tests use inert handlers, authenticated ASGI, verified loopback TLS and
PostgreSQL under administrator and restricted roles. Native Windows containment
and independent review remain distinct outstanding gates. Backup is waived by
the owner; migration review and CI/security gates remain required.
