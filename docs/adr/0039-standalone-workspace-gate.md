# ADR 0039 — Explicit native standalone workspace Gate consumer

Status: isolated NM-3 implementation for review; no publication or live enrollment.

## Scope and reuse

Provide one meaningful standalone fixed-HTTP Gate journey using existing workspace
metadata, shared contracts/plan validator, `AuthorizationLedger`, guarded Gate
runtime, native `Control`/Windows Job, grants, journal and audit/export. Do not add
a second scanner, policy engine, persistence/evidence system or trust service.
Legacy connected commands, queue and MCP do not change.

The operator selects existing public standalone trust and signed approval/contract,
case, canonical plan and execution files. Shared bounded regular-file parsing is
also used by the reference file CLI. Actual identity/workspace, current runtime
time and the fixed supported capability are code-supplied; a payload cannot assert
managed status or choose its own key source. No private key, issuance, approval,
state bootstrap or online issuer enrollment is added. Terminal confirmation uses
existing signed permission; it does not sign or widen it. This explicit local
reference-trust model does not resist an account that owns/modifies all trusted
files and does not prove legal authorization.

## Execution and failure boundary

Require native Windows containment. Unsupported Linux/Docker refuse; reusing the
uncontrolled library/legacy path would lose local cancellation. Keep the existing
native control implementation. Its local stop callback reads the existing signed
authority snapshot and stop request; reads do not reacquire the grant launch
writer lock. A sticky bounded control lease and immutable minimum of signed
contract expiry, approval expiry, testing end and duration ceiling compose through
the existing final `launch_guard` check. Revalidation failures stop permission.

The existing ledger atomically consumes once. A trusted reservation callback
records journal phases only after consumption; deadline calculation follows that
callback. These writes are not one cross-table transaction: a crash or callback
failure leaves spent/uncertain permission, never an automatic retry/refund.
Unique local invocation keys avoid collision with a Map job; the actual signed
job/attempt/fence and hashes remain audit metadata. Backend identity is absent,
not a fabricated Map URL. Only confirmed native termination clears PID metadata;
constructor-time uncertain PIDs are retained. Output is exclusive and partial
files remain. Known success uses normal manifest/hash/audit without upload phases.
All unfinished standalone records are excluded from legacy Map recovery.

## Verification and limitations

Synthetic tests cover binding, files/trust, expiry/revocation, unavailable state,
single use, callback/journal failure, stop eligibility, uncertain PID, final
creation timing, partial evidence and no Map interaction. Mocked native control
is not real Windows proof. Explicit opt-in native acceptance reuses the pinned
NM-1 loopback target and requires a receipt-bound real Gate binary: five phases,
14 dispatches, preserved case binding, zero replay traffic and credential-free
output. Native cancellation/fault verification and full-suite/95% coverage on an
adequate environment remain applicable gates; no unavailable case is called passed.

This increment does not enable unattended Docker, remote control, issuer bootstrap,
arbitrary recon pipelines, global request-rate guarantees or Full/Mapless packaging.
Original Docker watchdog-hang remains failed/open and independent of this path.
