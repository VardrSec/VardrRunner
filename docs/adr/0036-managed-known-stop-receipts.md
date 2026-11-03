# ADR 0036 — Explicit managed known-stop receipts

Status: local unregistered prototype; independent review and native Windows gates open.

A controlled managed attempt may stop without producing a complete artifact.
Previously the preclaim facade could retain this state but could not acknowledge
its exact known stop. Add `ManagedRun.report_stop` as a separate one-shot lane.
It does not fabricate an empty result or reuse the ordinary completion adapter.

The in-memory report right is sourced only from the existing native adapter's
`ExecutionStopped` with literal boolean `confirmed=True` and an allowlisted fixed
cause. It is established only after a durable marker write succeeds. Unknown
containment, arbitrary errors, truthy non-booleans, expired permission or a stale
PID cannot establish it. Lost proof after a crash is not reconstructed.

Observer-recorded PIDs remain audit metadata even for confirmed stops. The stop
intent snapshots this metadata for consistency; no PID is probed or signaled,
and neither existence nor absence establishes termination. Partial files remain
local and untouched. Local and remote stop requests remain distinct from native
confirmation and from server acknowledgement.

Before its only RPC, Runner reserves an additive intent bound to the original
claim owner, consumed/acknowledged contract, job/origin/Runner, contract hash,
attempt/fence, fixed cause and outcome. Local/remote emergency stop maps to
cancelled; lease/permission expiry, unavailable control cap, timeout and retained
descendants after exit map to failed. Both retain all spent allowances.

The exact server stop receipt can close the matching local ledger/journal. A lost
or malformed reply, inconsistent ownership or failed write holds the attempt
without retry, new claim or native execution. Explicit authenticated stop
inspection can observe the same immutable receipt after loss; missing receipts
never infer a stop, release capacity or authorize another send. Ordinary managed
recovery remains deferred and cannot reconstruct capabilities or stop proof.

Map accepts only the exact consumed owned contract and authenticated termination
assertion. This is not independent remote OS attestation. It atomically retains
one immutable stop receipt and releases only concurrency capacity, with no refund
of approval ordinal, represented targets or allocated duration. An existing result
protocol cannot be overwritten with a stop. This remains an unregistered library
operation: no CLI/queue/worker activation, enrollment or production route.

Portable tests use inert handlers and inspect protocol/journal decisions only.
The existing real Windows local-stop fixture retains its PID assertion, and an
additional opt-in native stop-receipt test is deferred to Papachin. Neither cloud
success nor the owner's backup waiver closes Windows, security, CI or review gates.
