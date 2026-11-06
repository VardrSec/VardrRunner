# Explicit managed worker

The separate worker composes the existing managed authorization, grants, budgets,
Gate execution and receipt protocols. It is inactive during ordinary Runner
startup. It does not change `jobs run`, direct commands or Mapless/standalone
execution, and it does not provide a second scanner.

The initial implementation permits **one physical attempt per admitted container**.
It can poll for approved pending work during a finite startup wait; it does not
claim sequential jobs, schedule scans or restart itself. Deployment, operator
enablement, public admission and host reconciliation belong to the distribution.
Actual Linux/Docker and Windows Docker Desktop acceptance remains separate from
the inert orchestration tests.

## Entry and authority

The fixed worker entrypoint is `python -I -m vardrrunner.managed_worker`, with no
container command override. Its public admission and trust files default to
`/run/vardr-worker-admission/admission.json` and `trust.json` in that same protected
read-only directory. Missing admission may be awaited; malformed or expired data
is refused immediately. The operator configures these profile values before start:

| Environment variable | Default | Accepted range |
| --- | --- | --- |
| `VARDRRUNNER_WORKER_DURATION_SECONDS` | 30 seconds | 1–86400 seconds; only narrows existing signed/local ceilings |
| `VARDRRUNNER_WORKER_ADMISSION_WAIT_SECONDS` | 60 seconds | 1–90 seconds |
| `VARDRRUNNER_WORKER_WAIT_SECONDS` | 30 seconds | 1–60 seconds for pending discovery |

The native owner's total startup ceiling is 120 seconds. Main also caps discovery
by its remaining startup time. Live owner readiness remains authoritative; elapsed
time cannot establish permission. A late discovery reply cannot start a claim
after the startup wait has elapsed. Explicit module options support reference
testing but do not replace the fixed reviewed container profile.

The entrypoint requires the actual lifecycle-owner connection before discovering
or claiming work. A public admission file, environment variable or boolean cannot
enable Linux controlled execution. The live owner must match the admitted startup
nonce and runtime identity. See [ADR 0043](adr/0043-proposed-linux-worker-lifecycle-owner.md)
for the approved development direction, privilege transition and remaining proof
obligations.

The worker uses the existing configured HTTPS Map origin and enrolled API key.
Reference trust is read through `authorization.documents.read_anchors`; the worker
does not create an issuer or approve its own work. Host stop secrets and owner
sessions never enter the worker, its environment or its journal.

## One attempt

1. Verify live owner readiness, public admission expiry, local identity and a
   writable journal without an unresolved local attempt. Reserve a permanent
   per-admission invocation tombstone before discovery.
2. Discover at most one approved fixed-Gate candidate per bounded request.
   `ManagedEntry` performs the existing local tool, target, resource and grant
   checks before claiming. The selected runtime is associated with the issued
   attempt atomically in the managed claim transaction.
3. Reuse `ManagedGate` validation and bounded authenticated lease refresh. Only a
   fully validated refresh reaches the owner lease callback. The callback cannot
   extend a signed hard ceiling or revive a lease that expired during IPC.
4. Preserve local single-use consumption. Strictly validate the server consumption
   acknowledgement, reserve a runtime-bind send intent, confirm the same exact
   runtime/attempt with the original control token, and persist its exact
   acknowledgement before returning the original consumption acknowledgement.
   Any failure launches no target work.
5. Invoke the existing Gate handler through the actual native control adapter.
   Normal return requires the lifecycle implementation's descendant-drain proof.
   The worker then uses the existing result/finish protocol and tells the owner
   it finished only after the terminal acknowledgement is durably recorded.

The additive `managed_runtime_bindings` table lives in the existing Runner
journal. It stores public runtime/attempt bindings and `waiting`, `bind_in_flight`
or `bound` state. It stores no control token, signed permission or host secret.
An invocation or uncertain send cannot be reconstructed as permission to retry.

## Failure and recovery

| Failure window | Required behavior |
| --- | --- |
| Lost claim reply | The server's atomic runtime association identifies the issued attempt for trusted host observation. The worker retains its claim hold and launches nothing. |
| Lost consumption or runtime-bind acknowledgement | Retain the send fence and partial state; do not launch, retry the mutation or claim another job. |
| Native owner/control loss | The independent lifecycle owner enforces the reviewed termination boundary. Host reconciliation requires direct proof of the exact stopped incarnation. |
| Physical exit before consumption | The host protocol may retire that exact issued attempt as failed while preserving `consumed=false`; observation creates no consumption acknowledgement or native execution handle. |
| Lost terminal reply | Observe the exact immutable receipt. Absence is a hold, never permission to replay execution or publication. |
| Result accepted but completion absent | Preserve the result and retain the hold until exact authenticated terminal observation. The host producer may fail the existing result only after direct stopped-incarnation proof; it creates no second stop receipt. |

Partial artifacts and conservative spent allowances remain retained. Unknown work
is not refunded or replayed. Automatic restart stays disabled until the stopped
incarnation is explicitly reconciled; a new start needs fresh admission. A
worker-disabled installation stays disabled.

Read-only observation recognizes an exact `observed_exit` failure receipt,
including the narrow pre-consumption retirement case. This never changes local
consumption markers, supplies a native confirmed-stop right or broadens the
ordinary native producer's allowlisted stop causes.

## Explicit local metadata reconciliation

After host reconciliation has committed the exact server receipt, the operator
can invoke `vardrrunner audit reconcile-managed <run-id>` using the original
Runner state, identity and enrolled API key. The distribution may invoke the
same command in a separate ordinary Runner helper after verifying the worker
container stopped. It must not insert an exec/health process into a live worker.

The command sends the original plan/case/association fingerprints to the
authenticated observation endpoint. A runtime pair is added only from the
immutable pre-send association described below. Existing native terminal result/stop
intents use their existing reconciliation functions. An exact `observed_exit`
failure can instead close local metadata atomically, retire its existing ledger
reservation and preserve the old PID as audit metadata. It neither signals that
PID nor rebuilds a native handle, control token or consumption acknowledgement.
Lost-claim retirement preserves `consumed=false` and the original unset claim
fields. Artifacts, counters, fences and one-use tombstones remain retained.

An authenticated failed completion for the exact original retained artifact can
also retire local metadata with `observed_failed_completion`. The original
intended outcome, finish-send and consumption flags, artifact and receipt hashes
stay unchanged. This records the server's failed terminal state; it creates no
native termination proof or successful completion. An absent, conflicting or
different-artifact receipt remains held. Protocol tests do not establish coupled
Docker Desktop or native Linux physical acceptance.

Before claim HTTP, the worker links its runtime ID/hash, enrollment, original
Runner/job/origin and fingerprints in the same SQLite transaction as the claim-send
marker. After physical exit, Map can irreversibly retire an unbound runtime under
the same row lock used by claim association. That barrier prevents a late claim
for the incarnation; a null binding without the retirement receipt proves nothing.

Only the durable link selects authenticated observation schema v2. The exact
`vardr.worker-unbound-retirement/1` receipt may close an unknown local intent as
`not_claimed_by_retired_runtime` when no local contract, consumption, PID, artifact,
result/stop intent or job ledger record exists. It preserves all original send/ACK
fields and job/runtime tombstones, and creates no retry, refund or execution right.
Older unlinked intents keep strict v1 observation and remain held. A revoked/lost
original enrolled key cannot be replaced through this read-only recovery path.

A known `denied_before_rpc` marker has a separate local retirement rule: only a
run without a contract, consumption, artifact or active ledger reservation can
close as not claimed. A specific permanent claim-tombstone conflict can close
only the new invocation-owned pre-RPC record. Unknown transport/database outcomes
cannot use either rule.

The command prints a fixed result state and `remaining_local_holds`; unresolved
runs, claims, active ledger reservations or inconsistent fences prevent a clear
result. This snapshot is not execution permission or automatic worker enablement.
Worker startup repeats the full hold audit before discovery. A retained result
without its terminal completion remains held and is never replaced by a stop
receipt or publication replay.
