# ADR 0033 — One-shot managed pre-claim entry

Status: local bounded prototype; independent acceptance and activation separate.

## Decision

Add an unregistered `authorization.claim.ManagedEntry` around ADR 0032's existing
native Gate composition. Trusted callers supply configured origin, Runner/job/
engagement identity, principal digest, trust anchors, reviewed unresolved case,
fixed execution options and authenticated claim/current callbacks. All HTTP stays
in `api.py`. This library grants no queue, CLI, worker or enrollment capability.
The actual claim reply must include the frozen `config.test_case`; absence or
change holds the attempt. Map currently supplies this only in the explicit test
adapter, not a new production route.

Before RPC, validate native control availability, typed config, actual binary and
compiled plan (including Gate auxiliary requests), grant metadata, local deny
rules/target ceiling/disk space and exclusive output. Preserve existing explicit
local deny override semantics. Revalidate after journal/preparation waits and
check grants last, immediately before transport. No credentials resolve into the
journal or request plan. Missing capabilities fail closed.

Use an additive `managed_claim_intents` table in the existing journal. Validate
the returned run's backend/job/engagement/tool/type/target-source identity, then
reserve with an independent-connection SQLite writer CAS and unique backend/job
tombstone. A per-invocation marker prevents another caller from continuing a
partially recorded invocation. The random local owner is not a server capability.
Persist only association/plan/case/tool/approval/authority hashes, public IDs,
state and clock metadata; never tokens, signed envelopes or credential values.

Sample monotonic time before UTC before the send transaction. Persist both
anchors and mark CLAIMING atomically before RPC. Preparation and reply latency
count against the original allocation and lease. Preserve that anchor through
wall-clock rollback. Validate signed contract/approval, owned allocation, exact
case/plan/association and fresh current control before binding public claim IDs
and hashes. A local invocation never retries a claim, including after a lost
reply, failed write or restart. These outcomes retain local tombstones and Map
ownership/counts without refund or false failure finalization.

Capture the first checked local grant IDs and earliest expiry in memory before
claim, then carry them into execution's existing Policy. Replaced/revoked/expired
grants cannot silently establish a fresh boundary or extend this attempt. Local
grant checks still serialize native creation through the existing grant store.
No credential material or restartable execution capability is persisted.

The one-use in-memory ManagedRun records native PID and local artifact state.
Apply the stricter captured local and signed artifact ceilings before hashing or
ARTIFACT_READY. Oversized evidence stays local and held. This is neither Map
upload/completion nor consumption acknowledgement. Stop requests use existing
journal/control behavior; successful local execution retains server reservations.

Recovery defers unfinished runs with either the profile marker or durable intent,
including an erased marker. Unreadable intent state also defers. It never signals
a retained PID, reconstructs a capability, retries, uploads, completes or releases
capacity. Ordinary legacy rows retain their existing recovery behavior.

## Evidence and limits

Unit tests cover independent connection ownership, foreign records, partial
writes, grant/clock/preparation races, reply mutation, replay and every recovery
phase. Map's four explicit Windows/TLS entry tests cover actual Gate output,
lost post-commit claim reply, binding write failure and a local stop request.
Tests use disposable profiles, synthetic trust and owned loopback targets.

Conservative holds may require future reviewed reconciliation. This increment
does not implement it, evidence finalization, distributed exactly-once execution
or ACK. Linux controlled execution remains unsupported. Docker, ffuf, public,
VPN and fresh-host behavior is not established by these fixtures. No production
route/schema, release pin, retained installation or trust enrollment changes.
