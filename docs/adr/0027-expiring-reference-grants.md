# ADR 0027 — Explicit expiring reference grants

Status: local NM-2 increment for independent review; no deployment enablement.

Opt-in `jobs run --expiring-grants` requires local grants for Gate references.
The explicit standalone reference adapter accepts
`execute_gate(..., expiring_grants=True)`. Default manual, queue, pipeline and
legacy approval behavior stays unchanged. No worker, budget or managed signed
contract is added. Linux/Docker and ffuf controlled execution remain unsupported.
A grant permits reference use; it is not execution authorization. An existing
human execution approval may authorize its unchanged plan within the approved
count, scope, limits and validity. AI cannot self-approve.

Issue grants using both `--issuer` (configured Map base URL or `standalone`) and
`--expires-in` (1–86400 seconds). Bind issuer, engagement, normalized origin,
provider (`env` or `keychain`) and exact reference name. Remove trailing issuer
slashes; otherwise match the configured URL exactly, including deployment path.
Every case origin needs every referenced identity's grant, including setup,
preflight, verification and reset. This conservative cross-product reuses existing
checks. Protected cases reject literal credentials, ambiguous providers and
malformed references. Existing environment/keychain resolution remains local.
Never store provider values in grants or send them to Map.

Separate config namespace `gate_credential_grants_v1` contains schema/revision and
rows with UUID, binding, issue/expiry UTC times and active/revoked state. Additional
tables in the existing journal contain only config-location/catalog digests,
observed UTC high-water mark, grant UUID and audit action/time: no names, origins
or values. No dependency, server endpoint or secret-store exposure is added.
Local storage permissions remain the trust root; this does not resist tampering
by the account owning both files.

SQLite `BEGIN IMMEDIATE` serializes issuance/revocation and final launch. Config
publication precedes transactional digest/audit publication. Torn updates, stale
config overwrites, missing catalog/anchor and malformed state fail closed; there
is no implicit repair, reinstall or fallback. Connections close on every exit.
Observed time survives an expired-use denial, so later clock rollback cannot
revive the grant. Rollback of both trusted files and clock is outside this local
guarantee. Paired-state recovery and operator clock correction must be explicit;
this increment adds no repair command.

First case validation snapshots grant UUIDs. Reapproval changes the UUID and
cannot authorize an already checked attempt silently; unrelated grant changes
leave the snapshot valid. Revalidate before/after claim, before/after provider
reads, then after private-file/environment/native preparation. Hold the writer
lock across actual `Popen`/`CreateProcessW`, establishing an order between
revocation and new process creation. Check expiry immediately before entering
the creation call; the OS call is not preempted at a wall-clock instant.
Revocation committed first blocks launch. Revocation after creation blocks
subsequent use, not a tool already holding credentials. Provider-side revocation
and active cancellation are distinct operations.

Recheck the immutable signed execution deadline after grant-lock waiting and the
controlled permission check. Retain a monotonic ceiling against clock rollback;
recompute process wait time after creation. Controlled supervision checks the
deadline independently of lease renewal. Timeout shutdown retains documented
cleanup latency; no instantaneous network cutoff is claimed.

Failures leaving a creation context retain process handles/PID. Windows Job Object
containment can verify termination. Legacy tree cleanup is bounded best effort
and conservatively retains an uncertain journal fence. Partial artifacts remain
local. Durable `grant_policy: expiring/1` survives redaction and defers automatic
recovery even without `--controlled`. Preserve case hashes and evidence semantics.

Legacy `credentials approve/revoke/approvals` without issuer options access only
the old namespace. Protected execution never falls back to it. Migration requires
explicit human issuance and mode selection. Revoking either namespace leaves the
other unchanged. Downgrading removes protected capability; do not present it as
protected operation. Retain paired config/journal evidence and unfinished fences;
do not reclassify protected attempts as ordinary recovered jobs.

Acceptance covers binding/TTL bounds, every auxiliary origin, stale/torn state,
revocation and expiry during preparation/claim/provider reads, clock rollback,
reapproval, writer-lock races, deadline composition, post-creation failures,
partial-state recovery and secret-free metadata/audit. Real guarded Gate loopback
must preserve all five phases, case binding and zero replay traffic.
