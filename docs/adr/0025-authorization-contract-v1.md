# ADR 0025: NM-1 authorization contracts and bounded execution approvals

Status: Accepted direction, 2026-11-01; opt-in reference prototypes only.

## Decision

Keep legacy CLI, queue and evidence behavior unchanged. One Runner validator checks
the same versioned signed permission in standalone and Map-origin prototypes. Map
owns engagement approval/issuance; Gate enforces the validated request projection.
No policy service, worker, installer or global budget system is introduced.

A human approval can authorize N executions of one unchanged plan within its scope,
limits and validity. Each issued contract reserves one ordinal and is single-use.
An unknown/failed launch may spend an ordinal; never refund ambiguous execution.
Changed approval context or an exhausted count requires new approval. AI cannot
approve, create trusted keys, expand scope or turn queued work into approved work.

## Wire and trust

Use `vardr.authorization-envelope/1`, unpadded base64url payload/signature and fixed
Ed25519. Sign `VardrSec.AuthorizationContract.v1` + NUL + ASCII purpose + NUL +
exact UTF-8 payload bytes.
Approval receipts use their own purpose/domain, preventing cross-purpose replay.
Only explicitly enrolled issuer/key/purpose/origin tuples establish trust. Never
fetch a key or control URL named by a payload. An issuer compromise and a privileged
host/journal rollback are outside this document's authenticity guarantee.

Use the maintained optional `cryptography` runtime extra, not handwritten crypto.
Standalone operator keys can issue approvals/contracts for their enrolled origin;
Map's prototype accepts a separately signed operator approval. That receipt stands
in for a future authenticated owner approval record, not a new browser/API endpoint.
Private approval keys are never available to an agent or future worker. Signatures
record an assertion of permission, not proof of legal permission or host attestation.

Contracts bind issuer, origin, Runner, engagement/job/attempt, monotonic fence,
approval digest/ordinal, exact plan digest, authority snapshot, scope, time, limits,
grants, mode, exception list and required enforcement capabilities. Strict parsing
rejects unknown fields, duplicate keys, non-finite numbers and unsupported versions.
Hash exact plan bytes; reconstruct the actual plan and compare strict structures.
Existing sorted compact ASCII Gate case hashes are preserved separately.

## Plan and request boundary

The initial executable profile is fixed-URL Gate HTTP dispatch. Bind every setup,
all resource identities (including skipped expectations), caller/reader preflight,
verification readback and reset. Preserve method, URL/query, application headers,
body and actor. Count repeated logical dispatches, not packets, transport retries
or aggregate RPS. CORS is an approved header change, not another destination.
Setup precedes preflight; a preflight failure never means no traffic occurred.

Runtime captures/substitutions and uninstrumented tools are unsupported by the first
profile, not partly Strict. The Gate request guard checks phase, actor, effective
request and count before HTTP dispatch; existing SSRF, TLS, mutation and semantic
checks remain mandatory. Missing guard/capability refuses the opt-in path. Do not
advertise an initial-target check as full crawler/template egress enforcement.

## Validation and durable state

Parse bounds -> verify enrolled signature/purpose -> check origin/audience/binding
-> verify approval/context/ordinal -> hash and rebuild plan -> scope/operations
-> capabilities -> current revocation/time/control -> atomically reserve in the
existing journal -> resolve approved local credential references -> guarded dispatch.
No target URLs, secret values or headers enter journal metadata. Reserve issuance
counts and consumption transactionally. Duplicate contract or approval ordinal loses.
Claims/fences are namespaced by issuer and job; stale attempts cannot replace a newer
attempt's result. Fencing does not stop traffic: live leases/cancellation are NM-2.

Map-origin runtime requires authenticated current control and enrolled per-Runner
credentials; UUID alone is not authentication. NM-1 can simulate status for reference
fixtures but cannot advertise managed-control capability. It cannot fall back to
standalone permission on disconnection. Local offline validity is bounded and cannot
promise receipt of remote revocation. Revocation/clock rollback/corrupt state fail
closed. Completed evidence can be inspected/exported after permission expires;
execution cannot restart automatically.

Strict has no policy exceptions. This first profile supports specific signed
Advisory scope exceptions only; window exceptions are unsupported. Authenticity,
single-use, grant, operation, hard network, revocation and
expiry failures always deny. An exception cannot enlarge the approved plan.

## Compatibility and rollback

No migration of engagements or change to legacy `--yes`, `jobs run`, direct commands,
case hashes or uploads. New v1-required work must never downgrade to legacy. An older
Runner cannot execute v1 work. Additive authorization journal tables are used only
when explicitly opening a prototype ledger, leaving existing run schema/records
intact. Keep prototype APIs separate from installed queue processing and MCP.

## Threats and acceptance

Negative fixtures cover forged/expired/wrong-origin contracts, issuer rotation,
purpose confusion, plan/case/auxiliary-request drift, missing approval, duplicate
ordinal, concurrent issuance/consumption, revoked authority, stale fence, closed
window, unsupported profiles, unapproved grants and phase/count/request mismatch.
Map/standalone issuer receipts must pass the same Runner validator. Runtime checks
use bounded synthetic loopback targets only. Windows Docker feasibility is a separate
disposable trial; VPN/public routes remain unverified without target authorization.
