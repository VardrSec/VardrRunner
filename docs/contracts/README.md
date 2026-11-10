# Authorization contract interface

The schemas describe decoded payloads/envelopes; signature, time, scope, plan
recompilation, grants and durable-state checks are additional mandatory rules.
This opt-in reference prototype does not change installed queue enforcement.
See the [threat model](threat-model.md) for trust bootstrap/rotation, G05/G13 and
the limits of the initial enforcement profile.

- An approval signs a complete context, including execution count, scope, limits
  and validity. It can allocate multiple unchanged-plan contracts. Each contract
  signs the approval receipt digest and one allocation ordinal.
- Signature input: ASCII `VardrSec.AuthorizationContract.v1`, NUL, ASCII purpose
  (`approval` or `contract`), NUL, exact UTF-8 payload bytes. Fixed Ed25519 only.
- Plan artifacts use sorted compact ASCII JSON (`ensure_ascii=True`, no non-finite
  numbers) without a trailing newline. Hash those exact bytes. The file interface
  rejects reformatting. Existing Gate case hash semantics remain unchanged.
- `gate-fixed-http/1` binds a local tool SHA-256, unresolved case digest, effective
  options, credential references and every dispatch descriptor. Captures and
  substitutions are unsupported. Scope is exact origin/method/path; exclusions
  precede includes, with specific signed Advisory scope exceptions.
- Window exceptions are unsupported by this first profile. Testing windows,
  contract/grant expiry, hard network and missing control capabilities always deny.
  Approve a corrected permission context rather than bypassing those checks.
- A contract may expire before its approval. Standalone execution uses the earliest
  contract/approval/window deadline and rechecks it after local preparation, before
  launching the tool. This does not implement remote in-flight cancellation.
- Additive journal tables contain identifiers/digests/counters only. Issuance
  allocations are conservative: expiry/failure does not refund an ordinal.
  Duplicate consumption and duplicate approval ordinals fail. Future multi-host
  managed claims still need authenticated server enrollment and fencing.
- Trusted current authority includes both a revision and snapshot digest. Neither
  a repeated revision with changed content nor a rolled-back control state is
  accepted. A reserved attempt blocks reissuance until the execution adapter records
  known completion. Unknown/interrupted launches remain reserved; expiry alone does
  not prove termination. Finalization cannot replace another attempt's state.

`tests/fixtures/authorization/` contains synthetic vectors with a publicly documented
test-only seed (`bytes(range(32))`); never enroll that key outside tests. The case
includes setup, caller/reader preflight, a skipped resource identity, verification
reads and reset: at most 14 logical dispatches. No network is needed for conformance.

Use `python -m vardrrunner.authorization --help`. `plan` binds an explicit binary;
`approve` requires a terminal and explicit review; `issue` requires an explicit
journal/control context; `validate` never executes targets. `state` is a trusted
local prototype operation, not a queue endpoint. No existing CLI/MCP command changes.
Tests alone may inject simulated verified managed status; the file interface refuses
it. File validation alone does not provide a live lease, cancellation or execution authority.

Approval signatures attest the issuer/operator assertion, not legal permission,
biological human action or trusted execution. Protect approval keys from agents
and workers. No general secret resolver, policy service or worker is introduced.

## Dormant finite recon discriminator

`plan-v1.schema.json` is unchanged and describes only `gate-fixed-http/1`
with schema `vardr.execution-plan/1`. It does not describe finite recon plans.
The dormant recon projection uses the distinct `vardr.finite-recon-plan/1`
discriminator and `finite-dns-http/1` profile. Its explicit, compiler-enforced
contract is documented in [finite-recon-plan-v1.md](finite-recon-plan-v1.md).
No claim of conformance to the Gate JSON schema or generic plan-v1 interchange
is made. Existing approval/contract envelopes still bind the entire plan digest.
