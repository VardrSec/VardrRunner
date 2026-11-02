# Authorization Contract v1 threat model

## Trust and assumptions

Treat Map records, queued jobs, AI proposals, target responses and contract files
as untrusted inputs. The local operator controls the enrolled trust store, current
authority snapshot, Gate executable and journal location. The validator authenticates
permission assertions; it cannot establish legal authority or attest an uncompromised
host. A privileged attacker who can replace the validator, keys or durable journal
is outside this prototype's guarantee.

Bootstrap by explicitly reviewing issuer ID, key ID, public-key fingerprint, allowed
origins and allowed purposes out of band, then provisioning an operator-owned trust
file. No contract can enroll its own issuer, name a key-fetch URL or redirect control
traffic. Approval and execution keys may be separate anchors with separate purposes.
Keep approval private keys outside AI and worker access; a terminal confirmation is
an additional review step, not proof that an actor is human. The reference file
interface is not a key-management or identity-verification service.

For rotation, enroll a new key through the same operator-controlled process, switch
issuance to its key ID and revoke/remove the old anchor. An explicitly reviewed
overlap may permit old unexpired receipts; revoking an approval key invalidates its
receipts even if the execution key remains trusted. Never derive trust from a shared
issuer name alone. Protect the journal and trust file with the operator's filesystem
permissions and retained backups; restoring an old ledger is not replay-safe.

## Attacks and boundaries

| Scenario | Required rejection or limitation |
|---|---|
| Forgery, tampering, algorithm/purpose confusion | Fixed Ed25519 and purpose/domain separation; enrolled issuer/key/purpose/origin only. |
| Duplicate JSON keys, unknown versions/fields, oversized documents | Bounded strict decoding and fixed versioned payload shapes. |
| Changed job, Runner, engagement or auxiliary URL | Bind all identifiers; rebuild the actual plan and compare its digest and content. |
| Scope evasion by suffix, port, scheme, method or path | Exact canonical origin/method/path; exclusions and explicit signed Advisory exceptions. Ambiguous encoded/traversal paths are unsupported. |
| Setup, skipped identity, preflight, reader or reset escapes | Compile all dispatches and check each before DNS/HTTP; bound per-descriptor and total logical counts. |
| Crawler/templates/captures not represented in the plan | Unsupported profile; no Strict capability assertion or legacy fallback. |
| Contract replay, duplicate ordinal or concurrent consume | Transactional journal uniqueness and consumption before tool launch. |
| Stale owner or reissued attempt while a tool may run (G05) | Monotonic per-issuer/job fences; active reservation blocks new issuance/consumption until trusted completion. Unknown termination remains reserved. |
| AI queues a job or fabricates approval metadata (G13) | Queueing has no approval authority. No approval MCP/API tool; signed operator receipt required. Map prototype accepts trusted owner-session provenance only. |
| Revoked/changed authorization, stop-work, expired grant | Check current revision and snapshot digest, stop/revocation state and grant expiry before consumption. No claim of terminating an already active process. |
| Disconnected Map masquerades as standalone | Origin/control binding; managed runtime unsupported without authenticated current control. No fallback. |
| Clock rollback or corrupted local state | Durable clock high-water mark and fail-closed ledger operations; privileged snapshot rollback remains outside the guarantee. |
| Binary/config change | Bind actual binary SHA-256 and normalized execution options; require the guarded Gate flag. |
| Credentials leak through a contract or journal | Use local approved references; journal stores identifiers/digests/counts. General detection of secrets hidden in arbitrary application content is not claimed. |

Fences do not stop network traffic. NM-2 must supply authenticated enrollment,
server-owned claim/fence persistence, leases/disconnection rules and process-tree
cancellation before a managed worker can advertise these capabilities. A caller-set
UUID or boolean is not that protocol; test injection is explicitly synthetic.

## Assurance limits and compatibility

`gate-fixed-http/1` bounds logical dispatches, not transport retries, packets, global
RPS or engagement-wide budgets. Existing Gate DNS/SSRF/TLS/private-target safeguards
remain necessary. Standalone dispatch enforces the approved wall-clock deadline;
artifact limits bound the accepted output after execution, not disk-write quotas.
Grant/provider revocation and immediate in-flight cancellation are separate concerns.

Legacy engagements and CLI/queue behavior remain unchanged and retain their current
limitations. Future v1-required jobs must negotiate support explicitly and refuse
older components rather than silently downgrade. Rollback removes the opt-in
prototype; retain its journal for audit and do not reuse spent contract IDs/counts.
Nothing here changes assessment classifications, case hashes or evidence semantics.

The synthetic fixture library, negative tests and explicit cross-repository trials
exercise these boundaries. They do not certify arbitrary tool egress, live managed
execution, host attestation or legal permission.
