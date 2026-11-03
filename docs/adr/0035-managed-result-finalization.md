# ADR 0035 — Managed result receipts, completion and explicit observation

Status: local unregistered prototype; independent review and real Windows acceptance open.

## Known native return and immutable intent

`ManagedRun.execute` records a known returned artifact only after the existing
controlled native adapter returns and the artifact/journal checks succeed. The
native adapter still requires both root exit and no active descendants; uncertain
stop, owner crash, PID disappearance or a partial file never establish this marker.
The marker is not reconstructed from an artifact after a restart.

The new explicit `finalize(submit, finish)` reads the retained exact bytes under
both local/signed ceilings and the receiver's 512000-byte ceiling, verifies the
journaled hash/size and compiled case binding, and reserves an additive result
intent before any transport. It persists only public association/attempt IDs,
hashes, size, expected outcome and send states. Tokens, signed envelopes, raw
results and credentials are not stored in this table. Failure preflight chooses
failed finalization; it cannot become a successful job.

## Two independently acknowledged writes

Map's result receipt binds origin, job, Runner, exact signed-contract hash,
contract/attempt/fence, raw artifact SHA-256 and frozen case hash. Map stores the
existing redacted evidence/assessment/candidate projection and its immutable
receipt atomically. This step never releases a reservation or completes work.

Only after an exact result ACK is durable does Runner reserve a single completion
send. The authenticated termination flag is the trusted adapter's assertion of
known return, not independent remote attestation. Successful completion still
requires current authority, grants, original duration and a live lease on Map.
Failed completion may report known finished work after expiry/revocation; that
never grants another execution or refunds approval/target/duration charges.

The exact terminal ACK closes the matching local ledger reservation and journal
atomically. Lost/malformed replies and failed writes preserve the one-shot intent.
A later call cannot replay an upload, finish RPC, native launch or claim.

## Explicit reconciliation

`authorization.results.reconcile` takes a journal/run ID and an independently
configured authenticated inspection callback. It sends only the persisted public
binding; the callback must supply the original capability through its trusted
transport. No token or execution permission is reconstructed from the journal.
Missing capability or missing/nonterminal receipt leaves the attempt held. An
observed result may update local receipt state but never triggers completion.
Only an exact terminal receipt with consistent server state and released capacity
can close the local ledger/journal. Conflicting, foreign or disappeared terminal
receipts deny; no PID is signaled and no count is refunded.

The ordinary recovery dispatcher continues to defer all unfinished managed work.
No CLI, worker, enrollment, production route, retry automation or support expansion
is introduced. Owned ASGI/TLS fixtures and portable inert handlers validate these
protocol decisions. Actual Windows finalization/containment is a distinct opt-in
gate to run on Papachin; independent acceptance remains with the designated reviewer.
