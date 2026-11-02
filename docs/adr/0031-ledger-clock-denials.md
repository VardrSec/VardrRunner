# ADR 0031 — Expiry observations survive denial and lock delay

Local NM-2 correction, independently reviewable before managed integration.

Previously, consume validated before durably observing time, and issue observed
inside the permission transaction. An expiry denial could roll back the clock
observation, leaving a valid unused contract consumable after wall-clock rollback.
Both paths were reproduced with synthetic signed fixtures.

Persist trusted runtime time in a separate short journal transaction before policy
validation. Recheck elapsed/trusted time after obtaining the writer lock, and at
the final reservation boundary. If the permission transaction fails, roll back
all ordinal/fence/contract changes and preserve only the trusted current clock in
an independent transaction. Storage failure refuses permission. Stored malformed
clock values fail closed. No payload timestamp establishes observed time.

The reference API anchors time in its trusted ValidationContext and includes real
monotonic elapsed time spent waiting/preparing inside the call. An execution
adapter must refresh this context immediately before entry. Managed adapters also
provide a trusted UTC callback; effective time is the stricter wall/elapsed bound.
Explicit frozen clock injection is restricted to historical conformance fixtures.
The file reference CLI still starts no tool and asserts no managed online control.

Tests hold a real SQLite writer lock while a trusted synthetic elapsed clock
advances past expiry, and separately delay validation. Neither issue nor consume
may reserve an ordinal/fence/contract; the denied time survives reload and a later
rollback. Existing native final launch/deadline checks remain mandatory. Commit
visibility, OS scheduling and storage latency are not hard real-time guarantees.

No schema migration or legacy CLI change. The high-water clock only becomes more
conservative; do not roll it back to restore expired permission. Rollback of code
does not authorize deletion/reset of ledger state. Privileged whole-host/journal
snapshot rollback remains outside the journal's authenticity guarantee.
