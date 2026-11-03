# Unreleased — managed pre-claim entry

The unregistered `authorization.claim.ManagedEntry` checks the actual fixed Gate
plan, binary, configured association, local grants and resource restrictions
before a single claim RPC. An additive intent/tombstone in the existing journal
owns the handoff; a returned `Journal.begin` record alone grants no ownership.
Lost replies, rejected binding and local write failures hold the attempt without
reclaim, refund or legacy finalization. Recovery defers marked or fenced runs.

Pre-RPC UTC/monotonic anchors and captured grant IDs/expiry persist across the
in-memory handoff. An unchanged grant cannot gain time through a replacement.
Local evidence is held under the stricter local/signed artifact ceiling. This
does not activate a command, worker, production transport, upload or completion.
See [ADR 0033](../docs/adr/0033-managed-preclaim-entry.md).
