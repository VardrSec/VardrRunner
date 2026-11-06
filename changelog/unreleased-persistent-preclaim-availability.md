# Persistent availability after known local denials

The default-off v3 candidate separates an unissued selection from an issued
attempt in the existing journal. Narrow, source-proven credential-policy denials
before the sole claim callback can leave the worker available for other jobs,
without issuing a sequence, spending allowance or creating a native owner epoch.

Initial missing/expired grants can be checked after remediation. A late denial
retains the generic unique claim tombstone; queue a new Map job instead of
reusing that reservation. Custody, clock, owner, storage and unknown-response
failures stay held. Crash recovery requires exact original-key physical evidence
and never recreates execution authority or replays a mutation.

Finite v1/v2 behavior remains unchanged. Matching unreleased Map v3 endpoints
and the complete platform/security acceptance matrix remain required.
