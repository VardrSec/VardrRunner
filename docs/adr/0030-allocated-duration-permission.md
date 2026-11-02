# ADR 0030 — Finite allocated wall-permission windows

Local NM-2 slice for independent review. Explicit
`jobs run --controlled --duration-budget SECONDS` requests 1–86400 finite seconds
from matching Map policy (`0035durationbudget`). Current full-scope owner controls
the engagement ceiling; Map allocates atomically with owned claim and never
refunds unknown, terminal, failed-before-launch or deleted attempts. This is
cumulative allocation, not actual measured usage, CPU time or arbitrary manual work.

Runner verifies exact owned receipt/quantity and starts an immutable monotonic
deadline immediately before claim HTTP. Postclaim preparation consumes it; late
responses or lease renewal cannot extend it. Compose by minimum with existing
signed/local timeouts. Reuse launch_guard so the final check follows grant-lock,
private-file/environment/native preparation and permit callbacks. Library entries
also reject an explicit allowance without controlled mode before contact.

The native supervisor stops active trees on expiry using existing graceful/forced
cleanup. Allow existing 2s grace + 2s verification plus polling/scheduling/local-I/O
latency; tools may emit traffic during grace. No hard universal network cutoff or
total job-duration claim. Preclaim review/setup and post-tool artifact transport/
finalization are outside this permission window. Blocked preparation can finish
late but cannot launch afterward. Measure preparation/runtime/cleanup separately.

No grant, target, concurrency, case hash or evidence semantics change. Default
calls omit duration fields. Receipts remain authenticated ownership metadata,
not signed v1 approval. No worker, enrollment or new dependency. Linux/Docker and
ffuf controlled execution remain unsupported; remaining NM-2 gates stay open.
