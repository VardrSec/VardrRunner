# Explicit local worker

Reuse the existing native worker owner, standalone signed authorization, ledger,
grants and Gate runtime for one explicitly invoked job. Ordinary Runner stays
UID10001/capability-free. Native DONE precedes ledger completion and journal DONE;
optional directory export failure keeps the successful run (Python exit 2,
native container exit 125). Keep the finite outer reporting interval separate
from the unchanged, shorter per-job execution ceiling.
See [ADR 0044](../docs/adr/0044-explicit-local-worker.md).
