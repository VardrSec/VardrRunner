# ADR 0028 — Explicit owned engagement capacity

Local NM-2 increment for review. `jobs run --controlled --concurrency-budget`
requests Map's configured engagement capacity reservation. Map owns policy and
atomic accounting; Runner executes and retains existing control, termination and
finalization. Require both flags before contact. A missing/false reservation
receipt refuses execution without fallback. Default payloads/CLI stay unchanged.

A slot covers the owned attempt through finalization, not requests, targets,
subprocesses or duration. Unregistered manual/direct work is uncounted. Only
confirmed terminal outcomes release capacity; cancel requests, disconnection,
lease expiry and uncertainty retain it. No force release is added. Existing
grant/deadline and partial-evidence fences remain. Capacity is not human execution
approval; existing approval counts, scope, limits and validity remain separate.

Requires matching unreleased Map `0033concurrencybudget`, explicit idle policy
configuration by its full-scope owner, and native Windows controlled capability.
Older servers refuse the strict new claim field; receipt validation also fails
closed. No managed signed approval, worker, target/duration budget or distribution
change. Linux/Docker and ffuf controlled execution remain unsupported.
