# Unreleased — Explicit engagement capacity

Add `jobs run --controlled --concurrency-budget` with mandatory Map reservation
receipt and no fallback. Requires matching unreleased Map `0033concurrencybudget`
and explicit owner configuration. Default calls stay unchanged. Counts owned
attempts, not manual work, requests, targets or duration; enables no worker.
See [ADR 0028](../docs/adr/0028-engagement-capacity.md).
