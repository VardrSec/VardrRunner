Add explicit one-shot managed stop reporting sourced only from confirmed native
stop decisions with fixed causes. Preserve observer PIDs and partial artifacts;
unknown containment and stale PIDs cannot release a reservation. Journal each
send and validate exact owned stop receipts, with observation-only reconciliation
after a lost response and no retry, refund or reexecution. Keep legacy behavior,
platform guards and ordinary recovery deferral unchanged.
