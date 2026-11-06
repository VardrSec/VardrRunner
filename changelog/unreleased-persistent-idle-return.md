# Preserve the owner channel at Python's optional idle cutoff

Python's optional persistent idle window can finish between a pending-query
sleep and the next native readiness check. Returning there could close fd3 before
PID 1 selects its native idle classification. The discovery cutoff now rechecks
native readiness and full local holds, then sleeps for at most 50 milliseconds
without sending requests. Only the existing owner cutoff can latch typed closure.

No claim cutoff, native/job deadline, shutdown reserve, wire field, authority,
API, privilege or default startup behavior changes. Count completion retains its
existing clean return; unlimited persistence and finite-v2 retain their paths.

Pure regressions use controlled clocks and inert I/O, including one original
signed synthetic claim, DONE and durable release. Their public test contract IDs
use UUIDs required by the real owner epoch validator. These models do not prove
actual PID-1 exit 124, platform timing or physical containment. Windows Docker
Desktop/Linux acceptance remains separate and NM-2 remains incomplete.
