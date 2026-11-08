# Persistent optional-idle shutdown classification

The inactive persistent-v3 candidate distinguishes an optional finite idle cutoff
with native exit 124 only in an unambiguous unarmed state. Pending channel events,
stop/EOF cleanup and waitable-child status retain their existing classifications.
The code does not treat this diagnostic as job success or a physical-stop receipt.

Runner latches its conservative pre-ACK cutoff, performs the full hold audit and
requires empty lineage before a nonspawning, no-RPC wait with its channel open.
A valid HELLO/DONE ACK establishes only a shutdown wait bound: post-ACK idle plus
a fixed five seconds, with uint64 overflow refusal. Readback faults and an
unconfirmed exit remain failures. No claim, native/job deadline, execution lease,
EOF cleanup bound, wire field, privilege or STOP authority is extended.

Pure-clock adapter regressions, the normal native Python suite and same-source
compiler scalar units are component evidence. Actual PID-1 classification,
bootstrap/live-channel/containment behavior and Windows Docker Desktop/Linux
acceptance remain separate open gates. Startup stays disabled; finite v1/v2,
manual and Mapless behavior are unchanged. No infrastructure, CLI flag, release
or deployment is introduced. See [ADR 0043](../docs/adr/0043-proposed-linux-worker-lifecycle-owner.md).
