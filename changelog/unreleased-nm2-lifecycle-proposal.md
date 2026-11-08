# Proposed NM-2 Linux lifecycle boundary

Record [ADR 0043](../docs/adr/0043-proposed-linux-worker-lifecycle-owner.md) for
review: a worker-only PID-1 owner with temporary SETUID/SETGID/SETPCAP bootstrap,
empty steady-state capability sets and a distinct protected host stop-report
authority. The proposal identifies trusted-host false-report and concurrency
release risks, plus the protocol and platform acceptance still required.

This is documentation only. The owner approved bounded implementation/testing
after review; runtime activation and acceptance remain pending. Existing
manual/native operation, container configuration and startup behavior are unchanged.
