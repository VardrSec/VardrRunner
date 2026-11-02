# NM-2 increment — expiring local reference grants

Status: implemented and tested locally; independent acceptance pending. This is
one bounded NM-2 increment, not completion of NM-2 or enablement of a worker.
Runner branch `codex/nm2-credential-grants` starts at accepted cancellation commit
`69469d1a3799a96c96ceace1c4f05a59fa7c1d76`. Map stays unchanged on
`codex/nm2-cancellation` at `45d4286190039462b942a69615214d6e480fb0ee`.
No publication, distribution pin or retained environment is changed.

## Implemented

- Explicit issuer/engagement/origin/provider/name-bound grants, TTL 1–86400 seconds,
  local revocation and name-only inspection in a separate config namespace.
- Opt-in queue and standalone reference integration. No implicit migration or
  fallback to legacy approvals; unsupported adapters refuse protected mode.
- Checks before/after claim, before/after environment/keychain resolution and at
  actual process creation after private-file/environment/native preparation.
  Existing auxiliary-origin checks cover setup, preflight, verification and reset.
- Grant UUID snapshots prevent in-flight replacement by reapproval. SQLite writer
  serialization orders revocation and launch; catalog digest anchoring blocks stale
  config resurrection. An observed expiry survives denial and later clock rollback.
- Signed deadline enforcement composes after grant-lock waits, retains a monotonic
  ceiling and recomputes remaining wait after creation. Windows controlled mode
  also supervises the signed deadline independently of control refresh.
- Post-creation guard failures retain handles/PID and bounded cleanup. Verified
  native containment may confirm termination; legacy cleanup remains uncertain.
  A durable redaction-safe grant marker prevents legacy recovery from promoting
  partial artifacts or clearing the ambiguous attempt's fence.

Details, migration and rollback limits are in
[ADR 0027](adr/0027-expiring-reference-grants.md). Grants authorize reference use,
not execution. Existing human execution approval may cover multiple unchanged
attempts only within its approved count, scope, limits and validity; AI cannot
self-approve. These changes add no MCP approval surface.

## Local evidence

| Check | Result |
|---|---|
| Complete native Runner suite | 1,905 passed, 10 skipped; 95.77% coverage, above the unchanged 95% floor. |
| Focused grant/runtime/CLI suite | 206 passed before final connection-close assertion strengthening; all final tests subsequently included in the full suite. |
| Required static checks | Ruff lint/format including container, mypy and Bandit at existing medium/high CI threshold passed. The unrestricted Bandit scan reports 24 low-severity findings, zero medium/high; it is not an all-severity clean claim. |
| Real guarded Gate with expiring grants | 14 requests across setup/preflight/resource/verification/reset, preserved case hash and zero replay requests. Synthetic environment values, isolated config and grant journal, ephemeral loopback only; no credentials in result. |
| Writer-lock and creation faults | Concurrent revocation serialized with launch. Lock held beyond signed deadline prevented entering either Windows process-creation body. Injected post-creation guard-exit failures stopped real children, preserved partial files and retained conservative recovery fences. |
| Map/frontend/PostgreSQL | No code changes in this increment; prior independently accepted cancellation evidence remains applicable. No retained database or Docker service was started. |

The real Gate binary is the unchanged native build from source `e99714b`, SHA-256
`2a89debd92eb30385da0b2949061cdd02cb5399cf5435adecc98e214eb6f55c0`.
Machine-readable evidence outside Git binds final commit and local log/receipt
hashes. Public fixture signing material and synthetic provider values are test-only.

## Corrected failures

- Expired-use denial originally rolled back observed time, allowing a later clock
  rollback to revive a grant. Time anchoring now survives denial; the exact
  issuance t0 / deny t11 / rollback t8 sequence is covered.
- Process creation could succeed before the grant context's commit failed. Both
  creation paths retain ownership before leaving the context and clean up
  conservatively; uncertain attempts cannot become completed evidence.
- The initial journal marker contained `credential` and was masked by redaction,
  defeating recovery deferral. `grant_policy` preserves the existing redactor and
  is tested through a real process failure, journal reload and recovery.
- Precomputed signed timeouts could outlive grant-lock waits. Deadline checks now
  run after the wait; older exact-integer timeout assertions were updated to verify
  the smaller positive remaining duration.
- The scratch integration wrapper initially reapplied its opt-in recursively.
  Correcting the wrapper produced the passing real Gate evidence; no product
  workaround or security relaxation was needed.

## Remaining boundaries

Grant revocation does not revoke provider credentials or stop a tool already
created. Expiry is checked immediately before the OS creation call; neither the
call nor timeout cleanup is an instantaneous wall-clock cutoff. Storage/OS stalls
are outside timing guarantees. Torn paired state refuses use and has no automatic
repair. Rolling back both trusted files and clock is outside local tamper
protection. Existing account/file permissions remain the trust root.

Linux/Docker controlled execution remains unsupported and independently unvalidated.
Current public/VPN/fresh-host exclusions and the separate blocked image/release
gate remain unchanged. No new Docker feasibility or fresh-host evidence is claimed.
Budget accounting, managed signed execution authorization, worker safety/readiness
and subsequent mandatory NM-2 gates remain open; NM-3 is not implemented here.
