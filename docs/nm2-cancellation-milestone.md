# NM-2 first increment — owned native Windows cancellation

Status: implemented and tested locally; independent review pending. This does not
close NM-2 or enable a worker. Runner and Map use isolated local
`codex/nm2-cancellation` branches, based respectively on NM-1 `ab5f23f` and
`6c06315`. Gate remains unchanged at `e99714b`. No source was pushed, no distribution
pin advanced and no retained installation/database/volume was modified.

## Implemented boundary

- Explicit `jobs run --controlled`, with a matching unreleased Map schema/API.
- One authenticated API-key/Runner/Map-URL/job capability per attempt; only its hash
  is persisted by Map. Claim/control validation errors do not reflect capabilities;
  control responses forbid caching.
- Stop-work blocks new claims and makes active cancellation sticky. Control and
  finalization share engagement → job → execution locking.
- Ten-second permission refresh, monotonic client expiry, no stale-response
  resurrection, local `jobs stop RUN_ID`, graceful signal then bounded forced
  termination. Local emergency stop never acts on a bare PID from a stale journal.
- Native Windows Job Object assignment before tool code runs, stable descendant
  handles during termination and kill-on-owner-exit. Graceful signalling may be
  unavailable without a console; forced cleanup remains required.
- Cancellation requests, confirmed local termination and remote acknowledgement
  remain distinct. Partial files stay local during interrupted execution. Late
  cancellation preserves any upload already completed and its original digest and
  journal phase. Ambiguous attempts remain fenced and are not automatically
  recovered through legacy finalization.
- Existing UI cancellation handling says it is waiting for Runner confirmation
  while the returned job remains running; legacy terminal wording is preserved.

See [ADR 0026](adr/0026-controlled-cancellation.md) for trust, timing and rollback.

## Validation

| Evidence | Result |
|---|---|
| Full Runner native suite | 1,855 passed, 10 skipped; 96.28% coverage. Ruff lint/format, mypy and Bandit medium/high checks passed. |
| Real Windows trees | Parent, child and grandchild; cooperative exit, refusal/escalation, parent exit, owner crash, observer failure, lease expiry, blocked/late refresh and local stop verified. Breakaway attempts remained inside the owned Job Object. |
| Final Map HTTP → Runner → OS fixture | Remote stop 2.906 s; local stop 2.575 s; disconnected control 12.199 s. All three processes stopped in each scenario and all three partial files remained. Disconnection retained Map uncertainty, no remote termination acknowledgement and an unfinished local fence. These are observed fixture times, not universal timing guarantees. |
| Real Gate through controlled Windows spawn | Unchanged Gate built from `e99714b`; signed NM-1 standalone fixture made 14 planned requests across all five phases, preserved case binding, exposed no synthetic credential values in results and issued zero replay traffic. Managed v1 approval is not exercised by this check. |
| PostgreSQL concurrency | Final cancellation/completion race: 20 iterations per administrator and restricted application role; no deadlock, lost stop or false cancellation. Earlier complete migration/concurrency set had 22 passing tests; the two affected rollback tests subsequently passed after correcting the head expectation. |
| PostgreSQL backend | Full suite: 1,255 passed, one skipped before the added capability-reflection regression; final nine control tests, including that regression, passed separately over PostgreSQL. |
| Affected SQLite checks | 48 passed after route/docs/key-fixture corrections; 102 affected job/control/local-auth tests passed after the capability-response correction. |
| Frontend | 255 tests in 28 suites passed, including both cancellation responses; typecheck and production build passed. Lint: zero errors, 21 existing warnings. Synthetic build configuration used; no deployment. |

PostgreSQL 18.6 ran only as a disposable loopback cluster, without installing a
service. Its temporary CA/server certificates used hostname-verified TLS and SCRAM;
application TLS defaults were preserved. Every created cluster was stopped; test
data/logs remain available outside Git. The temporary binary archive is not a
product dependency or a claim of release provenance.

## Corrected failures

- A late stop could regress FINALIZING to EXECUTING, reset upload state and erase
  an observer-recorded PID. The handler now reloads and preserves durable state.
- Opposite cancellation/finalization lock orders could deadlock. Both paths now
  serialize in the same order; real PostgreSQL races cover the correction.
- Windows PID existence alone could confuse an exited process object with live
  execution. Stable native handles and wait status now confirm termination.
- Malformed control payloads reflected synthetic capability values. Generic,
  non-caching validation responses now cover those endpoints.
- A controlled cancellation request was displayed as already cancelled. The UI
  now distinguishes the response states.
- Test infrastructure issues were corrected without weakening product settings:
  scratch temp isolation, orphan-fixture readiness, API-key fixture cleanup,
  file-backed PostgreSQL startup logs, disposable TLS, a current-head rollback
  assertion, and unambiguous/typed UI queries.

## Remaining gates

Linux/Docker controlled execution is **unsupported** and refuses before claim or
launch. Existing manual Linux paths remain unchanged; this increment supplies no
new Linux-runtime certification. ffuf controlled mode is also unsupported because
its in-process HTTP preflight lacks the required cancellation boundary.

Production managed signed approval/enrollment, engagement budgets, credential grant
TTL/revocation with launch-time revalidation and the opt-in worker remain later
NM-2 increments. The future grant tests must include expiry during credential and
private-file preparation; an earlier consumption check is not an in-flight grant
guarantee. Existing conditional Docker Desktop Full/native compatibility and the
public/VPN/fresh-host exclusions remain unchanged. The image vulnerability/release
gate remains blocked, without a risk waiver. No NM-3 work is included.
