# NM-2 native transport and recovery fault coverage

This is a bounded local test increment. Runner runtime and Map source are unchanged.
The bases are Runner `65c0b0a493568774f344eac44bb8e7e2189cdcf1` and Map
`80ecd3255ced018580dcc0e4a2181d6eed72fe89`; review branches are
`codex/nm2-native-faults`. Managed-contract branches are preserved separately.

## Gap and case matrix

Existing `test_execution_control.py` covers blocked/throwing refresh callbacks.
`nm2_control_acceptance.py` uses real Map HTTP, but its disconnect case substitutes
an `OSError` callback. The accepted duration owner-crash fixture already covers
native kill-on-close, retained allocation and deferred reload; this increment
does not repeat that scenario.

| New case | Actual fault | Required server and journal result |
| --- | --- | --- |
| `control_drop` | Proxy closes real control connections before forwarding; finalization also dropped | Last local lease expires, whole tree stops; Map becomes uncertain and retains reservation; journal remains unacknowledged |
| `control_delay` | Proxy forwards a real control request, holds its successful `continue` response past local permission, then delivers it | Expired local lease cannot renew; reconnect returns cancel; unresolved reservation retained |
| `finish_before_commit` | Local stop, then proxy drops finalization before Map receives it | Native termination confirmed locally; Map unresolved after lease expiry, reservation retained; journal unacknowledged |
| `finish_after_commit` | Local stop, Map commits finalization, proxy closes before client gets response | Map cancelled and reservation released; client journal still unacknowledged; cumulative charges retained |

Every case uses real `VardrMapClient`, owned claim/control/finish endpoints,
`jobs._execute_one`, Windows Job Object containment and a reloaded journal. One
three-process Python tree ignores graceful stop and retains three synthetic
partial files. Handler upload raises if called. The proxy records path counts
only, never request headers, capabilities or credential values. Reconciliation
must defer without any HTTP call; a repeated invocation of the unfinished job
must fail before claim or launch. One claim and one failed-acknowledgement finish
are required per case. Reconnection explicitly exercises the existing capability;
it never issues another claim or silently replays artifacts/finalization.

## Time and accounting bounds

Control retains its real ten-second monotonic lease and refresh thread. The
drop/finalization cases use production `(1, 1)` HTTP timeouts. Only the delayed
case injects a fifteen-second read timeout at the fixture session transport, so
an actual late HTTP response reaches the unchanged Control implementation.
This extends fixture waiting, not execution permission. The production API and
refresh callback are not replaced. The proxy releases after the sampled deadline
plus 0.3 seconds; assertions require the old deadline and terminal stop reason
to remain unchanged. A later real control request, after persisted server expiry,
must return cancel. No clocks are patched.

Each case enables existing concurrency limit 1, target ceiling 1, duration
allocation 120 seconds and a 300-second synthetic local environment-reference
grant. The fixture uses existing fixed Gate plan preparation and credential
checks, then substitutes a native Python handler. Its 90-second tool timeout,
120-second allocation and 300-second grant cannot explain a passing lease-loss
case: verified termination must occur within 40 seconds, with lease stop requested
within one second after the last verified deadline. These are bounded test
assertions, not a real-time service guarantee. Existing cleanup includes a
two-second graceful interval and up to two seconds of forced-termination
verification, plus scheduling/OS/storage delays.

Receipts measure the stop request at the actual WindowsJob graceful call and
verified termination after the invocation returns and all three saved PIDs are
checked stopped. Thus termination timing includes finalization/journal overhead,
and is an upper bound on the process-tree stop latency. The last permission anchor
is the refresh request's monotonic start (`deadline - 10`), not response arrival.
For local-stop cases, stop-before-deadline offsets are deliberately negative.

Map must retain target charge 1 and duration allocation 120 after every outcome,
reconnect and journal reload. The same capability digest and reservation state
must survive recovery. A server-confirmed terminal report may release concurrency
even if its response was lost. A genuinely unresolved attempt must retain it.
No refund, duplicate charge, new attempt, upload or finalization replay is allowed.

## Scope and limitations

All HTTP is synthetic loopback. Target `127.0.0.1:9` is a descriptive plan binding
and is never contacted. Authentication, environment reference and grant approval
are explicitly public disposable test material. The harness creates only a new
output directory and database. It changes no retained installation, secrets,
certificates, trust, firewall, VPN, service or Docker state.

This verifies the existing owned protocol with disposable SQLite, not PostgreSQL
concurrency/migrations, a real Gate invocation, request-level scanner enforcement,
signed human managed approval or a background worker. Prior independently accepted
PostgreSQL and real Gate evidence remains separate. Linux, Docker and ffuf
controlled execution remain unsupported. NM-2 remains open. The rejected Map
signer/enrollment architecture decision remains on hold pending explicit human
owner approval; this test increment implements no part of that boundary.

## Verification record

Final real-HTTP/native run: four cases passed, twelve processes verified stopped,
twelve partial files retained. Lease-loss stop requests occurred 0.0225 and
0.0476 seconds after the last verified deadline; stop-to-verified-termination
upper bounds were 2.0918 and 2.1295 seconds. The late response was released
0.3083 seconds after permission expiry and did not renew the deadline. These are
observed Windows results, not portable latency guarantees.

| Case | Map state after reconnect | Concurrency retained | Stop-to-verified-termination seconds |
| --- | --- | --- | --- |
| Control connection dropped | uncertain | yes | 2.0918 |
| Control response delayed | uncertain | yes | 2.1295 |
| Finish dropped before commit | uncertain | yes | 2.0872 |
| Finish committed, response lost | cancelled | no | 2.1329 |

All four journals remain `executing` with local status `cancelled` and no finish
acknowledgement. Each reload defers exactly one run and makes zero HTTP calls;
the same unfinished attempt cannot relaunch. Target charge 1, duration allocation
120 and the original owned capability digest remain unchanged. This difference
between local journal and server state is expected acknowledgement ambiguity,
not evidence that the process is still running.

The first development run passed both transport cases, then failed in the fixture:
`stop_job` opened the grant journal while the run lived in a different job journal
(`JournalError`). Its disposable tree was stopped through the correct run journal;
the failed source and log are retained. The correction makes grant/stop/run state
use the same configured journal, as the actual CLI does, and requests cleanup if
the trigger fails. No runtime correction was needed. The final four-case rerun
and repository-required quality results are recorded in the local hashed milestone
receipt, including original failure artifacts. No prior accepted fixture is edited.

Repository-required final checks passed: Ruff lint, Ruff format, mypy (56 source
files), whitespace checks and the full Runner suite (1,952 passed, 10 skipped,
95.81% coverage). The four-case opt-in harness is additional to pytest discovery.
Map is unchanged, so its accepted backend/PostgreSQL suites were not rerun. No
runtime/argv/parser changes required a new real scanner smoke run.
