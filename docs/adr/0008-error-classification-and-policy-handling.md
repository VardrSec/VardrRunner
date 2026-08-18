# ADR 0008 — Error classification and advisory policy handling

- **Status:** Accepted
- **Date:** 2026-08-17

## Context

VardrMap evaluates every job against its authorization, testing window and
recorded scope. Findings return as a `warnings` array and the work still runs;
**stop-work is the sole condition that refuses**, arriving as HTTP 403. That
split is deliberate on the backend side (see its ADR 0001 amendment): scope is
the operator's responsibility, and a platform that guesses wrong blocks
legitimate work mid-engagement.

VardrRunner ignored all of it. `commands/jobs.py` wrapped the claim in a single
handler whose comment anticipated only a 409:

```python
except Exception as e:
    # 409 = another runner won the race; just move on without failing the job.
    con.print(f"[red]Could not claim job:[/red] {e}")
    return
```

So a stop-work refusal, an expired API key, a 500 and a genuine race produced
identical output and identical behaviour — the job stayed pending, and the
daemon re-claimed it every `poll_interval` seconds indefinitely. An operator who
had pulled the emergency brake saw a runner that appeared to be retrying
normally, and the `warnings` array was never read at all.

## Decision

**One taxonomy, classified once, at the boundary.**

`vardrrunner/errors.py` defines `FailureCategory` plus a `RunnerError`
hierarchy. `classify_status(status, body)` is the single place an HTTP status
becomes a domain meaning. It is pure, stdlib-only, and imports nothing from the
package, so it sits at the bottom of the dependency graph and is testable
without a network stack.

Status mapping, specific to the VardrMap contract:

| Status | Error | Category |
|---|---|---|
| 401 | `AuthError` | `auth` |
| 403 | `StopWorkError` | `stop_work` |
| 404 | `NotFoundError` | `not_found` |
| 409 | `ClaimRace` | `claim_race` |
| 422 | `InvalidRequestError` | `invalid_request` |
| 429 | `RateLimited` | `rate_limited` |
| ≥500 | `BackendUnavailable` | `backend_unavailable` |

**403 means stop-work, not generic forbidden.** VardrMap answers cross-account
access with 404 rather than 403 precisely so object existence is not disclosed,
which leaves 403 free to carry one meaning. This assumption is load-bearing and
recorded here; if the backend contract changes, `_STATUS_MAP` and this ADR are
what need updating.

**Applied narrowly.** Only the job-lifecycle calls (`claim_job`,
`complete_job`) raise classified errors. The generic `get`/`post`/`patch` still
raise `requests.HTTPError`, so `doctor` and `status` — diagnostics that legitimately
care about raw status codes — are untouched. Classified errors are raised
`from` the original `HTTPError`, so the cause survives for triage.

**Policy parsing is isolated.** `vardrrunner/policy.py` owns every read of the
`warnings` array. The backend owns that shape and evolves independently, so a
change there touches exactly one file here. Parsing is total: any malformed,
absent or unexpected payload yields an empty tuple rather than raising, because
failing to *display* an advisory finding must never abort a job the backend
already permitted.

**Stop-work suppression.** `execute_pending_jobs()` accepts a
`blocked_engagements` set. The daemon owns one for its lifetime, so a halted
engagement is refused once, reported clearly, then skipped quietly instead of
being re-claimed every cycle. Restarting the daemon re-checks it — deliberately,
so a lifted stop-work needs no special command to resume.

## Consequences

- Stop-work halts and says so; it can never again be mistaken for a race.
- A claim race stays non-fatal and never marks another runner's job failed.
- Advisory warnings are printed before any tool runs, while the operator can
  still intervene, and emitted as a `policy_warning` job event.
- `FailureCategory` values are written to durable records from the execution
  journal (ADR 0009) onward. **Renaming a member is a breaking change** — add a
  new one instead. `tests/test_errors.py` asserts the wire values literally.
- Warnings are untrusted display data. They are rendered and recorded; they never
  influence control flow beyond display and are never interpolated into a
  command line.
- A catch-all remains around the claim as the daemon boundary. It logs a
  sanitized diagnostic and keeps the worker alive, per the availability
  requirement that one bad job must not end the poll loop.

## Alternatives considered

- **Treat scope warnings as blocking.** Rejected: it inverts a deliberate backend
  decision and would block legitimate work mid-engagement. Only local deny rules
  the operator configures explicitly may block.
- **Classify inside every generic HTTP method.** Rejected for this phase: it would
  change the exception type `doctor` and `status` already handle, for no gain on
  the path that needed fixing.
- **Persist stop-work suppression across restarts.** Deferred to the execution
  journal (ADR 0009). An in-memory set is correct and simple now, and a restart
  re-checking the backend is the safer default.
