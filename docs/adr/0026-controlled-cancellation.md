# ADR 0026 — Explicit owned execution control (NM-2 first increment)

Status: local implementation for review; no deployment or worker enablement.

`jobs run --controlled` adds active cancellation to an explicitly invoked manual
queue run. A matching Map migration and endpoints are required; a missing/mismatched
control receipt refuses execution, with no legacy fallback. Ordinary `jobs run`,
direct tools, pipelines and startup behavior remain unchanged. This control channel
is **not** an execution approval, signed v1 managed authorization or Strict scope
assurance. AI cannot approve work. No worker, budget or grant-TTL implementation
is included.

Map atomically binds one pending claim to a Runner UUID, exact configured Map URL,
authenticated API-key fingerprint and random per-attempt capability. Only its hash
is stored remotely; the capability stays in Runner memory. Authenticated control
and finalization messages require all bindings. A job never reopens after an
expired/uncertain attempt. Legacy PATCH cannot complete controlled jobs: a full
member's failure request becomes sticky cancellation while status stays running.

Permission lasts ten seconds. A refresh thread requests it every 0.5 seconds;
the process supervisor checks every 0.05 seconds. Receipt time cannot extend the
request-start deadline; stale responses cannot revive an expired lease. Local
emergency requests are read from the existing journal independently of network
refresh. HTTP controls use no redirects/retries. Unknown connectivity/auth/ownership
outcomes do not renew permission. These bounds assume a responsive OS and local
storage; remote stop is not instantaneous during disconnection.

Stop-work serializes with claims and marks active control records cancel-requested
in the same transaction. Releasing stop-work does not revive those attempts.
The lock order is engagement, job, execution record. Actual acknowledgement of
stopped execution is distinct from a request or expired lease. Unacknowledged stops
retain a local unfinished fence. Map reports uncertainty rather than cancellation
when it lacks acknowledgement. Control records are retained on code rollback;
there is no destructive downgrade or automatic legacy recovery of controlled runs.

On Windows 10+, tools enter a non-inherited kernel Job Object atomically using
`PROC_THREAD_ATTRIBUTE_JOB_LIST`, with kill-on-close and no configured breakaway.
Only NUL standard handles are inherited, with the existing tool environment
allowlist. Tool output files and Gate semantics remain unchanged. Graceful
CTRL_BREAK is attempted for the private process group when a console is attached;
otherwise it may be unavailable. After two seconds, terminate the Job Object and
allow two seconds to verify zero active processes. Owner-process death closes its
job handle. If cleanup cannot be verified, report uncertainty and retain the fence.
Microsoft documents [atomic job assignment](https://devblogs.microsoft.com/oldnewthing/20230209-00/?p=107812/)
and [job lifetime/inheritance](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

Linux controlled mode is explicitly unsupported and refuses before claim/launch.
A process group alone cannot contain deliberately detached processes; no unverified
prototype is advertised as reliable termination. Native Linux/Docker containment
and runtime verification remain required. Legacy Linux execution remains available.
ffuf controlled mode is refused because
its Python HTTP preflight has no independently cancellable process boundary.

Partial artifacts remain local on cancellation and are not uploaded as completed
assessments. A late stop preserves any upload already completed, its digest and
journal phase. Existing case hashes and evidence are not rewritten. Recovery does
not infer done, replay partial uploads or reclaim ambiguous controlled attempts.

Acceptance includes real parent/child/grandchild fixtures for cooperative and
refusing shutdown, owner crash, parent exit, blocked refresh, lease expiry and local
stop; late-stop/uncertain-PID regressions; cross-job/key/origin/Runner denial; and
PostgreSQL cancellation/finalization races. A separate loopback harness exercises
real Map HTTP, the Runner lifecycle and OS processes. Windows feasibility exclusions
and the blocked image vulnerability/release gate remain unchanged.

Before a future worker: prove Linux containment/control limitations, production
database races and restart behavior; bind managed signed authorization; implement
atomic engagement budgets and expiring/revocable grants with launch-time checks.
Grant expiry during credential/private-file preparation is a launch-boundary
acceptance requirement; NM-1's earlier consumption check is not an in-flight grant
guarantee.
