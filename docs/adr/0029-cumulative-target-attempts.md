# ADR 0029 — Cumulative represented-origin attempts

Local NM-2 increment for independent review. Explicit
`jobs run --controlled --target-budget` requires a matching Map target ceiling.
One unit is each distinct canonical HTTP(S) origin represented by a fixed Gate
case, per attempt, conservatively including setup, all preflights, resource,
verification and reset. Repeated attempts spend again. This is not unique IPs,
HTTP requests, DNS/proxy connections, arbitrary manual work or global RPS.

Reuse the existing fixed Gate compiler, canonical origin logic, case hash and
request guard. Compile before claim; refuse dynamic/unsupported profiles. Send
profile, unresolved case hash and sorted origins. Verify the owned receipt's exact
binding and integer charged/spent/limit fields. Pass the compiled projection to
the existing Gate handler with normalized `plan.execution`; an older Gate refuses
the required flag before traffic.
No duplicate validator, dependency or policy engine is introduced. Target metadata
is not human approval or managed signed v1 authorization.

Map atomically charges after winning claim under its engagement lock. Durable
spend never refunds on terminal/unknown outcomes and survives job deletion. Idle
owner/full-scope configuration cannot reduce the ceiling below spent or disable
after spend; deleting a spent engagement refuses. No reset/reaper is provided.
Requires matching unreleased Map `0034targetbudget`; default calls are unchanged.
Existing concurrency/grant/control/deadline and evidence semantics remain.
Duration budgets and worker implementation remain subsequent work. Linux/Docker
and ffuf controlled execution remain unsupported.
