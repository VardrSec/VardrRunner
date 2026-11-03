# ADR 0032 — Unregistered managed native Gate composition

Status: local prototype; production activation and whole NM-2 acceptance held.

`authorization.managed.ManagedGate` composes existing shared v1 validation,
authorization ledger, strict fixed-Gate target/duration receipts, credential grant
policy, Gate handler, execution Control and WindowsJob. It contains no HTTP client,
issuer, enrollment, queue, CLI or background worker. A trusted adapter supplies
the authenticated current-control provider, configured origin/principal, local
identity, actual claimed case and binary binding. No production path registers it.
The standalone `execute_gate` continues to refuse managed origins.

Permission is consumed durably before native creation. Signed contract, approval,
testing window, original allocation, approved/tool duration and local/signed grant
expiry remain immutable ceilings. The live lease can renew within those ceilings.
Every current reply must match job, Runner, origin, contract, attempt, fence and
authority revision/hash. A captured reply retains its actual server expiry through
trusted UTC/monotonic anchoring; request latency never creates additional time.
Control receives that absolute monotonic cap as well as the returned remaining
interval. Rejected refreshes retain the prior cap, not an older relative extension.
Legacy Control callers without a cap preserve their existing behavior.

Nested `launch_guard.revalidation` callbacks compose in registration order. The
managed recheck and in-transaction grant check must both run after preparation,
network and native permit delays. The actual Gate binary is rehashed at launch.
The grant writer stays held across native creation. Managed revalidation performs
no local ledger write inside that transaction, and a background grant check waits
for the grant writer before taking the HTTP mutex, avoiding a lock cycle.
There is no alternate process engine: the actual handler reaches runner's native
Control path and WindowsJob's final permission boundary. Linux remains unsupported.

A valid local Gate artifact is not managed Map completion. Local consumption and
Map capacity remain retained, including after successful local execution. No
legacy upload/completed adapter is used, and no false failure releases capacity.
Unknown spawn, lost claim reply, unconfirmed termination or unacknowledged
finalization remain conservative states with no retry/refund. Distributed consume,
ACK, recovery and managed completion transactions remain separate reviewed gates.

Map's explicitly opted-in native fixture uses real UTC/monotonic clocks, fresh
synthetic signatures, verified loopback HTTPS and an already verified development
Gate build against owned loopback resources. It records actual process/contact,
artifact, stop-cause and last-verified-lease timing evidence. This proves neither
installed CLI/queue readiness nor public/VPN/fresh-host/Docker/ffuf support, persistent
trust or deployment. No release pin or installed binary is changed.
