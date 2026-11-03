# ADR 0034 — One-shot managed consumption acknowledgement

Status: local prototype for independent review; activation and acceptance pending.

The preclaim facade now requires a trusted authenticated consumption callback before
native dispatch. The older direct `ManagedGate` composition remains a local-only
fixture primitive. Neither interface is registered in a CLI, queue or worker.

After full shared validation and local ledger consumption, `ManagedRun` commits
`consume_in_flight` before its single RPC. Map authenticates the existing owner,
API principal, capability and Runner binding, validates current authority and live
permission, compares the exact canonical signed-envelope SHA-256, and changes the
retained contract's `consumed` bit using a conditional update. Only the winner
receives an acknowledgement. Even an identical request cannot obtain another ACK.

The ACK has the exact schema `vardr.managed-consumption/1`, `consumed: true`,
origin/job/Runner IDs, contract/attempt/fence, authority revision/hash and contract
hash. Runner requires the complete exact field set, integer fence/revision and
literal boolean before committing `consume_acknowledged`. SQLite writer CAS binds
both transitions to the invocation owner. Additive `consumption_sent` and
`consumption_acknowledged` markers retain observations even after a later hold;
no secret, token or signed envelope is persisted. Existing intents default to zero.

ACK is not lease renewal. After transport and journal waits the existing refresh
and final native launch guards recheck permission. Lost/malformed/late ACK, missing
transport or failed journal writes cannot dispatch. Local consumption and server
reservations remain retained; expiry, cancellation, failure or a lost ACK do not
refund counts or establish termination. The one-use handle and durable preclaim
tombstone prevent replay, including after restart. ACK loss may conservatively
spend permission without executing; exactly-once physical execution is not claimed.

This increment does not upload evidence, complete jobs, release reservations,
reconcile unknown outcomes, provision trust or activate production routes. Those
remain separate implementation and acceptance gates. Portable inert-handler tests
check protocol and journal decisions; PostgreSQL fixtures check administrator and
restricted-role races/rollback. The updated Windows entry fixture still requires
real Windows/Gate/TLS containment verification and independent review.
