# NM-2 checklist audit and recovery verification

> Superseded as the phase denominator by [the canonical roadmap reconciliation](nm2-canonical-exit-status.md). The parent located the original Library roadmap after this historical scoped audit. Its former missing-checklist blocker and 8/12 row estimate are no longer current phase-status measures.

Status: scoped local evidence only; whole NM-2 remains incomplete and unaccepted.

The supplied independent-review package contains a 14-row `ACCEPTANCE_EVIDENCE.json` matrix. It explicitly disclaims full phase certification. The complete approved master checklist was not found in the supplied handoff, repositories or authorized staging folder. This audit preserves that uncertainty and does not invent additional requirements.

Of its 12 substantive rows, eight have local implementation evidence and four are partial. This is approximately 67% unweighted local row coverage, **not** a phase completion percentage or an acceptance estimate. `CI95` has local coverage/static evidence but lacks current hosted results; `FULL_NM2` is not met. Every row remains subject to designated independent review.

| ID | Current finding |
| --- | --- |
| G05 | local implementation evidence: Exact owned job/Runner/principal/contract/attempt/fence binding is checked by claim/control/consume/result/stop/observation paths; unknown attempts remain reserved. |
| G13 | partial: Signed approval, actual enrollment binding and no AI approval bypass are implemented in unregistered library paths. Production enrollment/operator/Runner transport integration and any explicitly invoked worker acceptance are not activated or accepted. Do not infer authority for a background worker. |
| ISSUE | local implementation evidence: Atomic count/ordinal/fence/concurrency/represented-target/allocated-duration reservations and rollback are implemented; PostgreSQL administrator/restricted-role evidence retained. These are defined accounting units, not universal network/RPS limits. |
| LOCK | local implementation evidence: Shared engagement/job/execution/contract/approval/key lock order and refreshed authority reads are covered by transactional/race tests. |
| REPLAY | local implementation evidence: One-shot claim, consume, evidence/finish and stop sends plus durable tombstones and receipt binding prevent retry/refund after ambiguity. |
| REVOKE | local implementation evidence: Current authority, stop-work and expiring/revocable grants are checked before consumption/renewal/native launch; historical observation cannot renew permission. |
| PLAN | local implementation evidence: Actual binary, fixed Gate plan and auxiliary request descriptors are bound for gate-fixed-http/1 only. No expanded tool/profile support is asserted. |
| GRANT | local implementation evidence: Original grant identity/expiry survives preparation and claim; the grant writer spans native creation. Actual Windows verification for the cumulative candidate remains open. |
| CANCEL | partial: Existing native Windows containment implementation and historical evidence retained. Current cumulative managed result/stop/recovery candidate has not passed affected real Windows/Papachin checks. |
| RECOVER | partial: Durable claims/result/stop intents, no replay, exact terminal receipts and original-principal observations implemented. This increment adds real fresh-process reconciliation and abrupt observer interruption. It does not certify native owner-crash containment, restore lost live proof or automatically release unknown attempts. |
| TLS | partial: Authenticated ASGI and verified loopback HTTPS exercise parser, bounded control, dropped replies and immutable receipts. Production managed transport remains fixture-only; deployed/public/VPN/fresh-host acceptance is not established. |
| LEGACY | local implementation evidence: Legacy advisory defaults, evidence/hash behavior and guarded refusal of managed jobs on legacy paths are retained; full local Runner/Map regressions pass at the prior candidate. |
| CI95 | partial: Current local Runner suite preserves the 95% floor and static checks. Required exact-current hosted CI/security/dependency/container results remain open; api.github.com is absent from enforced runtime revision 1 policy. |
| FULL_NM2 | not met: Not complete or accepted. Independent reviewer, Windows, hosted CI/security, final migration comparison and consolidation remain open. NM-3 has not begun. |

## Next necessary safe verification

The `RECOVER` gap was specific: the new capability-free result/stop reconciliation tests reloaded SQLite through a fresh object in the same process. Six subprocess cases now remove the originating handle, live capability and in-memory fixture state from the observer process. They cover exact receipt closure, missing-receipt holds, and abrupt observer exit before recording a receipt. They forbid network, process creation and PID signaling inside reconciliation, retain artifact/partial-file bytes and preserve PID audit metadata.

This adds tests only. No runtime module, production route, CLI flag, worker, enrollment, key provisioning or migration changes. Native Windows owner-crash containment and current-candidate reporting are still distinct Papachin gates. Broader activation/worker work awaits the exact approved checklist and applicable design decisions.

Prior baseline: Runner 2,136 passed / 36 skipped / 95.54%; Map 1,560 passed / 20 skipped; PostgreSQL 66 passed across administrator and restricted roles over verified TLS. New increment results are retained in the sanitized audit checkpoint. Existing source/evidence checkpoints and original checkouts remain intact.

Required independent review, Windows, exact-candidate hosted CI/security/dependency/container results, actual deployed migration comparison and consolidation remain open. The owner waived backup; no backup prerequisite remains. No publication, merge, deployment or acceptance is performed.
