# NM-2 bounded consolidation scope exception

Status: owner-authorized verification scope; acceptance pending.

Preserve existing Windows-native execution and cancellation. Consolidate the
existing cancellation, credential grants, concurrency, target, duration,
transactional issuance and execution-ownership capabilities with the companion
Map candidate. CLI/manual and legacy behavior remain compatible.

Unattended Docker managed execution stays disabled and unsupported. The watchdog
hang gate failed and remains open; no other watchdog layer, privileged container,
Docker socket, host credential exposure or uncontrolled fallback is introduced.
This exception is not completion of the original Docker Desktop worker exit.

Applicable regressions, Windows-native verification, PostgreSQL, exact-candidate
hosted CI, migration review and independent security/review gates must pass before
the bounded baseline is accepted or independent NM-3 work begins. No acceptance
or phase-completion claim is made here. Obtain current owner approval before a
main merge, release or deployment; formal PR approval needs action-time consent.
