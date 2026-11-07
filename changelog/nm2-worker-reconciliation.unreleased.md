# Explicit original worker reconciliation (unreleased)

Add `worker-reconcile` with six explicit existing-state selectors. Reuse the
complete worker audit to select a unique pending proposal or exact issued head,
then existing credential policy, one original-key observation POST and existing
receipt reconciliation. Preserve the closed worker-state/1 output and legacy
command behavior. Missing/replaced storage is held by a noncreating writer bound
to the originally observed DB identity; no journal migration or repair runs.

Already-retired and truly empty unissued state are offline. Empty N/A supplies no
physical retirement. Preclaim-only parent0 remains held and is an open NM-2 gap.
No new endpoint, service, execution authority, startup behavior or history ceiling
is added. Requires a new facade-bearing image;090/e8 lack this command. Full95%,
platform acceptance and an implemented next-enable operator flow remain separate.
