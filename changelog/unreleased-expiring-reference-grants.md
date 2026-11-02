# Unreleased — Opt-in expiring Gate reference grants

- Add explicit issuer/engagement/origin/provider/name-bound grants with TTL and
  revocation. `credentials approve --issuer URL --expires-in SECONDS` creates a
  separate local grant; `credentials revoke/approvals --issuer URL` manage it.
- `jobs run --expiring-grants` and the opt-in standalone adapter require grants
  without legacy fallback. Revalidate at claim, resolution and actual creation,
  including auxiliary origins. No implicit legacy migration or behavior change.
- Anchor catalog state and observed time in the existing journal. Stale/torn state
  fails closed. Preserve ownership and partial-artifact fences after launch-exit
  failure, including grant-protected execution without controlled mode.
- Preserve signed deadlines across grant-lock waits and native preparation.
  No Map endpoint requirement, worker, budget, distribution pin or managed Strict
  claim is added. Linux/Docker controlled execution remains unsupported. See
  [ADR 0027](../docs/adr/0027-expiring-reference-grants.md) for limitations.
