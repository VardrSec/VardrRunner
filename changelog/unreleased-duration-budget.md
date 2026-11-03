# Unreleased — Finite owned duration allocations

Add `jobs run --controlled --duration-budget SECONDS` with bound Map allocation
receipt and immutable monotonic enforcement at launch and supervision. Requires
matching Map `0035durationbudget` and explicit owner policy. Library entries fail
closed if control is absent. Default calls remain unchanged. Owned permission
cannot be renewed by repeated/concurrent claim or monitor
entry; a failed setup consumes that facade's entry. Allocated seconds
are not measured consumption; existing cleanup overshoot and post-tool transport
are separately scoped. See [ADR 0030](../docs/adr/0030-allocated-duration-permission.md).
