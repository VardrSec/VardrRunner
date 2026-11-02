# Unreleased — Preserve denied authorization expiry

The opt-in ledger now durably observes trusted time across denied issue/consume
attempts, accounts for writer-lock/preparation delays and refuses corrupt clock
state. Ordinal/fence/consumption changes remain atomic and are not committed on
denial. Static reference fixtures use explicit trusted clock injection. Managed
wire vectors exercise the same existing validator without claiming live control.
See [ADR 0031](../docs/adr/0031-ledger-clock-denials.md).
