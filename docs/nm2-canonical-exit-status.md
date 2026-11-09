# NM-2 exit reconciliation — historical checkpoint

This page is a historical reference, not the current phase checklist. The earlier
statement that no worker existed and NM-3 had not begun described an intermediate
implementation. It must not be used to assess the current source-built platform.

The complete original checkpoint, including its ten exit clauses, transport
limitations and then-current verification gaps, remains available at its
[immutable source revision](https://github.com/VardrSec/VardrRunner/blob/84bac2d50b8c50b1dafdf1bb1604039e4d759873/docs/nm2-canonical-exit-status.md).
Temporary development permissions, backup exceptions and machine-specific handoff
requests in that record are not current operating instructions.

## Current status and operating guidance

- [New Moon acceptance ledger](https://github.com/VardrSec/VardrSec/blob/main/docs/new-moon-acceptance.md) — current delivery status and exact evidence boundaries.
- [Architecture review](https://github.com/VardrSec/VardrSec/blob/main/docs/new-moon-architecture-review.md) — remaining safety and release dispositions, including NM-2 C09/C10.
- [Managed worker operator guide](https://github.com/VardrSec/VardrSec/blob/main/docs/nm2-worker-operator.md) — supported status, stop and recovery procedures.
- [Runner CLI reference](cli.md) — commands and compatibility behavior.

Source-built Community acceptance does not waive unresolved NM-2 safety gates or
authorize a release. Normal startup remains inert; worker availability and each
job's execution authority are separate.

## Necessary bounded transport increment

The original transport implementation and its limitations are recorded in the
[historical transport section](https://github.com/VardrSec/VardrRunner/blob/84bac2d50b8c50b1dafdf1bb1604039e4d759873/docs/nm2-canonical-exit-status.md#necessary-bounded-transport-increment).
Use current implementation documentation and the acceptance ledger for later
integration evidence; do not infer a total transfer deadline from read-idle timeouts.
