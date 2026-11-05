# Journal/export reconciliation

Combine existing workspace and portable-export ancestry without replaying shared
commits. Apply the existing observed-file check to export read_existing; preserve
read-only/no-migration semantics and live WAL reads. Existing focused tests now
cover the added connection. The concurrent FIFO replacement race, native Windows,
hosted CI and installed upgrade gates remain open. Recon and Docker-managed
execution remain disabled. This is not the unavailable combined Runner candidate.
