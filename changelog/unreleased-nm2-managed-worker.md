# Explicit managed worker and metadata recovery candidate

Compose the existing managed claim, authorization, grants, budgets and receipt
services with one worker-only Linux lifecycle owner. The reviewed bootstrap uses
only SETUID/SETGID/SETPCAP, then clears all five capability sets. Fixed code, sanitized
environment, inherited-descriptor cleanup, distinct UIDs, credentialed IPC,
conservative BOOTTIME deadlines and actual subreaper/drain readbacks form the
candidate boundary. Ordinary startup/manual/Mapless and native Windows behavior
remain unchanged.

The initial candidate handles one attempt per admitted container, up to 32
explicitly declared credential environment names, with no proxy-variable support.
It requires configured companion Map runtime admission/claim/binding endpoints and
existing separate operator public trust. Host STOP secrets remain outside Runner.
Actual Linux and Windows Docker Desktop acceptance remains open.

Use a fresh default-local readiness metadata volume for each incarnation, seeded
with an empty UID/GID-10000 directory, mode 0700, during image build. Owner metadata
remains a 0400 exclusive file; no stale overwrite, additional runtime capability
or STOP secret mount is introduced. Two bounded tmpfs readback attempts refused;
Docker documents that its copy API cannot read tmpfs resources. Their receipts
remain unchanged and the volume correction still needs committed-image proof.

Add `audit reconcile-managed RUN_ID` for authenticated observation and exact local
metadata retirement without uploads, PID actions, token reconstruction or fake
consumption acknowledgements. Retain artifacts, immutable receipts, fences and
spent counters. Known zero-RPC local refusals can retire their own placeholders;
ambiguous transport/database state remains held.
