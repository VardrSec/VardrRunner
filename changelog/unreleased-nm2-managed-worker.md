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

Anchor public admission expiry to BOOTTIME once at the actual connection, sampling
BOOTTIME before MONOTONIC and UTC. The private native HELLO stores immutable grant
and work ceilings; every first/renewed lease is capped at the earlier work ceiling.
Reserve a fixed 150 seconds before grant expiry for the existing host observation
and report operations. A full requested allocation must fit before any claim RPC.
Short admissions can remain valid reporting grants but cannot start a worker
attempt. No renewal, extra authority or queue sequencing is added. The runway is
an opportunity; an absent host, network failure, revocation or expired grant still
holds. Actual VM pause/resume and platform deadline proof remain open.

Add `audit reconcile-managed RUN_ID` for authenticated observation and exact local
metadata retirement without uploads, PID actions, token reconstruction or fake
consumption acknowledgements. Retain artifacts, immutable receipts, fences and
spent counters. Known zero-RPC local refusals can retire their own placeholders;
ambiguous transport/database state remains held.

Commit the original public runtime/enrollment association in the claim-send
transaction. Select observation v2 only from that durable link. An exact receipt
for Map's irreversibly retired unbound runtime can close only a local intent with
no execution/contract/artifact/ledger state; old unlinked intents remain held.
Authenticated failed completion for the original retained result has its distinct
metadata retirement path. Preserve original outcome/send/ACK history, artifacts,
allowances and one-use tombstones; no execution handle or retry is reconstructed.
