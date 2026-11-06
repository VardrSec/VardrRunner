# Opt-in Linux worker lifecycle candidate

This worker-only ADR0043 implementation is under review. It is not a supported
or accepted Linux containment baseline. Ordinary Runner images, manual execution,
Mapless operation and the native Windows Job Object path retain their behavior.
The Distribution owns explicit worker admission, enable/disable, Docker lifecycle
and host stop reconciliation; see [managed worker](managed-worker.md).

`Dockerfile.worker` overlays an explicitly selected immutable toolkit image. Its
only entrypoint is `/usr/local/bin/vardr-worker-owner`, with no command arguments.
The static, single-threaded helper requires actual namespace PID1, initial UID0
and exactly SETUID/SETGID/SETPCAP. Before NSS lookups it copies only a bounded
environment allowlist and clears the original environment. UID/GID10000 must be
unallocated; lookup errors refuse. It drops every bounding capability before
forking. The fixed child establishes a separate session, becomes UID/GID10001,
clears groups and every capability set, enables no-new-privileges, then executes
only isolated Python's `vardrrunner.managed_worker`. The owner becomes UID/GID10000
with the same empty capability sets and never executes target-selected code.

The child environment fixes HOME, PATH, tools directory, XDG state/cache, temp,
locale and the CA file `/trust/root.crt`. Only Map URL/API key, worker wait/duration,
identity label and the existing explicit target/resource safety settings survive.
`VARDRRUNNER_WORKER_CREDENTIAL_ENV` may declare at most 32 distinct portable
credential names (`[A-Za-z_][A-Za-z0-9_]*`, 128 characters each, 4096 characters
total). Interpreter, loader, CA, proxy, path and runtime configuration prefixes
are refused case-insensitively. An undeclared value
does not reach Python; declaration grants no permission to resolve a credential.
Existing engagement/origin grants and case checks still apply. Proxy-variable
support has not been added to this initial candidate.

The retained v1 image uses 56-byte messages. The explicit v2 image uses a distinct
magic value and fixed 64-byte messages carrying a uint64 attempt sequence over
the same unnamed inherited SOCK_SEQPACKET socket. Each
message requires kernel SCM_CREDENTIALS for the exact direct Runner child or
PID 1/UID 10000. The public startup nonce is matched to host admission. The actual
Python process sets and reads back nondumpability and child-subreaper status;
the control descriptor becomes non-inheritable before any tool creation. All
capability, credential, session, SIGCHLD and no-new-privileges readbacks must pass.
No admission JSON, environment flag or owner-ready file alone enables execution.
Before the fixed Python exec, the single-threaded child walks `/proc/self/fd`
with a 258-entry cap and closes every descriptor except stdin/stdout/stderr and
the known control descriptor. Enumeration, bounds or close errors refuse exec;
the directory descriptor is also closed. No newer close_range primitive is used.

The owner publishes one 0400 regular `owner.json` under its private 0700 readiness
volume. The image seeds an empty directory owned by UID/GID 10000 at build time;
a fresh default-local Docker volume copies that ownership for each incarnation.
No runtime capability is added for ownership changes. This public metadata volume
is distinct from Runner state and contains no STOP secret. Its name is explicit,
unused and never automatically reused; a stale file refuses rather than being
overwritten. Stopping retains it for review.
The Distribution reads it directly without inserting an exec/healthcheck process.
The earlier tmpfs transport failed two bounded platform proofs: Docker documents
that its copy API cannot read tmpfs resources. The volume correction is pending
fresh platform proof; see [Docker copy limitations](https://docs.docker.com/reference/cli/docker/container/cp/#corner-cases).
Neither refusal establishes a failure of the native writer; the copy API did not
provide its live tmpfs contents.
The child waits for the separate readonly public admission file. Startup has a
120-second owner ceiling. Each validated attempt binding may arm a short lease and
an immutable hard ceiling, both measured in CLOCK_BOOTTIME. Clock conversion
anchors BOOTTIME before MONOTONIC at connection establishment and rounds down.
Every conversion reuses that anchor, so later suspend or scheduling between
samples can shorten or refuse permission and cannot extend it. IPC latency does
not extend deadlines.
Renewal cannot change the binding, widen the hard ceiling or revive expiration.

The connection also anchors the public admission's UTC expiry using BOOTTIME
first, MONOTONIC second and UTC last. Private HELLO carries an immutable grant
ceiling and an earlier work ceiling, reserving a fixed 150 seconds for host
reconciliation/reporting. The native owner stores both once and caps every lease
and hard deadline before the work ceiling. The existing 120-second startup bound
is also shortened by that ceiling. A requested allocation must fit in full just
before the claim RPC; a short admission refuses before claim. This adds no expiry
renewal or permission. Helper and Python source must match;
the earlier zero-deadline HELLO refuses with the new native owner.

The ordinary literal host operation timeouts can total 110 seconds (physical
observation, custody/volume revalidation, binding lookup, final direct inspection,
report). An explicit sequence-transition continuation can add one ten-second
exact-history lookup. The extra margin is a reporting opportunity under a responsive host and
Map, not a promise that capacity will be released. Missing hosts, disconnected
services, grant revocation and expiry retain their holds. UTC trust/clock skew,
filesystem responsiveness and actual Windows/WSL/VM suspend behavior remain
acceptance limits; clock-order tests do not certify those environments.

The adapter enables Linux `execution_control` only inside this verified context.
It reuses `runner._spawn_tool`, including the existing launch guard, empty stdin
and tool environment allowlist. A process-wide Python audit barrier refuses
other subprocess/fork/exec paths in every Runner thread. This is a trusted Runner
code invariant, not an arbitrary native-code sandbox. There is one tool launch per attempt,
no installers/background helpers, no exec healthcheck and no external process
insertion in the closed-lineage proof window.

Normal completion first waits for the exact direct tool, then drains adopted
children with `waitpid(-1,WNOHANG|__WALL)`. Positive returns continue draining;
zero prevents completion; only ECHILD confirms an empty lineage. The owner lease
remains armed through drain and result acknowledgement. Stop-work sends a bounded
graceful group signal and waits for exact exit plus ECHILD for at most the existing
Control.grace and remaining owner lease/hard ceiling. Failure stays unconfirmed;
closing the channel or expiration makes PID1 exit and the private namespace is
terminated. A stop marker or an elapsed deadline is never a terminal receipt.

After DONE, clean channel EOF may arrive with both POLLIN and POLLHUP before the
tracked Runner child becomes waitable. The owner still validates queued packets,
then waits under the unchanged deadlines for that exact child to exit normally
with zero. EOF alone cannot establish success; an active-attempt EOF still refuses.
The compiler stage exercises ordinary own-socket close and queued-packet cases
under a five-second limit. These checks are separate from platform containment
acceptance.

Sequencing requires explicit `max_attempts` (1 through 32), owner-ready/2 and
admission/2. Omission retains the old one-shot mode against its matching image;
the new v2 image never downgrades its private protocol or admission. The six
physical identity fields and existing signed authorization contracts remain
unchanged. A v2 callback captures an immutable attempt epoch before claim. Each
attempt uses a fresh Gate, Control and journal run. Sealing the epoch rejects
late callbacks, and DONE independently requires its exact pinned Control to have
closed and its actual refresh thread to have exited, plus the lineage drain.
Only the canonical completed path may use its original Map token to release the
active runtime association and advance.
Unknown send, result, release or cleanup state prevents another claim.

After each healthy DONE, the owner permits at most 60 seconds of nonspawning
idle, capped by the original work ceiling. Idle cannot be renewed. The next lease
must use exactly the next sequence and a fresh attempt binding; stale, duplicate,
skipped or exhausted sequences refuse. All ACK fields, including sequence, must
match. A validated DONE ACK produces `native_done_sha256` for the existing-token
idle-release correlation. This digest is not independent server attestation.
The compiler stage adds bounded protocol-state checks; actual sequential platform
and failure-path acceptance remain pending.

The candidate requires little-endian Linux, Python 3.10+ and kernel support for
the checked primitives. Host/VM suspend behavior, deadline responsiveness under
resource pressure, hostile process-control boundaries and full failure-path
acceptance remain open. CLOCK_BOOTTIME includes Linux suspend but does not wake
a suspended host or certify Windows/WSL pause behavior. Stopped adversarial
experiments remain stopped; this implementation does not close those gates.

Protocol and state-machine tests use mocks; actual native bootstrap, descriptor
isolation and descendant proof require separately reviewed platform evidence.

The explicit inactive persistent image compiles the same owner with
`VARDR_PERSISTENT=1`, native magic `0x33574456`, and immutable owner-ready/3. It
cannot negotiate or downgrade to the finite image. The fixed 64-byte HELLO uses
its lease slot for optional idle seconds (`0` means none) and hard slot for the
optional attempt count (`0` means none). These slots carry policy, not execution
deadlines. The bounded startup still precedes HELLO; afterward nonspawning idle
has no default expiry. A first LEASE for the exact next sequence is mandatory
before any launch and fixes a finite per-job hard ceiling. Refresh, expiry and
namespace-exit rules remain unchanged.

The adapter captures BOOTTIME before MONOTONIC for each fresh persistent epoch;
an active epoch never resamples its offset. DONE independently requires normal
native return, no Control stop reason and no rejected or failed refresh, as well
as the existing actual drain and quiescence checks. The refresh-failure latch
only denies v3 reuse; existing active-lease renewal and expiry behavior is
unchanged. Only then does DONE clear job authority back to idle. V3
binding digests include the admission hash and canonical decimal sequence;
legacy bindings and native frames remain unchanged. Optional count/idle limits
are immutable, and signed-int64 exhaustion refuses rather than wrapping. Native
state tests model these transitions without PID1 bootstrap or credential changes;
they do not establish persistent platform or hostile-process acceptance.
The Python discovery window also respects an explicitly selected idle limit for
best-effort clean no-job exit. A stalled RPC still faces the authoritative native
idle ceiling; this does not widen that ceiling.

Primary semantics: [Unix credentials](https://man7.org/linux/man-pages/man7/unix.7.html),
[subreaper](https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html),
[wait](https://man7.org/linux/man-pages/man2/waitpid.2.html),
[PID namespaces](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html).
