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

An unnamed inherited SOCK_SEQPACKET socket carries fixed 56-byte messages. Each
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
120-second owner ceiling. One validated attempt binding may arm a short lease and
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
renewal, permission or sequential queue loop. Helper and Python source must match;
the earlier zero-deadline HELLO refuses with the new native owner.

The current literal host operation timeouts can total 110 seconds (physical
observation, custody/volume revalidation, binding lookup, final direct inspection,
report). The extra margin is a reporting opportunity under a responsive host and
Map, not a promise that capacity will be released. Missing hosts, disconnected
services, grant revocation and expiry retain their holds. UTC trust/clock skew,
filesystem responsiveness and actual Windows/WSL/VM suspend behavior remain
acceptance limits; clock-order tests do not certify those environments.

The adapter enables Linux `execution_control` only inside this verified context.
It reuses `runner._spawn_tool`, including the existing launch guard, empty stdin
and tool environment allowlist. A process-wide Python audit barrier refuses
other subprocess/fork/exec paths in every Runner thread. This is a trusted Runner
code invariant, not an arbitrary native-code sandbox. There is one tool launch,
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

The candidate requires little-endian Linux, Python 3.10+ and kernel support for
the checked primitives. Host/VM suspend behavior, deadline responsiveness under
resource pressure, hostile process-control boundaries and full failure-path
acceptance remain open. CLOCK_BOOTTIME includes Linux suspend but does not wake
a suspended host or certify Windows/WSL pause behavior. Stopped adversarial
experiments remain stopped; this implementation does not close those gates.

Protocol and state-machine tests use mocks; actual native bootstrap, descriptor
isolation and descendant proof require separately reviewed platform evidence.
Primary semantics: [Unix credentials](https://man7.org/linux/man-pages/man7/unix.7.html),
[subreaper](https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html),
[wait](https://man7.org/linux/man-pages/man2/waitpid.2.html),
[PID namespaces](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html).
