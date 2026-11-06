# ADR 0043 — Proposed Linux worker lifecycle owner

Status: owner-approved for bounded implementation and testing, 2026-11-05;
candidate implemented, default-disabled; platform/security acceptance pending.

Implementation references: [lifecycle boundary](../worker-lifecycle.md) and
[managed orchestration/recovery](../managed-worker.md). Build/unit evidence is
separate from actual runtime acceptance; this status does not certify the worker.

## Owner authorization record

After reviewing variant B and the trusted-host false-report/concurrency-release
risk, the owner explicitly selected: "Approve this bounded design for
implementation and testing." This authorizes only the combined candidate described
below. It does not waive platform/security acceptance, enable default startup,
authorize release or permit the stopped adversarial experiments to resume.
References below to the proposed or unapproved candidate describe the review
proposal preceding this decision; this authorization record controls its current
development status.

On 2026-11-06, after reviewing the persistent-v3 departure from the finite
reporting lifetime below, the owner explicitly selected: "Approve persistent
STOP reporting for isolated testing." For that protocol only, its purpose-limited
secret remains valid until explicit revocation or physical retirement of the
exact incarnation. It cannot claim jobs, consume authorization, renew execution,
publish success or refund allowances. The owner was explicitly informed that a
compromised host or secret holder could forge exit and release concurrency early.
This approves isolated implementation/testing, not deployment or release, and
waives no independent review, containment or platform acceptance. Finite v1/v2
reporting lifetimes retain their existing meaning; ordinary startup stays inert.

This document records the reviewed NM-2 container-containment candidate.
The owner-approved exception is worker-only; ADR 0019's manual baseline, NM-3 branches,
evidence, default startup and manual/legacy behavior remain preserved.

## Problem and scope

The existing native Windows control path uses a kernel Job Object. Linux controlled
execution remains unsupported. Existing Docker experiments did not establish a
complete replacement: process groups do not contain detached descendants, and an
ordinary init/reaper does not itself provide execution authority or a deadline.
Further adversarial experiments encountered a tool safety block and were stopped.
This proposal does not repeat them or substitute documentation for their missing
acceptance evidence.

The candidate places a small trusted lifecycle owner at the actual PID 1 of the
worker's private PID namespace. Its steady-state UID differs from Runner and its
tools. Runner remains the only execution engine and continues to validate shared
contracts, authenticate Map control, resolve grants and account for budgets.
The lifecycle owner supplies termination enforcement, not a second policy engine.

The first two bounded Desktop readiness trials refused before admission or target
execution: Docker's copy API cannot read the original tmpfs readiness path.
The candidate now uses a fresh, dedicated default-local metadata volume, seeded
empty at image build with UID/GID10000 and mode0700. The owner exclusively writes
one mode0400 public readiness file; stale data is refused. It adds no secret store,
service or runtime privilege. Exact volume ownership/attachments and the corrected
readiness transport still require platform proof. See
[Docker copy limitations](https://docs.docker.com/reference/cli/docker/container/cp/#corner-cases)
and [the implementation boundary](../worker-lifecycle.md).

The recommended candidate for owner review is bootstrap variant B below, paired
with a bounded host stop-report capability for recovery after whole-container
exit. This recommendation is not approval or implementation of either change.

The design is limited initially to one active attempt per worker container. It
adds no host service, Docker API broker, Docker socket mount, privileged mode,
host PID namespace, raw-packet capability or new enrollment service.
The recovery protocol below applies to the existing Map-coordinated worker lane.
It does not make Map a new dependency of standalone/manual or Mapless Runner,
and it does not close that distribution's separate acceptance requirements.

## Proposed process boundary

The worker would use its own reviewed native PID-1 entrypoint. Docker `init: true`
would insert a different PID 1, so it cannot be combined with this ownership model
without a separately reviewed design. A basename check, PPID check or assumed
numeric child PID is not sufficient to establish lifecycle ownership.

Proposed steady-state identities are:

| Process | Identity and authority |
| --- | --- |
| Lifecycle owner, PID 1 | Reserved UID/GID 10000; empty effective, permitted, inheritable, ambient and bounding capability sets. |
| Runner | UID/GID 10001, existing state and credential handling; all five capability sets empty. |
| Tool processes | Existing UID/GID 10001 and allowlisted tool environment; all five capability sets empty and no inherited lifecycle-control descriptors. |

The proposed owner identity 10000 must be reserved and checked against the actual
image before activation; a collision refuses activation. A different GID alone
does not provide the proposed process boundary.
This also does not turn Runner and tools, which still share UID 10001, into
separately isolated security principals.

Linux signal permissions normally depend on matching process UIDs or `CAP_KILL`.
UID separation therefore removes several ambient same-UID control permissions;
it does not establish a complete sandbox. The newly forked Runner child must create
its own session before UID/GID transitions and target execution, with admission
checking that its SID differs from the lifecycle owner's. This removes shared
session membership from the `SIGCONT` permission exception. It also separates
autogroups where that kernel feature applies; it does not reserve CPU, and a
non-root CPU cgroup can override autogroup behavior. Failure of session setup
refuses launch. See [setsid](https://man7.org/linux/man-pages/man2/setsid.2.html)
and [scheduler autogroups](https://man7.org/linux/man-pages/man7/sched.7.html).
See [signal permissions](https://man7.org/linux/man-pages/man2/kill.2.html).

## Bootstrap privilege choices

Stock Docker starts a container's initial process with its configured user and
capability sets. Starting every process as UID 10001 with no capabilities does
not provide authority to create a sibling process under another UID. The proposed
worker therefore needs a disclosed bootstrap exception. The existing manual
Runner service would retain its current configuration.

Recommended variant B requires a single-threaded, immutable, tightly scoped
bootstrap starting as UID 0 with only `SETUID`, `SETGID` and `SETPCAP`, before any
target-facing code, queue processing or untrusted state parsing:

1. Start the trusted PID-1 bootstrap with the reviewed initial privileges.
2. While `SETPCAP` is effective, drop every bounding-set entry, clear inheritable
   and ambient sets, and verify the empty bounding set. Retain only the effective
   and permitted bootstrap rights needed for the remaining credential changes;
   perform no intervening exec. Create a private control channel and fork the
   fixed Runner child, which inherits the empty bounding set.
3. Have that child establish its separate session before changing credentials;
   retain the lifecycle owner as its direct parent.
4. Clear supplementary groups and set all real/effective/saved GIDs and UIDs:
   Runner to 10001 and the lifecycle owner to 10000. Do not enable keep-caps or
   otherwise retain a saved UID that permits a later return to UID 0.
5. Clear effective, permitted, inheritable and ambient capabilities in both
   processes. Keep `no_new_privs` enabled and verify actual credentials before
   accepting work. A failed or incomplete transition exits the namespace.
6. Execute only the fixed reviewed Runner entrypoint in the child. The lifecycle
   owner does not execute a tool, plugin or target-selected executable.

Credential-transition ordering, capability clearing and error handling require
implementation review. A maintained helper such as util-linux `setpriv` may be
evaluated for credential transitions; it does not replace the PID-1 owner or prove
the complete lifecycle. See [setpriv](https://man7.org/linux/man-pages/man1/setpriv.1.html).

| Variant | Bootstrap capability exception | Required disclosure |
| --- | --- | --- |
| A: considered alternative, not recommended | `SETUID`, `SETGID` | E/P/I/A become zero, but those capabilities remain in the bounding set. The implementation must not describe this as every capability set being empty. |
| B: recommended for owner review | `SETUID`, `SETGID`, `SETPCAP` | The trusted bootstrap drops every bounding-set entry while authorized, then performs the required UID transitions and clears remaining E/P/I/A. Exact ordering must be verified; no bootstrap capability may remain available to Runner or tools. |

Recommended variant B drops the bounding set before the fork and UID transitions,
so the child inherits the empty set. Clearing the bounding set does not clear the
current E/P/I/A sets; those
must still be cleared explicitly. An intervening exec must not be assumed to
preserve the privileges needed for the remaining bootstrap operations.

`PR_CAPBSET_DROP` requires `CAP_SETPCAP`. UID changes or clearing E/P/I/A do not
by themselves clear `CapBnd`. Under the stock Docker model this document identifies
no way to promise an empty bounding set with only SETUID/SETGID. A custom OCI
credential setup would be a different deployment mechanism requiring review.
See [PR_CAPBSET_DROP](https://man7.org/linux/man-pages/man2/PR_CAPBSET_DROP.2const.html)
and [capability sets](https://www.man7.org/linux/man-pages/man7/capabilities.7.html).

The bounding set is a ceiling, not a currently effective permission.
`no_new_privs` prevents privilege gains through exec and is inherited, but it does
not prevent an already privileged bootstrap from calling UID-changing system
calls. It is not a substitute for dropping the actual capability sets or for
reviewing the bootstrap. See [no-new-privileges](https://www.kernel.org/doc/html/latest/userspace-api/no_new_privs.html).

Variant B is the selected recommendation in this proposal, not an accepted runtime
baseline. Its initial user and added bootstrap capabilities depart from the
current UID-10001/no-added-capabilities baseline even though all steady-state
processes would become unprivileged. The manual/legacy service retains its
existing baseline and the proposed worker remains inactive by default.

## Private control and deadline ownership

The lifecycle owner would retain a private, bounded IPC endpoint to the exact
Runner child. Tools must receive neither endpoint and must be unable to recover
one through process inspection or a writable pathname. Peer identity, descriptor
inheritance, Runner dumpability and the actual platform's process-inspection
restrictions require proof. A caller-provided PID or environment variable is not
an authenticated owner binding.

Only trusted Runner control code may request an attempt transition after existing
contract, authority, grant and budget validation. IPC messages contain fixed
message types, attempt identifiers and bounded deadline metadata, not credentials,
case bodies or arbitrary executable arguments. The owner rejects oversized,
malformed, stale or mismatched messages. It does not fetch Map URLs, sign approval,
resolve secrets or widen permission.

The owner maintains the immutable minimum of the approved hard ceilings and a
short current-control lease. A lease renewal cannot extend a signed hard ceiling
or revive an already expired attempt. Its event loop must enforce expiry without
waiting for Runner HTTP, a journal lock or a writable filesystem operation.
Control-channel failure fails closed.

`CLOCK_BOOTTIME` is a candidate elapsed clock because Linux documents that it
includes system suspend. It does not wake a suspended host, and that documentation
does not establish Windows/WSL/Docker-VM pause/resume behavior. Actual supported
hosts need acceptance evidence. POSIX timers are deleted on exec: any design using
them must arm the final owner's timer after its last trusted exec and keep that
owner from later exec transitions. See [timer semantics](https://man7.org/linux/man-pages/man2/timer_create.2.html).

PID 1 has special signal rules. This proposal does not assume that a timer's
default fatal signal kills namespace init like an ordinary process. The reviewed
owner would take an explicit exit path on its enforced deadline. This remains a
userspace owner dependent on a responsive OS; it is not a real-time kernel deadline
or a guarantee under host/kernel compromise.

## Graceful and forced stop

On stop-work, explicit operator stop, lease loss or a hard ceiling, new claims and
launches stop through the existing control state machine. Runner attempts the
applicable bounded graceful cleanup through its normal execution path. The exact
treatment of hard expiry versus graceful cancellation must be documented without
silently extending execution permission.

A zero-capability lifecycle owner under another UID cannot assume it can signal
Runner or tools directly. The proposed graceful request uses the private channel.
If cleanup cannot be confirmed within the reviewed bound, or Runner exits or loses
its control channel, the actual PID-1 owner exits. Linux then terminates the other
processes in that PID namespace. This is a whole-container failure boundary and
must not be used with shared/host PID namespaces. See [PID-namespace init](https://www.man7.org/linux/man-pages/man7/pid_namespaces.7.html).

Read-only owner code, restricted writable mounts, CPU/memory/PID limits, bounded
IPC/logging and process-inspection controls are part of the proposal. They do not
create a general untrusted-code or hostile-host sandbox. Additional seccomp or
Landlock layers may supplement the boundary but must not be asserted as completed
containment merely because installation succeeds.

## Attempt lifecycle, evidence and restart

Initial proof should cover one active attempt and whole-container failure.
Concurrent attempts share the same failure domain and are outside this proposal.
A sequential queue loop is a separate integration step: it must not admit another
attempt until the previous attempt's descendants and durable result/stop state are
resolved through the existing protocols. Merely observing the main tool's exit or
an empty process group does not establish that condition.

Before tool launch, retain the existing single-use consumption, grants, reservation
and journal ordering. Preserve partial artifacts and conservative spent allowances
after owner loss or forced container exit. Do not refund ambiguous work or replay
a tool to regenerate its result.

### Normal completion: proposed subreaper drain

The managed Runner process can be evaluated as a Linux child subreaper. Enable and
read back `PR_SET_CHILD_SUBREAPER` in that actual process before any tool children
exist, and keep the setting unchanged. It survives exec but is not inherited as a
subreaper setting through fork, so enabling only a parent bootstrap is insufficient.
Orphaned descendants are adopted by the nearest living ancestor subreaper.
See [subreaper semantics](https://man7.org/linux/man-pages/man2/PR_SET_CHILD_SUBREAPER.2const.html).

Under a process-wide launch barrier, one active attempt and no unrelated children,
a candidate completion condition is: wait for the exact direct Gate process,
drain adopted children using `waitpid(-1, ..., WNOHANG | __WALL)`, then require
`ECHILD`. A positive PID means a status was reaped and draining continues; zero
means eligible children remain and is not completion. Interrupted waits retry
within the control deadline; other errors fail closed. Plain `WNOHANG` without
Linux `__WALL` can exclude clone children whose exit notification is not SIGCHLD.
Do not use `__WNOTHREAD`, which excludes other threads' children.
See [wait-family semantics](https://man7.org/linux/man-pages/man2/waitpid.2.html).

This is a proposed kernel-observed descendant-drain condition, rather than a
process-group or `/proc` emptiness snapshot. The inference depends on preserving
ancestry: `setsid` does not change parentage; double-forked descendants are adopted;
and `CLONE_PARENT` from a direct tool child creates another child of Runner.
Thread-group completion and clone children require the documented Linux wait
semantics. Kernel reparenting is part of the proof argument, not an application
enumeration/recheck loop. See [clone](https://man7.org/linux/man-pages/man2/clone.2.html)
and [Linux exit/reparenting source](https://github.com/torvalds/linux/blob/v6.6/kernel/exit.c).

Readiness must verify controlled SIGCHLD handling, the actual wait options, an
exclusive waiter, and a barrier covering every Runner thread that could launch a
process. A concurrent reaper must not steal the direct tool's result. Do not allow
parallel attempts, background subprocess helpers, tool installers or updater
processes in this proof window. External `docker exec`, tracing or process
insertion is outside the closed-lineage assumption; a configured exec-based
health check must also be considered. A launcher that creates siblings of Runner
instead of its descendants invalidates the argument.

Once the direct tool has exited, any surviving adopted descendant prevents normal
completion. The owner deadline remains active through this drain; failure to drain
takes the whole-container failure path. The `ECHILD` condition is not containment
or a kill primitive, does not apply after Runner dies, and cannot establish absence
of unrelated processes in the namespace. The actual supported kernel/runtime and
the closed-lineage implementation still require independent acceptance evidence.

### Forced exit: proposed explicit host observation

An owner-written "about to exit" marker proves intent, not completed termination.
Container/host names, numeric PIDs, expired leases and a fresh startup alone are
also insufficient terminal receipts. An explicit distribution CLI may instead
observe the local Docker daemon directly, without a host daemon or socket in
Runner. A candidate adapter must bind:

1. The selected local daemon identity and exact full container ID, expected owner
   labels, image identity and private PID-namespace configuration.
2. A protected prelaunch runtime record linking that container incarnation to the
   exact managed job/Runner/origin, contract hash, attempt and fence. Include the
   daemon's start identity and a fresh lifecycle-owner startup nonce; a container
   ID or restart count alone does not distinguish successive starts.
3. A successful bounded daemon wait and a consistent inspect result showing the
   same incarnation actually exited, with no running, paused, restarting, dead or
   removal state. Its nonzero start/finish records and wait/inspect exit status
   must agree; unset or inconsistent timestamps refuse rather than manufacture an
   incarnation. A missing container, failed wait, nonzero exit code alone or
   caller-supplied inspection JSON is insufficient physical evidence.
4. Unchanged binding on a final direct inspection before a stop intent is
   committed. If another start occurs, evidence is incomplete, or the incarnation
   cannot be matched, retain the hold and do not operate on a new occupant.

The minimal initial observation mode retains the stopped container and disables
automatic restart/removal until explicit reconciliation. This preserves its exit
record. An explicit later restart needs fresh runtime admission. Automatic restart
would need a separately reviewed durable incarnation history; labels do not supply
one. The CLI's proof object must be created only by the direct, validated daemon
adapter, not deserialized from an arbitrary file or accepted as a boolean flag.
Docker provides [container wait](https://docs.docker.com/reference/cli/docker/container/wait/)
and [inspect](https://docs.docker.com/reference/cli/docker/container/inspect/);
the [daemon state model](https://github.com/moby/moby/blob/master/daemon/container/state.go)
also shows why `not-running` alone includes an unstarted container.

The recommended prelaunch mechanism uses the existing distribution enable/start
command to establish the protected host record and register the runtime admission
described below, after checking the new container and fresh owner-ready nonce.
Runner receives only public admission metadata through a protected read-only
record. It must not launch target work before the exact admission and attempt
binding have been acknowledged. This proposed file/handshake adds no service.

For the proposed private PID-1 boundary, completed init termination has a kernel
basis: Linux namespace teardown prevents new PID allocation, signals the remaining
tasks and waits for them before init can be reaped. That is stronger than an exit
intent. It still requires verifying that the observed container used this exact
boundary; it does not prove why it exited, successful evidence publication or
behavior under a compromised host. See [namespace teardown source](https://github.com/torvalds/linux/blob/v6.6/kernel/pid_namespace.c).

### Existing protocol gap and recommended stop-only adapter

The current `authorization.stops.report` requires a live `ManagedRun` owner and
its native confirmed-stop right. Map's `Stops.report` also checks the original
per-attempt control token. `observations.reconcile_stop` can observe an already
existing exact server receipt; it cannot manufacture the first receipt after
owner/token loss. Host observation is therefore not a drop-in call to these
functions. Do not fake `_confirmed_stop`, rebuild a native handle or reconstruct
an execution/control token from journal contents.

The recommended extension has a distinct observed-exit producer and a purpose-
specific host-generated stop capability. Its proposed registration and use are:

1. The existing distribution CLI generates a cryptographically random 256-bit
   secret on the host. It stores the secret and exact runtime metadata in a
   protected host record outside every container bind source, volume and other
   mounted path. Platform ACLs must limit access to the trusted host operator.
   The secret must not enter container environment, command arguments, labels,
   public admission, logs, Runner journal or server storage. It is not an owner
   account credential or an execution/control token.
2. An explicit operator action registers its purpose-separated hash and exact
   runtime admission through the existing authenticated owner-session and CSRF
   protections. First-run Community use reuses local-owner setup/login and its
   session; ordinary API keys or Runner enrollment do not implicitly approve the
   new reporting authority. Registration verifies the session's owner, active
   enrollment, Runner identity and origin. Its immutable runtime identity covers
   the selected daemon, full container ID, expected ownership labels/image and
   private PID profile, start identity and fresh owner startup nonce. The server
   stores only the capability hash, never its raw secret. Public admission carries
   the registration identifier, hash and runtime metadata only.
3. Before target launch, the managed Worker uses its original per-attempt control
   token to bind that selected, already registered runtime to the exact consumed
   contract hash, attempt and fence. Existing origin, Runner, principal and
   enrollment checks remain mandatory. A token can bind its own attempt, not
   register a runtime or acquire the host capability. Trusted Runner control
   compares admission with its own current lifecycle-owner readiness/nonce through
   the private channel before requesting this binding; arbitrary caller-selected
   runtime metadata is insufficient local readiness. Require durable server
   acknowledgement of the runtime binding and existing single-use consumption
   before launch. Atomically permit only one active attempt for a runtime; reject
   stale admission, rebinding, changed incarnation and cross-owner/origin use.
4. After owner loss, the explicit host CLI obtains the direct Docker proof above,
   checks the retained binding against authenticated server observation, and
   records a one-shot observed-exit intent in the existing host journal. A new
   server operation verifies the secret against the stored hash, its scope,
   current enrollment/registration state and the exact bound attempt. Only then
   may it produce a failed/stopped terminal receipt for that attempt. It cannot
   claim, refresh a control lease, extend permission, publish success, resolve
   grants, refund spent allocations or replay work. A capability authorizes this
   one reporting lane; it must never be accepted by an execution API.

Use a finite, explicitly reviewed capability expiry independent of the execution
approval deadline so expiry of work does not itself prevent safe reconciliation.
Registration is revocable through the owner-session path; expired or revoked
authority leaves the attempt held and requires explicit owner-authorized recovery.
The precise lifetime and replacement procedure remain protocol review items, not
an implicit permission to revive execution. A stopped incarnation's registration
is retired on its terminal stop receipt and cannot authorize a later start. Every
new start needs a new secret, startup nonce and owner-approved admission. A normal
sequential attempt, if later supported, needs a fresh exact attempt binding after
the prior attempt has durably resolved.

Reuse the existing database and journal; an additive runtime/attempt binding table
is justified only if current records cannot enforce these explicit immutable
bindings and atomic uniqueness. No new credential volume, root owner credential
store, authentication server or host daemon is proposed. Bounded inputs, constant-
time secret-hash comparison, secret redaction, atomic revocation/report races and
immutable duplicate-receipt handling require protocol tests and security review.

This is a new, bounded reporting-authority decision, not a capability already
supplied by the read-only observation API. The remote server cannot inspect the
operator's Docker daemon. The physical-proof assertion therefore explicitly trusts
the host CLI, host OS and protected secret record; it is not remote attestation.
Anyone holding the secret could bypass the intended CLI and submit a false exit
assertion. Premature terminalization could release concurrency while an old tool
still runs, violating execution limits despite granting no new execution token.
The owner decision must accept that precise trust dependency. A typed proof object
created only by the direct daemon adapter prevents accidental caller-JSON
substitution; it cannot protect against a compromised capability holder or host.

The producer should reuse the immutable managed-stop receipt and existing atomic
concurrency-release rules, while preserving approval/target/duration charges.
The physical exit does not establish a cancellation cause: use an explicitly
reviewed observed-exit failure classification unless an existing fixed cause is
independently known. A hash of submitted JSON is integrity metadata, not evidence
that the daemon inspection happened. Lost replies are reconciled by observing the
same receipt; they do not permit an automatic report retry, re-execution or claim.
Keep the original native reporting lane unchanged. The new producer, authenticated
server operation, registration lifetime/recovery policy, runtime binding and
journal transition are not implemented by this ADR and must be reviewed together.
The final protocol must also provide authenticated lookup of only the bound
immutable receipt after a lost response without recovering the original attempt
token or storing an owner session as a long-lived host credential.

Until that proof exists, restart retains an unknown/held attempt and its evidence;
it does not acknowledge confirmed cancellation or release a fence automatically.
Restart policy must not silently enable an operator-disabled worker. Health and
readiness are observations, not authorization or termination evidence.

## Implementation approval and acceptance gates

The explicit owner decision recorded above authorizes bounded implementation and
testing of variant B and the protected host stop-report producer, including their
disclosed privilege and trusted-host departures. No repeated approval is required
for that same development scope. Default startup remains disabled; this decision
does not approve extra infrastructure, host sandbox claims, release or deployment.

Independent security review and actual Windows Docker Desktop/Linux acceptance
must then cover bootstrap failures and actual capability sets, PID-1 identity,
control-channel isolation, current-control expiry, graceful/forced stop, owner loss,
restart/unknown holds, partial evidence, disabled-worker behavior, grants, budgets
and duplicate claims. Platform tests must report measured bounds and limitations;
mocked tests and a successful init launch do not close those gates.

The stopped adversarial tests remain stopped. No alternate worker or environment
may be used merely to rerun the blocked operation. Missing proof remains an open
NM-2 gate rather than accepted risk, an advertised capability or a reason to
advance NM-3.

## Alternatives retained for review

- Tini/process-group forwarding remains useful lifecycle plumbing, but does not
  supply this UID separation, authority binding or deadline. [Tini](https://github.com/krallin/tini)
- cgroup-v2 `cgroup.kill` is a standard whole-subtree termination primitive. It
  needs verified delegation and a trusted writer outside tool control; stock
  Docker's read-only cgroup mount cannot be assumed to provide that. A writable
  delegation or external lifecycle controller changes deployment authority and
  requires its own review. [Kernel cgroups](https://docs.kernel.org/admin-guide/cgroup-v2.html),
  [Moby defaults](https://github.com/moby/moby/blob/master/daemon/pkg/oci/defaults.go)
- A new host daemon, Docker-socket proxy or alternative container runtime would
  introduce infrastructure. None is selected or required by this proposed ADR.
