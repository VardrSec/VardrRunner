# Managed worker lifecycle

The distribution owns explicit worker admission, enable/disable, Docker lifecycle
and host stop reporting. Ordinary startup does not enable a worker. Use the
[managed worker guide](managed-worker.md) with the matching source-built
[distribution setup](https://github.com/VardrSec/VardrSec/blob/main/docs/local-managed-setup.md).

The worker-only lifecycle owner starts as namespace PID 1 with only SETUID,
SETGID and SETPCAP for its bounded bootstrap. It drops capability sets before
work; ordinary Runner and tools use UID 10001. This does not add a Docker socket,
privileged container or host service. Public admission and environment flags
cannot substitute for the trusted lifecycle-owner context.

Each job independently needs valid authorization, credential grants and finite
execution budgets. A running worker does not grant indefinite job authority.
Unknown claims/results remain held. A new incarnation must not replace one whose
physical exit and original accounting are uncertain.

Stop through the distribution's exact-incarnation controls and reconcile the
original Runner journal before subsequent startup. Preserve stopped state and
artifacts. Host STOP reporting trusts the host; a false exit report can release
accounting prematurely. Host reporting secrets remain outside the worker.

See [support limits](limitations.md) for suspend/resume, connectivity and native
platform boundaries. These instructions are not a security or release acceptance
claim.
