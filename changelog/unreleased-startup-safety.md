# Manual invocation only

Older versions could register a native service at sign-in. Its daemon polled pending
jobs, reconciled interrupted execution, and ran scans without a new manual invocation.

Startup registration and background workers have been removed. `service install` and
`daemon start` return errors without creating files, processes, or network requests,
including when their former `--run-jobs`, `--detach`, or installation flags are supplied.
`init` never offers startup and rejects legacy service options before changing state.
`doctor --production` checks credentials, disk, identity, and journal without requiring
background execution.

Install the program with `pipx install vardrrunner` and its supported scan dependencies
with `vardrrunner tools install --all`. Invoke `run`, `pipeline run`, or `jobs run` when
ready to execute. `jobs run` retains its one-shot queue and recovery behavior; it does
not leave a worker running. The backend can still hold queued or scheduled work, but
VardrRunner no longer checks for or executes it in the background.

## Existing installations

Run `vardrrunner daemon stop` and `vardrrunner service uninstall` to stop legacy workers
and remove their startup registration. An active old scan may finish before cooperative
shutdown. Verify with `daemon status` and `service status`.

Upgrading alone does not remove OS registrations or stop a running old executable.
A remaining registration that calls the updated `daemon start` exits with an error;
remove the registration to prevent the invocation itself on sign-in.

Regression tests cover all native cleanup plans, rejected legacy flags, setup accepting
all normal prompts without startup, production preflight without a service, and manual
queue execution. No real target scans are required to validate these changes.
