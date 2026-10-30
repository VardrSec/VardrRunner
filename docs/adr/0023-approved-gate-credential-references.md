# ADR 0023: Operator-approved VardrGate credential references

- **Status:** Accepted
- **Date:** 2026-10-30

## Context

A `vardrgate_api_test` case comes from the backend. Each identity names where its
secret lives: an environment variable (`value_env`) or an OS keychain account
(`value_keychain`, under the `vardrrunner-secrets` service). The runner resolved any
named reference and sent the value to the case's target. A case could therefore name
an unrelated variable, including `VARDRMAP_API_KEY`, which the container distribution
supplies in the same environment, and point it at a target its author chose.

VardrGate also expanded `${VAR}` references anywhere in the job from the environment
it inherited, which reached the same secrets without any credential field, and it
re-read already resolved values as references.

## Decision

1. **Approval.** The runner resolves a reference only when the operator has approved
   it on this machine with `vardrrunner credentials approve --engagement <id> --origin
   <url> (--env NAME | --keychain ACCOUNT)`. An approval binds one reference name to
   one engagement and one origin (`scheme://host[:port]`). It is stored in the runner's
   owner-only config file and holds names only, never values. The backend has no way to
   create one.
2. **Every origin.** A reference must be approved for every origin the case contacts:
   the request, setup steps, identity preflights and the write verifier with its reset. Origins require a
   fixed authority with no URL user information or setup captures in the host/port;
   setup captures in paths and queries remain supported.
3. **No environment placeholders.** A case containing `${` anywhere is refused.
4. **Before claim.** The job loop checks both rules after parsing the job and before
   claiming it. A refused job fails with a reason that includes the approval command.
   Resolution checks again before reading any secret.
5. **Literal Gate input.** The runner invokes `vardrgate run --job <file> --literal-job`,
   so Gate uses the resolved job as written and expands nothing (VardrGate ADR 0028).
   An older Gate rejects the flag before sending any request.
6. **Confirmation.** The pre-run preview lists each identity's reference names.

## Consequences

- Breaking: an existing case's references fail until approved. The error names the
  exact command to run.
- Approvals are per machine. A container Runner keeps them in its state volume.
- Literal `value` credentials are unchanged; VardrMap refuses non-empty literals at
  save time.
- An approval says this reference may be sent to this origin for this engagement. It
  is not scope enforcement; scope stays advisory.
- Requires VardrGate with `--literal-job`, and VardrMap that refuses `${...}` in
  stored cases for a consistent error at save time.
