# ADR 0011: Stable runner identity and native user-service management

- **Status:** Accepted
- **Date:** 2026-08-18

## Context

Hostname alone is not a stable runner identity: images are cloned, hosts are renamed, and
small teams often operate several workers. Detached processes also lack the restart and
status semantics expected for an unattended service. Requiring Kubernetes, an agent
platform, or a bespoke supervisor would work against the small-team deployment goal.

## Decision

Generate one UUID per installation and persist it in an owner-only JSON file. Creation uses
exclusive filesystem semantics so simultaneous first-use commands converge on one value.
Corrupt identity state fails closed instead of being silently replaced. A human label is
stored separately from hostname and may be overridden by `VARDRRUNNER_NAME`.

Include UUID and name as additive heartbeat fields. Older backends may ignore them and keep
their hostname behavior.

Manage unattended execution through native **per-user** facilities:

- systemd user unit on Linux;
- LaunchAgent on macOS;
- Scheduled Task on Windows.

Generated definitions run the ordinary foreground daemon with rotating JSON logs. They do
not embed credentials. Linux may reference an operator-owned EnvironmentFile by path; other
platforms use keychain/config credential resolution. All manager commands are argv arrays,
never shell strings.

## Consequences

- Operators gain stable local identity and familiar install/status/uninstall workflows.
- Service semantics vary slightly by OS because no portable Python process can implement
  the Windows Service Control Manager protocol without another runtime dependency.
- Windows uses an ONLOGON per-user task; machines requiring pre-login operation should run
  VardrRunner under their established enterprise supervisor instead.
- Identity files, unit files, and logs remain local operational state and must be included
  in host backup/retention policy where required.
