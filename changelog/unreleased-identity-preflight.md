# Identity/session preflight

Gate cases may declare a reviewed same-origin GET session check on each authenticated
identity. Match public subject/tenant/role metadata with the matching Gate build;
secrets remain local `value_env` or `value_keychain` references.

Runner passes `--require-identity-preflight` whenever an identity declares preflight.
Older Gate binaries reject that flag before contacting a target. Exit 3 is accepted
for artifact inspection only on this path: an exact diagnostic record for every
declared check, at least one failure, empty executions/findings and matching process
status are required. Missing, duplicate or inconsistent reports fail the job.
Unconfigured cases preserve their exit-code behavior.

Failed session artifacts retain the unresolved case hash, upload before the job is
marked failed, and produce a preflight-failure summary rather than a zero-findings
success. Recovery also preserves failure, including deferred finalization. Map
stores safe bound diagnostics separately from resource authorization decisions.

Deploy the matching Map backend and upgrade Gate/Runner before authoring these
cases. Old Runner versions lack the compatibility guard. No background session
keeper, automatic refresh or scope enforcement is introduced. Tests use disposable
loopback targets; no production credentials or hosted OAuth are exercised.
