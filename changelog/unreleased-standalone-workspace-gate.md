# Unreleased — native standalone workspace Gate

`workspace gate` consumes existing operator-approved standalone files for the
fixed HTTP Gate profile without a Map account/token. It binds the local workspace
and actual Runner identity, uses current time and known capabilities, requires
explicit terminal confirmation, existing local authority state and expiring
credential-reference grants. It creates no keys, approval or authority state.

The consumer reuses native Windows control, local stop, PID observation and the
immutable deadline at creation. Linux/Docker refuse before consumption; there is
no legacy execution fallback. New evidence directories are exclusive. Existing
journal/manifests/audit remain the record; no upload is invented. Failed or
uncertain consumption stays spent, partial files remain, and standalone records
never enter legacy Map recovery. This is not complete Mapless installation or
general-tool execution, production trust enrollment, release or worker adoption.
