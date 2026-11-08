# Unreleased — scoped local audit history

`audit list` and `audit export` accept `--engagement ID` (`-e`) to select local
history for an exact engagement or workspace. Selection happens in the existing
parameterized journal query before sorting/limits and composes with `--since`.
It is local-only and needs no Map account, token, Gate or worker. Existing
unscoped calls, redaction, schema-1 export and atomic output behavior remain.

This increment provides scoped history/metadata retention, not complete portable
workspace evidence: artifact bytes, signed input files and credentials are not
copied. It adds no authority, execution path, database schema or new evidence store.
