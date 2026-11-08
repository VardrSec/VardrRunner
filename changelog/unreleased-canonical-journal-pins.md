# Unreleased — canonical journal identity and Windows name pins

Reuse one canonical SQLite pathname for journal, workspace and grant connections.
Ordinary symlink aliases now use the database's original WAL name on Windows.
Open every canonical Windows ancestor and leaf as a non-reparse object and retain
no-delete-sharing handles until SQLite closes; permit legitimate database writers.
Refuse hardlinked Windows databases rather than split WAL state across aliases.
No new dependency, Windows version requirement, database schema or snapshot API.

Add native replacement-at-SQLite-open and handle-lifetime tests, protocol refusal
tests and a complete read-only inventory for conservative evidence retention.
Keep process-creation refusal assertions across all intercepted Windows library
loads; loading a journal pin is not process creation. Remove temporary WAL diagnosis
prints while preserving the original live-WAL regression.

POSIX pathname replacement, sidecar replacement, strict source/sidecar non-mutation
and installed acceptance remain open. No release or full NM-3 acceptance is claimed.
