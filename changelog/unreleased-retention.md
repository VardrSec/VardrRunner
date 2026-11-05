# Unreleased: preserve journal-linked run evidence during age cleanup

Direct-run startup previously removed every run directory older than seven days,
including artifacts still referenced by unfinished or uncertain journal records.
Age cleanup now preserves all journal-referenced run directories, artifacts and
manifests, including terminal records with retained PIDs or uncertain uploads.
Nested evidence also protects its containing run directory.

Old unjournaled direct-run directories remain eligible for seven-day cleanup only
where Python 3.11+ provides descriptor-relative, symlink-resistant `rmtree` and
directory enumeration. Cleanup opens a verified nonlinked root, checks its device
and inode, then lists, inspects and deletes relative to that held descriptor. A
substituted root pathname cannot redirect deletion into another directory.
Windows, Python 3.10 and unsupported runtimes skip automatic cleanup; direct
execution still works, but old run data accumulates until explicitly managed.

Journal-linked evidence requires a separately reviewed retention policy; this
change introduces no automatic journal-evidence deletion. Unreadable, excessive
or relative journal path inventory skips cleanup, and an absent journal is not
created or migrated. The path-only inventory refuses more than 10,000 rows,
oversized paths or more than 8 MiB of path data without truncation. Observed linked
roots and children are skipped. The inventory is a point-in-time observation,
not a stable snapshot or an assurance that SQLite sidecars remain unchanged.

Behavioral regressions use disposable real journals and synthetic local evidence,
without scanners or network access. They cover unfinished work, terminal retained
PIDs, uncertain uploads, completed journal evidence, nested artifact/manifest
references, unreadable state, relative paths, observed directory links and
physical substitution of the run root with unrelated disposable evidence.
Unsupported-runtime tests require preservation; active descriptor cleanup also
needs verification on a supported Linux runtime.
