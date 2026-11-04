# Journal file type precheck

Journal connections, read-only workspace listing and the grant store's separate
connection refuse observed special objects before calling SQLite. Missing journals
retain the existing creation/read-only behavior; ordinary symlinks to regular
files remain supported, including committed live WAL state. Dangling symlinks and
observed non-symlink Windows reparse objects refuse with fixed errors.

This corrects pre-existing special-file availability failures. It does not prevent
concurrent path replacement or impose an I/O deadline; SQLite still opens a
pathname. No remote attacker control has been established. Native Windows reparse
behavior and the separately developed portable-export read connection require
their own verification/integration. No new persistence, execution or authority
mechanism is introduced.
