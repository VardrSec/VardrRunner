# Unreleased — Gate launch failure cleanup

The private Gate job file can contain locally resolved credentials. Executable
resolution (including installation receipt validation) and preflight inspection
now run inside its existing cleanup block, so a failure before subprocess launch
also attempts removal immediately. Previously these failures bypassed cleanup,
and startup recovery deliberately leaves directories belonging to live PIDs alone.

The original failure remains primary if deletion fails, and cleanup errors still
use fixed log messages. Successful execution still fails closed on cleanup error.
Credential approvals, grants, request guards, deadlines and Gate arguments are
unchanged. No execution route or background work is enabled.

Synthetic tests cover malformed/unreadable receipts, executable resolution and
preflight failures, including failed cleanup, with no subprocess execution or real
credentials. This fixes a local retention path; it does not establish disclosure.
