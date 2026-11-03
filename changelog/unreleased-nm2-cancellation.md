# Unreleased — explicit controlled cancellation

Add `jobs run --controlled` and local `jobs stop RUN_ID`, using the existing journal
and adapters. Matching Map source/migration is required before publication/use.
No startup worker or background queue consumption is enabled. See ADR 0026 for
ownership, lease, platform, partial-evidence and rollback limits.
