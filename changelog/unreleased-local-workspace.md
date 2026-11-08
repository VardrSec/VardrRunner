# Unreleased — local workspace metadata

Add `vardrrunner workspace create <name>` and `workspace show <id>`. They return
inert local metadata as JSON using the existing journal, with no Map account,
API key or `--local` flag. Creation is additive and never replaces an existing
workspace or run. Invalid labels, unknown metadata and incompatible tables fail
without implicit repair. Existing connected commands and audit/export remain.

This increment does not attach authorization/scope, select an active context,
launch tools, create credentials, approve work, enable a worker or implement the
Full/Mapless installer. Workspace presence grants no execution authority.
