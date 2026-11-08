# Standalone diagnostics

Use explicit `doctor --standalone --offline --json` to check local Runner state,
permissions, journal, resources and tools without Map credentials or release
discovery. The existing `--offline` alone still checks configured Map access.
Standalone plus platform checks refuses; defaults are unchanged.
