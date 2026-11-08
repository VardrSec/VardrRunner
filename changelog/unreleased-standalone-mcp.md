# Unreleased — standalone MCP metadata

Add explicit `mcp --standalone` using the existing local workspace/journal readers.
Expose only bounded identifiers/timestamps and workspace-bound run metadata.
Keep paths, bodies, credentials, authority, execution and exports out of this surface;
default connected MCP behavior remains unchanged.
