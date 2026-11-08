# Docker MCP support (unreleased)

- Development toolkit installs the existing `[authorization,mcp]` extras; no new
  dependency declaration, service, port, privilege or default startup is added.
- Existing container smoke verifies SDK initialization, tool discovery and one
  local workspace read in a fresh network-none UID10001 container, without volumes
  or scans. Session and request deadlines bound the check; SDK contexts close it.
- Use canonical Python distribution entrypoints for MCP raw stdio. Preserve the
  existing exclusive installation lock and close the client before issuer,
  execution or maintenance commands; concurrent canonical sessions are not claimed.
- Core remains CLI-only; native installations retain optional MCP extra selection.
