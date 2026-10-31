# Architecture Decision Records (ADRs)

This directory records non-trivial design decisions for VardrRunner. Each ADR captures the
context, the decision, and its consequences so future work understands *why* the code looks
the way it does.

## Conventions
- One file per decision: `NNNN-short-kebab-title.md` (zero-padded, sequential).
- Never delete an ADR. To reverse one, add a new ADR and mark the old one **Superseded**.
- Use [`0000-template.md`](0000-template.md) as the starting point.

## Index
| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-extract-vardrrunner-from-vardrmap.md) | Extract VardrRunner from the VardrMap monorepo | Accepted |
| [0002](0002-tool-handler-registry.md) | Tool-handler registry for job execution | Accepted |
| [0003](0003-distribution-and-release.md) | Distribution and release process | Accepted |
| [0004](0004-credential-storage.md) | Credential storage (OS keychain by default) | Accepted |
| [0005](0005-run-scoped-pipelines.md) | Run-scoped pipeline isolation via local handoff files | Accepted |
| [0006](0006-vardrgate-api-test-handler.md) | VardrGate as a job type, executed via binary contract | Accepted |
| [0007](0007-local-secret-resolution.md) | Local secret resolution for VardrGate identities | Accepted |
| [0008](0008-error-classification-and-policy-handling.md) | Error classification and advisory policy handling | Accepted |
| [0009](0009-fail-closed-credential-storage.md) | Fail closed on plaintext credential storage | Accepted |
| [0010](0010-durable-execution-journal.md) | Durable execution journal and conservative reconciliation | Accepted |
| [0011](0011-runner-identity-and-service-management.md) | Stable runner identity and native user-service management | Service portions superseded by 0016; service code removed in v0.51.0 |
| [0012](0012-compatibility-and-local-safety-controls.md) | Compatibility negotiation and local execution safety controls | Accepted |
| [0013](0013-guided-setup-and-host-lifecycle.md) | Guided setup and verified host lifecycle | Service portions superseded by 0016 |
| [0014](0014-pinned-verified-tool-installs.md) | Pinned, verified tool installs in one managed directory | Accepted |
| [0015](0015-mcp-server.md) | MCP server for agent-driven engagements | Accepted |
| [0016](0016-explicit-daemon-execution.md) | Manual invocation and removal of startup workers | Accepted; cleanup commands removed in v0.51.0 |
| [0017](0017-interactive-console.md) | Interactive console | Accepted |
| [0018](0018-platform-diagnostics.md) | Opt-in platform readiness and offline diagnostics | Accepted |
| [0019](0019-container-packaging.md) | Container baseline for the first Compose distribution | Accepted |
| [0020](0020-container-source-katana.md) | Recorded source build for existing container Katana | Accepted for development security remediation |
| [0021](0021-gau-patched-source.md) | Recorded Gau TLS and provider-error source fixes | Accepted for development security remediation |
| [0022](0022-minimal-tool-environment.md) | Minimal environment for tool processes | Accepted |
| [0023](0023-approved-gate-credential-references.md) | Operator-approved VardrGate credential references | Accepted |
| [0024](0024-nmap-outside-supported-toolkit.md) | Nmap outside the supported toolkit; naabu for port discovery | Accepted |
