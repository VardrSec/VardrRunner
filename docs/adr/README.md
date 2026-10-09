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
| [0011](0011-runner-identity-and-service-management.md) | Stable runner identity and native user-service management | Accepted |
| [0012](0012-compatibility-and-local-safety-controls.md) | Compatibility negotiation and local execution safety controls | Accepted |
| [0013](0013-guided-setup-and-host-lifecycle.md) | Guided setup and verified host lifecycle | Accepted |
| [0014](0014-pinned-verified-tool-installs.md) | Pinned, verified tool installs in one managed directory | Accepted |
| [0015](0015-mcp-server.md) | MCP server for agent-driven engagements | Accepted |
