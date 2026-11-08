# Operator-approved queue proposals (unreleased)

- MCP `queue_job` and `queue_pipeline` create only pending VardrMap proposals.
  Responses explicitly report `queued:false` and `requires_operator_approval:true`.
- Requires the matching unreleased VardrMap queue-proposal endpoint increment:
  `POST /engagements/{id}/proposals` must accept `queue_job` and `queue_pipeline`.
  Deploy that reviewed Map change before publishing this dependent Runner feature.
  Older Map versions refuse the kinds; there is no fallback to direct queueing.
- The operator reviews exact payload/configuration in VardrMap's Proposals panel.
  Only its full-scope approval applies the request; MCP exposes no approve tool.
- Approval queues work, not execution authority. Existing job/claim authorization,
  credential, case-snapshot, stop-work and budget requirements remain in force.
- Ordinary CLI/API queue commands retain their existing behavior; no remote OAuth,
  service, migration, new dependency or tool execution is introduced.

Managed Gate proposals can explicitly request the existing contract-required
profile; proposal approval still grants no execution authority. Pipelines retain
their existing profile restrictions.

Gate and finite Recon artifacts retain redacted unresolved input structure,
original case hashes and known tool identities. Verified binaries reuse existing
runtime hashes; stopped copies distinguish approved-plan hashes from observations.
Raw stopped files and physical-stop guards remain unchanged. Version labels stay
unknown when unavailable. Removed request inputs require fresh operator review;
the derivative is informational and not an independent reassessment.
