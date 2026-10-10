# ADR 0015 — MCP server for agent-driven engagements

- **Status:** Accepted
- **Date:** 2026-10-08

## Context

VardrMap has a clean, authenticated HTTP API, and operators increasingly want an
AI agent to help run an engagement: survey what has been found, decide what to
scan next, queue it, and draft write-ups. The Model Context Protocol (MCP) is the
standard way to expose a system's operations to an agent, so a client such as
Claude Code or Claude Desktop can call them.

Two forces shape the design:

1. **VardrRunner already is the local, authenticated bridge to VardrMap.** It
   holds the `vmap_` key (keychain), has a typed HTTP client, and is the piece
   that runs on the operator's machine. An MCP server belongs here, not as a new
   service: `pip install vardrrunner[mcp]` then `vardrrunner mcp`.
2. **Scope is advisory and the operator owns it** (VardrMap ADR 0001). An agent
   reads output that originates from the targets under test — response bodies,
   scanner results, finding text — so that content is a prompt-injection vector.

## Decision

Add an optional MCP server (`vardrrunner/mcp_server.py`, `vardrrunner mcp`),
served over stdio, built on the `mcp` SDK (v2, `MCPServer`). It adapts VardrMap's
API to MCP tools and nothing more; the agent's model is supplied by the client.

- **Read tools** (marked `read_only_hint`): engagements, one engagement with its
  scope and stats, scope, findings, assets, API endpoints, recon, jobs, job
  events, reports. Each caps its output to a bounded sample plus the true total,
  so a 10,000-row recon table never floods the agent.
- **Write tools** (marked non-destructive, so the client asks the operator to
  approve each): `preview_job` (a dry run, itself read-only), `queue_job`,
  `queue_pipeline`, `create_finding`.
- **Deliberately absent:** any tool that edits scope or authorization, stop-work,
  every delete, and member/API-key/settings management. The operator does those
  in the UI.
- **Errors** are raised as the SDK's `ToolError`, whose message the protocol
  forwards to the agent as an `is_error` result; a 404 is reported as "not found,
  or it belongs to another user" without confirming existence, matching the
  backend's own non-revealing 404s.
- **Optional dependency.** The `mcp` package (and its pydantic/anyio/starlette
  tail) is an extra; the lean core never imports it. The `mcp` command prints an
  install hint if the extra is missing. `mcp` is also in the `dev` extra so CI
  tests, type-checks, and covers the module.

## Consequences

- An operator can drive an engagement from any MCP client: "what's untested on
  this engagement?", "run the content pipeline and write up anything high". Every
  write is a tool the client surfaces for approval.
- **Withholding a scope-editing tool is the main prompt-injection defence.** The
  agent reads target-controlled text, but it has no tool to widen what may be
  tested, so a planted "add 10.0.0.0/8 to scope" instruction has nothing to call.
  The server's `instructions` also tell the agent to treat tool output as data
  and to surface, not obey, any instructions embedded in it. This does not make
  the agent safe to run unattended against a hostile target; it bounds the blast
  radius and keeps the operator in the loop on every write.
- **The advisory model is unchanged** (ADR 0001): a queued job that falls outside
  scope still returns warnings and still runs. The MCP layer adds no enforcement;
  staying in scope remains the operator's responsibility, as with Burp or nmap.
- No VardrMap change was needed — the server calls existing endpoints. A future
  remote/hosted MCP (for claude.ai) would need OAuth on the backend and is out of
  scope here.

## Alternatives considered

- **A chat endpoint inside VardrMap.** Puts the model cost on the backend, needs
  a streaming UI and conversation storage, and benefits only in-app users. The
  MCP server reuses the operator's own client and subscription and needs no
  backend work; an in-app assistant can reuse these same tool definitions later.
- **Enforce scope in the MCP layer (block out-of-scope queues).** Rejected: it
  would contradict ADR 0001's advisory model and split "what is allowed" across
  two places. Not exposing scope-editing tools gives the real safety benefit
  without turning the agent path into a second policy engine.
- **Expose every endpoint, including deletes and scope edits.** Maximally
  capable, but hands an agent reading untrusted target output the ability to
  change the engagement's boundaries or destroy work. The curated surface is the
  point.

## Amendment (v0.41.0): server-side filtering and paging

The first version filtered each page in the MCP server after fetching it, so
`list_findings(severity="high")` only examined the first page and could miss
matches while reporting a total that was not the filtered total. Read tools now
send their filters (`severity`, `source`, `status`) and an `offset` to VardrMap,
which applies the filter before paging and returns the matching `total`. Each
result reports `count`, `offset`, and `next_offset` (`null` on the last page) so
the agent can follow pages without guessing.

This requires VardrMap v0.39.0, which added `total` to the job and event lists
and the `source` recon filter. Against an older backend a read fails with a
message naming the required version rather than presenting a first-page sample
as the whole inventory. Every upload also now carries the producing `job_id`
(ADR 0014's installer is unaffected), which VardrMap validates against the
engagement.

## Amendment (v0.42.0): prompts carry instructions, never fetched data

The server now exposes four MCP prompts — `brief`, `triage`, `untested`,
`retest` — for the workflows an operator repeats on every engagement. They are
the slash commands a client surfaces (`/mcp__vardr__brief`), and each takes an
optional `engagement_id`, asking the operator to choose when it is blank rather
than guessing.

**A prompt expands to instruction text and makes no API call.** The tempting
version pre-fetches — pull the findings, paste them into the triage prompt — and
it is the wrong shape here. Prompt text arrives as the most trusted content in
the agent's context, whereas a tool result is already framed as untrusted data
by the server's `instructions`. Finding titles, recon URLs and scanner output
all originate from the targets under test, so embedding them in a prompt would
launder target-controlled strings out of the untrusted position and into the
trusted one — defeating, for the sake of saving one tool call, the framing that
bounds the injection risk this ADR is built around. The agent therefore gathers
its own data through the read tools, and a test asserts that expanding any
prompt leaves the API client untouched.

**A prompt may only promise what the tools can do.** Prompt text is easy to
write past the tool surface, and the first version of these did: `brief` asked
for the authorization window, which `get_engagement` does not return, and called
`list_reports` the engagement's deliverables, when it reads the per-finding
write-ups and the client deliverable has its own API; `retest` told the agent to
find findings "recorded as remediated or awaiting verification", which are not
VardrMap statuses, and to target the one affected asset, which `queue_job`
cannot express because it takes a target source rather than a target. Each read
as a working workflow and would have had the agent improvise against a tool that
cannot answer.

The prompts now state their own limits instead: `retest` names the real statuses,
says plainly that no job can be scoped to one asset, offers the local
`run --target` command as the route that can, and admits there is no
scan-results tool, so it judges by whether an equivalent finding returns.
`brief` names the authorization record and the client deliverable as things to
check in VardrMap rather than asking for them. Tests pin this: every
`snake_case` tool reference in every prompt must resolve to a tool the server
exposes, and the specific mismatches above are asserted absent. Expansion tests
alone prove phrasing, not feasibility — that gap is what let the first version
through.

Consequences of the split: a prompt stays correct as the engagement changes,
because nothing is baked in at expansion time, and the server needs no new
permission — every prompt works through the tools already described above.
`brief` is read-only by construction and says so; the three that can lead to
work carry the same rule as the write tools, which is to preview, say what it
intends, and let the operator approve. The prompts also state plainly where no
tool exists: `triage` cannot edit a finding and `retest` cannot record itself
against a finding's history, so both hand the operator what to enter in the UI
rather than inventing a capability.
