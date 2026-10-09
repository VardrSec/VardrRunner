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

## Amendment (v0.45.0): checklists suggest, engagements evidence

Phase 6 ships two versioned methodology checklists inside the package — the
OWASP API Security Top 10 (2023) and WSTG 4.2 — served by `list_methodologies`
and `get_methodology`, plus a `methodology` prompt. Neither tool makes an API
call; the data is local, which also means a checklist cannot be influenced by
anything a target says.

**Coverage is not representable in the data, deliberately.** The schema refuses
`status`, `covered`, `done` and `coverage` at load time. The temptation is a
tick-box per item, and it is a trap: a checklist that can hold a tick will get
one as soon as a scanner runs, and "we assessed against the OWASP API Top 10"
with ticks earned by a nuclei job is a false claim in a client deliverable.
Wrong data in an engagement's record is worse than none — the same reasoning as
ffuf's auto-calibration and its unreadable-report failure.

So an item says what to look at, which job types relate, and one thing more —
`method`, which records **how an item is tested, not whether it has been**:

- `method: "tooling"` — a job type here can produce evidence bearing on it, and
  evidence of a *candidate* at that.
- `method: "manual"` — no job type here can establish it; it is tested by hand.
  Business logic, authentication flows and session handling sit here, and both
  shipped methodologies are asserted by test to contain some, so the distinction
  cannot quietly become decorative.

Method and evidence are independent, and keeping them so took a correction. The
field was first called `evidence`, and the prompt then routed every `manual` item
to "requires manual testing" whatever the engagement's record said — so a
hand-tested authentication issue, written up as a finding with an activity
history, could never count as covered. That is backwards: how a test is performed
says nothing about whether it was performed. The field is now `method`, the old
name is refused at load so the conflation cannot creep back, and the prompt sorts
on the record: evidenced (citing ids, whatever the method), not evidenced where a
job would help, not evidenced where hands-on work is needed.

Whether this engagement covered an item is derived at the point of asking, from
its own jobs and findings, cited by id. The prompt is told not to report a
percentage: a number collapses that distinction back into the claim the design
exists to prevent.

**Scope is stated per methodology.** The WSTG entry covers the guide's twelve
top-level categories by section number. OWASP additionally gives every test
scenario a stable identifier of the form `WSTG-<version>-<category>-<number>`
(`WSTG-v42-INFO-02`), and a category is not coverage of the scenarios beneath it,
so each methodology carries a `scope` field saying what level it works at and the
prompt is told not to cite a scenario identifier it has not assessed.
Scenario-level mapping is deferred, not implied.

Every `suggests` entry must name a job type in the handler registry. That check
immediately caught the checklist suggesting `ffuf` while its handler was still on
an unmerged branch — a suggestion pointing at a tool the runner cannot run.

Only identifiers, official titles and source URLs are referenced from OWASP. The
guides are CC BY-SA 4.0 and the repositories are AGPL-3.0, so rather than reason
about share-alike interaction, no OWASP prose is shipped: the "what to look at"
notes are this project's own, and each methodology carries an `attribution` field
naming the source and its licence.

## Amendment (v0.44.0): two writes are assertions, not capabilities

Phases 4/5 add the reads the prompts were missing — `list_authorizations`,
`get_finding_activity`, `list_deliverables`, `get_deliverable_revision` — plus
two drafting tools: `draft_test_cases` (VardrMap's `test-cases/preview`, which
stores and queues nothing) and `draft_report` (a per-finding write-up).

Two writes that exist in VardrMap stay out, for a reason distinct from the
scope/auth/delete set above. That set is withheld to bound what a compromised
agent could do. These are withheld because **they are assertions only a person
can honestly make**:

- **Saving a VardrGate test case** (`POST /test-cases/reviewed`). Saving declares
  that a human reviewed the case. That declaration is the entire purpose of the
  step — the CLI spells it `--reviewed`, writes the review file exclusively, and
  refuses literal credentials precisely so a person has to look. An agent calling
  it would be signing the operator's name to a review it performed itself, and a
  case is what later drives real authorization tests against a client's API.
- **Creating or revising a client deliverable.** A revision is immutable once
  written and is the document handed to the client. An agent cannot unsay it, and
  the signature on a deliverable is the operator's professional judgement, not a
  model's.

So the server drafts and reads in both areas and stops at the point where a human
has to commit. `draft_report` takes no `status` argument and always posts `draft`,
so it cannot mark a write-up final or delivered. A test asserts no tool by any of
the plausible names for these operations exists, kept separate from the
scope/delete forbidden set so the two rationales do not blur.

This is a narrower surface than "expose the API", and deliberately so: the value
of an agent here is in the drafting and the reading, which is most of the work,
while the assertions stay where accountability already sits.

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
