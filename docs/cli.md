# VardrRunner — CLI Reference

All commands are sub-commands of `vardrrunner`. Run any command with `--help` for its
exact flags. Commands that talk to the backend require a prior `login` (they exit with a
helpful message otherwise).

```
vardrrunner [COMMAND] [SUBCOMMAND] [OPTIONS]
```

Every command that acts on an engagement takes `--engagement <uuid>`. `--program` and
`-p` are accepted as aliases on the same flag, so scripts written before the v0.27.0
rename keep working.

---

## `init` — guided host setup

```bash
vardrrunner init
vardrrunner init --production --install-service
vardrrunner init --non-interactive --name runner-a --production --install-service
```

`init` composes the secure setup steps in their required order: configure or reuse auth,
create the stable runner identity, initialize the durable journal, offer to install the
pinned scan tools, optionally install the native per-user service, then run `doctor`. Setup succeeds only when the final doctor
profile succeeds. It is safe to rerun; completed local state is reused.

| Option | Purpose |
|--------|---------|
| `--url` / `--key` | Supply VardrMap credentials; omit `--key` interactively for a hidden prompt |
| `--name` | Set the durable human runner label |
| `--production` | Require the strict unattended doctor profile |
| `--install-tools` / `--no-install-tools` | Install pinned, verified scan tools. Asked interactively (default yes); off under `--non-interactive` unless `--install-tools` is passed |
| `--install-service` | Install the native per-user background worker |
| `--start-service` / `--no-start-service` | Start after installation (default: start) |
| `--env-file <path>` | Attach an existing Linux systemd credential environment file; also enables service installation |
| `--allow-plaintext-credentials` | Explicitly accept config-file key storage if no keychain exists |
| `--non-interactive` | Never prompt; fail if auth input is missing |

Non-interactive setup accepts existing environment credentials. For an installed service,
those credentials must also survive a fresh process: use keychain/config auth, or on Linux
pass an operator-owned, owner-readable-only (`chmod 600`) `--env-file`. Setup never creates
or displays a secret env file. As with `login`, prefer the hidden prompt over `--key` so the
credential does not enter shell history.

---

## `login`
Authenticate to a Vardr product. Verifies the key against `GET /me` before saving anything,
then stores it in the **OS keychain** (macOS Keychain / Windows Credential Locker / Linux
Secret Service). The backend URL is kept in `~/.vardrmap/config.json`. On a machine with no
keyring backend, login fails closed unless cleartext storage is explicitly accepted.

```bash
vardrrunner login vardrmap
```

| Option | Purpose |
|--------|---------|
| `--url` | Backend base URL; prompted for if omitted |
| `--key` | The `vmap_` API key; prompted for (with hidden input) if omitted |
| `--allow-plaintext-credentials` | Permit cleartext storage when no OS keychain exists |

**Login fails closed.** With no OS keychain available — or when a keychain write fails —
`login` verifies your key, **saves nothing**, and exits 1 rather than quietly writing
cleartext to `~/.vardrmap/config.json`. It prints three routes: use `VARDRMAP_API_KEY`
(recommended for servers; nothing touches disk), install a keyring backend, or pass
`--allow-plaintext-credentials` to accept it deliberately. See
[ADR 0009](adr/0009-fail-closed-credential-storage.md).

**Prefer the prompt for the key.** Passing `--key` puts a live credential into your shell
history — on PowerShell it persists to `(Get-PSReadlineOption).HistorySavePath`, and on
POSIX shells to `~/.bash_history` or equivalent. Omitting `--key` reads it with echo
disabled, so it never reaches your history.

That is the only thing the prompt protects. **Where the key is then stored does not depend
on how you supplied it:** if an OS keychain is available it goes there; otherwise login
refuses unless `--allow-plaintext-credentials` was supplied. `vardrrunner credentials` and
`doctor` both report which source is in use. On a headless box or a container, where a
keyring backend usually is not present, set
`VARDRMAP_API_KEY` in the environment instead of logging in at all; nothing is written to
disk on that path.

Key resolution order at runtime: **`VARDRMAP_API_KEY` env → keychain → config file**.

## `logout`
Remove the stored API key from the keychain and config file. The backend URL is left in
place (re-authenticate with `login`); warns if `VARDRMAP_API_KEY` is still set.

```bash
vardrrunner logout
```

## `credentials`
Report how this machine is authenticated, without ever displaying the key: source
(`environment` / `keychain` / `config file`), whether it is encrypted at rest, keychain
availability, whether the config file holds cleartext, and file permissions. Exits
non-zero when no credential is configured, so it composes into provisioning scripts.

```bash
vardrrunner credentials
```

Only the OS keychain counts as **encrypted at rest**. `VARDRMAP_API_KEY` is not written
to disk by the runner — a real improvement — but any process running as your user can
read it, so it is reported as unencrypted rather than safe.

## `whoami`
Show the identity tied to the configured API key (`GET /me`). Confirms *which* account a
key belongs to without printing the key itself.

```bash
vardrrunner whoami
```

---

## `identity`

Each installation has a stable UUID independent of hostname and a human-readable label:

```bash
vardrrunner identity show
vardrrunner identity set-name chicago-runner-1
```

The first identity is created at `~/.vardrmap/runner-identity.json` with owner-only
permissions. Corrupt state fails closed; it is never silently replaced with a new UUID.
Set `VARDRUNNER_NAME` for a deployment-time label override without rewriting the file.

---

## `engagements`
List every engagement visible to the configured key.

```bash
vardrrunner engagements          # alias of `engagement-list`
```

`vardrrunner programs` still runs as a retired alias; it is hidden from `--help`.

## `scope`
Show the in-scope and out-of-scope items for one engagement — useful before a run to
confirm what the `--scope` target source will expand to.

```bash
vardrrunner scope <engagement-id>
```

---

## `status`
Show local configuration, runner version, and each external tool's source: a verified
managed install, an unverified copy on `PATH`, or missing. Does not require auth for the
local parts. This is the quick human glance — *"show me where I stand."*

```bash
vardrrunner status
```

---

## `doctor`
Deep preflight before unattended use — *"validate this machine."* Unlike `status`, `doctor`
is built for scripts: it **exits 0 only when the runner is healthy enough to work**, exits
non-zero on any actionable failure, and prints a remediation hint per problem.

```bash
vardrrunner doctor && vardrrunner daemon start --detach   # gate provisioning on health
vardrrunner doctor --json                                  # machine-readable report
vardrrunner doctor --production                            # strict unattended profile
```

Checks: credential source (env vs file), backend URL validity (HTTPS), config-file
permissions, API auth, daemon PID health (running / stale), run-dir writability, free disk,
effective resource policy, tool versions and sources, and per-pipeline readiness. Output falls back to plain ASCII when the terminal or a redirect can't encode its status symbols (Windows piped output), so a redirected report never crashes.
**Failures** (no creds, bad URL, auth failure, unwritable run dir, critically low disk, zero
tools, or a managed tool that **fails hash verification**) set a non-zero exit; missing
individual tools, unverified `PATH` copies of tools VardrRunner can manage, a missing
naabu capture library, and low-ish disk are **warnings** that don't block.

`--production` additionally treats plaintext credentials as a failure, raises disk
thresholds to 1 GiB minimum / 5 GiB warning, verifies the execution journal and stable
identity, and requires either a live daemon or active native service. JSON output includes
`"profile": "standard" | "production"`.

---

## `heartbeat`
Send a single heartbeat to the backend (hostname, version, OS, tool availability). Useful
to confirm connectivity and that the backend's Bridge sees this machine.

```bash
vardrrunner heartbeat
```

The heartbeat also advertises runner version, job-schema versions, and capabilities. A
newer backend may return compatibility constraints. Definite mismatches pause queue claims;
warnings and legacy responses do not.

---

## `update` — check for runner releases

```bash
vardrrunner update check [--force] [--json]
```

Checks public PyPI metadata and reports whether a newer semantic version exists. Results
are cached for 24 hours under `~/.vardrmap/update-check.json`; `--force` bypasses the cache.
This command never installs or upgrades software. Use `pipx upgrade vardrrunner` or
`uv tool upgrade vardrrunner` after reviewing the release.

---

## `mcp` — serve the engagement to an AI agent

```bash
pip install 'vardrrunner[mcp]'   # one-time: the MCP server is an optional extra
vardrrunner mcp                  # serve over stdio (clients launch this for you)
```

Runs a [Model Context Protocol](https://modelcontextprotocol.io) server over stdio so an MCP
client — Claude Code, Claude Desktop — can drive a VardrMap engagement with the same `vmap_`
key this runner already uses. The agent's model is supplied by the client; this command only
adapts VardrMap's API to MCP tools. See [ADR 0015](adr/0015-mcp-server.md).

Register it once with your client:

```bash
claude mcp add vardr -- vardrrunner mcp        # Claude Code
```

For Claude Desktop, add to its MCP config:

```json
{ "mcpServers": { "vardr": { "command": "vardrrunner", "args": ["mcp"] } } }
```

**Tools exposed**

| Kind | Tools |
|------|-------|
| Read (no change) | `list_engagements`, `get_engagement`, `list_scope`, `list_findings`, `list_assets`, `list_api_endpoints`, `list_recon`, `list_jobs`, `get_job_events`, `list_reports`, `preview_job` |
| Write (client asks you to approve each) | `queue_job`, `queue_pipeline`, `create_finding` |

**Not exposed, by design:** editing scope or authorization, stop-work, any delete, and
member/API-key/settings management — do those in the UI. Withholding a scope-editing tool is
the main guard against prompt injection: the agent reads target-controlled text (response
bodies, scanner output) and must not be able to act on a planted "add this to scope"
instruction. Read tools return one page at a time with the true `count`, an `offset`, and a
`next_offset` to follow until it is `null`; filters (`severity`, `source`, `status`) are applied by
VardrMap **before** paging, so they cover the whole inventory rather than one page. This needs
VardrMap v0.39.0 or newer; against an older backend the reads fail with a clear message instead of
reporting a first-page sample as the total. Large recon or
asset tables never flood the agent. A queued job that falls outside scope still returns
warnings and still runs — staying in scope is the operator's call, exactly as elsewhere.

Requires a configured key (as for any authenticated command). The command exits with an
install hint if the `mcp` extra is missing.

---

## `test-cases` — draft and save reviewed authorization cases

```bash
vardrrunner test-cases draft <engagement-id> --output review.json --endpoint <id> [--endpoint <id> ...]
vardrrunner test-cases draft <engagement-id> --output review.json --openapi api.json [--base-url https://api.example.test]
vardrrunner test-cases save  <engagement-id> --file review.json --reviewed
```

Drafts [VardrGate](https://github.com/VardrSec/VardrGate) authorization test cases from the
engagement's observed API operations, or from an OpenAPI 3.x JSON file, and saves them only after
you have reviewed them. Nothing is queued: run a saved case from the job composer.

- **`draft`** asks VardrMap to generate drafts and writes them to a **new** file (`--output` must not
  exist, so a draft you are editing is never overwritten). Exactly one of `--endpoint` (repeatable)
  or `--openapi` is required. `--offset` / `--limit` (1-100, default 50) page through large inputs;
  the file records `total` and `next_offset`. A draft containing a literal credential value is refused
  and no file is written; identities use `value_env` / `value_keychain` references that this runner
  resolves locally at run time.
- **Review the file.** Replace `{path variables}` with concrete values, set each identity's secret
  reference, and replace every `skip` with `allow` or `deny`. Observed responses say what the API
  *does*, not who *should* have access, so drafts never guess. Delete cases you do not want.
- **`save`** needs `--reviewed` (your confirmation that you checked targets, identities and access
  decisions) and posts the file to VardrMap, which validates each case again. It accepts the file
  `draft` wrote or a bare JSON array of cases.

---

## `audit` — local execution evidence

Queue-driven jobs are recorded in `~/.vardrmap/runner-journal.sqlite3`. Audit commands are
local and never contact the backend:

```bash
vardrrunner audit list [--since <iso-timestamp>] [--limit 100] [--json]
vardrrunner audit show <run-id>
vardrrunner audit export --output audit.json [--since <iso-timestamp>] [--limit 10000]
```

`list` shows recent lifecycle outcomes, `show` prints one full sanitized record, and
`export` atomically writes a versioned JSON document suitable for incident review or
retention. Records include target counts, sanitized tool settings, lifecycle timestamps,
failure categories, policy warnings, and artifact SHA-256/size. They exclude raw targets,
credentials, request bodies, and headers.

Completed runs write the same evidence to `manifest.json` beside the artifact. The SQLite
journal remains the recovery source of truth; manifests are portable run evidence.

---

## `tools` — pinned, verified tool installs

```bash
vardrrunner tools install --all            # every tool VardrRunner pins
vardrrunner tools install httpx nuclei     # or name them
vardrrunner tools install httpx --force    # reinstall even if already verified
vardrrunner tools list                     # source, version, location of every tool
vardrrunner tools verify                   # re-hash managed tools; exit 1 on a mismatch
vardrrunner tools remove httpx
vardrrunner tools purge [--yes]            # delete every managed tool and tool data
```

Installs go to `~/.vardrmap/tools`, with a receipt in `~/.vardrmap/tools/tools.lock.json`.
Each tool is pinned in the package to an exact version and, per platform, a release archive
and its SHA-256. `install` downloads the archive over HTTPS, refuses it unless the hash
matches the pin, extracts only the expected binary, requires it to report the pinned
version, and moves it into place in one step. Anything that fails installs nothing.

| Tool | Managed | Notes |
|---|---|---|
| httpx, nuclei, subfinder, dnsx, katana | yes | |
| gau, ffuf | yes | `.tar.gz` on Linux/macOS, `.zip` on Windows; same single-file extraction. ffuf also needs a [wordlist](#wordlists), which is not installed for you |
| naabu | yes | port scans also need libpcap (Linux/macOS) or [Npcap](https://npcap.com) (Windows) |
| nmap | no | install with your OS installer or package manager |
| vardrgate | no | install from the VardrGate repository |

**Resolution.** The runner uses a managed install when one exists and otherwise falls back
to `PATH`, which `tools list`, `status`, and `doctor` report as *unverified*. A managed
binary is re-hashed before its first use in each process and whenever it changes on disk;
one that no longer matches its receipt is **never executed** — the job fails with the
reason, and it does not fall back to a `PATH` copy.

**Antivirus.** Penetration-testing tools are often flagged by antivirus, which may block a
tool on launch and quarantine it. `install` detects a binary that disappears during its
version check and says so; `verify` reports a quarantined tool as missing. If you trust the
tools, an exclusion for `~/.vardrmap/tools` covers all of them.

---

## `run` — run a tool locally and upload results
```bash
vardrrunner run httpx     --engagement <id> [options]
vardrrunner run subfinder --engagement <id> [options]
vardrrunner run nuclei    --engagement <id> [options]
vardrrunner run nmap      --engagement <id> [--top-ports N] [--timing 0-4] [options]
vardrrunner run dnsx      --engagement <id> [options]
vardrrunner run naabu     --engagement <id> [--top-ports N] [options]
vardrrunner run katana    --engagement <id> [--depth N] [--js-crawl] [options]
vardrrunner run gau       --engagement <id> [--no-subs] [--providers otx,wayback]
vardrrunner run ffuf      --engagement <id> [--wordlist common] [--rate N] [options]
```
Executes the named tool, captures output into an atomically unique timestamp-prefixed run
directory under `~/.vardrmap/runs`, and uploads parsed results to the backend.
- `run nmap` — safe-profile service discovery (normalizes URLs to hosts, never uses
  `-A`/`-O`/`-p-`/`--script`/`-T5`) → services API.
- `run dnsx` — DNS resolution; uploads the **resolvable** hosts as recon targets, so a later
  httpx/nuclei pass only probes hosts that exist.
- `run nuclei` — a managed nuclei keeps its templates under `~/.vardrmap/data/nuclei-templates`,
  so the whole install lives in one place `tools purge` can remove. A nuclei on your `PATH` is
  left with whatever template directory it already uses.
- `run naabu` — fast top-ports scan → open ports to the services API.
- `run katana` — crawls each target URL (staying on its root domain) and uploads every
  endpoint found as recon, with method, status, size, and content type. Response bodies
  are dropped before upload.
- `run gau` — passive: asks public archives (Wayback Machine, Common Crawl, AlienVault
  OTX, urlscan) for URLs they have recorded under each wildcard scope domain, and
  uploads them as recon. Nothing is sent to the target itself.
- `run ffuf` — active content discovery: fuzzes each target's **site root** for hidden paths
  and uploads the hits as recon. Targets collapse to roots first, so a recon table with
  twenty URLs on one host fuzzes that host once, not twenty times. See
  [Wordlists](#wordlists) — ffuf needs one, and a job names it rather than giving a path.
- katana, gau and ffuf upload large results in pieces under VardrMap's 2 MiB import limit.

#### Wordlists

ffuf reads wordlists from `~/.vardrmap/wordlists`, named without the extension:

```bash
mkdir -p ~/.vardrmap/wordlists
cp /usr/share/seclists/Discovery/Web-Content/common.txt ~/.vardrmap/wordlists/common.txt
ln -s /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
      ~/.vardrmap/wordlists/api-paths.txt        # a symlink is fine
vardrrunner run ffuf --engagement <id> --scope --wordlist api-paths
```

`--wordlist` and a queued job's `wordlist` take a **name** (lowercase letters, digits, `-`
and `_`), never a path. The name is resolved against this one directory on the machine
running the scan, so a job cannot name an arbitrary file for ffuf to read and replay at a
target; a path, a traversal, or anything else path-shaped is refused at queue time and again
before the subprocess starts. A missing or empty wordlist fails the job with a message naming
the file it expected. No wordlists ship with VardrRunner — their licences and sizes are the
operator's choice.

### Choosing targets
Every `run` command except `subfinder` and `gau` takes one target source (`subfinder` and
`gau` always read wildcard entries from the engagement's scope):

| Flag | Source |
|------|--------|
| `--scope` | In-scope assets from the engagement |
| `--from-recon` | Live recon items from the backend recon store |
| `--target <value>` | A single inline target |
| `--targets <path>` | A targets `.txt` file, one per line |

With `--from-recon`, `--limit` caps how many recon items are pulled (default 100 for
httpx/nuclei/katana/ffuf, 500 for nmap/dnsx/naabu) and `--status-code` filters them by HTTP status
(httpx and nuclei only).

All sources are treated as untrusted. Empty entries are removed and duplicates collapsed;
targets containing control characters, whitespace, a leading option marker, non-HTTP URL
schemes, or URL credentials are rejected before a subprocess starts. Target files are
limited to 10 MiB. The same validation applies to backend data and pipeline handoffs.

### Per-tool options
| Command | Options |
|---------|---------|
| `run nuclei` | `--severity high,critical` · `--templates`/`-t <path-or-tag>` |
| `run nmap` | `--top-ports N` (default 100) · `--timing 0-4` (default 3; 5 is never allowed) |
| `run naabu` | `--top-ports N` (default 100) |
| `run katana` | `--depth N` (1-10, default 3) · `--js-crawl` (also parse JavaScript for endpoints) |
| `run gau` | `--subs/--no-subs` (default on) · `--providers` (any of `wayback,commoncrawl,otx,urlscan`; default all) |
| `run ffuf` | `--wordlist <name>` (default `common`) · `--extensions .php,.bak` · `--match-codes 200,301,403` (default: ffuf's own) · `--rate N` (1–1000, default 50) |

`--yes`/`-y` skips the confirmation prompt on any of them.

**ffuf's request rate is always capped.** It is the one tool here that puts sustained load on
a client's host, so `--rate` has a modest default and a ceiling of 1000, and there is no value
that disables it. The rate applies per target. ffuf also always runs with auto-calibration
(`-ac`): a host that answers every path with `200` would otherwise import thousands of
phantom endpoints into the shared recon store. A non-zero exit on any one target fails the
whole job rather than skipping that host, because a silent skip would report coverage the
engagement does not actually have.

**"Found nothing" and "outcome unknown" are different results.** A valid ffuf report with
an empty `results` array means no matches, and the job succeeds. A report that is absent,
unreadable or not the shape ffuf writes fails the job — otherwise a broken run would finish
green while recording that this host has nothing on it. A single malformed *entry* inside an
otherwise valid report is skipped instead, since the report parsed and one bad row should
not discard a long scan.

**`--limit` counts recon rows, not hosts.** Targets collapse to roots *after* the limit is
applied, so 100 recon URLs that all live on one host consume the default limit and fuzz a
single root. Raise `--limit`, or use `--scope`, when a recon table is dense on few hosts.

**Each target is probed once before it is fuzzed, because ffuf cannot say it was unreachable.**
Observed on ffuf 2.3.0: for a host that refuses the connection, ffuf exits `0` and writes a
valid, empty report — with `-s`, `-se` and `-sa` alike — so neither the exit code nor the
report can tell "there was nothing there" from "it could not look". The runner therefore sends
**one GET per target first**; if nothing answers, the job **fails** with the reason and **no
fuzzing traffic is sent**. Any HTTP answer counts as reachable, including `404`, `403`, `500`
and redirects (a redirect is not followed, matching ffuf). Connection errors, timeouts and TLS
verification failures count as unreachable — TLS is verified, as it is for ffuf, so a host ffuf
would have silently seen nothing from fails with a reason you can act on.

The cost is one extra request per target, identified by `User-Agent: VardrRunner-reachability-probe`.
It closes the common case, not the window between the probe and the fuzz: a host that answers
and then drops during the run still yields whatever ffuf saw. Any one unreachable target fails
the whole job, like a non-zero exit, because skipping it would report coverage that does not
exist.
**These limits apply per execution, not across the engagement.** A job queued by a schedule
is an ordinary job: each run is a fresh ffuf process with its own full `--rate`, and nothing
aggregates traffic across runs or across jobs that overlap. An hourly schedule therefore means
active fuzzing traffic every hour, indefinitely, for as long as the schedule exists. `--rate`
bounds how hard one run pushes; it does not bound how often runs happen. The same is true of
`run dalfox` and its `--worker`/`--delay`.

### Target classification and local deny rules

Every resolved target is classified before any tool runs. Loopback, link-local and **cloud
instance-metadata** addresses produce an advisory warning:

```
⚠ 169.254.169.254 — cloud instance-metadata endpoint — reachable from inside the cloud
  network and commonly serves instance credentials
```

**Warnings never block** — the same contract the backend's scope findings follow. To make
something actually block, configure a local deny rule:

| Where | How |
|---|---|
| Config file | `"deny_targets": ["cloud_metadata", "10.0.0.0/8"]` in `~/.vardrmap/config.json` |
| Environment | `VARDRRUNNER_DENY_TARGETS=cloud_metadata,loopback` |

A rule is a class name (`public`, `private`, `loopback`, `link_local`, `cloud_metadata`), a
literal host, or a CIDR. **Nothing is denied by default.** Set
`VARDRRUNNER_ALLOW_DENIED_TARGETS=1` to override the rules; the override is recorded as a
`deny_override` job event. It is an environment variable rather than a flag so it also
applies to the daemon, where deny rules matter most and there is no command line.

### Target cap
A run aborts before executing anything if the resolved target count exceeds
`--max-targets` (default **500**), so a broad scope can't turn into a several-thousand-host
scan by accident. Pass `--max-targets 0` to disable the cap, or a higher number to raise
it. The cap applies to `run` and `pipeline run` alike, and it applies even with `--yes` —
`--yes` means "skip the confirmation prompt", not "ignore safety guards".

```bash
vardrrunner run httpx --engagement <id> --scope --max-targets 2000
vardrrunner run httpx --engagement <id> --scope --max-targets 0     # no cap
```

Every tool run is bounded by a timeout (default 1800 s; set `VARDRRUNNER_TOOL_TIMEOUT`); a
hung tool and its child-process tree are killed rather than blocking or continuing in the
background.

---

## `import` — import an existing output file
```bash
vardrrunner import nuclei --engagement <id> --file <path>
vardrrunner import httpx  --engagement <id> --file <path>
```
Pushes results from a tool output file (JSONL) you already have, without running the
tool. `-f` is shorthand for `--file`. Supported tools: `httpx`, `nuclei` — the two
formats the backend's file-import endpoint accepts. `subfinder`/`dnsx` are excluded
because they convert to httpx-format JSONL before uploading; `nmap`/`naabu` upload via
the services API rather than file import.

`import ffuf` was removed in v0.28.0; it had lingered in `--help` since v0.21.1 despite
always failing.

---

## `pipeline` — chain tools into one recon workflow
```bash
vardrrunner pipeline list                              # show available pipelines
vardrrunner pipeline run recon --engagement <id> [options]
```
A pipeline runs an ordered chain of tools. Each stage writes its discovered targets to a
local handoff file; the next stage reads from that file instead of pulling from the backend
recon store. This keeps the pipeline fast and consistent even when the backend is slow.
Built-in pipelines:

| Name | Chain |
|------|-------|
| `recon` | subfinder (enumerate subdomains from wildcard scope) → httpx (probe) → nuclei (scan) |
| `quick` | subfinder → httpx |
| `deep` | subfinder → **dnsx** (keep only resolvable) → httpx → nuclei |
| `ports` | subfinder → dnsx → **naabu** (fast port scan → services) |
| `content` | subfinder → httpx → **katana** (crawl live hosts) → **gau** (archived URLs for scope) |

Options for `pipeline run`:
- `--severity high,critical` — nuclei severity filter for the scan stage
- `--yes` / `-y` — skip the confirmation prompt
- `--continue-on-error` — keep going if a stage fails (default: stop)
- `--dry-run` — resolve first-stage targets and print the plan without executing any tool
- `--json` — emit a machine-readable JSON result (run ID, per-stage status/targets/elapsed)
- `--max-targets N` — per-stage target cap (default 500; `0` disables)

Each run prints an 8-hex run ID at start and end. Progress renders as a live table — one
row per stage, with a spinner while running and a final status icon (`✓` done, `✗` failed,
`⊘` no targets, `—` aborted) plus target count, result summary, and elapsed time. When a
stage stops the pipeline, the remaining stages are marked aborted immediately.

The pipeline preflights that every tool in the chain is installed, stops early if a stage
produces no targets (e.g. no subdomains discovered), and applies the same 500-target cap
per stage as the `run` commands.

---

## `jobs` — one-shot queue operations
```bash
vardrrunner jobs list     # show pending/running jobs for your account
vardrrunner jobs run      # claim and execute all currently pending jobs, then exit
```
`jobs run` auto-sends a heartbeat first, then for each pending job: claims it
(`POST /jobs/{id}/claim`), resolves targets, executes, and reports lifecycle events.
This is the same execution core the daemon uses.

Before claim, the runner validates the job schema, target shape/count, and free-disk
reserve. Before upload it enforces the artifact ceiling. Defaults are 500 targets, 100 MiB
per artifact, 512 MiB free, and one worker. `VARDRRUNNER_MAX_CONCURRENT_JOBS` may enable up
to eight workers across engagements; jobs belonging to one engagement always remain
sequential and each worker uses an isolated API client.

### How claim outcomes are reported

| Outcome | Behaviour |
|---|---|
| **Stop-work** (`403`) | Prints `STOP-WORK — not running this job.`, emits a `blocked` event, runs nothing. That engagement is suppressed for 60 seconds, then rechecked automatically. |
| **Claim race** (`409`) | Another runner won. Skipped quietly, **not** marked failed — the job is theirs to finish. |
| **Auth** (`401`) | Reported as `auth`. Re-run `vardrrunner login vardrmap`. |
| **Rate limited** (`429`) | Reported as `rate_limited`; the daemon backs off. |
| **Backend down** (`5xx`) | Reported as `backend_unavailable`; the daemon backs off and retries. |
| **Anything else** | Reported as `unknown` and logged. The job is left pending and the worker stays alive. |

### Advisory policy warnings

The backend evaluates authorization, testing window and scope on claim. Findings come back
as warnings and are printed **before any tool runs**, so you see them while you can still
intervene:

```
⚠ Target is not in the recorded scope: a.com not in scope
⚠ Outside the agreed testing window
```

They do **not** block execution — that is deliberate, and staying in scope remains your
responsibility. They are also emitted as a `policy_warning` job event so the backend
Terminal records them. Stop-work is the only policy condition that halts.

Recognized job types are the recon tools (`httpx`, `subfinder`, `nuclei`, `nmap`,
`dnsx`, `naabu`, `katana`, `gau`) plus `vardrgate_api_test`, which runs a VardrGate API authorization
test via the local `vardrgate` binary and uploads the result to the job. See
[ADR 0006](adr/0006-vardrgate-api-test-handler.md).

For `vardrgate_api_test`, an identity credential may reference a secret instead of
embedding it — `value_env` (an environment variable on the runner) or
`value_keychain` (an OS-keychain account) — resolved locally at execution so the
secret never reaches the backend. A missing referenced secret fails the job. See
[ADR 0007](adr/0007-local-secret-resolution.md).

---

## `daemon` — continuous background worker
```bash
vardrrunner daemon start [--detach]   # poll jobs (5 s) + heartbeat (60 s) continuously
vardrrunner daemon stop               # cooperative graceful shutdown (removes PID file)
vardrrunner daemon status             # report whether the daemon is running
```

Options for `daemon start`:

| Option | Default | Purpose |
|--------|---------|---------|
| `--detach` / `-d` | off | Run in the background and write the PID file |
| `--poll-interval N` | 5 | Seconds between job polls |
| `--heartbeat-interval N` | 60 | Seconds between heartbeats |
| `--log-file <path>` | none | Append output to a rotating log file |
| `--log-format text|json` | `text` | Human text or redacted JSON Lines |

Poll intervals are bounded to 1–3600 seconds and heartbeat intervals to 1–86400 seconds.
The PID file is claimed with exclusive creation, so concurrent starts cannot both become
workers; malformed or dead PID state is replaced as stale.

- The PID file is `~/.vardrrunner.pid`. A double-start guard prevents two daemons from
  running at once, and `daemon status` cleans up a stale PID file.
- `--log-file` writes through a rotating handler — **5 MB per file, 3 backups** — so a
  long-lived VPS daemon can't fill the disk. Every line is prefixed with an ISO 8601
  timestamp, and Rich markup is rendered to plain text rather than written literally.
- Poll failures back off exponentially (5 s → 10 s → 20 s …, capped at 5 min) and reset on
  the next successful poll, so a downed backend isn't hammered.
- The daemon opens the SQLite execution journal before writing its PID or claiming work.
  Journal failure is a startup failure, preventing unaccounted execution.
- Every poll first reconciles interrupted runs. Complete artifacts can resume upload and a
  confirmed upload can resume finalization. An upload with an unknown outcome is never
  duplicated automatically; it is retained as an `upload_failed` audit record.
- Shutdown is cooperative: `stop` removes the PID file; an active job may finish, then the
  daemon claims no additional jobs and exits cleanly (graceful SIGTERM handling on Unix,
  ctypes liveness probe on Windows).

JSON log records contain `log_schema_version`, UTC `timestamp`, `level`, `event`, stable
`runner_id`, `pid`, and redacted `message`. Rotation remains 5 MiB × four files total.

---

## `service` — native unattended startup

```bash
vardrrunner service install [--no-start] [--dry-run]
vardrrunner service status
vardrrunner service uninstall
```

The command installs a systemd **user** unit on Linux, LaunchAgent on macOS, or per-user
ONLOGON Scheduled Task on Windows. It runs the foreground daemon with rotating JSON logs;
no separate worker implementation is introduced. `--dry-run` prints paths and manager
commands without changing the host.

Actual installation first verifies local authentication, the execution journal, and stable
identity so a broken configuration does not enter a native supervisor restart loop.

Authentication must be available to a newly started service process. A keychain or
explicitly accepted config credential satisfies this. Credentials that exist only in the
current shell are rejected unless Linux `--env-file` is supplied; macOS and Windows users
must use keychain/config resolution or an established external supervisor. Linux env files
must already exist with mode `0600`; a missing file is a service startup failure rather than
being silently ignored.

On Linux only, `--env-file <path>` adds a systemd `EnvironmentFile` reference. The file is
never copied or displayed, and no secret is embedded in the unit. macOS and Windows should
use the OS keychain or config-based credential resolution. Windows hosts that must start
before user logon should use their existing enterprise supervisor rather than the per-user
task.

A systemd user unit starts at boot only when user lingering is enabled. The installer does
not change that host policy; it prints the administrator command
`loginctl enable-linger <user>` after installation.

---

## Exit behavior
- Commands requiring auth exit with a clear "Not logged in. Run: `vardrrunner login vardrmap`"
  message when no config is present.
- A missing or failing tool marks the corresponding job **failed** with a reason — the
  runner never silently skips work.
