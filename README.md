# VardrRunner

The local execution engine for the VardrSec security-testing platform.

Run tools and reviewed API authorization assessments on your own machine. Connected
commands exchange jobs and results with [VardrMap](https://github.com/VardrSec/VardrMap).
The source-built [VardrSec distribution](https://github.com/VardrSec/VardrSec) also
provides standalone Mapless workspaces without a Map account, API key or PostgreSQL.
Both modes use the same Runner engine.

Normal installation starts no scans, startup service or detached worker. Manual
`jobs run` remains explicitly invoked. Managed Full operation is a separate opt-in
workflow; a running worker does not grant execution authority to individual jobs.

> Source-built capabilities may require the distribution's compatible component
> pins. A published package is not automatically equivalent to the current source.
> Read [security reporting](SECURITY.md) and [support limits](docs/limitations.md).

## Install

Native installation requires Python 3.10+ and the external tools you intend to use.

```sh
pipx install vardrrunner
# Or, inside an existing virtual environment:
pip install vardrrunner
```

For source-built Full or Mapless, use the distribution's
[installation guide](https://github.com/VardrSec/VardrSec/blob/main/docs/installation.md)
and [Mapless walkthrough](https://github.com/VardrSec/VardrSec/blob/main/docs/mapless.md).
Native operation retains the platform and network limitations in the component
and distribution guides.

## Manual connected workflow

```sh
vardrrunner init
vardrrunner tools install --all
vardrrunner doctor
vardrrunner jobs list
vardrrunner jobs run
vardrrunner audit list
```

`init` configures connected access and diagnostics; it does not install a service.
A bare `vardrrunner` in a terminal opens the interactive console. For a separately
enabled managed worker, follow the distribution's
[managed setup guide](https://github.com/VardrSec/VardrSec/blob/main/docs/local-managed-setup.md).
Do not substitute ordinary queue access for the required per-job authorization.

## Capabilities

- Explicit tool execution and connected recon pipelines, with typed inputs,
  normalized targets, bounded execution, unique run directories and journaled results.
- Hash-verified managed installations of supported tools, checked again before use.
  A failed managed-binary verification is not permission to fall back silently.
- Reviewed VardrGate cases with locally resolved credential references and retained
  case/result binding. A finding is a candidate for human review, not a security verdict.
- Local workspaces and portable evidence in the source-built standalone workflow.
  Its controlled finite Recon profile is not equivalent to every connected pipeline.
- Diagnostics, original-run audit and recovery, evidence export and connected result upload.
  Unknown execution remains held; recovery must not replay or refund uncertain work.
- Optional MCP access for reading, analysis, drafts and pending queue proposals.
  An operator approves queue proposals in Map; the model has no approval or delete
  tool. Treat target-controlled output as untrusted data, not instructions.

For the complete command reference, see [CLI documentation](docs/cli.md).

## Tools and credentials

`tools install --all` installs reviewed versions of httpx, subfinder, nuclei, dnsx,
naabu, katana, ffuf and dalfox. VardrGate is obtained separately or through the
pinned distribution. Native Gau is excluded; its reviewed container form has
separate limits. Nmap is not bundled: its integration requires the explicit
`VARDRRUNNER_ENABLE_NMAP=1` opt-in and a separately licensed installation.
For ffuf, provide named wordlists under `~/.vardrmap/wordlists`.

Connected workflows need a backend URL and API key. Mapless does not. The legacy
connected API minimum is VardrMap v0.22.0; newer features require their matching
endpoints, migrations and reviewed versions, not merely that minimum.

`vardrrunner login` stores the key in the OS keychain. Missing keychain support
fails closed unless the operator explicitly selects `--allow-plaintext-credentials`.
For headless operation, provide `VARDRMAP_URL` and `VARDRMAP_API_KEY`. Credential
precedence is environment, OS keychain, then the explicitly allowed config file.
Use HTTPS except for the documented local development boundary. Never disable TLS
verification or expose host credentials to a container to bypass setup problems.

Gate credential references must be approved with `vardrrunner credentials approve`
for the engagement and origins they contact. Map receives references, not the
resolved secrets. Key custody and managed enrollment follow their own operator
instructions; a startup setting is not per-job consent.

## Configuration

| Variable | Purpose |
|---|---|
| `VARDRMAP_URL` | Connected backend URL |
| `VARDRMAP_API_KEY` | Connected API key; never commit it |
| `VARDRRUNNER_TOOL_TIMEOUT` | Per-tool timeout, default 1800 seconds |
| `VARDRUNNER_NAME` | Optional heartbeat/display name |
| `VARDRUNNER_MAX_TARGETS` | Queue target ceiling, default 500; 1–100000 |
| `VARDRUNNER_MAX_ARTIFACT_MB` | Upload ceiling, default 100 MiB; 1–10240 |
| `VARDRUNNER_MAX_CONCURRENT_JOBS` | Parallel engagement groups, default 1; 1–8 |
| `VARDRUNNER_MIN_FREE_DISK_MB` | Free-space reserve, default 512 MiB; 0 disables |
| `VARDRUNNER_DENY_TARGETS` | Explicit local target restrictions |
| `VARDRUNNER_ALLOW_DENIED_TARGETS` | Explicit audited override of local deny rules |

These legacy settings do not replace the stronger restrictions in a controlled
execution contract. See the CLI reference for the exact command-specific behavior.

## Documentation and development

[CLI](docs/cli.md) · [Container use](docs/container.md) ·
[Managed worker](docs/managed-worker.md) · [Finite Recon](docs/finite-recon.md) ·
[Architecture](docs/architecture.md) · [Development](docs/development.md) ·
[Changelog](CHANGELOG.md)

```sh
pip install -e '.[dev]'
ruff check vardrrunner tests
ruff format --check vardrrunner tests
mypy vardrrunner
pytest tests
```

Preserve existing commands and security controls. Tests that require real tools
or platform privileges retain their explicit prerequisites; a skip is not a pass.
Do not use a production engagement as a development fixture.

## License

[MIT](LICENSE). VardrMap and VardrGate retain their independent licenses.
