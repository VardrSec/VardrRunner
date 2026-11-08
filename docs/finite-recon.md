# Explicit finite Recon

This source feature adds a bounded DNS-to-HTTPS journey to the existing standalone
workspace workflow. It does not enable background work. Full and Mapless use the
same Runner, journal, signed permission and export. Compatible distribution pins
and installed evidence are separate from source implementation.

Use a workspace and private issuer created with the existing `workspace create`
and `workspace authority-init` commands. Prepare a reviewed `recon.json` containing:

- `hostnames`: a finite list of exact lowercase DNS names; no wildcard or IP literal.
- `candidates`: exact objects with `hostname`, `scheme: "https"`, `port: 443`,
  `path: "/"`, `method: "GET"`. Each hostname must be in the seed list.
- `destination_cidrs`: canonical IPv4 networks authorized for HTTP connections.
- `resolvers`: numeric IPv4 `address` and integer `port` objects, explicitly
  authorized for DNS. Resolvers are not inferred from HTTP scope.

No discovery output expands these lists. The first profile supports A-only DNS
and the original HTTPS/443 GET-root candidates, not arbitrary crawling or scanning.
Existing direct commands and broader legacy pipelines keep their current behavior.

```sh
vardrrunner workspace authorize WORKSPACE_ID --profile recon \
  --authority /private/issuer --case recon.json --output /private/recon-authorization
```

Review the displayed DNS seeds, resolvers, destination networks, logical HTTP
scope, two actual tool hashes and request ceilings before typing `APPROVE`.
The issuer key is kept outside execution state and outside the public bundle.
Managed DNSx 1.3.1 and HTTPx 1.12.0 are required; an unverified PATH installation
cannot enable this profile. The existing toolkit includes the reviewed builds.

Optional `--execution recon-execution.json` accepts exactly `deadline` (UTC),
`timeout_seconds` (1..600), `max_artifact_bytes` and `allow_private_targets`.
Defaults are a finite deadline within the approval window, at most 300 seconds,
64 MiB (or the lower local limit), and no private targets. Private destinations
or resolvers need the signed private option and the existing explicit local
`VARDRRUNNER_ALLOW_PRIVATE_TARGETS=1` selection. Hard-denied ranges remain denied.

Native controlled execution uses the existing confirmation and export:

```sh
vardrrunner workspace execute WORKSPACE_ID --authorization /private/recon-authorization \
  --output /private/recon-run --export /private/recon-export
```

For Full or Mapless Compose, use the existing distribution transfer wrapper:

```sh
python3 vardrsec.py runner --authority-volume assessment-issuer \
  --input-directory reviewed-recon --output-directory recon-authorization -- \
  workspace authorize WORKSPACE_ID --profile recon --authority /issuer/assessment \
  --case /inputs/recon.json --output /exports/bundle
python3 vardrsec.py runner --controlled --input-directory recon-authorization/bundle \
  --output-directory recon-result --
```

On Windows use `python` and one-line PowerShell commands. Output directories must
be new. The issuer volume is never mounted into execution. A successful run uses
the existing `artifact.json`, `audit.json`, `manifest.json` redacted export;
original JSONL observations remain in private Runner state. Inspect with `audit
show RUN_ID` and recover export using `audit export-run`, never by replaying the job.

Evidence separates the approved logical hostname from the validated address used
for the connection. No response is an inconclusive observation, not proof that a
host or vulnerability is absent. `handoff.candidate_urls` is data for review: use
the existing Gate case format, state the identities and expected access yourself,
then obtain a separate Gate authorization. Recon never approves a Gate case or
creates further execution authority.

The existing whole-plan consumption, cancellation, deadline and held-failure
rules apply across both stages. See [the decision](adr/0045-finite-recon-execution.md).
