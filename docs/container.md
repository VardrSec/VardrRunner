# Container packaging (development)

The initial VardrSec Compose distribution uses a Linux Runner container. Native
installation remains supported, especially for host VPNs, OS keychains and tools
requiring host networking. This source build is not a published distribution image.

Build from this repository:

```sh
docker build -t vardrrunner:local .
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges vardrrunner:local
```

The default command prints help and exits. The image runs as UID/GID 10001 and
contains the Runner CLI only: no Gate or scanning binaries, browser, wordlists or
templates are bundled. Missing tools remain visible in doctor; this image alone
does not satisfy full installation acceptance. An optional `toolkit` target adds Gate, nmap/libpcap and checksum-verified managed
tools. Immutable release digests remain a later step. The base tag and Python dependency
ranges make this a development build, not a reproducible release artifact.

Persist `/home/runner/.vardrmap` in a named volume; it contains configuration,
identity, journal, evidence, managed tools and data. Never remove it during normal
stop/update operations. Bind mounts must already be writable by UID 10001.

```sh
docker volume create vardrrunner-state
docker run --rm --cap-drop ALL --security-opt no-new-privileges \
  --mount source=vardrrunner-state,target=/home/runner/.vardrmap \
  -e VARDRMAP_URL -e VARDRMAP_API_KEY \
  vardrrunner:local doctor --platform --offline --json
```

Set the two variables securely in the invoking environment; never put keys in a
Dockerfile, image build argument or committed Compose file. Environment credentials
are visible to Docker administrators. Containers do not inherit the host keychain.
Do not mount a host home directory or Docker socket. No ports need to be published.

Use an HTTPS backend URL reachable **from the container**. `localhost` refers to
the container itself. For a private CA, mount its public CA bundle read-only and
set `REQUESTS_CA_BUNDLE` to that container path; never mount a CA private key or
disable certificate verification. Certificate trust enrollment and proxy routing
are owned by the distribution's separate HTTPS setup.

`--offline` skips release discovery, but still contacts the configured backend.
Diagnostics never run scans. Invoke `jobs run` explicitly only after reviewing
queued work. Container networking may not reach host-only or VPN targets; verify
the intended route before execution. Raw-packet tools are not supported by the
capability-free baseline; do not solve missing capabilities with `--privileged`.

Back up the state volume while no Runner command is executing. Restore with
UID/GID 10001 ownership. Container removal preserves the named volume; explicit
volume deletion destroys the stored state and evidence.

## Tool-enabled target

Supply a separate Gate source checkout at the distribution's tested commit:

```sh
docker build --target toolkit --build-context gate=/path/to/pinned-gate -t vardrrunner:toolkit .
```

The default `core` target remains CLI-only and needs no Gate context. `toolkit`
compiles Gate and installs all nine managed tools through the existing verified
installer. It sets `VARDRRUNNER_TOOLS_DIR=/opt/vardrtools`; that directory and its
integrity receipt are root-owned image content and remain visible when a state
volume is mounted. This environment setting affects only tools, not credentials,
identity, journal, evidence or data. Rebuild the image to repair/update bundled
tools; an unprivileged runtime cannot overwrite them. Native installations retain
`~/.vardrmap/tools` when the override is absent.

The toolkit places XDG configuration in `.vardrmap` and cache in
`.vardrmap/tool-cache`, inside the persistent user-owned state volume. Its legacy
`~/.config` path links to `.vardrmap` for clients such as Katana that ignore XDG.
The link targets the existing volume root, so existing volumes need no migration.
Build-time version probes may initialize root-owned defaults; those defaults are
removed before selecting the runtime user. This keeps Nuclei and Katana
clients writable as UID 10001 without changing native/core paths or making
`/opt/vardrtools` writable. Review each tool's separate provider credentials and
data requirements; this does not certify every mode.

Wordlists, nuclei templates, headless browser support and raw-packet capabilities
are separate operator requirements. Bundled binary availability does not prove
that every scan mode works. No target requests run during image startup.
