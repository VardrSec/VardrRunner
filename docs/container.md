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
tools. Python/Debian Trixie and the Gate Go build image use reviewed base digests.
Python dependency ranges and apt packages still resolve during builds, so this is
a development build; immutable published releases and reproducibility remain
separate work. Native Runner's Python support and state paths are unchanged.

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
VardrGate credential references are approved with `credentials approve` run in a
container that mounts the same state volume; approvals are stored there by name
only (ADR 0023). Tool processes receive an allowlisted environment (ADR 0022).
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
compiles Gate and retains all nine managed tools. Five use the existing verified
archive installer. Katana 1.8.0, DNSx 1.3.1 and Naabu 2.6.1 use Go-checksummed upstream source
with Go 1.27.3, x/net 0.60.0 and compress 1.18.7; Katana also selects pgx 5.9.2,
and Naabu selects x/crypto 0.57.0. Naabu enables CGO and uses libpcap-dev only
in its build stage; the runtime retains its existing libpcap0.8 package. This adds
no raw-socket privileges; bounded TCP-connect operation remains unprivileged.
These remediate bundled runtime/dependencies. Native archive pins and installation
are unchanged.

Gau 2.2.4 also selects logrus 1.9.3 and fasthttp 1.34.0 plus four reviewed source
substitutions: enable normal provider TLS verification, make initialization/
worker errors exit nonzero, and retain extensionless URLs in JSON output.
Valid empty provider results remain successful.
The original module checksum/revision and original/patched file hashes are
recorded separately from the honestly marked `(devel)` main module. Its upstream
license is retained. Status adds `reviewed source patches`; a failed binary hash
still blocks execution. Native archive installation does not acquire these fixes.
See [ADR 0021](adr/0021-gau-patched-source.md) for source and acceptance boundaries.
It sets `VARDRRUNNER_TOOLS_DIR=/opt/vardrtools`; that directory and its
integrity receipt are root-owned image content and remain visible when a state
volume is mounted. This environment setting affects only tools, not credentials,
identity, journal, evidence or data. Rebuild the image to repair/update bundled
tools; an unprivileged runtime cannot overwrite them. Native installations retain
`~/.vardrmap/tools` when the override is absent.

Each source-build receipt explicitly records source origin, module checksums, compiler,
binary SHA256 and hashes of retained `provenance/TOOL/` build metadata. It does
not claim an upstream archive checksum. Ordinary managed verification still hashes
the executable and fails closed on tampering; status reports `verified source
build`. The helper is restricted to the root image-build directory and is removed
from the final image. See [ADR 0020](adr/0020-container-source-katana.md).
This changes the development toolkit's existing build, not its tool count or the
undecided alpha shipping scope. Other tool vulnerabilities, release provenance and
broader mode acceptance remain open. No release image is published.

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


### Go source download reliability

Go source-build stages set `GODEBUG=http2client=0` so module-proxy and checksum-database
requests use HTTPS over HTTP/1.1. Repeated independent CI builds hit upstream HTTP/2
`INTERNAL_ERROR` streams at both services. The proxy remains `https://proxy.golang.org`,
the public checksum database stays enabled, and TLS verification is unchanged. Every
source receipt and binary hash is still checked. The setting belongs only to builders;
the runtime image does not inherit it, so tools retain their HTTP/2 support. Container
CI verifies that the final toolkit has no `GODEBUG` environment override.
