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
does not satisfy full installation acceptance. Tool-enabled images and immutable
release digests are a later packaging step. The base tag and Python dependency
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
