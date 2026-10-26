# ADR 0019: Container baseline for the first Compose distribution

Status: Accepted, 2026-10-26.

Use a Linux container for Runner in the initial VardrSec Compose distribution.
Retain the native CLI for host-specific network/tool requirements. The image is a
one-shot CLI, not a worker service: default startup prints help, and diagnostics
and job execution require explicit commands. Run as UID 10001 with persistent
state and no required Docker socket, published port or added capability.

The first image builds the existing package without changing credential or job
behavior. The default core target contains no scanner binaries. An optional toolkit target
compiles the separately pinned Gate context and bundles nmap/libpcap and managed
tools through the existing verified installer. A trusted environment override
places tools/receipts outside persistent state, avoiding volume masking or stale
volume copies after image updates. Release provenance and trusted HTTPS acceptance
remain separate work;
this development Dockerfile is not a claim of a runnable full distribution.

See [container operations](../container.md) for state, credentials and networking.
