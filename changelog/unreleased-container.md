# Unreleased: container baseline

Add a non-root, one-shot development container for the existing CLI. Default
startup prints help without scanning. Preserve state in `/home/runner/.vardrmap`.
An optional toolkit target compiles Gate and bundles verified managed tools plus
nmap/libpcap. VARDRRUNNER_TOOLS_DIR separates immutable bundled tools from writable
state. No images are published by this change. Native installation is unchanged.
See [container guide](../docs/container.md) and ADR 0019.
