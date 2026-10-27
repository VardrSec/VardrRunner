# Unreleased — container DNSx security remediation

Build existing DNSx 1.3.1 with Go 1.27.3, x/net 0.60.0 and compress 1.18.7 using
the recorded source-build contract introduced for Katana. Reuse one fixed-name
build helper with per-tool module/dependency checks. Reject changed binaries,
compiler/modules, replacements and existing installs before execution/replacement.

Record honest source origin and retained build metadata; runtime hash verification
is unchanged. Real container regression resolves only a synthetic .test A name
through a loopback resolver, without external DNS or extra capabilities.

Native archive pins, the other tools, default CLI-only image, authentication,
backend contracts and explicit execution are unchanged. No tool is added, no
alpha shipping-scope decision or release is made, and residual findings remain.
