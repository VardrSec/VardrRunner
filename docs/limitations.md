# Execution and support limits

Normal startup is inert. Explicitly enabled managed availability does not grant
job authority: each job must independently satisfy its contract, local credential
grants, target/duration/concurrency limits and cancellation controls.

Host suspend/resume behavior is not qualified. Do not rely on execution deadlines
across suspension. Remote stop cannot be assumed instantaneous while disconnected.
Preserve unknown claim/result/finish state and use original-run reconciliation;
never reconstruct a lost capability or replay uncertain execution.

The trusted host's exit report is a trust boundary: a compromised host can falsely
report an incarnation stopped and prematurely release accounting. Host reporting
secrets must not be mounted into the worker or confused with execution credentials.

Native and container support differ. Do not infer universal VPN, split-DNS,
reconnect, raw-packet or macOS Docker support from a successful local run. Native
Windows redacted export retains its documented supported Windows/local-NTFS
boundary. Native Linux controlled execution needs its lifecycle-owner context;
an environment flag or public admission file does not replace that boundary.

The standalone controlled Recon profile is finite DNS-A followed by approved
original-host HTTPS/443 GET-root work. Broader discovery and automatic execution
of suggested Gate cases are not implied. Evidence hashes provide correlation and
integrity checks, not proof of vulnerability detection or a trustworthy host.

Use the matching source-built distribution for documented Full/Mapless workflows.
Unresolved container vulnerability and release reviews are not waived by passing
component tests. Keep authorization, local secrets, user data and safety warnings
intact when updating an installation.
