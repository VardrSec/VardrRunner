# Unreleased — container Katana security remediation

The existing tool-enabled image builds Katana 1.8.0 with Go 1.27.3 and reviewed
pgx/x/net/compress patches. Its managed receipt records source origin and retained
build metadata instead of claiming an upstream archive checksum. Runtime integrity
verification remains mandatory and status identifies the source build.

Native tool installation/pins, the other eight tools, default CLI-only image,
authentication, explicit execution and image privileges are unchanged. No backend
contract change or release is introduced. Other vulnerabilities and acceptance
gates remain open; see ADR 0020 and the distribution's alpha assessment.
