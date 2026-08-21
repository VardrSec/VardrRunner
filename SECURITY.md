# Security policy

VardrRunner executes security tools and handles backend and test credentials, so security
reports are treated as sensitive.

## Supported versions

Security fixes are provided for the latest released VardrRunner version. Upgrade before
reporting an issue that may already be fixed.

## Reporting a vulnerability

Please use GitHub's private vulnerability-reporting form:

https://github.com/VardrSec/VardrRunner/security/advisories/new

Do not open a public issue for a suspected vulnerability. Include the affected version,
platform, reproduction steps, impact, and any suggested mitigation. Remove real API keys,
credentials, targets, and client data from evidence.

The maintainers will acknowledge a report within five business days, investigate it, and
coordinate disclosure and remediation with the reporter. Please allow a reasonable period
for a fix and supported-user migration before public disclosure.

## Scope

In scope are vulnerabilities in VardrRunner itself, its packaging and release automation,
credential handling, target validation, local execution boundaries, and its documented
VardrMap HTTP integration. Vulnerabilities in external scanners, VardrMap, VardrGate, or
third-party infrastructure should be reported to their respective maintainers.
