# Unreleased: container runtime package fixes

The shared Python/Trixie base upgrades only `apt`, `libapt-pkg7.0` and `zlib1g`
from the existing signed repositories. Build-time version checks require apt/libapt
3.0.4 or later and zlib `1:1.3.dfsg+really1.3.1-1+deb13u1` or later. Core and toolkit
inherit the same correction; reviewed base digests and UID/capability boundaries
are unchanged. Native installations are unaffected.

These fix CVE-2026-109518 and the zlib advisories covered by Debian DSA-6613-1 at
the package level. Rebuilt image reports must verify removal; this source change
does not clear other findings or authorize a release.

- [Debian apt security status](https://security-tracker.debian.org/tracker/source-package/apt)
- [Debian zlib DSA-6613-1](https://lists.debian.org/debian-security-announce/2026/msg00532.html)
