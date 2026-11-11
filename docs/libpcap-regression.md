# Bounded libpcap regression evidence

The toolkit rebuilds upstream libpcap 1.10.7 for Trixie from checksum-pinned
Debian source. Its upstream CHANGES identifies CVE-2026-0799 (scratch register
bounds) and CVE-2026-6554 (backward jump termination) as fixed in this release.
Debian's Trixie tracker still describes its unmodified 1.10.5 package as affected;
that package-version finding alone does not test this locally rebuilt payload.

Container smoke now runs seven offline interpreter cases against the actual
loaded shared library: accept/valid-register controls, four invalid register
load/store variants, and a backward self-jump. Every case runs in its own process
with 2 CPU seconds, 128 MiB address space, zero core dumps and a 5-second parent
timeout. The container has no network, no capabilities, a read-only filesystem,
192 MiB memory and a 32-process limit. No capture device is opened or packet sent.

The JSON receipt records every verdict, the mapped library path/SHA256/version,
installed package version and UID; the workflow retains the image ID alongside
it. A failing case, timeout, signal, missing library or changing identity fails
the check. Do not substitute a different image's receipt.

Local fixture qualification used isolated official Debian 1.10.7-1 and 1.10.5-2
amd64 packages downloaded from snapshot.debian.org, not installed into the host.
Both controls passed on both libraries. All five security cases passed on 1.10.7;
all four invalid-register cases failed on 1.10.5 and its self-jump hit the CPU
limit. This qualifies the fixture, not the final toolkit's binary identity.
Fresh container CI is required for that identity. The test does not establish
all libpcap safety, complete upstream coverage or reproducible package bytes,
and introduces no vulnerability suppression or release approval.
