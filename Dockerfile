# Coordinated ACL/caller build; no runtime suite or glibc migration.
FROM debian:trixie-slim@sha256:7378260c0a098d27ac206225db5e7d92b8c7c84ea7afccc86eeb513756bbd392 AS acl-callers-build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential debhelper dh-exec gettext libattr1-dev libacl1-dev libselinux1-dev libgmp3-dev libssl-dev libsystemd-dev gperf bison autoconf automake autopoint texinfo fakeroot acl attr python3 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /build/inputs
ADD --checksum=sha256:b987ebbeb3d498794bad29cd65301b77384978493d8765c94dba8bad8fa325b6 https://deb.debian.org/debian/pool/main/a/acl/acl_2.4.0-1.dsc acl_2.4.0-1.dsc
ADD --checksum=sha256:e661131456d2708a01c614a0f400e11d7d1bfaeb6f3e74b75bb980b72f0161a3 https://deb.debian.org/debian/pool/main/a/acl/acl_2.4.0.orig.tar.xz acl_2.4.0.orig.tar.xz
ADD --checksum=sha256:65931c2fb3e821bda67f8d8d72d77e99ac61502748dcdf38b6805fe89339085e https://deb.debian.org/debian/pool/main/a/acl/acl_2.4.0-1.debian.tar.xz acl_2.4.0-1.debian.tar.xz
ADD --checksum=sha256:c3a207e3aaad165765c7a6fab89045f5fd20035fea6830b9f9ebbb92ebfbff89 https://deb.debian.org/debian/pool/main/c/coreutils/coreutils_9.7-3.dsc coreutils_9.7-3.dsc
ADD --checksum=sha256:e8bb26ad0293f9b5a1fc43fb42ba970e312c66ce92c1b0b16713d7500db251bf https://deb.debian.org/debian/pool/main/c/coreutils/coreutils_9.7.orig.tar.xz coreutils_9.7.orig.tar.xz
ADD --checksum=sha256:483f77876a080577f63da1d004cc1cf17d16df65d6925aefdd3294c6101eccfb https://deb.debian.org/debian/pool/main/c/coreutils/coreutils_9.7-3.debian.tar.xz coreutils_9.7-3.debian.tar.xz
ADD --checksum=sha256:5bb58d4966d94c99a9f1b182676089ecc05058d62fdb927f5c07539d9cda4077 https://deb.debian.org/debian/pool/main/t/tar/tar_1.35+dfsg-3.1.dsc tar_1.35+dfsg-3.1.dsc
ADD --checksum=sha256:9ae57e981c1e73c0eebc2b26c9b0c4497fe310ef1d516ea430efb5470b71f7a8 https://deb.debian.org/debian/pool/main/t/tar/tar_1.35+dfsg.orig.tar.xz tar_1.35+dfsg.orig.tar.xz
ADD --checksum=sha256:0d0278034b82ed84dce04a461879b6e1871e4cb416a0ff04d3d35ff05fc30a53 https://deb.debian.org/debian/pool/main/t/tar/tar_1.35+dfsg-3.1.debian.tar.xz tar_1.35+dfsg-3.1.debian.tar.xz
ADD --checksum=sha256:5f4f0b9b78821764fe6b88e32aef6ec519628522c211c36706bcb78d6f3f036b https://deb.debian.org/debian/pool/main/a/acl/acl_2.4.0.orig.tar.xz.asc acl_2.4.0.orig.tar.xz.asc
ADD --checksum=sha256:5070e9428bd372a7fa1f66b395b81092bb40c98f9f56a2e2bc55c47fd387e901 https://deb.debian.org/debian/pool/main/c/coreutils/coreutils_9.7.orig.tar.xz.asc coreutils_9.7.orig.tar.xz.asc
COPY container/acl/ /recipe/
RUN mkdir -p /out && chown -R 65534:65534 /build /out
USER 65534:65534
RUN --network=none sh /recipe/build.sh acl
USER root
RUN --network=none dpkg --install /out/packages/libacl1_*.deb /out/packages/libacl1-dev_*.deb /out/packages/acl_*.deb && apt-get check
USER 65534:65534
RUN --network=none sh /recipe/build.sh callers

FROM debian:trixie-slim@sha256:7378260c0a098d27ac206225db5e7d92b8c7c84ea7afccc86eeb513756bbd392 AS glibc-build
WORKDIR /work
ADD --checksum=sha256:f24aa441021121a79266f0d75242706cab8843a47901fefe74527491807f1998 https://deb.debian.org/debian/pool/main/g/glibc/glibc_2.41.orig.tar.xz ./
COPY container/glibc/ ./
RUN echo 'f1b5f57fefd122f7d7e1264a1a6f36039dc4fd5d0ec5f7a833f87095f06996d1  glibc_2.41-12+deb13u4+vardr1.dsc' | sha256sum -c - \
    && apt-get update && apt-get install -y --no-install-recommends build-essential dpkg-dev fakeroot \
    && dpkg-source -x glibc_2.41-12+deb13u4+vardr1.dsc src \
    && apt-get build-dep -y --no-install-recommends ./src \
    && useradd -m builduser && chown -R builduser:builduser /work
WORKDIR /work/src
# Reproduce the previously tested amd64 packages; reject any byte difference.
RUN --network=none { runuser -u builduser -- env DEB_BUILD_OPTIONS=nocheck dpkg-buildpackage -us -uc -b -Pnobiarch -j4 > /tmp/glibc-build.log 2>&1 || { tail -100 /tmp/glibc-build.log; exit 1; }; } \
    && mkdir -p /out/packages /out/source \
    && cp ../libc6_*_amd64.deb ../libc-bin_*_amd64.deb ../libc-l10n_*_all.deb ../locales_*_all.deb /out/packages/ \
    && cp ../glibc_*.dsc ../glibc_*.tar.xz ../glibc_*.buildinfo ../glibc_*.changes /out/source/ \
    && cd /out/packages && sha256sum -c /work/qualified-packages.sha256 \
    && cd /out/source && sha256sum glibc_* > SHA256SUMS \
    && rm -rf /work/src /work/*.deb

FROM debian:trixie-slim@sha256:7378260c0a098d27ac206225db5e7d92b8c7c84ea7afccc86eeb513756bbd392 AS util-linux-build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential debhelper dh-exec dh-package-notes dh-sequence-installsysusers dh-debputy asciidoctor bc bison flex gettext libaudit-dev libcap-ng-dev libcrypt-dev libcryptsetup-dev libncurses-dev libpam0g-dev libreadline-dev libselinux1-dev libsqlite3-dev libsystemd-dev libtool libudev-dev netbase pkgconf po-debconf po4a socat systemd systemd-dev zlib1g-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /work
ADD --checksum=sha256:5b327ccd22f0f4ed28a389870aa51d04ecedb8693e52a1d122850f2b3188cbf6 https://deb.debian.org/debian/pool/main/u/util-linux/util-linux_2.41.5-0+deb13u1.debian.tar.xz util-linux_2.41.5-0+deb13u1.debian.tar.xz
ADD --checksum=sha256:43e9b2cbebd10fdc598c4ad10217c8202c28de53af6eafc892c8e9b5cbf3a3a5 https://deb.debian.org/debian/pool/main/u/util-linux/util-linux_2.41.5-0+deb13u1.dsc util-linux_2.41.5-0+deb13u1.dsc
ADD --checksum=sha256:f586e35d320ff537aab3ffeca37e9ecd482ccbe013590db4429a414d8aa6a728 https://deb.debian.org/debian/pool/main/u/util-linux/util-linux_2.41.5.orig.tar.xz util-linux_2.41.5.orig.tar.xz
RUN --network=none dpkg-source --no-check -x util-linux_2.41.5-0+deb13u1.dsc source
COPY container/util-linux/*.patch /work/source/debian/patches/
WORKDIR /work/source
RUN for p in debian/patches/vardr-*.patch; do basename "$p" >> debian/patches/series; done && dpkg-source --before-build . && { printf 'util-linux (2.41.5-0+deb13u1+vardr2) trixie; urgency=high\n\n  * Backport upstream stable 485dbb67f1b6 for CVE-2026-78408.\n\n -- VardrSec Qualification <local@invalid>  Tue, 17 Nov 2026 00:00:00 +0000\n\n'; cat debian/changelog; } > /tmp/changelog && mv /tmp/changelog debian/changelog
RUN --network=none dpkg-source --build .
ENV DEB_BUILD_OPTIONS='nocheck parallel=2'
RUN --network=none dpkg-buildpackage -us -uc -B > /work/package-build.log 2>&1 || (grep -n -i -B 4 -A 5 -E "error:|fatal|undefined|not found|No such" /work/package-build.log | head -n 100; tail -n 15 /work/package-build.log; exit 1)
RUN mkdir -p /out/packages /out/source && cp ../libmount1_*.deb ../libblkid1_*.deb ../libsmartcols1_*.deb ../libuuid1_*.deb ../liblastlog2-2_*.deb ../mount_*.deb ../util-linux_*.deb /out/packages/ && cp ../util-linux_*.dsc ../util-linux_*.tar.* ../util-linux_*.buildinfo ../util-linux_*.changes /out/source/ || (tail -n 50 /work/package-build.log; ls -l /work; exit 1)
COPY Dockerfile /out/source/Dockerfile
COPY container/util-linux/source.txt /out/source/util-linux-source.txt
COPY container/util-linux/qualified-packages.sha256 /out/source/qualified-packages.sha256
RUN cd /out/packages && sha256sum -c /out/source/qualified-packages.sha256
RUN chmod 0644 /out/source/* && cd /out/source && sha256sum ./* > SHA256SUMS

FROM scratch AS util-linux-source-delivery
COPY --from=util-linux-build /out/source/ /

FROM golang:1.27.4@sha256:08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c AS ncurses-build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential debhelper libgpm-dev pkgconf autoconf-dickey && rm -rf /var/lib/apt/lists/*
WORKDIR /build
ADD --checksum=sha256:546930a8992ae3325d8c38378f290265d969cf6333cfae9648ac6d69e1e8a8a6 https://deb.debian.org/debian/pool/main/n/ncurses/ncurses_6.5+20250216-2.debian.tar.xz ncurses_6.5+20250216-2.debian.tar.xz
ADD --checksum=sha256:00539cc2bc6bb84be1b8a8a5decf606682e14b6f39b76b9aa090e65d2c2d4580 https://deb.debian.org/debian/pool/main/n/ncurses/ncurses_6.5+20250216-2.dsc ncurses_6.5+20250216-2.dsc
ADD --checksum=sha256:b37baafa436e7133bb12a185cb8f60e1599b1947e9f0181c76f3190acf28b6eb https://deb.debian.org/debian/pool/main/n/ncurses/ncurses_6.5+20250216.orig.tar.gz ncurses_6.5+20250216.orig.tar.gz
ADD --checksum=sha256:64f4d17923322176c44079f18f170e2164a59d551d7e4e9c1a6e4eebedc5dd6f https://deb.debian.org/debian/pool/main/n/ncurses/ncurses_6.5+20250216.orig.tar.gz.asc ncurses_6.5+20250216.orig.tar.gz.asc
RUN --network=none dpkg-source --no-check -x ncurses_6.5+20250216-2.dsc source
COPY container/infocmp-bound.patch /build/source/debian/patches/vardr-infocmp-bound.patch
WORKDIR /build/source
RUN printf '\nvardr-infocmp-bound.patch\n' >> debian/patches/series && dpkg-source --before-build . && { printf 'ncurses (6.5+20250216-2+vardr1) trixie; urgency=high\n\n  * Bound infocmp analysis copy (CVE-2025-69720).\n\n -- VardrSec local build <local@invalid>  Wed, 11 Nov 2026 00:00:00 +0000\n\n'; cat debian/changelog; } > /tmp/changelog && mv /tmp/changelog debian/changelog
ENV DEB_BUILD_OPTIONS='nocheck parallel=2'
ENV DEB_BUILD_PROFILES='nobiarch'
RUN --network=none dpkg-buildpackage -us -uc -B > /build/package-build.log 2>&1 || (tail -n 70 /build/package-build.log; exit 1)
RUN mkdir -p /out/packages /out/source && cp ../ncurses-bin_*.deb /out/packages/ && debian/rules clean >> /build/package-build.log 2>&1 && dpkg-source --build . >> /build/package-build.log 2>&1 && cp ../ncurses_*.dsc ../ncurses_*.tar.* ../ncurses_*.buildinfo ../ncurses_*.changes /out/source/
COPY Dockerfile /out/source/Dockerfile
COPY container/ncurses-source.txt /out/source/ncurses-source.txt
RUN chmod 0644 /out/source/* && cd /out/source && sha256sum ./* > SHA256SUMS

FROM scratch AS ncurses-source-delivery
COPY --from=ncurses-build /out/source/ /

# Rebuild the fixed SQLite source on Trixie; build tools are discarded.
FROM golang:1.27.4@sha256:08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c AS sqlite-build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential debhelper autoconf libtool automake pkgconf chrpath lynx \
    libreadline-dev tcl8.6-dev tcl9.0-dev libtommath-dev libicu-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
ADD --checksum=sha256:d3b2efbeb509dfac38a0653112a400d48eaa86f14432c255a6fea8569df407f1 https://snapshot.debian.org/file/adad8188a1de9f6403ff70b3e41ea62465d3ae22 sqlite3_3.54.1-1.dsc
ADD --checksum=sha256:67906ee141109bebe43cdcf197892806397dabc79f5cd7f05f1278f47b0c5e25 https://snapshot.debian.org/file/8bc602b0433a4cc92fe095627afe1c89e1335cb5 sqlite3_3.54.1.orig-www.tar.xz
ADD --checksum=sha256:faeff7682200b3dd58c8f0f229892a7271c73c1fdabc86e7315eb31eb7cb6e83 https://snapshot.debian.org/file/c49acf244fe87e12aa11698a792dd6090c1b4eb9 sqlite3_3.54.1.orig.tar.xz
ADD --checksum=sha256:3f05602b0f4e1441b88f92e9afb2980e148659842565b1f1e27012988433a1d9 https://snapshot.debian.org/file/a8d6dc71abece0bd8f04fc52c793728ef7340a4d sqlite3_3.54.1-1.debian.tar.xz
RUN --network=none dpkg-source --no-check -x sqlite3_3.54.1-1.dsc source
WORKDIR /build/source
RUN sed -i 's/tcl9.1-dev/tcl9.0-dev/' debian/control \
    && sed -i 's/TCLV_SECONDARY = 9.1/TCLV_SECONDARY = 9.0/' debian/rules \
    && { printf 'sqlite3 (3.54.1-1+vardr1) trixie; urgency=high\n\n  * Rebuild the upstream security release with Trixie Tcl 9.0.\n\n -- VardrSec local build <local@invalid>  Wed, 11 Nov 2026 00:00:00 +0000\n\n'; cat debian/changelog; } > /tmp/changelog \
    && mv /tmp/changelog debian/changelog
ENV DEB_BUILD_OPTIONS='nocheck parallel=2'
RUN --network=none mkdir -p /out/packages /out/source \
    && (dpkg-buildpackage -us -uc -B > /tmp/package-build.log 2>&1 || (tail -n 75 /tmp/package-build.log; exit 1)) \
    && cp ../libsqlite3-0_*.deb /out/packages/ \
    && debian/rules clean >> /tmp/package-build.log 2>&1 \
    && dpkg-source --build . >> /tmp/package-build.log 2>&1 \
    && cp ../sqlite3_*.dsc ../sqlite3_*.tar.xz ../sqlite3_*.buildinfo ../sqlite3_*.changes /out/source/
COPY Dockerfile /out/source/Dockerfile
COPY container/sqlite-source.txt /out/source/sqlite-source.txt
RUN chmod 0644 /out/source/* && cd /out/source && sha256sum ./* > SHA256SUMS

FROM scratch AS sqlite-source-delivery
COPY --from=sqlite-build /out/source/ /

FROM python:3.12-slim-trixie@sha256:12316debbfb86890f6b2d825820612741ba527ad5a44e3902759141d572bfe8f AS base

# Target reviewed Trixie security fixes without changing the base or suite.
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade apt libapt-pkg7.0 zlib1g \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' apt)" ge 3.0.4 \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' libapt-pkg7.0)" ge 3.0.4 \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' zlib1g)" ge '1:1.3.dfsg+really1.3.1-1+deb13u1' \
    && rm -rf /var/lib/apt/lists/*
COPY --from=acl-callers-build /out/runtime/ /tmp/acl-security/
RUN --network=none dpkg --install /tmp/acl-security/libacl1_*.deb \
    && dpkg --install /tmp/acl-security/coreutils_*.deb /tmp/acl-security/tar_*.deb \
    && apt-get check && rm -rf /tmp/acl-security
COPY --from=acl-callers-build /out/source/ /usr/share/doc/libacl1/vardr-source/
# Retained public source evidence must remain readable by non-root runtimes.
RUN find /usr/share/doc/libacl1/vardr-source -type d -exec chmod 0755 {} + \
    && find /usr/share/doc/libacl1/vardr-source -type f -exec chmod 0644 {} +
COPY --from=sqlite-build /out/packages/ /tmp/sqlite-security/
RUN --network=none dpkg --install /tmp/sqlite-security/*.deb \
    && apt-get check && rm -rf /tmp/sqlite-security
COPY --from=sqlite-build /out/source/ /usr/share/doc/libsqlite3-0/vardr-source/
COPY --from=ncurses-build /out/packages/ /tmp/ncurses-security/
RUN --network=none dpkg --install /tmp/ncurses-security/*.deb \
    && apt-get check && rm -rf /tmp/ncurses-security
COPY --from=ncurses-build /out/source/ /usr/share/doc/ncurses-bin/vardr-source/
COPY --from=glibc-build /out/packages/libc6_*_amd64.deb /out/packages/libc-bin_*_amd64.deb /tmp/glibc-security/
RUN --network=none dpkg -i /tmp/glibc-security/*.deb && apt-get check && rm -rf /tmp/glibc-security
COPY --from=glibc-build /out/source/ /usr/share/doc/libc6/vardr-source/
COPY --from=util-linux-build /out/packages/ /tmp/util-linux-security/
RUN --network=none dpkg --install /tmp/util-linux-security/lib*.deb \
    && dpkg --install /tmp/util-linux-security/mount_*.deb /tmp/util-linux-security/util-linux_*.deb \
    && apt-get check && rm -rf /tmp/util-linux-security
COPY --from=util-linux-build /out/source/ /usr/share/doc/util-linux/vardr-source/

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/runner

WORKDIR /opt/runner
COPY pyproject.toml README.md LICENSE ./
COPY vardrrunner ./vardrrunner
RUN pip install --no-cache-dir . \
    && useradd --uid 10001 --create-home runner \
    && mkdir -p /home/runner/.vardrmap \
    && chown runner:runner /home/runner/.vardrmap \
    && chmod 700 /home/runner/.vardrmap

USER 10001:10001
WORKDIR /home/runner
ENTRYPOINT ["vardrrunner"]
CMD ["--help"]

# Rebuild the upstream security release on the same Trixie ABI; no sid packages.
FROM golang:1.27.4@sha256:08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c AS libpcap-build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential bison flex debhelper libbluetooth-dev libdbus-1-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
ADD --checksum=sha256:d6868b85a03361f45be66a95bb49e9c12a37b41e1e377834631e63e6ae05c0bb https://snapshot.debian.org/file/1744bda81b7d5ecc02f43f0af90bb7fe99469cc5 libpcap_1.10.7-1.dsc
ADD --checksum=sha256:68fa62cffb974f4275641ce14c2e2d75739251f30e00e6a0900903b247d76a03 https://snapshot.debian.org/file/b95b0204a7ee243d4f972065328a89d492a42a44 libpcap_1.10.7.orig.tar.xz
ADD --checksum=sha256:e2781d2daea2b4bfedc18fe7588a8e7a960c622eb786dfe5c23c756d08992c55 https://snapshot.debian.org/file/b787d6fd4cecf76ab8de5bc4c836e124bc22e4a9 libpcap_1.10.7.orig.tar.xz.asc
ADD --checksum=sha256:22934aca1eebbed28e67b63d8c7198ab8978327ca1e2e0a25d8e490fb24c0362 https://snapshot.debian.org/file/62eb0fe1c49833b58db3d41519631fb87070fe03 libpcap_1.10.7-1.debian.tar.xz
COPY Dockerfile /build/runner.Dockerfile
COPY container/libpcap-source.txt /build/libpcap-source.txt
RUN --network=none dpkg-source --no-check -x libpcap_1.10.7-1.dsc source
WORKDIR /build/source
RUN sed -i 's/debhelper-compat (= 14)/debhelper-compat (= 13)/' debian/control \
    && { printf 'libpcap (1.10.7-1+vardr1) trixie; urgency=high\n\n  * Rebuild the upstream security release for Trixie with debhelper compat 13.\n\n -- VardrSec local build <local@invalid>  Wed, 11 Nov 2026 00:00:00 +0000\n\n'; cat debian/changelog; } > /tmp/changelog \
    && mv /tmp/changelog debian/changelog
# Qualify offline BPF behavior separately; do not run the broad upstream suite.
ENV DEB_BUILD_OPTIONS='nocheck parallel=2'
RUN --network=none mkdir -p /out/packages /out/source \
    && (dpkg-buildpackage -us -uc -B > /tmp/package-build.log 2>&1 || (tail -n 70 /tmp/package-build.log; exit 1)) \
    && cp ../libpcap0.8t64_*.deb /out/packages/ \
    && debian/rules clean >> /tmp/package-build.log 2>&1 \
    && dpkg-source --build . >> /tmp/package-build.log 2>&1 \
    && cp ../libpcap_*.dsc ../libpcap_*.tar.xz ../libpcap_*.asc ../libpcap_*.buildinfo ../libpcap_*.changes ../runner.Dockerfile ../libpcap-source.txt /out/source/ \
    && chmod 0644 /out/source/* \
    && cd /out/source && sha256sum ./* > SHA256SUMS

FROM scratch AS libpcap-source-delivery
COPY --from=libpcap-build /out/source/ /

# Optional tool-enabled target; the default final target remains CLI-only.
# Supply the pinned Gate source as BuildKit's named `gate` context.
FROM golang:1.27.4@sha256:08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c AS gate-build
ENV GODEBUG=http2client=0
WORKDIR /src
COPY --from=gate . .
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/vardrgate ./cmd/vardrgate \
    && go mod verify \
    && mkdir -p /out/provenance \
    && go version -m /out/vardrgate > /out/provenance/build-info.txt \
    && cp go.mod go.sum LICENSE /out/provenance/ \
    && cp /usr/local/go/LICENSE /out/provenance/GO-LICENSE
# Preserve the exact builder's legal payloads; downstream audit matches only
# linked module identities, never counts unrelated cache entries as coverage.
RUN cd /go/pkg/mod \
    && find . -type f \( -iname 'license*' -o -iname 'licence*' -o -iname 'notice*' -o -iname 'copying*' -o -iname 'copyright*' \) -print0 > /tmp/gate-module-notices \
    && tar --null -T /tmp/gate-module-notices -czf /out/provenance/dependency-notices.tar.gz

# Upstream module/checksum HTTP/2 streams repeatedly failed; keep verified HTTPS over HTTP/1.1.
FROM golang:1.27.4@sha256:08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c AS katana-build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GODEBUG=http2client=0
RUN go mod init vardrrunner-katana-build \
    && go get github.com/projectdiscovery/katana/cmd/katana@v1.8.0 \
        github.com/jackc/pgx/v5@v5.9.2 golang.org/x/net@v0.62.0 golang.org/x/crypto@v0.58.1-0.20261009181718-2f1f834330b2 github.com/andybalholm/brotli@v1.2.7 github.com/klauspost/compress@v1.20.2 \
    github.com/yuin/goldmark@v1.7.17 \
    && go build -trimpath -o /out/katana github.com/projectdiscovery/katana/cmd/katana \
    && go version -m /out/katana > /out/build-info.txt \
    && sha256sum /out/katana > /out/katana.sha256 \
    && cp go.mod go.sum /out/

# Retain legal texts from this builder's exact downloaded module cache.
# The archive is a notice collection (possibly a superset), not source closure.
RUN cd /go/pkg/mod \
    && find . -type f \( -iname 'license*' -o -iname 'licence*' -o -iname 'notice*' -o -iname 'copying*' -o -iname 'copyright*' \) -print0 > /tmp/module-notices \
    && tar --null -T /tmp/module-notices -czf /out/dependency-notices.tar.gz \
    && cp /usr/local/go/LICENSE /out/GO-LICENSE

FROM base AS nuclei-openpgp-source
USER root
WORKDIR /build
ADD --checksum=sha256:34ccb01d56786a8f7eb876e82f33dc79034c9bd2ce863e182cae6544861a2a3d https://proxy.golang.org/github.com/google/go-github/v30/@v/v30.1.0.zip /build/upstream.zip
COPY container/nuclei_openpgp.py /build/
COPY container/nuclei-openpgp/ /build/changes/
RUN --network=none python /build/nuclei_openpgp.py /build/upstream.zip /build/changes /build/source /out


FROM golang:1.27.4@sha256:08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c AS dnsx-build
WORKDIR /src
COPY --from=nuclei-openpgp-source /build/source/ /src/go-github-v30-patched/
COPY --from=nuclei-openpgp-source /out/ /out/
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GODEBUG=http2client=0
RUN go mod init vardrrunner-dnsx-build \
    && go mod edit -replace github.com/google/go-github/v30=/src/go-github-v30-patched \
    && go get github.com/ProtonMail/go-crypto@v1.5.2 \
    && go get github.com/projectdiscovery/dnsx/cmd/dnsx@v1.3.1 \
        golang.org/x/net@v0.62.0 golang.org/x/crypto@v0.58.1-0.20261009181718-2f1f834330b2 github.com/andybalholm/brotli@v1.2.7 github.com/klauspost/compress@v1.20.2 \
    github.com/yuin/goldmark@v1.7.17 \
    && go build -trimpath -o /out/dnsx github.com/projectdiscovery/dnsx/cmd/dnsx \
    && go version -m /out/dnsx > /out/build-info.txt \
    && sha256sum /out/dnsx > /out/dnsx.sha256 \
    && cp go.mod go.sum /out/

RUN go mod verify \
    && test "$(go list -m -f '{{.Version}}' github.com/ProtonMail/go-crypto)" = v1.5.2 \
    && go test -json github.com/google/go-github/v30/github -run 'TestGitService_|TestCryptoCompatibilityAudit|TestExpiredLegacySigningKeyRejected' -count=1 > /out/openpgp-tests.json

# Retain legal texts from this builder's exact downloaded module cache.
# The archive is a notice collection (possibly a superset), not source closure.
RUN cd /go/pkg/mod \
    && find . -type f \( -iname 'license*' -o -iname 'licence*' -o -iname 'notice*' -o -iname 'copying*' -o -iname 'copyright*' \) -print0 > /tmp/module-notices \
    && tar --null -T /tmp/module-notices -czf /out/dependency-notices.tar.gz \
    && cp /usr/local/go/LICENSE /out/GO-LICENSE

FROM golang:1.27.4@sha256:08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c AS naabu-build
WORKDIR /src
COPY --from=nuclei-openpgp-source /build/source/ /src/go-github-v30-patched/
COPY --from=nuclei-openpgp-source /out/ /out/
ENV CGO_ENABLED=1 GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GODEBUG=http2client=0
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/*
RUN go mod init vardrrunner-naabu-build \
    && go mod edit -replace github.com/google/go-github/v30=/src/go-github-v30-patched \
    && go get github.com/ProtonMail/go-crypto@v1.5.2 \
    && go get github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1 \
        golang.org/x/net@v0.62.0 golang.org/x/crypto@v0.58.1-0.20261009181718-2f1f834330b2 github.com/andybalholm/brotli@v1.2.7 github.com/klauspost/compress@v1.20.2 \
    github.com/yuin/goldmark@v1.7.17 \
    && go build -trimpath -o /out/naabu github.com/projectdiscovery/naabu/v2/cmd/naabu \
    && go version -m /out/naabu > /out/build-info.txt \
    && sha256sum /out/naabu > /out/naabu.sha256 \
    && cp go.mod go.sum /out/

RUN go mod verify \
    && test "$(go list -m -f '{{.Version}}' github.com/ProtonMail/go-crypto)" = v1.5.2 \
    && go test -json github.com/google/go-github/v30/github -run 'TestGitService_|TestCryptoCompatibilityAudit|TestExpiredLegacySigningKeyRejected' -count=1 > /out/openpgp-tests.json

# Retain legal texts from this builder's exact downloaded module cache.
# The archive is a notice collection (possibly a superset), not source closure.
RUN cd /go/pkg/mod \
    && find . -type f \( -iname 'license*' -o -iname 'licence*' -o -iname 'notice*' -o -iname 'copying*' -o -iname 'copyright*' \) -print0 > /tmp/module-notices \
    && tar --null -T /tmp/module-notices -czf /out/dependency-notices.tar.gz \
    && cp /usr/local/go/LICENSE /out/GO-LICENSE

FROM golang:1.27.4@sha256:08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c AS gau-source
WORKDIR /src
ENV GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GODEBUG=http2client=0
RUN go mod init vardrrunner-gau-source \
    && go get github.com/lc/gau/v2/cmd/gau@v2.2.4 && go mod verify \
    && mkdir /out \
    && go mod download -json github.com/lc/gau/v2@v2.2.4 > /out/upstream-module.json \
    && cp -a "$(go list -m -f '{{.Dir}}' github.com/lc/gau/v2)" /out/source \
    && chmod -R u+w /out/source

FROM base AS gau-patch
USER root
ENV VARDRRUNNER_TOOLS_DIR=/opt/vardrtools
COPY --from=gau-source /out/ /build/
COPY container/go_tool_install.py container/nuclei_openpgp.py /build/
RUN python /build/go_tool_install.py --patch-gau

FROM golang:1.27.4@sha256:08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c AS gau-build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GODEBUG=http2client=0
COPY --from=gau-patch /build/source/ ./
COPY --from=gau-patch /build/provenance/ /out/
RUN go get golang.org/x/net@v0.62.0 github.com/klauspost/compress@v1.20.2 \
        github.com/sirupsen/logrus@v1.9.3 github.com/valyala/fasthttp@v1.34.0 \
    && go mod verify && go build -trimpath -o /out/gau ./cmd/gau \
    && go version -m /out/gau > /out/build-info.txt \
    && sha256sum /out/gau > /out/gau.sha256 \
    && cp go.mod go.sum /out/

# Retain legal texts from this builder's exact downloaded module cache.
# The archive is a notice collection (possibly a superset), not source closure.
RUN cd /go/pkg/mod \
    && find . -type f \( -iname 'license*' -o -iname 'licence*' -o -iname 'notice*' -o -iname 'copying*' -o -iname 'copyright*' \) -print0 > /tmp/module-notices \
    && tar --null -T /tmp/module-notices -czf /out/dependency-notices.tar.gz \
    && cp /usr/local/go/LICENSE /out/GO-LICENSE

FROM golang:1.27.4@sha256:08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c AS httpx-build
WORKDIR /src
COPY --from=nuclei-openpgp-source /build/source/ /src/go-github-v30-patched/
COPY --from=nuclei-openpgp-source /out/ /out/
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GODEBUG=http2client=0
RUN go mod init vardrrunner-httpx-build \
    && go mod edit -replace github.com/google/go-github/v30=/src/go-github-v30-patched \
    && go get github.com/ProtonMail/go-crypto@v1.5.2     && go get github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0         golang.org/x/net@v0.62.0 golang.org/x/crypto@v0.58.1-0.20261009181718-2f1f834330b2 github.com/andybalholm/brotli@v1.2.7 github.com/klauspost/compress@v1.20.2     github.com/yuin/goldmark@v1.7.17 \
    && go build -trimpath -o /out/httpx github.com/projectdiscovery/httpx/cmd/httpx     && go version -m /out/httpx > /out/build-info.txt     && sha256sum /out/httpx > /out/httpx.sha256     && cp go.mod go.sum /out/

RUN go mod verify \
    && test "$(go list -m -f '{{.Version}}' github.com/ProtonMail/go-crypto)" = v1.5.2 \
    && go test -json github.com/google/go-github/v30/github -run 'TestGitService_|TestCryptoCompatibilityAudit|TestExpiredLegacySigningKeyRejected' -count=1 > /out/openpgp-tests.json

# Retain legal texts from this builder's exact downloaded module cache.
# The archive is a notice collection (possibly a superset), not source closure.
RUN cd /go/pkg/mod \
    && find . -type f \( -iname 'license*' -o -iname 'licence*' -o -iname 'notice*' -o -iname 'copying*' -o -iname 'copyright*' \) -print0 > /tmp/module-notices \
    && tar --null -T /tmp/module-notices -czf /out/dependency-notices.tar.gz \
    && cp /usr/local/go/LICENSE /out/GO-LICENSE

FROM golang:1.27.4@sha256:08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c AS subfinder-build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GODEBUG=http2client=0
RUN go mod init vardrrunner-subfinder-build     && go get github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.17.0         golang.org/x/net@v0.62.0 golang.org/x/crypto@v0.58.1-0.20261009181718-2f1f834330b2 github.com/andybalholm/brotli@v1.2.7 github.com/klauspost/compress@v1.20.2     github.com/yuin/goldmark@v1.7.17 \
    && go build -trimpath -o /out/subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder     && go version -m /out/subfinder > /out/build-info.txt     && sha256sum /out/subfinder > /out/subfinder.sha256     && cp go.mod go.sum /out/

# Retain legal texts from this builder's exact downloaded module cache.
# The archive is a notice collection (possibly a superset), not source closure.
RUN cd /go/pkg/mod \
    && find . -type f \( -iname 'license*' -o -iname 'licence*' -o -iname 'notice*' -o -iname 'copying*' -o -iname 'copyright*' \) -print0 > /tmp/module-notices \
    && tar --null -T /tmp/module-notices -czf /out/dependency-notices.tar.gz \
    && cp /usr/local/go/LICENSE /out/GO-LICENSE

FROM golang:1.27.4@sha256:08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c AS ffuf-build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GODEBUG=http2client=0
RUN go mod init vardrrunner-ffuf-build     && go get github.com/ffuf/ffuf/v2@v2.3.0         golang.org/x/net@v0.62.0 github.com/andybalholm/brotli@v1.2.7     && go build -trimpath -ldflags "-X github.com/ffuf/ffuf/v2/pkg/ffuf.VERSION=2.3.0 -X github.com/ffuf/ffuf/v2/pkg/ffuf.VERSION_APPENDIX=" -o /out/ffuf github.com/ffuf/ffuf/v2     && go version -m /out/ffuf > /out/build-info.txt     && sha256sum /out/ffuf > /out/ffuf.sha256     && cp go.mod go.sum /out/

# Retain legal texts from this builder's exact downloaded module cache.
# The archive is a notice collection (possibly a superset), not source closure.
RUN cd /go/pkg/mod \
    && find . -type f \( -iname 'license*' -o -iname 'licence*' -o -iname 'notice*' -o -iname 'copying*' -o -iname 'copyright*' \) -print0 > /tmp/module-notices \
    && tar --null -T /tmp/module-notices -czf /out/dependency-notices.tar.gz \
    && cp /usr/local/go/LICENSE /out/GO-LICENSE

# Ordinary CLI stays UID10001; only the explicit local-worker overlay invokes this binary.
FROM golang:1.27.4@sha256:08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c AS local-owner-build
COPY container/worker_owner.c /src/worker_owner.c
RUN gcc -std=c11 -O2 -Wall -Wextra -Werror -static -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 -o /vardr-worker-owner /src/worker_owner.c

FROM base AS toolkit
# Existing optional authorization/MCP extras stay in the explicitly selected toolkit.
USER root
RUN python -m pip install --no-cache-dir '/opt/runner[authorization,mcp]'
# Nmap is deliberately not installed: its license terms are unresolved for distribution. libpcap is for naabu.
USER root
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=libpcap-build /out/packages/ /tmp/libpcap-security/
RUN dpkg --install /tmp/libpcap-security/*.deb && rm -rf /tmp/libpcap-security
COPY --from=libpcap-build /out/source/ /usr/share/doc/libpcap0.8t64/vardr-source/
ENV VARDRRUNNER_TOOLS_DIR=/opt/vardrtools
COPY --from=katana-build /out/ /tmp/katana-build/
COPY --from=dnsx-build /out/ /tmp/dnsx-build/
COPY --from=naabu-build /out/ /tmp/naabu-build/
COPY --from=httpx-build /out/ /tmp/httpx-build/
COPY --from=subfinder-build /out/ /tmp/subfinder-build/
COPY --from=ffuf-build /out/ /tmp/ffuf-build/
COPY --from=gau-build /out/ /tmp/gau-build/
COPY container/go_tool_install.py container/nuclei_openpgp.py /tmp/
RUN python -c 'from vardrrunner import toolchain; [toolchain.install(n) for n in toolchain.manageable_tools() if n not in ("katana", "dnsx", "naabu", "gau", "httpx", "subfinder", "ffuf", "nuclei")]' \
    && python /tmp/go_tool_install.py \
    && rm -rf /tmp/katana-build /tmp/dnsx-build /tmp/naabu-build /tmp/gau-build /tmp/httpx-build /tmp/subfinder-build /tmp/ffuf-build /tmp/go_tool_install.py /tmp/nuclei_openpgp.py \
    && chmod -R a+rX /opt/vardrtools \
    && rm -rf /home/runner/.config /home/runner/.cache /home/runner/.pdcp \
    && ln -s /home/runner/.vardrmap /home/runner/.config
# Some tools ignore XDG_CONFIG_HOME; both config paths must reach the state volume.
ENV XDG_CONFIG_HOME=/home/runner/.vardrmap \
    XDG_CACHE_HOME=/home/runner/.vardrmap/tool-cache
COPY --from=gate-build /out/vardrgate /usr/local/bin/vardrgate
COPY --from=gate-build /src/LICENSE /usr/share/licenses/vardrgate/LICENSE
COPY --from=gate-build /out/provenance/ /opt/vardrtools/provenance/vardrgate/
COPY --from=local-owner-build /vardr-worker-owner /usr/local/bin/vardr-worker-owner
RUN chmod 0555 /usr/local/bin/vardr-worker-owner \
    && mkdir -m 0700 /run/vardr-worker-ready \
    && chown 10000:10000 /run/vardr-worker-ready \
    && install -d -m 0700 -o 10001 -g 10001 /issuer /exports
USER 10001:10001

FROM base AS core
