#!/bin/sh
# Exact Debian sources; ordinary unprivileged builds on the supported Trixie ABI.
set -eu
# Keep failures in cleanup/source repacking visible as well as compile failures.
trap 'status=$?; if [ "$status" -ne 0 ]; then
    for log in /out/source/*/evidence/*.log; do
        [ -f "$log" ] || continue
        printf "\\n=== %s ===\\n" "$log"
        tail -n 100 "$log"
    done
fi' 0
export DEB_BUILD_OPTIONS=parallel=2
export DEB_BUILD_PROFILES=noudeb
cd /build
mkdir -p /out/packages /out/runtime /out/source
build_package() {
    package=$1
    descriptor=$2
    version=$3
    mkdir -p "/out/source/$package/evidence"
    cd /build
    dpkg-source --no-check -x "inputs/$descriptor" "$package"
    cd "$package"
    if [ "$package" != acl ]; then
        cp "/recipe/$package-descriptor-acl.patch" "debian/patches/vardr-descriptor-acl.patch"
        printf '\nvardr-descriptor-acl.patch\n' >> debian/patches/series
    fi
    { printf '%s (%s+vardr1) trixie; urgency=high\n\n  * Coordinate descriptor-bound ACL handling on the existing Trixie ABI.\n\n -- VardrSec local build <local@invalid>  Sun, 15 Nov 2026 00:00:00 +0000\n\n' "$package" "$version"; cat debian/changelog; } > /build/changelog
    mv /build/changelog debian/changelog
    dpkg-source --before-build .
    if [ -f .pc/applied-patches ]; then
        cp .pc/applied-patches "/out/source/$package/evidence/applied-patches.txt"
    fi
    find . -type f \( -name '*.c' -o -name '*.h' \) -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > "/out/source/$package/evidence/patched-source-SHA256SUMS"
    dpkg-query -W -f='${binary:Package} ${Version} ${Architecture}\n' > "/out/source/$package/evidence/build-environment.txt"
    # Archive exact patched inputs before builds regenerate manuals or caches.
    # Do not ignore post-build source diffs or turn generated output into source.
    dpkg-source --build . > "/out/source/$package/evidence/source-build.log" 2>&1
    dpkg-buildpackage -us -uc -B -rfakeroot > "/out/source/$package/evidence/package-build.log" 2>&1 || {
        tail -n 80 "/out/source/$package/evidence/package-build.log"; exit 1;
    }
    if [ "$package" = coreutils ]; then
        # Debian disables this suite in its packaging rules. Exercise the existing
        # upstream ACL cases explicitly, without changing their assertions.
        # check-am keeps these top-level test paths out of recursive gnulib suites.
        make check-am TESTS='tests/cp/acl.sh tests/mv/acl.sh tests/ls/acl.sh tests/ls/slink-acl.sh tests/mkdir/p-acl.sh' RUN_EXPENSIVE_TESTS=yes > /out/source/coreutils/evidence/upstream-acl-tests.log 2>&1 || {
            tail -n 80 /out/source/coreutils/evidence/upstream-acl-tests.log; exit 1;
        }
        # Native gnulib ACL targets use their own relative paths and assertions.
        make -C gnulib-tests check-am TESTS='test-copy-acl.sh test-copy-acl-1.sh test-copy-acl-2.sh test-set-mode-acl.sh test-set-mode-acl-1.sh test-set-mode-acl-2.sh' > /out/source/coreutils/evidence/gnulib-acl-tests.log 2>&1 || {
            tail -n 80 /out/source/coreutils/evidence/gnulib-acl-tests.log; exit 1;
        }
    fi
    cp /build/"$package"_*.deb /out/packages/
    if [ "$package" = acl ]; then
        cp /build/libacl1_*.deb /build/libacl1-dev_*.deb /out/packages/
    fi
    debian/rules clean >> "/out/source/$package/evidence/package-build.log" 2>&1
    cp /build/inputs/"$package"_* "/out/source/$package/"
    cp /build/"$package"_*+vardr1.dsc /build/"$package"_*+vardr1.debian.tar.xz "/out/source/$package/"
    cp /build/"$package"_*.buildinfo /build/"$package"_*.changes "/out/source/$package/"
}
case "$1" in
    acl) build_package acl acl_2.4.0-1.dsc 2.4.0-1 ;;
    callers)
        build_package coreutils coreutils_9.7-3.dsc 9.7-3
        build_package tar tar_1.35+dfsg-3.1.dsc 1.35+dfsg-3.1
        cp /out/packages/libacl1_*_amd64.deb /out/packages/coreutils_*_amd64.deb /out/packages/tar_*_amd64.deb /out/runtime/
        mkdir -p /out/source/evidence /build/payload
        for package in /out/runtime/*.deb; do dpkg-deb -x "$package" /build/payload; done
        cc -Wall -Wextra -Werror -fPIC -shared /recipe/swap-acl.c -ldl -o /build/swap-acl.so
        export LD_LIBRARY_PATH=/build/payload/usr/lib/x86_64-linux-gnu
        python3 /recipe/regression.py --cp /usr/bin/cp --tar /usr/bin/tar --preload /build/swap-acl.so --expect-vulnerable > /out/source/evidence/negative-controls.log 2>&1 || {
            cat /out/source/evidence/negative-controls.log; exit 1;
        }
        python3 /recipe/regression.py --cp /build/payload/usr/bin/cp --tar /build/payload/usr/bin/tar --preload /build/swap-acl.so > /out/source/evidence/stripped-payload-regressions.log 2>&1 || {
            cat /out/source/evidence/stripped-payload-regressions.log; exit 1;
        }
        cp /recipe/*.sh /recipe/*.py /recipe/*.c /recipe/*.patch /recipe/README.md /out/source/
        (cd /out/packages && sha256sum ./*.deb) > /out/source/package-SHA256SUMS
        for package in /out/runtime/*.deb; do
            name=$(basename "$package")
            dpkg-deb -f "$package" Package Version Architecture Source > "/out/source/$name.control.txt"
            payload=$(mktemp -d)
            dpkg-deb -x "$package" "$payload"
            (cd "$payload" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) > "/out/source/$name.files-SHA256SUMS"
        done
        cd /out/source
        find . -type f ! -path ./SHA256SUMS -print0 | LC_ALL=C sort -z | xargs -0 sha256sum > SHA256SUMS
        ;;
    *) exit 2 ;;
esac
