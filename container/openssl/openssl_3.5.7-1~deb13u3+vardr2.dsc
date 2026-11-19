Format: 3.0 (quilt)
Source: openssl
Binary: openssl, openssl-provider-legacy, openssl-provider-fips, libssl3t64, libcrypto3-udeb, libssl3-udeb, libssl-dev, libssl-doc
Architecture: any all
Version: 3.5.7-1~deb13u3+vardr2
Maintainer: Debian OpenSSL Team <pkg-openssl-devel@alioth-lists.debian.net>
Uploaders: Christoph Martin <christoph.martin@uni-mainz.de>, Kurt Roeckx <kurt@roeckx.be>, Sebastian Andrzej Siewior <sebastian@breakpoint.cc>
Homepage: https://openssl-library.org
Standards-Version: 4.7.2
Vcs-Browser: https://salsa.debian.org/debian/openssl
Vcs-Git: https://salsa.debian.org/debian/openssl.git
Testsuite: autopkgtest
Testsuite-Triggers: perl
Build-Depends: debhelper-compat (= 13), dpkg-dev (>= 1.22.5), libzstd-dev, zlib1g-dev
Package-List:
 libcrypto3-udeb udeb debian-installer optional arch=any profile=!noudeb
 libssl-dev deb libdevel optional arch=any
 libssl-doc deb doc optional arch=all
 libssl3-udeb udeb debian-installer optional arch=any profile=!noudeb
 libssl3t64 deb libs optional arch=any
 openssl deb utils optional arch=any
 openssl-provider-fips deb utils optional arch=any
 openssl-provider-legacy deb utils optional arch=any
Checksums-Sha1:
 53d331880fbde8e6fe25870d5325a61201f6264d 53153930 openssl_3.5.7.orig.tar.gz
 9408998095f984b36591732286ef1df1ba7ce492 833 openssl_3.5.7.orig.tar.gz.asc
 05735f651b8adeccda20fbdfee62f017e7ccac67 160232 openssl_3.5.7-1~deb13u3+vardr2.debian.tar.xz
Checksums-Sha256:
 a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8 53153930 openssl_3.5.7.orig.tar.gz
 d3d082bee3f658c31db53af625eceecf29d777c7010394bed5787ebcc98abdf2 833 openssl_3.5.7.orig.tar.gz.asc
 b27a5680609596037990f39a2c073ab22fcbddb30fbfd62ef5cf9aec5702f31a 160232 openssl_3.5.7-1~deb13u3+vardr2.debian.tar.xz
Files:
 36608cd5445f708d0c2200aea9682c35 53153930 openssl_3.5.7.orig.tar.gz
 1550a37dc3382ec617b5fd7d4140b92c 833 openssl_3.5.7.orig.tar.gz.asc
 4dd12831f7cf600e9eaed3ac9031c673 160232 openssl_3.5.7-1~deb13u3+vardr2.debian.tar.xz
