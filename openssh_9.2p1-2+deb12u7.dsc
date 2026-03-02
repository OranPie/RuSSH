-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

Format: 3.0 (quilt)
Source: openssh
Binary: openssh-client, openssh-server, openssh-sftp-server, openssh-tests, ssh, ssh-askpass-gnome, openssh-client-udeb, openssh-server-udeb
Architecture: any all
Version: 1:9.2p1-2+deb12u7
Maintainer: Debian OpenSSH Maintainers <debian-ssh@lists.debian.org>
Uploaders: Colin Watson <cjwatson@debian.org>, Matthew Vernon <matthew@debian.org>,
Homepage: https://www.openssh.com/
Standards-Version: 4.6.2
Vcs-Browser: https://salsa.debian.org/ssh-team/openssh
Vcs-Git: https://salsa.debian.org/ssh-team/openssh.git
Testsuite: autopkgtest
Testsuite-Triggers: devscripts, haveged, krb5-admin-server, krb5-kdc, openssl, putty-tools, python3-twisted, sudo, sysvinit-utils
Build-Depends: debhelper (>= 13.1~), debhelper-compat (= 13), dh-exec, dh-runit (>= 2.8.8), libaudit-dev [linux-any], libedit-dev, libfido2-dev (>= 1.5.0) [linux-any], libgtk-3-dev <!pkg.openssh.nognome>, libkrb5-dev | heimdal-dev, libpam0g-dev | libpam-dev, libselinux1-dev [linux-any], libssl-dev (>= 1.1.0g), libsystemd-dev [linux-any] | libelogind-dev [linux-any], libwrap0-dev | libwrap-dev, pkg-config, zlib1g-dev
Package-List:
 openssh-client deb net standard arch=any
 openssh-client-udeb udeb debian-installer optional arch=any profile=!noudeb
 openssh-server deb net optional arch=any
 openssh-server-udeb udeb debian-installer optional arch=any profile=!noudeb
 openssh-sftp-server deb net optional arch=any
 openssh-tests deb net optional arch=any
 ssh deb net optional arch=all
 ssh-askpass-gnome deb gnome optional arch=any profile=!pkg.openssh.nognome
Checksums-Sha1:
 3b172b8e971773a7018bbf3231f6589ae539ca4b 1852380 openssh_9.2p1.orig.tar.gz
 057ac5ac6e2fa0a26a105b085822a09f1a068683 833 openssh_9.2p1.orig.tar.gz.asc
 49d55f9e69d9c4037fb44b043e2b83c350551b70 197308 openssh_9.2p1-2+deb12u7.debian.tar.xz
Checksums-Sha256:
 3f66dbf1655fb45f50e1c56da62ab01218c228807b21338d634ebcdf9d71cf46 1852380 openssh_9.2p1.orig.tar.gz
 7acc8e9502040972aeecb785fa3b6bb00c069cc01fbd7c214f8f7867033a6dbb 833 openssh_9.2p1.orig.tar.gz.asc
 38fe612408e19713b7c971d9987d788eecf27bbb13a81a6edca4137fd38a9251 197308 openssh_9.2p1-2+deb12u7.debian.tar.xz
Files:
 f78b2acac4bb299629a8c58ddc3fac63 1852380 openssh_9.2p1.orig.tar.gz
 4b8baeab4dd1ff732a02e94c227cf788 833 openssh_9.2p1.orig.tar.gz.asc
 3affcc62259635fca246ff45374fb2b5 197308 openssh_9.2p1-2+deb12u7.debian.tar.xz
Dgit: 23a4933f1b923e239cec1c2ea8e8c84cff05903c debian archive/debian/1%9.2p1-2+deb12u7 https://git.dgit.debian.org/openssh
Git-Tag-Info: tag=bb2faba5900d0a5b0e82014efbe9c73049104623 fp=ac0a4ff12611b6fccf01c111393587d97d86500b
Git-Tag-Tagger: Colin Watson <cjwatson@debian.org>

-----BEGIN PGP SIGNATURE-----

iQIzBAEBCgAdFiEEN02M5NuW6cvUwJcqYG0ITkaDwHkFAmiHZ6sACgkQYG0ITkaD
wHnSpw//bG5mxP8fJDbP6HDHXImYhwXK7aGzQa88p1XyC8IYcc158d4ug2tbzSg+
m/868zJTCizukyPAT6utAySqfzLQ3l/E4HFqa5Ar4p31A3uo5jPZyVhU0ZHIFshD
II5NX0eac1qMP+l/GXU9w6wLhiXgp4xXEeAo9ji0PkQMAOXAsVgVrJlKXpCUJge7
C4jMVDV8dEGo9yGGXGaah6DWXqXD0hZT49E0LcP8IW+TOJnuGUFLFIbIBTDkH3Nc
Io5fgpQatH7Q00zpB9ucSK5y56HKBTE+YLNUeP3qh7AcMgh3UUtW7Aie+gvotm8w
vZjLjmjzcYHeSrj8MvJJZ9hoim6AK8J00Quooz7JDdEQGz48xhobEsz9JCE2gMxD
2QXVHuqiqicAgP4j+PkUpr1TBcvnaXUVclyT80S0mE+E3OYhNJqd1/RmlPd20Gbp
Ome0kPfAnxWPNqIs6sQGMu+9uwXob+VAXmAdYrcOTqRKjU9s6mB/14RCD0oaXlwC
474zaP6Y1MVmmg0NUvcA2OQDMRGDY48D/bQFg6+ZtFWM2M+QWy640ev11CdB8Y9f
jx9nlA49ggB4msEFGw0ig+NAak31Wq/Q18zyAylOMbjh0GCG6kNivjTiy5XM4/h0
AgR3ruVi2YT8vqWvKxq82DJ3qgF5N6AgXf7r1tlPhgCno+YMRuw=
=5F/8
-----END PGP SIGNATURE-----
