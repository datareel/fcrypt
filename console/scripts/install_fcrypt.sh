#!/bin/bash
# 11/18/2026: Installs fcrypt, fdecrypt and fmigrate from the Linux binary
# package (fcrypt_<version>_rhel_8_9_10_binaries.tar.gz), choosing the
# build for this host:
#   RHEL 10            rhel10/           the system OpenSSL 3.5
#   RHEL 9             rhel9/            the system OpenSSL 3.5
#   RHEL 8, FIPS mode  rhel8/            Red Hat's FIPS-validated system
#                                        OpenSSL 1.1.1 (no ML-KEM hybrid users)
#   RHEL 8, otherwise  rhel8_openssl35/  OpenSSL 3.5 LTS built in
# FIPS mode is read from /proc/sys/crypto/fips_enabled.
#
# Dry run by default: it shows what it would copy. Run with --install to
# copy. Nothing is removed; programs already in the target folder are
# kept as name.backup-YYYYMMDD-HHMMSS.
#
#   ./install_fcrypt.sh [--install] [--system | --prefix=DIR] [--build=DIR]
#     --system      install in /usr/local/bin (run as root)
#     --prefix=DIR  install in DIR (default: ~/bin)
#     --build=DIR   use this build folder of the package instead of the one
#                   chosen for the host (for example rhel8 on a host that
#                   will be put in FIPS mode)

set -u
PKG=$(cd $(dirname $0) && pwd)
GO=0
PREFIX=${HOME}/bin
BUILD=""
for a in "$@"; do
    case "$a" in
	--install) GO=1 ;;
	--system) PREFIX=/usr/local/bin ;;
	--prefix=*) PREFIX=${a#--prefix=} ;;
	--build=*) BUILD=${a#--build=} ;;
	-h|--help) sed -n 2,23p $0; exit 0 ;;
	*) echo "ERROR: unknown option $a, see $0 --help"; exit 1 ;;
    esac
done

if [ ! -f /etc/redhat-release ]; then
    echo "ERROR: /etc/redhat-release not found: this package is for RHEL 8, 9 and 10"
    exit 1
fi
REL=$(sed -n 's/.*release \([0-9]*\).*/\1/p' /etc/redhat-release | head -1)
FIPS=0
[ -r /proc/sys/crypto/fips_enabled ] && [ "$(cat /proc/sys/crypto/fips_enabled)" = "1" ] && FIPS=1

if [ -z "${BUILD}" ]; then
    case "${REL}" in
	10) BUILD=rhel10 ;;
	9) BUILD=rhel9 ;;
	8) if [ ${FIPS} -eq 1 ]; then BUILD=rhel8; else BUILD=rhel8_openssl35; fi ;;
	*) echo "ERROR: $(cat /etc/redhat-release) is not supported, the package is for RHEL 8, 9 and 10"; exit 1 ;;
    esac
fi
SRC=${PKG}/${BUILD}
if [ ! -d "${SRC}" ]; then
    echo "ERROR: ${SRC} not found in the package"
    exit 1
fi

echo "Host: $(cat /etc/redhat-release), FIPS mode $([ ${FIPS} -eq 1 ] && echo on || echo off)"
case "${BUILD}" in
    rhel8) echo "Build: ${BUILD} (Red Hat's FIPS-validated system OpenSSL 1.1.1, no ML-KEM hybrid users)" ;;
    rhel8_openssl35) echo "Build: ${BUILD} (OpenSSL 3.5 LTS built in, for hosts not in FIPS mode)" ;;
    *) echo "Build: ${BUILD} (the system OpenSSL 3.5)" ;;
esac
if [ "${REL}" = "8" ] && [ ${FIPS} -eq 1 ] && [ "${BUILD}" = "rhel8_openssl35" ]; then
    echo "WARNING: this host is in FIPS mode; the rhel8 build uses Red Hat's FIPS-validated OpenSSL"
fi
if [ "${BUILD}" = "rhel8" ]; then
    if ! rpm -q openssl-libs >/dev/null 2>&1; then
	echo "ERROR: the rhel8 build needs the openssl-libs package"
	exit 1
    fi
fi

(cd "${SRC}" && sha256sum -c --quiet sha256sum.txt) || { echo "ERROR: the sha256 check of ${SRC} failed, nothing was installed"; exit 1; }
echo "sha256 check of ${SRC}: OK"

# fcrypt --version exits 1 like the help, so check its output
if ! "${SRC}/fcrypt" --version 2>&1 | grep -q "File Encrypt version"; then
    echo "ERROR: ${SRC}/fcrypt does not run on this host, nothing was installed"
    "${SRC}/fcrypt" --version 2>&1 | tail -3
    exit 1
fi

stamp=$(date +%Y%m%d-%H%M%S)
for p in fcrypt fdecrypt fmigrate; do
    if [ -e "${PREFIX}/${p}" ]; then
	echo "$([ ${GO} -eq 1 ] || echo 'DRY RUN: ')keep ${PREFIX}/${p} as ${PREFIX}/${p}.backup-${stamp}"
    fi
    echo "$([ ${GO} -eq 1 ] || echo 'DRY RUN: ')install ${SRC}/${p} -> ${PREFIX}/${p}"
done
if [ ${GO} -eq 0 ]; then
    echo "Dry run only, nothing was changed. Run with --install to install."
    exit 0
fi

mkdir -p "${PREFIX}" || exit 1
for p in fcrypt fdecrypt fmigrate; do
    if [ -e "${PREFIX}/${p}" ]; then
	mv "${PREFIX}/${p}" "${PREFIX}/${p}.backup-${stamp}" || exit 1
    fi
    # Copy to a new name, then rename, so a running copy is never overwritten
    cp -p "${SRC}/${p}" "${PREFIX}/.${p}.new" && chmod 755 "${PREFIX}/.${p}.new" && mv "${PREFIX}/.${p}.new" "${PREFIX}/${p}" || exit 1
done
echo "Installed in ${PREFIX}:"
"${PREFIX}/fcrypt" --version 2>&1 | grep -E "File Encrypt version|Version string|FIPS mode|OpenSSL build"
exit 0
