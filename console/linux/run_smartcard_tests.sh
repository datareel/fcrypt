#!/bin/bash
# Smart card tests for fcrypt, fdecrypt and fmigrate.
#
# Adds smart card access to encrypted files, from the card and from an
# exported cert file, and checks the card decrypts them. With an old
# build directory, also checks that files given smart card access by
# the old build decrypt with this build and convert with fmigrate.
#
# Usage: SC_PIN=pin SC_CERT=cert.pem ./run_smartcard_tests.sh [old_build_dir]
#
#   SC_PIN     Smart card PIN (required). Use a test card, a wrong PIN
#              uses up the card's PIN tries.
#   SC_CERT    PEM cert exported from the card for the cert ID (required)
#   SC_ID      Smart card cert ID, default 01
#   SC_MODULE  PKCS#11 module, default /usr/lib64/opensc-pkcs11.so
#
# For a YubiKey, slot 9D is cert ID 03. Export its cert with:
#   ykman piv certificates export 9d cert.pem
#
# The FIPS test runs with FCRYPT_FIPS=1. Software tokens that use
# OpenSSL inside the program, such as SoftHSM, fail in FIPS mode.

NEW_DIR=$(cd $(dirname $0) && pwd)
FCRYPT=${NEW_DIR}/fcrypt
FDECRYPT=${NEW_DIR}/fdecrypt
FMIGRATE=${NEW_DIR}/fmigrate
OLD_DIR=$1
OLD_ENV="env -u OPENSSL_CONF -u OPENSSL_MODULES -u FCRYPT_FIPS"
testDIR=${HOME}/tmp/fcrypt_smartcard_testing_$(date +%Y_%m_%d_%H%M%S)
logFILE=${testDIR}/fcrypt_smartcard_testing.log
PW=--password=smartcard_test_password
passed=0
failed=0

if [ -z "${SC_PIN}" ] || [ -z "${SC_CERT}" ] || [ ! -f "${SC_CERT}" ]; then
    echo "ERROR: Set SC_PIN and SC_CERT, see the usage at the top of $0"
    exit 1
fi
if [ ! -f ${FCRYPT} ] || [ ! -f ${FDECRYPT} ] || [ ! -f ${FMIGRATE} ]; then
    echo "ERROR: Missing binaries in ${NEW_DIR}"
    exit 1
fi
SC_CERT=$(cd $(dirname ${SC_CERT}) && pwd)/$(basename ${SC_CERT})
SC="--smartcard-cert-id=${SC_ID:-01} --smartcard-provider=${SC_MODULE:-/usr/lib64/opensc-pkcs11.so}"
mkdir -p ${testDIR}
cat /dev/null > ${logFILE}
cd ${testDIR}
# 10/27/2026: The PIN goes in a file only you can read, never argv
umask 077
printf '%s\n' "${SC_PIN}" > ${testDIR}/pin.txt
trap 'rm -f ${testDIR}/pin.txt' EXIT
PIN="--smartcard-pin-file=${testDIR}/pin.txt"

# 10/26/2026: CAC and PIV cards lock after 3 wrong PINs. Stop before any
# login if the card reports a locked PIN, one try left or low tries, or
# if more than one card is present, and stop at once after any PIN or
# login error so the PIN is never sent to the card again.
MODULE=${SC_MODULE:-/usr/lib64/opensc-pkcs11.so}
if command -v pkcs11-tool >/dev/null 2>&1; then
    TOKEN_INFO=$(pkcs11-tool --module "${MODULE}" --list-token-slots 2>&1)
    if [ $(echo "${TOKEN_INFO}" | grep -c "token label") -ne 1 ]; then
	echo "${TOKEN_INFO}"
	echo "ERROR: Insert exactly one card"
	exit 1
    fi
    if echo "${TOKEN_INFO}" | grep -i "token flags" | grep -qiE "PIN locked|final try|count low"; then
	echo "${TOKEN_INFO}" | grep -i "token flags"
	echo "ERROR: The card reports a locked PIN, one PIN try left or low PIN tries. No PIN was sent."
	exit 1
    fi
fi
PIN_ERRORS='PIN is incorrect|PIN is locked|login failed|PIN not sent|PIN error|PIN is empty|PIN may be wrong'

function run_test() {
    echo "== $1" >> ${logFILE}
    if eval "$2" > ${testDIR}/last_test.log 2>&1; then
	cat ${testDIR}/last_test.log >> ${logFILE}
	echo "Passed: $1"
	passed=$((passed+1))
    else
	cat ${testDIR}/last_test.log >> ${logFILE}
	echo "FAILED: $1"
	failed=$((failed+1))
    fi
    if grep -qE "${PIN_ERRORS}" ${testDIR}/last_test.log; then
	grep -E "${PIN_ERRORS}" ${testDIR}/last_test.log
	echo "STOPPING: smart card PIN or login error, no more card logins are made. Check the PIN tries left."
	exit 2
    fi
}

head -c 200000 /dev/urandom > orig.bin

run_test "add smart card access from the card" \
    "cp orig.bin a.bin && ${FCRYPT} ${PW} a.bin && ${FCRYPT} ${PW} --add-smartcard-cert --smartcard-username=card ${SC} a.enc"
run_test "decrypt with the smart card" \
    "rm -f a.bin && ${FDECRYPT} --smartcard-cert --smartcard-username=card ${SC} ${PIN} a.enc && cmp a.bin orig.bin"
run_test "decrypt with the password after adding a card" \
    "rm -f a.bin && ${FDECRYPT} ${PW} a.enc && cmp a.bin orig.bin"
run_test "unknown smart card user is refused" \
    "rm -f a.bin && ! ${FDECRYPT} --smartcard-cert --smartcard-username=nobody ${SC} ${PIN} a.enc && [ ! -f a.bin ]"
run_test "add smart card access from a cert file" \
    "cp orig.bin b.bin && ${FCRYPT} ${PW} b.bin && ${FCRYPT} ${PW} --add-smartcard-cert-file=${SC_CERT} --smartcard-username=certfile b.enc"
run_test "decrypt the cert file access with the smart card" \
    "rm -f b.bin && ${FDECRYPT} --smartcard-cert --smartcard-username=certfile ${SC} ${PIN} b.enc && cmp b.bin orig.bin"
# SoftHSM2 uses OpenSSL inside the program and fails its login in FIPS
# mode, which would look like a wrong PIN
if echo "${TOKEN_INFO}" | grep -i "token manufacturer" | grep -qi "SoftHSM"; then
    echo "Skipped: FCRYPT_FIPS=1 test, SoftHSM2 does not work in FIPS mode"
else
    run_test "FCRYPT_FIPS=1: add and decrypt smart card access" \
        "cp orig.bin f.bin && ${FCRYPT} ${PW} f.bin && FCRYPT_FIPS=1 ${FCRYPT} ${PW} --add-smartcard-cert --smartcard-username=fips ${SC} f.enc && rm -f f.bin && FCRYPT_FIPS=1 ${FDECRYPT} --smartcard-cert --smartcard-username=fips ${SC} ${PIN} f.enc && cmp f.bin orig.bin"
fi

# 10/27/2026: Key management with a card user. C_Login calls are
# counted with OpenSC's pkcs11-spy module when it is installed.
SPY=/usr/lib64/pkcs11-spy.so
logins() { if [ -f ${testDIR}/spy.log ]; then grep -c "^[0-9]*: C_Login$" ${testDIR}/spy.log; else echo 0; fi; }
spy() { rm -f ${testDIR}/spy.log; PKCS11SPY=${MODULE} PKCS11SPY_OUTPUT=${testDIR}/spy.log "$@"; }
if [ -f ${SPY} ]; then
    SPYSC="--smartcard-cert-id=${SC_ID:-01} --smartcard-provider=${SPY}"
    printf '%s\n' "Known-Pass#2026" > ${testDIR}/pw.txt
    openssl genrsa -out alice.pem 2048 >/dev/null 2>&1; openssl rsa -in alice.pem -pubout -out alice.pub >/dev/null 2>&1
    run_test "remove a smart card user with the password: no card login" \
	"cp orig.bin k.bin && ${FCRYPT} --password-file=pw.txt k.bin && ${FCRYPT} --password-file=pw.txt --add-smartcard-cert-file=${SC_CERT} --smartcard-username=card k.enc && ${FCRYPT} --password-file=pw.txt --add-rsa-key=alice.pub --rsa-key-username=alice k.enc && cp k.enc k2.enc && spy ${FCRYPT} --password-file=pw.txt --non-interactive --remove-user=card ${SPYSC} k2.enc && [ \$(logins) -eq 0 ]"
    run_test "rekey reads the card public key with no login" \
	"printf 'rsa:alice=alice.pub\nsmartcard:card=card\n' | spy ${FCRYPT} --password-file=pw.txt --non-interactive --rekey ${SPYSC} k.enc && [ \$(logins) -eq 0 ]"
    run_test "the card user decrypts the rekeyed file with one C_Login" \
	"rm -f k.bin && spy ${FDECRYPT} --smartcard-cert --smartcard-username=card ${SPYSC} ${PIN} k.enc && cmp k.bin orig.bin && [ \$(logins) -eq 1 ]"
    run_test "rekey with the card user's cert file: no login" \
	"printf 'rsa:alice=alice.pub\nsmartcard:card=${SC_CERT}\n' | spy ${FCRYPT} --password-file=pw.txt --non-interactive --rekey ${SPYSC} k.enc && [ \$(logins) -eq 0 ]"
    run_test "rekey authenticated with the card: exactly one C_Login" \
	"printf 'password=Known-Pass#2026\nrsa:alice=alice.pub\nsmartcard:card=card\n' > rk.txt && spy ${FCRYPT} --smartcard-cert --smartcard-username=card ${SPYSC} ${PIN} --non-interactive --rekey --rekey-file=rk.txt k.enc && [ \$(logins) -eq 1 ] && rm -f k.bin && ${FDECRYPT} --password-file=pw.txt k.enc && cmp k.bin orig.bin"
    run_test "--check-version never touches the card" \
	"spy ${FDECRYPT} --check-version k.enc ${SPYSC} && [ \$(logins) -eq 0 ]"
else
    echo "Skipped: card login counts, ${SPY} (opensc) is not installed"
fi

if [ -n "${OLD_DIR}" ]; then
    OLD_DIR=$(cd ${OLD_DIR} && pwd)
    OLD_VERSION=$(${OLD_ENV} ${OLD_DIR}/fcrypt --version 2>&1 | grep -m1 -i "version")
    echo "Old build: ${OLD_VERSION}"
    run_test "old build smart card access decrypts with this build" \
	"cp orig.bin c.bin && ${OLD_ENV} ${OLD_DIR}/fcrypt ${PW} c.bin && ${OLD_ENV} ${OLD_DIR}/fcrypt ${PW} --add-smartcard-cert-file=${SC_CERT} --smartcard-username=old c.enc && rm -f c.bin && ${FDECRYPT} --smartcard-cert --smartcard-username=old ${SC} ${PIN} c.enc && cmp c.bin orig.bin"
    run_test "fmigrate converts the old file with the smart card" \
	"rm -f c.bin && ${FMIGRATE} --smartcard-cert --smartcard-username=old ${SC} ${PIN} c.enc && ${FDECRYPT} ${PW} c.enc && cmp c.bin orig.bin"
fi

echo ""
echo "${passed} passed, ${failed} failed"
echo "Logged output to: ${logFILE}"
[ ${failed} -eq 0 ]
