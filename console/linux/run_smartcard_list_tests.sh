#!/bin/bash
# Smart card listing tests for fcrypt --smartcard-list (SC_list_tokens)
# and --smartcard-match (SC_match_public_keys), with SoftHSM2 only.
#
# The tests make their own throwaway SoftHSM2 tokens in a test directory
# and never use a real card: the module must be a libsofthsm2.so, and
# SOFTHSM2_CONF points at the test tokens. C_Login calls are counted
# with OpenSC's pkcs11-spy module, the list must make none.
#
# Usage: SOFTHSM_MODULE=/usr/lib64/pkcs11/libsofthsm2.so ./run_smartcard_list_tests.sh
#
#   SOFTHSM_MODULE  SoftHSM2 PKCS#11 module (required)
#   SOFTHSM_UTIL    softhsm2-util, default next to the module or in PATH

NEW_DIR=$(cd $(dirname $0) && pwd)
FCRYPT=${NEW_DIR}/fcrypt
testDIR=${HOME}/tmp/fcrypt_smartcard_list_testing_$(date +%Y_%m_%d_%H%M%S)
logFILE=${testDIR}/fcrypt_smartcard_list_testing.log
SPY=/usr/lib64/pkcs11-spy.so
passed=0
failed=0

MODULE=${SOFTHSM_MODULE}
if [ -z "${MODULE}" ] || [ ! -f "${MODULE}" ]; then
    echo "ERROR: Set SOFTHSM_MODULE to the SoftHSM2 module, see the usage at the top of $0"
    exit 1
fi
# Never a real card module
if [ "$(basename ${MODULE})" != "libsofthsm2.so" ]; then
    echo "ERROR: ${MODULE} is not a SoftHSM2 module, these tests only use SoftHSM2 test tokens"
    exit 1
fi
MODULE=$(cd $(dirname ${MODULE}) && pwd)/$(basename ${MODULE})
# pkcs11-spy loads PKCS11SPY, set it so the spy can never fall back to a
# real card module
export PKCS11SPY=${MODULE}
SOFTHSM_UTIL=${SOFTHSM_UTIL:-$(dirname ${MODULE})/../../bin/softhsm2-util}
[ -x ${SOFTHSM_UTIL} ] || SOFTHSM_UTIL=$(dirname ${MODULE})/../bin/softhsm2-util
[ -x ${SOFTHSM_UTIL} ] || SOFTHSM_UTIL=softhsm2-util
for p in ${FCRYPT} ${SPY}; do
    if [ ! -f ${p} ]; then
	echo "ERROR: Missing ${p}"
	exit 1
    fi
done
if ! command -v pkcs11-tool >/dev/null 2>&1 || ! command -v ${SOFTHSM_UTIL} >/dev/null 2>&1; then
    echo "ERROR: pkcs11-tool (opensc) and softhsm2-util are needed"
    exit 1
fi

mkdir -p ${testDIR}/tokens
cat /dev/null > ${logFILE}
cd ${testDIR}
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' "${testDIR}/tokens" > softhsm2.conf
export SOFTHSM2_CONF=${testDIR}/softhsm2.conf
SHIM=${testDIR}/p11_flag_shim.so
gcc -shared -fPIC -I${NEW_DIR}/../../include -o ${SHIM} ${NEW_DIR}/p11_flag_shim.c -ldl >>${logFILE} 2>&1 || { echo "ERROR: Cannot build ${SHIM}"; exit 1; }

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
}

# Test tokens. The keys and certs are made with openssl and written to
# the tokens with the test PIN (SoftHSM2 only).
PIN=123456
function make_cert() { # name keyspec cn
    if [ "$2" = "ec" ]; then
	openssl ecparam -name prime256v1 -genkey -noout -out $1.key 2>>${logFILE}
    else
	openssl genrsa -out $1.key $2 2>>${logFILE}
    fi
    openssl req -new -x509 -key $1.key -out $1.pem -days 365 -subj "/CN=$3/O=fcrypt test" 2>>${logFILE}
    openssl x509 -in $1.pem -outform der -out $1.der 2>>${logFILE}
    openssl pkcs8 -topk8 -nocrypt -in $1.key -outform der -out $1.p8 2>>${logFILE}
    openssl pkey -in $1.key -pubout -outform der -out $1.pub.der 2>>${logFILE}
}
function slot_of() { pkcs11-tool --module ${MODULE} --list-token-slots 2>/dev/null | awk -v l="$1" '/^Slot/ { s=$0 } $0 ~ "token label *: *"l"$" { sub(/.*\(0x/, "", s); sub(/\).*/, "", s); print strtonum("0x" s); exit }'; }
function put() { # slot file type id label
    pkcs11-tool --module ${MODULE} --slot $1 --login --pin ${PIN} --write-object $2 --type $3 --id $4 --label "$5" >>${logFILE} 2>&1
}
for t in "card one" "card two" "locked card"; do
    ${SOFTHSM_UTIL} --module ${MODULE} --init-token --free --label "${t}" --so-pin 87654321 --pin ${PIN} >>${logFILE} 2>&1
done
S1=$(slot_of "card one"); S2=$(slot_of "card two"); S3=$(slot_of "locked card")
make_cert rsa1 2048 "Test User One"; make_cert ec1 ec "Test EC User"; make_cert rsa3 3072 "Test User Two"
make_cert rsa4 2048 "No Cert Key"; make_cert rsa5 2048 "Locked User"; make_cert other 2048 "Not On Any Card"
put ${S1} rsa1.p8 privkey 01 "key one"; put ${S1} rsa1.der cert 01 "cert one"
put ${S1} ec1.p8 privkey 02 "ec key"; put ${S1} ec1.der cert 02 "ec cert"
put ${S2} rsa3.p8 privkey 03 "key three"; put ${S2} rsa3.der cert 03 "cert three"
put ${S2} rsa4.pub.der pubkey 04 "pub only"
put ${S3} rsa5.p8 privkey 05 "key five"; put ${S3} rsa5.der cert 05 "cert five"
echo "Test tokens: card one = slot ${S1}, card two = slot ${S2}, locked card = slot ${S3}" | tee -a ${logFILE}

logins() { if [ -f ${testDIR}/spy.log ]; then grep -c "C_Login" ${testDIR}/spy.log; else echo 99; fi; }
spy() { rm -f ${testDIR}/spy.log; PKCS11SPY=${MODULE} PKCS11SPY_OUTPUT=${testDIR}/spy.log "$@"; }
LIST="${FCRYPT} --smartcard-list --smartcard-provider=${SPY}"
TOKENS_BEFORE=$(pkcs11-tool --module ${MODULE} --list-token-slots 2>&1)

run_test "the list shows the three test tokens with no C_Login" \
    "spy ${LIST} > list.txt && grep -q 'Token label: card one' list.txt && grep -q 'Token label: card two' list.txt && grep -q 'Token label: locked card' list.txt && [ \$(logins) -eq 0 ] && grep -q C_GetTokenInfo spy.log"
run_test "the list shows the slots, SoftHSM manufacturer and serials" \
    "grep -q \"^Slot ${S1} \" list.txt && grep -q \"^Slot ${S2} \" list.txt && grep -q 'Manufacturer: SoftHSM' list.txt && [ \$(grep -c 'Serial: [0-9a-f]' list.txt) -eq 3 ]"
run_test "the cert IDs, labels, key sizes and subjects are listed" \
    "grep -q 'Cert ID 01 label \"cert one\" RSA 2048' list.txt && grep -q 'Cert ID 03 label \"cert three\" RSA 3072' list.txt && grep -q 'Cert ID 05 label \"cert five\" RSA 2048' list.txt && grep -q 'Subject CN: Test User One  Issuer CN: Test User One  Expires: 20' list.txt"
run_test "an EC cert is listed and flagged as not usable" \
    "grep -q 'Cert ID 02 label \"ec cert\" non-RSA 256 (cannot be used, RSA keys only)' list.txt"
run_test "a public key with no cert is listed" \
    "grep -q 'Public key ID 04 label \"pub only\" RSA 2048' list.txt"
run_test "private keys are not shown before login" \
    "! grep -q 'key one\|key three\|key five' list.txt"
run_test "a matching cert file finds its card and cert ID" \
    "spy ${LIST} --smartcard-match=rsa1.pem --smartcard-match=rsa3.der --smartcard-match=rsa4.pub.der > match.txt && grep -q \"Match: rsa1.pem is on slot ${S1} .*\\\"card one\\\" cert ID 01\" match.txt && grep -q \"Match: rsa3.der is on slot ${S2} .*\\\"card two\\\" cert ID 03\" match.txt && grep -q \"Match: rsa4.pub.der is on slot ${S2} .* cert ID 04\" match.txt && [ \$(logins) -eq 0 ]"
run_test "a cert that is on no card is not matched" \
    "spy ${LIST} --smartcard-match=other.pem > nomatch.txt && grep -q 'No match: other.pem' nomatch.txt && ! grep -q '^Match:' nomatch.txt"
# Token flags from the shim: locked, final try, low tries
run_test "a PIN locked card is listed as LOCKED with no C_Login" \
    "PKCS11SPY=${SHIM} FC_SHIM_MODULE=${MODULE} FC_SHIM_FLAGS=40000 PKCS11SPY_OUTPUT=${testDIR}/spy.log ${LIST} > locked.txt && [ \$(grep -c 'PIN: LOCKED' locked.txt) -ge 3 ] && ! grep -q 'PIN: ok' locked.txt && [ \$(logins) -eq 0 ]"
run_test "one PIN try left and low tries are shown, no C_Login" \
    "rm -f spy.log && PKCS11SPY=${SHIM} FC_SHIM_MODULE=${MODULE} FC_SHIM_FLAGS=20000 PKCS11SPY_OUTPUT=${testDIR}/spy.log ${LIST} | grep -q 'PIN: ONE TRY LEFT' && [ \$(logins) -eq 0 ] && rm -f spy.log && PKCS11SPY=${SHIM} FC_SHIM_MODULE=${MODULE} FC_SHIM_FLAGS=10000 PKCS11SPY_OUTPUT=${testDIR}/spy.log ${LIST} | grep -q 'PIN: low on tries' && [ \$(logins) -eq 0 ]"
run_test "every session is closed and the module finalized" \
    "spy ${LIST} >/dev/null && [ \$(awk '/^[0-9]+: C_OpenSession/ { o=1 } /^Returned:/ { if(o && \$2 == 0) n++; o=0 } END { print n+0 }' spy.log) -eq \$(grep -c '^[0-9]*: C_CloseSession' spy.log) ] && [ \$(grep -c '^[0-9]*: C_CloseSession' spy.log) -ge 3 ] && grep -q '^[0-9]*: C_Finalize' spy.log"
run_test "the token flags and PIN state are unchanged after listing" \
    "[ \"\$(pkcs11-tool --module ${MODULE} --list-token-slots 2>&1)\" = \"\${TOKENS_BEFORE}\" ]"
run_test "the test PIN still works after listing (no tries used)" \
    "pkcs11-tool --module ${MODULE} --slot ${S3} --login --pin ${PIN} --list-objects --type privkey | grep -q 'key five'"
run_test "a new, uninitialized SoftHSM slot is listed as not initialized" \
    "grep -q 'Token: not initialized' list.txt"
run_test "a missing module is an error" \
    "! ${FCRYPT} --smartcard-list --smartcard-provider=${testDIR}/softhsm2.conf"
run_test "a missing match file is an error" \
    "! ${LIST} --smartcard-match=${testDIR}/nofile.pem"

echo ""
echo "${passed} passed, ${failed} failed"
echo "Logged output to: ${logFILE}"
[ ${failed} -eq 0 ]
