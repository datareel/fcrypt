#!/bin/bash
# Backwards compatibility tests for fcrypt and fdecrypt.
#
# Encrypts files with each older build and decrypts them with this
# build, for password, key file, RSA and SSH-RSA access. Also checks
# that this build can add RSA keys to files from older builds, and
# that new 2026102 format files round trip with this build.
#
# Older builds cannot read 2026102 format files, so files from this
# build are only checked to fail cleanly with the older fdecrypt.
#
# Usage: ./run_compat_tests.sh /path/to/old/console/linux [...]
#
# Each argument is a directory with older fcrypt and fdecrypt
# binaries, for example a release tag built with:
#   git archive 2023.107 | tar -x -C /tmp/fcrypt-2023.107
#   cd /tmp/fcrypt-2023.107/console/linux && make
#
# To run the tests in FIPS mode, set FCRYPT_FIPS=1, or point
# OPENSSL_CONF at a configuration that turns on FIPS mode. Old format
# files are then decrypted with --no-fips, and the tests check that
# they are refused without it. The older builds always run with the
# FIPS settings removed from their environment, and so do the openssl
# and ssh-keygen commands that make the test keys.

if [ $# -lt 1 ]; then
    echo "Usage: $0 old_build_dir [old_build_dir ...]"
    exit 1
fi

NEW_DIR=$(cd $(dirname $0) && pwd)
testDIR=${HOME}/tmp/fcrypt_compat_testing_$(date +%Y_%m_%d_%H%M%S)
logFILE=${testDIR}/fcrypt_compat_testing.log
KEYS=${testDIR}/keys
PASSWORD=--password=compat_password
OLD_ENV="env -u OPENSSL_CONF -u OPENSSL_MODULES -u FCRYPT_FIPS"
passed=0
failed=0

mkdir -p ${KEYS}
cat /dev/null > ${logFILE}

if [ ! -f ${NEW_DIR}/fcrypt ] || [ ! -f ${NEW_DIR}/fdecrypt ]; then
    echo "ERROR: Missing binaries in ${NEW_DIR}" | tee -a ${logFILE}
    exit 1
fi

# Old format files need --no-fips when this build runs in FIPS mode
NEW_FIPS=0
LEGACY_OPTS=""
if ${NEW_DIR}/fdecrypt --version 2>&1 | grep -q "FIPS mode on"; then
    NEW_FIPS=1
    LEGACY_OPTS="--no-fips"
fi

echo "Creating test keys" | tee -a ${logFILE}
dd if=/dev/urandom of=${KEYS}/master.key bs=1 count=128 &>> ${logFILE}
chmod 600 ${KEYS}/master.key
${OLD_ENV} openssl genrsa -out ${KEYS}/user1_private_key.pem 2048 &>> ${logFILE}
chmod 600 ${KEYS}/user1_private_key.pem
${OLD_ENV} openssl rsa -in ${KEYS}/user1_private_key.pem -pubout -out ${KEYS}/user1_public_key.pem &>> ${logFILE}
${OLD_ENV} ssh-keygen -q -t rsa -f ${KEYS}/user2_id_rsa -N 'password' &>> ${logFILE}
${OLD_ENV} ssh-keygen -q -p -P password -N password -f ${KEYS}/user2_id_rsa -e -m PEM &>> ${logFILE}
# FIPS mode cannot read a traditional PEM key with a passphrase, since
# its key derivation uses MD5. PKCS#8 with PBKDF2 and AES works.
${OLD_ENV} openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -passin pass:password -passout pass:password \
    -in ${KEYS}/user2_id_rsa -out ${KEYS}/user2_pkcs8.pem &>> ${logFILE}
chmod 600 ${KEYS}/user2_pkcs8.pem

result() {
    if [ $2 -eq 0 ]; then
	passed=$(( $passed + 1 ))
	echo "Passed: $1" | tee -a ${logFILE}
    else
	failed=$(( $failed + 1 ))
	echo "FAILED: $1" | tee -a ${logFILE}
    fi
}

new_case_dir() {
    caseDIR=${testDIR}/case
    rm -rf ${caseDIR}
    mkdir -p ${caseDIR}
    cd ${caseDIR}
    printf x > one.bin
    head -c 1000003 /dev/urandom > big.bin
    seq 1 5000 > text.txt
    mkdir orig
    cp one.bin big.bin text.txt orig
}

# Usage: run_tests encrypt_command decrypt_command label [decrypt_opts]
# Encrypt with the first build and decrypt with the second
run_tests() {
    ENC=$1
    DEC=$2
    DOPTS=$4
    USER2_KEY=${KEYS}/user2_id_rsa
    if [ ${NEW_FIPS} -eq 1 ] && [ -z "${DOPTS}" ]; then USER2_KEY=${KEYS}/user2_pkcs8.pem; fi
    for f in one.bin big.bin text.txt; do
	for opts in "${PASSWORD}" "--key=${KEYS}/master.key" \
	    "--key=${KEYS}/master.key --iter=5000" \
	    "${PASSWORD} --static-data-size=8192"; do
	    new_case_dir
	    enc=${f%.*}.enc
	    # fdecrypt reads the static data size from the encrypted file
	    dec_opts=${opts% --static-data-size=*}
	    echo "${ENC} ${opts} ${f}; ${DEC} ${DOPTS} ${dec_opts} ${enc}" >> ${logFILE}
	    ( ${ENC} -r ${opts} ${f} && ${DEC} ${DOPTS} ${dec_opts} ${enc} && cmp ${f} orig/${f} ) &>> ${logFILE}
	    result "$3 ${f} ${opts}" $?
	done
    done

    # RSA and SSH-RSA keys added by the encrypting version
    new_case_dir
    ( ${ENC} --key=${KEYS}/master.key big.bin && \
	${ENC} --key=${KEYS}/master.key --add-rsa-key=${KEYS}/user1_public_key.pem --rsa-key-username=user1 big.enc && \
	${OLD_ENV} ssh-keygen -f ${KEYS}/user2_id_rsa.pub -m PKCS8 -e | ${ENC} --key=${KEYS}/master.key --add-rsa-key --rsa-key-username=user2 big.enc && \
	rm big.bin && \
	${DEC} ${DOPTS} --rsa-key=${KEYS}/user1_private_key.pem --rsa-key-username=user1 big.enc && \
	cmp big.bin orig/big.bin && rm big.bin && \
	${DEC} ${DOPTS} --rsa-key=${USER2_KEY} --rsa-key-passphrase=password --rsa-key-username=user2 big.enc && \
	cmp big.bin orig/big.bin && \
	${DEC} ${DOPTS} --list-users big.enc | grep -q "Username: user2" && \
	${DEC} ${DOPTS} ${PASSWORD} --key=${KEYS}/master.key -l big.enc | grep -q "Decrypted name: big.bin" ) &>> ${logFILE}
    result "$3 RSA and SSH-RSA keys, --list-users and -l" $?
}

echo "Starting tests at $(date)" | tee -a ${logFILE}
NEW="${NEW_DIR}"
NEW_VERSION=$(${NEW}/fcrypt --version 2>&1 | grep -m1 -i "version")
echo "$(${NEW}/fdecrypt --version 2>&1 | grep "FIPS mode")" | tee -a ${logFILE}

echo "" | tee -a ${logFILE}
echo "Testing ${NEW_VERSION} round trips" | tee -a ${logFILE}
run_tests "${NEW}/fcrypt" "${NEW}/fdecrypt" "new to new:"

if [ ${NEW_FIPS} -eq 1 ]; then
    new_case_dir
    ( ${NEW}/fcrypt -r ${PASSWORD} text.txt && \
	${OLD_ENV} ssh-keygen -f ${KEYS}/user2_id_rsa.pub -m PKCS8 -e | ${NEW}/fcrypt ${PASSWORD} --add-rsa-key --rsa-key-username=user2 text.enc && \
	! ${NEW}/fdecrypt --rsa-key=${KEYS}/user2_id_rsa --rsa-key-passphrase=password --rsa-key-username=user2 text.enc && \
	[ ! -e text.txt ] ) &>> ${logFILE}
    result "FIPS mode refuses a traditional PEM key with a passphrase" $?
fi

for OLD_DIR in "$@"; do
    OLD_DIR=$(cd ${OLD_DIR} && pwd)
    OLD="${OLD_ENV} ${OLD_DIR}"
    OLD_VERSION=$(${OLD}/fcrypt --version 2>&1 | grep -m1 -i "version")
    echo "" | tee -a ${logFILE}
    echo "Testing ${NEW_VERSION} against ${OLD_VERSION} in ${OLD_DIR}" | tee -a ${logFILE}
    run_tests "${OLD}/fcrypt" "${NEW}/fdecrypt" "old to new:" "${LEGACY_OPTS}"

    # Old format file, RSA key added by this build. Adding a key to an
    # old file uses PKCS#1 v1.5, which FIPS mode does not allow.
    new_case_dir
    ( ${OLD}/fcrypt --key=${KEYS}/master.key big.bin && \
	${NEW}/fcrypt --no-fips --key=${KEYS}/master.key --add-rsa-key=${KEYS}/user1_public_key.pem --rsa-key-username=user1 big.enc && \
	rm big.bin && \
	${OLD}/fdecrypt --rsa-key=${KEYS}/user1_private_key.pem --rsa-key-username=user1 big.enc && \
	cmp big.bin orig/big.bin && rm big.bin && \
	${NEW}/fdecrypt --no-fips --rsa-key=${KEYS}/user1_private_key.pem --rsa-key-username=user1 big.enc && \
	cmp big.bin orig/big.bin ) &>> ${logFILE}
    result "old file, RSA key added by the new version" $?

    # Old format files are refused in FIPS mode without --no-fips
    if [ ${NEW_FIPS} -eq 1 ]; then
	new_case_dir
	( ${OLD}/fcrypt -r ${PASSWORD} text.txt && \
	    ! ${NEW}/fdecrypt ${PASSWORD} text.enc && [ ! -e text.txt ] && \
	    ${NEW}/fdecrypt --no-fips ${PASSWORD} text.enc && cmp text.txt orig/text.txt ) &>> ${logFILE}
	result "old file refused in FIPS mode, decrypts with --no-fips" $?
    fi

    # Older builds cannot read new files and must not write any output
    new_case_dir
    ( ${NEW}/fcrypt -r ${PASSWORD} text.txt && \
	! ${OLD}/fdecrypt ${PASSWORD} text.enc && [ ! -e text.txt ] ) &>> ${logFILE}
    result "old fdecrypt refuses a new file without writing output" $?
done

echo "" | tee -a ${logFILE}
echo "${passed} passed, ${failed} failed" | tee -a ${logFILE}
echo "Logged output to: ${logFILE}"
if [ ${failed} -ne 0 ]; then exit 1; fi
exit 0
