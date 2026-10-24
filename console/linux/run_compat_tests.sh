#!/bin/bash
# Backwards compatibility tests for fcrypt and fdecrypt.
#
# Encrypts files with this build and decrypts them with each older
# build, and the other way around, for password, key file, RSA and
# SSH-RSA access.
#
# Usage: ./run_compat_tests.sh /path/to/old/console/linux [...]
#
# Each argument is a directory with older fcrypt and fdecrypt
# binaries, for example a release tag built with:
#   git archive 2023.107 | tar -x -C /tmp/fcrypt-2023.107
#   cd /tmp/fcrypt-2023.107/console/linux && make

if [ $# -lt 1 ]; then
    echo "Usage: $0 old_build_dir [old_build_dir ...]"
    exit 1
fi

NEW_DIR=$(cd $(dirname $0) && pwd)
testDIR=${HOME}/tmp/fcrypt_compat_testing_$(date +%Y_%m_%d_%H%M%S)
logFILE=${testDIR}/fcrypt_compat_testing.log
KEYS=${testDIR}/keys
PASSWORD=--password=compat_password
passed=0
failed=0

mkdir -p ${KEYS}
cat /dev/null > ${logFILE}

if [ ! -f ${NEW_DIR}/fcrypt ] || [ ! -f ${NEW_DIR}/fdecrypt ]; then
    echo "ERROR: Missing binaries in ${NEW_DIR}" | tee -a ${logFILE}
    exit 1
fi

echo "Creating test keys" | tee -a ${logFILE}
dd if=/dev/urandom of=${KEYS}/master.key bs=1 count=128 &>> ${logFILE}
chmod 600 ${KEYS}/master.key
openssl genrsa -out ${KEYS}/user1_private_key.pem 2048 &>> ${logFILE}
chmod 600 ${KEYS}/user1_private_key.pem
openssl rsa -in ${KEYS}/user1_private_key.pem -pubout -out ${KEYS}/user1_public_key.pem &>> ${logFILE}
ssh-keygen -q -t rsa -f ${KEYS}/user2_id_rsa -N 'password' &>> ${logFILE}
ssh-keygen -q -p -P password -N password -f ${KEYS}/user2_id_rsa -e -m PEM &>> ${logFILE}

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

# Usage: run_tests encrypt_dir decrypt_dir label
run_tests() {
    ENC=$1/fcrypt
    DEC=$2/fdecrypt
    for f in one.bin big.bin text.txt; do
	for opts in "${PASSWORD}" "--key=${KEYS}/master.key" \
	    "--key=${KEYS}/master.key --iter=5000" \
	    "${PASSWORD} --static-data-size=8192"; do
	    new_case_dir
	    enc=${f%.*}.enc
	    # fdecrypt reads the static data size from the encrypted file
	    dec_opts=${opts% --static-data-size=*}
	    echo "${ENC} ${opts} ${f}; ${DEC} ${dec_opts} ${enc}" >> ${logFILE}
	    ( ${ENC} -r ${opts} ${f} && ${DEC} ${dec_opts} ${enc} && cmp ${f} orig/${f} ) &>> ${logFILE}
	    result "$3 ${f} ${opts}" $?
	done
    done

    # RSA and SSH-RSA keys added by the encrypting version
    new_case_dir
    ( ${ENC} --key=${KEYS}/master.key big.bin && \
	${ENC} --key=${KEYS}/master.key --add-rsa-key=${KEYS}/user1_public_key.pem --rsa-key-username=user1 big.enc && \
	ssh-keygen -f ${KEYS}/user2_id_rsa.pub -m PKCS8 -e | ${ENC} --key=${KEYS}/master.key --add-rsa-key --rsa-key-username=user2 big.enc && \
	rm big.bin && \
	${DEC} --rsa-key=${KEYS}/user1_private_key.pem --rsa-key-username=user1 big.enc && \
	cmp big.bin orig/big.bin && rm big.bin && \
	${DEC} --rsa-key=${KEYS}/user2_id_rsa --rsa-key-passphrase=password --rsa-key-username=user2 big.enc && \
	cmp big.bin orig/big.bin ) &>> ${logFILE}
    result "$3 RSA and SSH-RSA keys" $?

    # File from the encrypting version, RSA key added by the other version
    new_case_dir
    ( ${ENC} --key=${KEYS}/master.key big.bin && \
	$2/fcrypt --key=${KEYS}/master.key --add-rsa-key=${KEYS}/user1_public_key.pem --rsa-key-username=user1 big.enc && \
	rm big.bin && \
	$1/fdecrypt --rsa-key=${KEYS}/user1_private_key.pem --rsa-key-username=user1 big.enc && \
	cmp big.bin orig/big.bin ) &>> ${logFILE}
    result "$3 RSA key added by the other version" $?
}

echo "Starting tests at $(date)" | tee -a ${logFILE}
NEW_VERSION=$(${NEW_DIR}/fcrypt --version 2>&1 | grep -m1 -i "version")
for OLD_DIR in "$@"; do
    OLD_DIR=$(cd ${OLD_DIR} && pwd)
    OLD_VERSION=$(${OLD_DIR}/fcrypt --version 2>&1 | grep -m1 -i "version")
    echo "" | tee -a ${logFILE}
    echo "Testing ${NEW_VERSION} against ${OLD_VERSION} in ${OLD_DIR}" | tee -a ${logFILE}
    run_tests ${OLD_DIR} ${NEW_DIR} "old to new:"
    run_tests ${NEW_DIR} ${OLD_DIR} "new to old:"
done

echo "" | tee -a ${logFILE}
echo "${passed} passed, ${failed} failed" | tee -a ${logFILE}
echo "Logged output to: ${logFILE}"
if [ ${failed} -ne 0 ]; then exit 1; fi
exit 0
