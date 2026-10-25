#!/bin/bash
# Tests for fmigrate, which converts files from releases before
# 2026.102 to the 2026102 file format.
#
# Encrypts files with each older build, converts them with this build's
# fmigrate, and checks that this build's fdecrypt decrypts the result to
# the original data with the same stored file name. Also checks that a
# failed conversion leaves the old file as it was.
#
# Usage: ./run_migrate_tests.sh /path/to/old/console/linux [...]
#
# Each argument is a directory with older fcrypt and fdecrypt binaries.
# Use 2026.101 for the tests of modified old files, since it is the
# first release that adds an integrity record to old format files.
#
# To run the tests on a system in FIPS mode, set FCRYPT_FIPS=1 or point
# OPENSSL_CONF at a configuration that turns on FIPS mode. fmigrate then
# needs --no-fips, and the new files are decrypted in FIPS mode.

if [ $# -lt 1 ]; then
    echo "Usage: $0 old_build_dir [old_build_dir ...]"
    exit 1
fi

NEW_DIR=$(cd $(dirname $0) && pwd)
FCRYPT=${NEW_DIR}/fcrypt
FDECRYPT=${NEW_DIR}/fdecrypt
FMIGRATE=${NEW_DIR}/fmigrate
testDIR=${HOME}/tmp/fcrypt_migrate_testing_$(date +%Y_%m_%d_%H%M%S)
logFILE=${testDIR}/fcrypt_migrate_testing.log
KEYS=${testDIR}/keys
PW=--password=migrate_password
OLD_ENV="env -u OPENSSL_CONF -u OPENSSL_MODULES -u FCRYPT_FIPS"
passed=0
failed=0

for f in ${FCRYPT} ${FDECRYPT} ${FMIGRATE}; do
    if [ ! -f ${f} ]; then
	echo "ERROR: Missing ${f}"
	exit 1
    fi
done
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is needed to modify the test files"
    exit 1
fi

mkdir -p ${KEYS}
cat /dev/null > ${logFILE}

MIG_OPTS=""
NEW_FIPS=0
if ${FDECRYPT} --version 2>&1 | grep -q "FIPS mode on"; then
    MIG_OPTS="--no-fips"
    NEW_FIPS=1
fi

result() {
    if [ $2 -eq 0 ]; then
	passed=$(( $passed + 1 ))
	echo "Passed: $1" | tee -a ${logFILE}
    else
	failed=$(( $failed + 1 ))
	echo "FAILED: $1" | tee -a ${logFILE}
    fi
}

# Run a command that must fail
must_fail() {
    echo "+ $*" >> ${logFILE}
    "$@" &>> ${logFILE}
    [ $? -ne 0 ]
}

# Run a command that must succeed
must_pass() {
    echo "+ $*" >> ${logFILE}
    "$@" &>> ${logFILE}
}

new_case_dir() {
    caseDIR=${testDIR}/case
    rm -rf ${caseDIR}
    mkdir -p ${caseDIR}
    cd ${caseDIR}
    head -c 300007 /dev/urandom > big.bin
    seq 1 5000 > text.txt
    printf x > one.bin
    mkdir orig
    cp big.bin text.txt one.bin orig
}

is_new_format() {
    [ "$(head -c 8 $1 | od -An -c | tr -d ' ')" = "FCRYPT032004" ]
}

no_temp_files() {
    [ -z "$(find . -name '*.fmigrate_*' -o -name '*.fcrypt_*' -o -name '*.fdecrypt_*')" ]
}

echo "Creating test keys" | tee -a ${logFILE}
dd if=/dev/urandom of=${KEYS}/master.key bs=1 count=128 &>> ${logFILE}
chmod 600 ${KEYS}/master.key
${OLD_ENV} openssl genrsa -out ${KEYS}/user1.pem 2048 &>> ${logFILE}
${OLD_ENV} openssl rsa -in ${KEYS}/user1.pem -pubout -out ${KEYS}/user1.pub &>> ${logFILE}
${OLD_ENV} openssl genrsa -out ${KEYS}/user3.pem 2048 &>> ${logFILE}
${OLD_ENV} openssl rsa -in ${KEYS}/user3.pem -pubout -out ${KEYS}/user3.pub &>> ${logFILE}
${OLD_ENV} ssh-keygen -q -t rsa -f ${KEYS}/user2_id_rsa -N 'password' &>> ${logFILE}
${OLD_ENV} ssh-keygen -q -p -P password -N password -f ${KEYS}/user2_id_rsa -e -m PEM &>> ${logFILE}
chmod 600 ${KEYS}/*.pem

cat > ${testDIR}/enctool.py <<'EOF'
import struct, sys
# Old format: static data header (276 bytes), static data area,
# encrypted file header (844 bytes), then data blocks of 844 bytes
d = bytearray(open(sys.argv[2], 'rb').read())
if sys.argv[1] == 'drop-last':
    static_len = struct.unpack('<I', d[8:12])[0]
    start = 276 + static_len + 844
    n = (len(d) - start) // 844
    d = d[:start + max(n - 1, 0) * 844] if (len(d) - start) % 844 == 0 else d[:start + n * 844]
elif sys.argv[1] == 'flip':
    d[int(sys.argv[3])] ^= 0x01
open(sys.argv[2], 'wb').write(bytes(d))
EOF
TOOL="python3 -I ${testDIR}/enctool.py"

echo "Starting tests at $(date)" | tee -a ${logFILE}
echo "$(${FDECRYPT} --version 2>&1 | grep "FIPS mode")" | tee -a ${logFILE}

for OLD_DIR in "$@"; do
    OLD_DIR=$(cd ${OLD_DIR} && pwd)
    OLD_FCRYPT="${OLD_ENV} ${OLD_DIR}/fcrypt"
    OLD_VERSION=$(${OLD_FCRYPT} --version 2>&1 | grep -m1 -i "version")
    echo "" | tee -a ${logFILE}
    echo "Testing fmigrate with files from ${OLD_VERSION} in ${OLD_DIR}" | tee -a ${logFILE}

    # Password, key file and iteration counts
    for opts in "${PW}" "--key=${KEYS}/master.key" "--key=${KEYS}/master.key --iter=5000"; do
	for f in big.bin text.txt one.bin; do
	    new_case_dir
	    enc=${f%.*}.enc
	    ( ${OLD_FCRYPT} -r ${opts} ${f} && ${OLD_ENV} ${OLD_DIR}/fdecrypt ${opts} -l ${enc} > name_before.txt && \
		${FMIGRATE} ${MIG_OPTS} ${opts} ${enc} && is_new_format ${enc} && \
		${FDECRYPT} ${opts} -l ${enc} | grep -q "Decrypted name: ${f}" && \
		${FDECRYPT} ${opts} ${enc} && cmp ${f} orig/${f} && no_temp_files ) &>> ${logFILE}
	    result "${f} ${opts}" $?
	done
    done

    # Converting a second time does nothing
    ( ${FMIGRATE} ${MIG_OPTS} --key=${KEYS}/master.key --iter=5000 one.enc 2>&1 | grep -q "already in the 2026102 format" ) &>> ${logFILE}
    result "a converted file is skipped" $?

    # Empty file. Old releases refuse to encrypt an empty file, so the
    # test is skipped when the old fcrypt fails.
    new_case_dir
    printf "" > empty.bin
    if ${OLD_FCRYPT} -r ${PW} empty.bin &>> ${logFILE}; then
	( ${FMIGRATE} ${MIG_OPTS} ${PW} empty.enc && is_new_format empty.enc && \
	    ${FDECRYPT} ${PW} empty.enc && [ -f empty.bin ] && [ ! -s empty.bin ] ) &>> ${logFILE}
	result "empty file" $?
    else
	echo "Skipping the empty file test, the old fcrypt does not encrypt empty files" | tee -a ${logFILE}
    fi

    # RSA key users. The user who converts the file keeps RSA access,
    # the password still works, and the other users are listed.
    new_case_dir
    ( ${OLD_FCRYPT} -r ${PW} big.bin && \
	${OLD_FCRYPT} ${PW} --add-rsa-key=${KEYS}/user1.pub --rsa-key-username=user1 big.enc && \
	${OLD_FCRYPT} ${PW} --add-rsa-key=${KEYS}/user3.pub --rsa-key-username=user3 big.enc && \
	${FMIGRATE} ${MIG_OPTS} --rsa-key=${KEYS}/user1.pem --rsa-key-username=user1 big.enc > out.txt 2>&1 && \
	cat out.txt && grep -q "RSA user user3" out.txt && is_new_format big.enc && \
	${FDECRYPT} --rsa-key=${KEYS}/user1.pem --rsa-key-username=user1 big.enc && cmp big.bin orig/big.bin && rm big.bin && \
	${FDECRYPT} ${PW} big.enc && cmp big.bin orig/big.bin && rm big.bin && \
	! ${FDECRYPT} --rsa-key=${KEYS}/user3.pem --rsa-key-username=user3 big.enc && \
	${FCRYPT} ${PW} --add-rsa-key=${KEYS}/user3.pub --rsa-key-username=user3 big.enc && \
	${FDECRYPT} --rsa-key=${KEYS}/user3.pem --rsa-key-username=user3 big.enc && cmp big.bin orig/big.bin ) &>> ${logFILE}
    result "RSA users: converting user kept, other users listed and added again" $?

    # SSH-RSA key with a passphrase, the only access to the file
    new_case_dir
    dd if=/dev/urandom of=temp.key bs=1 count=64 &>> ${logFILE}
    USER2_KEY=${KEYS}/user2_id_rsa
    if [ ${NEW_FIPS} -eq 1 ]; then
	# FIPS mode needs PKCS#8 to read the key after the conversion
	${OLD_ENV} openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 -passin pass:password -passout pass:password \
	    -in ${KEYS}/user2_id_rsa -out user2_pkcs8.pem &>> ${logFILE}
	USER2_KEY=user2_pkcs8.pem
    fi
    ( ${OLD_FCRYPT} -r --key=temp.key text.txt && \
	${OLD_ENV} ssh-keygen -f ${KEYS}/user2_id_rsa.pub -m PKCS8 -e | ${OLD_FCRYPT} --key=temp.key --add-rsa-key --rsa-key-username=user2 text.enc && \
	rm temp.key && \
	${FMIGRATE} ${MIG_OPTS} --rsa-key=${KEYS}/user2_id_rsa --rsa-key-passphrase=password --rsa-key-username=user2 text.enc && \
	is_new_format text.enc && \
	${FDECRYPT} --rsa-key=${USER2_KEY} --rsa-key-passphrase=password --rsa-key-username=user2 text.enc && \
	cmp text.txt orig/text.txt ) &>> ${logFILE}
    result "SSH-RSA key with a passphrase" $?

    # --outdir keeps the old files, -R converts a directory tree and
    # skips files that are not encrypted
    new_case_dir
    mkdir -p tree/sub out
    cp big.bin tree/a.bin; cp text.txt tree/sub/b.txt; echo "plain" > tree/sub/notes.txt
    ( ${OLD_FCRYPT} -r ${PW} tree/a.bin tree/sub/b.txt && cp -r tree tree_orig && \
	${FMIGRATE} ${MIG_OPTS} ${PW} --outdir=out tree/a.enc && is_new_format out/a.enc && \
	cmp tree/a.enc tree_orig/a.enc && \
	! ${FMIGRATE} ${MIG_OPTS} ${PW} --outdir=out tree/a.enc && \
	${FMIGRATE} ${MIG_OPTS} ${PW} -o --outdir=out tree/a.enc && \
	${FMIGRATE} ${MIG_OPTS} ${PW} -R tree && is_new_format tree/a.enc && is_new_format tree/sub/b.enc && \
	cmp tree/sub/notes.txt tree_orig/sub/notes.txt && \
	${FMIGRATE} --check -R tree | grep -q "notes.txt: not an fcrypt encrypted file" && \
	cd tree && ${FDECRYPT} ${PW} --no-path a.enc && cmp a.bin ../big.bin && cd .. && no_temp_files ) &>> ${logFILE}
    result "--outdir keeps the old file, -o, -R and --check" $?

    # Failures leave the old file as it was
    new_case_dir
    ( ${OLD_FCRYPT} -r ${PW} big.bin && cp big.enc big.save && \
	! ${FMIGRATE} ${MIG_OPTS} --password=wrong_password_123 big.enc && cmp big.enc big.save && \
	! ${FMIGRATE} ${MIG_OPTS} --rsa-key=${KEYS}/user1.pem --rsa-key-username=user1 big.enc && cmp big.enc big.save && \
	! ${FMIGRATE} ${MIG_OPTS} ${PW} --iter=7000 big.enc && cmp big.enc big.save && \
	no_temp_files ) &>> ${logFILE}
    result "wrong password, unknown RSA user and wrong --iter leave the old file" $?

    # Modified old files. Only 2026.101 and later old files carry an
    # integrity record, so a removed block is detected only for them.
    new_case_dir
    ${OLD_FCRYPT} -r ${PW} big.bin &>> ${logFILE}
    cp big.enc t.enc; ${TOOL} flip t.enc 30000; cp t.enc t.save
    ( ! ${FMIGRATE} ${MIG_OPTS} ${PW} t.enc && cmp t.enc t.save && no_temp_files ) &>> ${logFILE}
    result "changed data block is rejected, old file kept" $?
    if ${OLD_FCRYPT} --version 2>&1 | grep -q "version 2026"; then
	cp big.enc d.enc; ${TOOL} drop-last d.enc; cp d.enc d.save
	( ! ${FMIGRATE} ${MIG_OPTS} ${PW} d.enc && cmp d.enc d.save && no_temp_files ) &>> ${logFILE}
	result "truncated file is rejected, old file kept" $?
    fi

    # Mode 0 test files need --allow-unencrypted
    new_case_dir
    if ${OLD_FCRYPT} -0 -r ${PW} text.txt &>> ${logFILE}; then
	( ! ${FMIGRATE} ${MIG_OPTS} ${PW} text.enc && ! is_new_format text.enc && \
	    ${FMIGRATE} ${MIG_OPTS} ${PW} --allow-unencrypted text.enc && is_new_format text.enc && \
	    ${FDECRYPT} ${PW} text.enc && cmp text.txt orig/text.txt ) &>> ${logFILE}
	result "mode 0 file needs --allow-unencrypted" $?
    fi
done

# FIPS mode
echo "" | tee -a ${logFILE}
new_case_dir
if [ ${NEW_FIPS} -eq 1 ]; then
    ( ${OLD_ENV} ${1}/fcrypt -r ${PW} text.txt && \
	! ${FMIGRATE} ${PW} text.enc && ! is_new_format text.enc && \
	${FMIGRATE} --no-fips ${PW} text.enc && is_new_format text.enc && \
	${FDECRYPT} ${PW} text.enc && cmp text.txt orig/text.txt ) &>> ${logFILE}
    result "FIPS mode: fmigrate needs --no-fips, the new file decrypts in FIPS mode" $?
elif ${FDECRYPT} --version 2>&1 | grep -q "FIPS mode not available"; then
    echo "Skipping the FIPS test, this build uses OpenSSL before 3.0" | tee -a ${logFILE}
else
    ( ${OLD_ENV} ${1}/fcrypt -r ${PW} text.txt && \
	! FCRYPT_FIPS=1 OPENSSL_MODULES=/nonexistent ${FMIGRATE} ${PW} text.enc && ! is_new_format text.enc && \
	FCRYPT_FIPS=1 ${FMIGRATE} --no-fips ${PW} text.enc && is_new_format text.enc ) &>> ${logFILE}
    result "FCRYPT_FIPS=1: fmigrate refuses without --no-fips" $?
fi

echo "" | tee -a ${logFILE}
echo "${passed} passed, ${failed} failed" | tee -a ${logFILE}
echo "Logged output to: ${logFILE}"
if [ ${failed} -ne 0 ]; then exit 1; fi
exit 0
