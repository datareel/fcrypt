#!/bin/bash
# 10/27/2026: Tests for fcrypt key management: --remove-user, --rekey,
# secrets from file descriptors and files, the access log, the version
# check and the automation options.
#
# Usage: ./run_keymgmt_tests.sh
#   COMPAT_DIR=dir  a console/linux directory with a 2026.105 build, to
#                   check it decrypts files changed by this build
#   LEGACY_DIR=dir  a console/linux directory with a 2025.104 or older
#                   fcrypt, to make a v1 file for the version check
#
# Run after building fcrypt, fdecrypt and fmigrate with make.

NEW_DIR=$(cd $(dirname $0) && pwd)
FC=${NEW_DIR}/fcrypt
FD=${NEW_DIR}/fdecrypt
FM=${NEW_DIR}/fmigrate
testDIR=${HOME}/tmp/fcrypt_keymgmt_testing_$(date +%Y_%m_%d_%H%M%S)
logFILE=${testDIR}/fcrypt_keymgmt_testing.log
PW='Known-Pass#2026'
passed=0
failed=0

for p in ${FC} ${FD} ${FM}; do
    if [ ! -f ${p} ]; then
	echo "ERROR: Missing ${p}, run make first"
	exit 1
    fi
done
mkdir -p ${testDIR}
cd ${testDIR}

pass() { echo "Passed: $1" | tee -a ${logFILE}; passed=$((passed+1)); }
fail() { echo "FAILED: $1" | tee -a ${logFILE}; failed=$((failed+1)); }
check() { if [ "$1" -eq 0 ]; then pass "$2"; else fail "$2"; fi; }
sum() { sha256sum $1 | cut -d' ' -f1; }

printf '%s\n' "${PW}" > pw.txt; chmod 600 pw.txt
printf 'Wrong-Pass#2026\n' > bad.txt; chmod 600 bad.txt
for u in alice bob; do
    openssl genrsa -out ${u}.pem 2048 >/dev/null 2>&1
    openssl rsa -in ${u}.pem -pubout -out ${u}.pub >/dev/null 2>&1
    chmod 600 ${u}.pem
done
openssl genrsa -aes256 -passout pass:Phrase-2026 -out carol.pem 2048 >/dev/null 2>&1
openssl rsa -in carol.pem -passin pass:Phrase-2026 -pubout -out carol.pub >/dev/null 2>&1
chmod 600 carol.pem
printf 'Phrase-2026\n' > carol_pass.txt; chmod 600 carol_pass.txt
head -c 300000 /dev/urandom > data.bin
A="--password-file=pw.txt --non-interactive"

newfile() {
    rm -f $1.enc
    cp data.bin $1.bin
    ${FC} --password-file=pw.txt --outfile=$1.enc $1.bin >>${logFILE} 2>&1
    for u in $2; do
	${FC} --password-file=pw.txt --add-rsa-key=${u}.pub --rsa-key-username=${u} $1.enc >>${logFILE} 2>&1
    done
}
opens() { # file key user
    ${FD} --rsa-key=$2.pem --rsa-key-username=$3 --non-interactive --stdout $1 2>/dev/null | cmp -s - data.bin
}

# ---- Secrets from file descriptors, files and stdin ----
newfile s1 "carol"
${FD} --password-fd=3 --stdout s1.enc 3<pw.txt 2>>${logFILE} | cmp -s - data.bin
check $? "fdecrypt --password-fd"
${FD} --password-file=pw.txt --stdout s1.enc 2>>${logFILE} | cmp -s - data.bin
check $? "fdecrypt --password-file"
printf '%s\n' "${PW}" | ${FD} --password-fd=0 --stdout s1.enc 2>>${logFILE} | cmp -s - data.bin
check $? "fdecrypt --password-fd=0 reads stdin"
${FD} --rsa-key=carol.pem --rsa-key-username=carol --rsa-key-passphrase-fd=4 --stdout s1.enc 4<carol_pass.txt 2>>${logFILE} | cmp -s - data.bin
check $? "fdecrypt --rsa-key-passphrase-fd"
${FD} --rsa-key=carol.pem --rsa-key-username=carol --rsa-key-passphrase-file=carol_pass.txt --stdout s1.enc 2>>${logFILE} | cmp -s - data.bin
check $? "fdecrypt --rsa-key-passphrase-file"
chmod 644 carol_pass.txt
${FD} --rsa-key=carol.pem --rsa-key-username=carol --rsa-key-passphrase-file=carol_pass.txt --stdout s1.enc >/dev/null 2>err.txt
[ $? -ne 0 ] && grep -q "chmod 600" err.txt
check $? "a passphrase file other users can read is refused"
chmod 600 carol_pass.txt
${FD} --rsa-key=carol.pem --rsa-key-username=carol --non-interactive --stdout s1.enc >/dev/null 2>err.txt
[ $? -eq 1 ] && grep -q "non-interactive" err.txt
check $? "--non-interactive refuses to prompt for the passphrase"
( ${FD} --rsa-key=carol.pem --rsa-key-username=carol --rsa-key-passphrase=Phrase-2026 --stdout s1.enc > /dev/null 2>err_argv.txt & pid=$!; sleep 0.3; tr '\0' ' ' < /proc/${pid}/cmdline > cmdline.txt 2>/dev/null; wait ${pid} )
! grep -q "Phrase-2026" cmdline.txt && grep -q "WARNING" err_argv.txt
check $? "--rsa-key-passphrase= is wiped from argv and warns"
mkdir -p mig; cp s1.enc mig/
(cd mig && ${FM} --rsa-key=../carol.pem --rsa-key-username=carol --rsa-key-passphrase-file=../carol_pass.txt --check s1.enc >>${logFILE} 2>&1)
check $? "fmigrate --rsa-key-passphrase-file"

# ---- Remove user ----
newfile r1 "alice bob"
before=$(sum r1.enc)
${FC} ${A} --remove-user=bob --dry-run r1.enc >>${logFILE} 2>&1
[ $? -eq 0 ] && [ "$(sum r1.enc)" = "${before}" ]
check $? "--remove-user --dry-run changes nothing"
${FC} ${A} --remove-user=bob r1.enc > out.txt 2>&1
[ $? -eq 0 ] && grep -q "does not revoke" out.txt && grep -q -- "--rekey" out.txt
check $? "remove an RSA user, with the note about revoking and --rekey"
! opens r1.enc bob bob && opens r1.enc alice alice
check $? "the removed user cannot decrypt, the other user can"
b=$(ls r1.backup-*.enc 2>/dev/null | head -1)
[ -n "${b}" ] && opens ${b} bob bob
check $? "the backup copy keeps the original (the removed user still opens it)"
${FC} ${A} --remove-user=nobody r1.enc >>${logFILE} 2>&1
[ $? -eq 3 ]
check $? "removing an unknown user exits 3"
${FD} --list-users --json r1.enc | python3 -I -m json.tool >/dev/null
check $? "fdecrypt --list-users --json is valid JSON"
printf 'rsa:alice=alice.pub\ndrop-password=yes\n' | ${FC} ${A} --rekey r1.enc >>${logFILE} 2>&1
${FC} --rsa-key=alice.pem --rsa-key-username=alice --non-interactive --remove-user=alice r1.enc > out.txt 2>&1
[ $? -ne 0 ] && grep -q "last key slot" out.txt && opens r1.enc alice alice
check $? "the last key slot cannot be removed"

# ---- Rekey ----
newfile k1 "alice bob"
before=$(sum k1.enc)
${FC} ${A} --rekey k1.enc </dev/null > out.txt 2>&1
[ $? -ne 0 ] && grep -q "rsa:alice=" out.txt && grep -q "rsa:bob=" out.txt && [ "$(sum k1.enc)" = "${before}" ]
check $? "rekey without public keys lists the missing slots and changes nothing"
printf 'rsa:alice=alice.pub\nrsa:bob=bob.pub\n' | ${FC} ${A} --rekey --dry-run k1.enc >>${logFILE} 2>&1
[ $? -eq 0 ] && [ "$(sum k1.enc)" = "${before}" ]
check $? "--rekey --dry-run changes nothing"
cp k1.enc k1_before.enc
${FC} ${A} --remove-user=bob k1.enc >>${logFILE} 2>&1
printf 'rsa:alice=alice.pub\n' | ${FC} ${A} --rekey k1.enc >>${logFILE} 2>&1
check $? "rekey keeping the password and the RSA user"
opens k1.enc alice alice && ${FD} ${A} --stdout k1.enc 2>/dev/null | cmp -s - data.bin && ! opens k1.enc bob bob
check $? "after remove and rekey: password and alice open, bob does not"
# Bob's slot from before, spliced into the rekeyed header, must not work
python3 -I - <<'PYEOF'
import struct
old=open('k1_before.enc','rb').read(); new=bytearray(open('k1.enc','rb').read())
area=struct.unpack('<I',new[36:40])[0]
new[128:128+area]=old[128:128+area]
open('k1_splice.enc','wb').write(new)
PYEOF
! opens k1_splice.enc bob bob
check $? "an old key slot of the removed user does not open the rekeyed file"
printf 'new-password=Another-Pass#77\nrsa:alice=alice.pub\n' | ${FC} ${A} --rekey k1.enc >>${logFILE} 2>&1
printf 'Another-Pass#77\n' > pw2.txt; chmod 600 pw2.txt
${FD} --password-file=pw2.txt --stdout k1.enc 2>/dev/null | cmp -s - data.bin && ! ${FD} ${A} --stdout k1.enc >/dev/null 2>&1
check $? "rekey with new-password: the new password opens, the old one does not"
rm -f gen.txt
printf 'rsa:alice=alice.pub\n' | ${FC} --password-file=pw2.txt --non-interactive --rekey --rekey-new-password-file=gen.txt k1.enc > out.txt 2>&1
${FD} --password-file=gen.txt --stdout k1.enc 2>/dev/null | cmp -s - data.bin && [ $(stat -c %a gen.txt) = "600" ] && ! grep -q "$(cat gen.txt)" out.txt
check $? "a generated password is written only to --rekey-new-password-file and opens the file"
printf 'drop-rsa:alice=yes\ndrop-password=yes\n' | ${FC} --password-file=gen.txt --non-interactive --rekey k1.enc >>${logFILE} 2>&1
[ $? -ne 0 ] && opens k1.enc alice alice
check $? "a rekey that would leave no key slot is refused"
printf 'password=%s\nrsa:alice=alice.pub\n' "$(cat gen.txt)" > rk.txt; chmod 600 rk.txt
${FC} --rsa-key=alice.pem --rsa-key-username=alice --non-interactive --rekey --rekey-file=rk.txt k1.enc >>${logFILE} 2>&1
check $? "rekey authenticated with an RSA key, the password slot kept with password= from --rekey-file"
${FD} --password-file=gen.txt --stdout k1.enc 2>/dev/null | cmp -s - data.bin
check $? "the password slot still opens after that rekey"
newfile x1 ""
before=$(sum x1.enc)
FCRYPT_TEST_CRASH_BEFORE_RENAME=1 ${FC} ${A} --rekey x1.enc </dev/null >>${logFILE} 2>&1
rv=$?
[ ${rv} -eq 137 ] && [ "$(sum x1.enc)" = "${before}" ] && ${FD} ${A} --stdout x1.enc 2>/dev/null | cmp -s - data.bin
check $? "a rekey killed before the rename leaves the original file working (rc=${rv})"
rm -f x1.enc.rekey.tmp

# ---- Access log ----
newfile l1 "alice"
LOG=${testDIR}/access.log
${FC} ${A} --access-log=${LOG} --remove-user=alice l1.enc >>${logFILE} 2>&1
${FD} --password-file=bad.txt --non-interactive --access-log=${LOG} --stdout l1.enc >/dev/null 2>&1
${FD} ${A} --access-log=${LOG} --stdout l1.enc >/dev/null 2>&1
${FC} ${A} --access-log=${LOG} --rekey l1.enc </dev/null >>${logFILE} 2>&1
${FD} ${A} --access-log=${LOG} --verify-access-log l1.enc > out.txt 2>&1
[ $? -eq 0 ] && grep -q "OK" out.txt
check $? "the access log verifies after remove-user, a failed open and a rekey"
grep -q "action=remove-user" ${LOG} && grep -q "result=fail" ${LOG} && grep -q "action=rekey" ${LOG}
check $? "the log has the remove, the failed open and the rekey"
! grep -q -e "${PW}" -e "Wrong-Pass" ${LOG} && [ $(stat -c %a ${LOG}) = "600" ]
check $? "the log holds no password and is mode 600"
cp ${LOG} log_orig.txt
sed -i '3s/pid=/pid=9/' ${LOG}
${FD} ${A} --access-log=${LOG} --verify-access-log l1.enc > out.txt 2>&1
[ $? -ne 0 ] && grep -q "TAMPERED" out.txt
check $? "--verify-access-log catches an edited line"
cp log_orig.txt ${LOG}
HOME_SAVE=${HOME}; export HOME=${testDIR}/home; mkdir -p ${HOME}
${FD} ${A} --access-log --stdout l1.enc >/dev/null 2>&1
[ -f ${HOME}/.fcrypt/logs/access.log ] && [ $(stat -c %a ${HOME}/.fcrypt/logs) = "700" ]
check $? "the default log is ~/.fcrypt/logs/access.log in a mode 700 directory"
export HOME=${HOME_SAVE}

# ---- Version check ----
${FD} --check-version s1.enc > out.txt 2>&1
[ $? -eq 0 ] && grep -q "v2" out.txt
check $? "--check-version reports v2 and exits 0"
${FD} --check-version pw.txt >/dev/null 2>&1
[ $? -eq 7 ]
check $? "--check-version of a file that is not encrypted exits 7"
${FD} --check-version --json s1.enc pw.txt | python3 -I -m json.tool >/dev/null
check $? "--check-version --json is valid JSON"
if [ "${LEGACY_DIR}" != "" ]; then
    cp data.bin v1.bin
    ${LEGACY_DIR}/fcrypt --password="${PW}" v1.bin >>${logFILE} 2>&1
    ${FD} --check-version s1.enc v1.enc > out.txt 2>&1
    [ $? -eq 5 ] && grep -q "v1.enc: v1" out.txt && grep -q "fmigrate" out.txt
    check $? "--check-version reports a v1 file, names fmigrate and exits 5"
    ${FD} ${A} --stdout v1.enc 2>err.txt | cmp -s - data.bin && grep -q "WARNING: v1.enc uses fcrypt v1" err.txt
    check $? "decrypting a v1 file warns on stderr and names fmigrate"
    ${FC} ${A} --remove-user=x v1.enc > out.txt 2>&1
    [ $? -ne 0 ] && grep -q "fmigrate" out.txt
    check $? "--remove-user refuses a v1 file and points to fmigrate"
fi

# ---- Exit codes and locking ----
${FD} --password-file=bad.txt --non-interactive --stdout s1.enc >/dev/null 2>&1
[ $? -eq 2 ]
check $? "fdecrypt with the wrong password exits 2"
${FD} ${A} --stdout nosuch.enc >/dev/null 2>&1
[ $? -eq 3 ]
check $? "fdecrypt of a missing file exits 3"
${FC} --password-file=bad.txt --non-interactive --remove-user=alice s1.enc >/dev/null 2>&1
[ $? -eq 2 ]
check $? "fcrypt --remove-user with the wrong password exits 2"
newfile lk "alice"
( flock -x 9; sleep 4 ) 9>lk.enc.lock &
sleep 0.5
${FC} ${A} --lock-timeout=1 --remove-user=alice lk.enc >>${logFILE} 2>&1
[ $? -eq 4 ]
check $? "a held lock makes fcrypt --remove-user exit 4"
wait

# ---- KMS style pipe, with a local stand-in ----
fake_kms() { printf '%s' "${PW}" | base64; }
fake_kms | base64 -d | ${FD} --password-fd=0 --non-interactive --stdout s1.enc 2>/dev/null | cmp -s - data.bin
check $? "a KMS style pipe (base64 -d into --password-fd=0) decrypts"

# ---- 2026.105 decrypts the files this build changed ----
if [ "${COMPAT_DIR}" != "" ]; then
    ${COMPAT_DIR}/fdecrypt --password="${PW}" --stdout r1.backup-*.enc 2>/dev/null | cmp -s - data.bin
    newfile c1 "alice bob"
    ${FC} ${A} --remove-user=bob c1.enc >>${logFILE} 2>&1
    ${COMPAT_DIR}/fdecrypt --password="${PW}" --stdout c1.enc 2>/dev/null | cmp -s - data.bin
    check $? "2026.105 fdecrypt decrypts a file after --remove-user"
    printf 'rsa:alice=alice.pub\n' | ${FC} ${A} --rekey c1.enc >>${logFILE} 2>&1
    ${COMPAT_DIR}/fdecrypt --password="${PW}" --stdout c1.enc 2>/dev/null | cmp -s - data.bin
    check $? "2026.105 fdecrypt decrypts a rekeyed file (key generation in the reserved header bytes)"
    ${COMPAT_DIR}/fdecrypt --rsa-key=alice.pem --rsa-key-username=alice --stdout c1.enc 2>/dev/null | cmp -s - data.bin
    check $? "2026.105 fdecrypt decrypts a rekeyed file with the kept RSA user"
    ${COMPAT_DIR}/fdecrypt --rsa-key=alice.pem --rsa-key-username=alice --stdout r1.enc 2>/dev/null | cmp -s - data.bin
    check $? "2026.105 fdecrypt decrypts a file with no password slot"
fi

echo "" | tee -a ${logFILE}
echo "${passed} passed, ${failed} failed" | tee -a ${logFILE}
echo "Logged output to: ${logFILE}"
if [ ${failed} -ne 0 ]; then exit 1; fi
exit 0
