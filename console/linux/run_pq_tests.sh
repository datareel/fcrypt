#!/bin/bash
# 11/18/2026: Tests for the quantum-resistant (hybrid) users of release
# 2026.110: an RSA key or smart card plus an ML-KEM-1024 key (NIST FIPS
# 203) wrap the file key, and both are needed to open the file.
#
# Usage: ./run_pq_tests.sh [old_build_dir ...]
#   old_build_dir  console/linux directories with 2026.102 or later builds
#                  (2026.102, 2026.106, 2026.108, 2026.109): each must still
#                  decrypt a file with hybrid users with the password, list
#                  its users, refuse a hybrid user, and not drop or damage the
#                  hybrid slots when it changes the file.
#   SC_MODULE, SC_PIN, SC_CERT, SC_ID  (optional) a SoftHSM2 token, as for
#                  run_smartcard_tests.sh, to test a smart card hybrid user.
#                  Only a SoftHSM2 token: never a real card.
#
# Run after building fcrypt, fdecrypt and fmigrate with make. Needs
# OpenSSL 3.5 or later (ML-KEM-1024).

NEW_DIR=$(cd $(dirname $0) && pwd)
FC=${NEW_DIR}/fcrypt
FD=${NEW_DIR}/fdecrypt
testDIR=${HOME}/tmp/fcrypt_pq_testing_$(date +%Y_%m_%d_%H%M%S)
logFILE=${testDIR}/fcrypt_pq_testing.log
passed=0
failed=0

for p in ${FC} ${FD}; do
    if [ ! -f ${p} ]; then
	echo "ERROR: Missing ${p}, run make first"
	exit 1
    fi
done
OLD_DIRS=""
for d in "$@"; do
    d=$(cd "$d" 2>/dev/null && pwd)
    if [ -z "$d" ] || [ ! -x "$d/fcrypt" ] || [ ! -x "$d/fdecrypt" ]; then
	echo "ERROR: $1 has no fcrypt and fdecrypt build"
	exit 1
    fi
    OLD_DIRS="${OLD_DIRS} $d"
done
mkdir -p ${testDIR}
cd ${testDIR}

pass() { echo "Passed: $1" | tee -a ${logFILE}; passed=$((passed+1)); }
fail() { echo "FAILED: $1" | tee -a ${logFILE}; failed=$((failed+1)); }
check() { if [ "$1" -eq 0 ]; then pass "$2"; else fail "$2"; fi; }
sum() { sha256sum $1 | cut -d' ' -f1; }

${FC} --version >> ${logFILE} 2>&1
printf 'Known-Pass#2026\n' > pw.txt; chmod 600 pw.txt
printf 'Alice-PQ-2026\n' > a_pp.txt; chmod 600 a_pp.txt
printf 'Bob-PQ-2026xx\n' > b_pp.txt; chmod 600 b_pp.txt
for u in alice bob carol; do
    openssl genrsa -out ${u}.pem 3072 >/dev/null 2>&1
    openssl rsa -in ${u}.pem -pubout -out ${u}.pub >/dev/null 2>&1
    chmod 600 ${u}.pem
done
head -c 300000 /dev/urandom > data.bin
A="--password-file=pw.txt --non-interactive"
newfile() { # name [static data size]
    rm -f $1.enc
    cp data.bin $1.bin
    ${FC} ${A} ${2:+--static-data-size=$2} --outfile=$1.enc $1.bin >>${logFILE} 2>&1
}
addh() { # file user pq_public_key
    ${FC} ${A} --add-rsa-key=$2.pub --rsa-key-username=$2 --add-pq-public-key=$3 $1 >>${logFILE} 2>&1
}
openh() { # file user pq_key pq_passphrase_file fdecrypt
    ${5} --rsa-key=$2.pem --rsa-key-username=$2 --pq-key=$3 --pq-key-passphrase-file=$4 --non-interactive --stdout $1 2>>${logFILE} | cmp -s - data.bin
}

# ---- A build without ML-KEM (the RHEL 8 FIPS build on the system OpenSSL 1.1.1) ----
if ${FC} --version 2>&1 | grep -q "no ML-KEM hybrid users"; then
    ${FC} --generate-pq-key=nokem_pq --pq-key-passphrase-file=a_pp.txt > out.txt 2>&1
    [ $? -ne 0 ] && grep -q "ML-KEM" out.txt && [ ! -f nokem_pq ]
    check $? "a build without ML-KEM refuses --generate-pq-key with a clear message"
    newfile nk
    ${FC} ${A} --add-rsa-key=alice.pub --rsa-key-username=alice --add-pq-public-key=nokem.pub.pem nk.enc > out.txt 2>&1
    [ $? -ne 0 ] && grep -q "ML-KEM" out.txt
    check $? "a build without ML-KEM refuses --add-pq-public-key with a clear message"
    ${FC} ${A} --add-rsa-key=alice.pub --rsa-key-username=alice nk.enc >>${logFILE} 2>&1 && \
      ${FD} --rsa-key=alice.pem --rsa-key-username=alice --non-interactive --stdout nk.enc 2>>${logFILE} | cmp -s - data.bin
    check $? "a build without ML-KEM still adds and opens RSA users"
    echo "" | tee -a ${logFILE}
    echo "This build has no ML-KEM: run run_pq_tests.sh of an OpenSSL 3.5 build with this build's directory" | tee -a ${logFILE}
    echo "as an old_build_dir to test that it reads files with hybrid users." | tee -a ${logFILE}
    echo "${passed} passed, ${failed} failed" | tee -a ${logFILE}
    [ ${failed} -ne 0 ] && exit 1
    exit 0
fi

# ---- ML-KEM-1024 keys ----
${FC} --generate-pq-key=alice_pq --pq-key-passphrase-file=a_pp.txt >>${logFILE} 2>&1
[ $? -eq 0 ] && [ -f alice_pq ] && [ -f alice_pq.pub.pem ] && [ "$(stat -c %a alice_pq)" = "600" ]
check $? "--generate-pq-key writes the private key (mode 600) and file.pub.pem"
grep -q "ENCRYPTED PRIVATE KEY" alice_pq && ! grep -q "BEGIN PRIVATE KEY" alice_pq
check $? "the ML-KEM private key file is encrypted with the passphrase"
if openssl version 2>/dev/null | grep -q "^OpenSSL 3\.[5-9]\|^OpenSSL [4-9]"; then
    openssl pkey -pubin -in alice_pq.pub.pem -noout -text 2>/dev/null | grep -q "ML-KEM-1024"
else # RHEL 8: the openssl command is 1.1.1k, the OS OpenSSL 3.5 has no command
    grep -q "BEGIN PUBLIC KEY" alice_pq.pub.pem && [ $(stat -c %s alice_pq.pub.pem) -gt 2100 ]
fi
check $? "the public key file holds an ML-KEM-1024 key"
${FC} --generate-pq-key=bob_pq --pq-key-passphrase-file=b_pp.txt >>${logFILE} 2>&1
${FC} --generate-pq-key=alice_pq --pq-key-passphrase-file=a_pp.txt >>${logFILE} 2>&1
[ $? -ne 0 ]
check $? "--generate-pq-key refuses to overwrite an existing key"
${FC} --generate-pq-key=nopass_pq --non-interactive >>${logFILE} 2>&1
[ $? -ne 0 ] && [ ! -f nopass_pq ]
check $? "--generate-pq-key --non-interactive without a passphrase writes nothing"

# ---- Hybrid RSA users ----
newfile h1
addh h1.enc alice alice_pq.pub.pem
check $? "add an RSA + ML-KEM-1024 (hybrid) user"
openh h1.enc alice alice_pq a_pp.txt ${FD}
check $? "the hybrid user opens the file with the RSA key and the ML-KEM key"
${FD} ${A} --stdout h1.enc 2>>${logFILE} | cmp -s - data.bin
check $? "the password still opens the file"
${FD} --rsa-key=alice.pem --rsa-key-username=alice --non-interactive --stdout h1.enc >/dev/null 2>err.txt
[ $? -eq 2 ] && grep -q -- "--pq-key" err.txt
check $? "the RSA key alone does not open a hybrid user (exit 2, names --pq-key)"
openh h1.enc alice bob_pq b_pp.txt ${FD}
[ $? -ne 0 ]
check $? "the RSA key with another user's ML-KEM key does not open the file"
openh h1.enc bob alice_pq a_pp.txt ${FD}
[ $? -ne 0 ]
check $? "another RSA key with the right ML-KEM key does not open the file"
${FD} --rsa-key=alice.pem --rsa-key-username=alice --pq-key=alice_pq --pq-key-passphrase-file=b_pp.txt --non-interactive --stdout h1.enc >/dev/null 2>&1
[ $? -eq 2 ]
check $? "a wrong ML-KEM key passphrase exits 2"
chmod 644 alice_pq
${FD} --rsa-key=alice.pem --rsa-key-username=alice --pq-key=alice_pq --pq-key-passphrase-file=a_pp.txt --non-interactive --stdout h1.enc >/dev/null 2>err.txt
rv=$?
chmod 600 alice_pq
[ ${rv} -ne 0 ] && grep -q "chmod 600" err.txt
check $? "an ML-KEM private key file other users can read is refused"
${FD} --list-users h1.enc > out.txt 2>&1
grep -q "Username: alice Access: RSA key + ML-KEM-1024" out.txt && [ $(grep -c "Username:" out.txt) -eq 1 ]
check $? "--list-users shows one hybrid user (the part slots are not listed)"
${FD} --list-users --json h1.enc > out.txt 2>&1
grep -q '"quantum_resistant": true' out.txt
check $? "--list-users --json marks the hybrid user quantum_resistant"
addh h1.enc alice alice_pq.pub.pem
[ $? -ne 0 ]
check $? "a user cannot be added twice"
${FC} ${A} --add-rsa-key=alice.pub --rsa-key-username=alice h1.enc >>${logFILE} 2>&1
[ $? -ne 0 ]
check $? "a hybrid user cannot also get an RSA-only slot"
${FC} ${A} --require-pq --add-rsa-key=bob.pub --rsa-key-username=bob h1.enc > out.txt 2>&1
[ $? -ne 0 ] && grep -q "require-pq" out.txt
check $? "--require-pq refuses an RSA-only user"

# ---- Key management ----
newfile k1
addh k1.enc alice alice_pq.pub.pem
${FC} ${A} --add-rsa-key=bob.pub --rsa-key-username=bob k1.enc >>${logFILE} 2>&1
printf 'rsa:alice=alice.pub\nrsa:bob=bob.pub\n' | ${FC} ${A} --rekey k1.enc > out.txt 2>&1
[ $? -ne 0 ] && grep -q "hybrid user" out.txt
check $? "a rekey without pq= for a hybrid user is refused (no silent downgrade)"
printf 'rsa:alice=alice.pub\nrsa:bob=bob.pub\n' | ${FC} ${A} --require-pq --rekey k1.enc >/dev/null 2>&1
[ $? -ne 0 ]
check $? "--require-pq refuses a rekey that keeps an RSA-only user"
printf 'rsa:alice=alice.pub,pq=alice_pq.pub.pem\nrsa:bob=bob.pub,pq=bob_pq.pub.pem\n' | ${FC} ${A} --rekey k1.enc >>${logFILE} 2>&1
[ $? -eq 0 ] && openh k1.enc alice alice_pq a_pp.txt ${FD} && openh k1.enc bob bob_pq b_pp.txt ${FD}
check $? "a rekey moves an RSA user to a hybrid user and keeps the other"
${FD} --list-users k1.enc 2>/dev/null | grep -c "RSA key + ML-KEM-1024" | grep -q "^2$"
check $? "after the rekey both users are hybrid"
before=$(sum k1.enc)
${FC} ${A} --remove-user=bob --dry-run k1.enc >>${logFILE} 2>&1
[ $? -eq 0 ] && [ "$(sum k1.enc)" = "${before}" ]
check $? "--remove-user --dry-run of a hybrid user changes nothing"
${FC} --rsa-key=alice.pem --rsa-key-username=alice --pq-key=alice_pq --pq-key-passphrase-file=a_pp.txt --non-interactive --remove-user=bob k1.enc >>${logFILE} 2>&1
[ $? -eq 0 ] && ! openh k1.enc bob bob_pq b_pp.txt ${FD} && openh k1.enc alice alice_pq a_pp.txt ${FD}
check $? "a hybrid user authenticates --remove-user of another hybrid user"
${FD} --list-users --json k1.enc 2>/dev/null | grep -q '"bob"'
[ $? -ne 0 ]
check $? "the removed hybrid user is gone from the list"
${FC} --rsa-key=alice.pem --rsa-key-username=alice --non-interactive --remove-user=alice k1.enc >/dev/null 2>&1
[ $? -eq 2 ]
check $? "key management as a hybrid user without --pq-key exits 2"

# ---- Space ----
newfile s1 4096
addh s1.enc alice alice_pq.pub.pem > out.txt 2>&1
before=$(sum s1.enc)
addh s1.enc bob bob_pq.pub.pem
rv=$?
${FC} ${A} --add-rsa-key=bob.pub --rsa-key-username=bob --add-pq-public-key=bob_pq.pub.pem s1.enc > out.txt 2>&1
[ ${rv} -ne 0 ] && grep -q "No space left in the key slot area" out.txt && [ "$(sum s1.enc)" = "${before}" ]
check $? "a key slot area too small for another hybrid user refuses it and leaves the file as it was"
newfile s2
for u in alice bob carol; do addh s2.enc ${u} $([ ${u} = bob ] && echo bob_pq.pub.pem || echo alice_pq.pub.pem); done
openh s2.enc carol alice_pq a_pp.txt ${FD}
check $? "three hybrid users fit the default key slot area"

# ---- FIPS mode ----
if FCRYPT_FIPS=1 ${FC} --version 2>/dev/null | grep -q "FIPS mode on"; then
    FCRYPT_FIPS=1 ${FD} ${A} --stdout h1.enc 2>>${logFILE} | cmp -s - data.bin
    check $? "FIPS mode: the password opens a file with hybrid users"
    if FCRYPT_FIPS=1 ${FC} --generate-pq-key=fips_pq --pq-key-passphrase-file=a_pp.txt >>${logFILE} 2>&1; then
	FCRYPT_FIPS=1 ${FD} --rsa-key=alice.pem --rsa-key-username=alice --pq-key=alice_pq --pq-key-passphrase-file=a_pp.txt --non-interactive --stdout h1.enc 2>>${logFILE} | cmp -s - data.bin
	check $? "FIPS mode: the hybrid user opens the file"
    else
	FCRYPT_FIPS=1 ${FD} --rsa-key=alice.pem --rsa-key-username=alice --pq-key=alice_pq --pq-key-passphrase-file=a_pp.txt --non-interactive --stdout h1.enc >/dev/null 2>err.txt
	[ $? -ne 0 ] && grep -q "ML-KEM" err.txt
	check $? "FIPS mode without ML-KEM in the FIPS provider: a clear error for the hybrid user"
    fi
fi

# ---- Smart card hybrid user (SoftHSM2 only) ----
if [ -n "${SC_MODULE}" ] && [ -n "${SC_PIN}" ] && [ -n "${SC_CERT}" ]; then
    if ! echo "${SC_MODULE}" | grep -qi softhsm; then
	fail "SC_MODULE is not a SoftHSM2 module, the smart card hybrid tests only use SoftHSM2"
    else
	printf '%s\n' "${SC_PIN}" > pin.txt; chmod 600 pin.txt
	SCA="--smartcard-provider=${SC_MODULE} --smartcard-cert-id=${SC_ID:-01}"
	newfile c1
	${FC} ${A} --add-smartcard-cert --smartcard-username=card ${SCA} --add-pq-public-key=alice_pq.pub.pem c1.enc >>${logFILE} 2>&1
	check $? "add a smart card + ML-KEM-1024 (hybrid) user from the card (no PIN)"
	${FD} --smartcard-cert --smartcard-username=card ${SCA} --smartcard-pin-file=pin.txt --pq-key=alice_pq --pq-key-passphrase-file=a_pp.txt --non-interactive --stdout c1.enc 2>>${logFILE} | cmp -s - data.bin
	check $? "the card and the ML-KEM key open the file"
	${FD} --smartcard-cert --smartcard-username=card ${SCA} --smartcard-pin-file=pin.txt --non-interactive --stdout c1.enc >/dev/null 2>err.txt
	[ $? -eq 2 ] && grep -q -- "--pq-key" err.txt
	check $? "the card alone does not open a hybrid card user (no card login)"
	newfile c2
	cp ${SC_CERT} card_cert.pem
	${FC} ${A} --add-smartcard-cert-file=card_cert.pem --smartcard-username=card --add-pq-public-key=alice_pq.pub.pem c2.enc >>${logFILE} 2>&1
	${FD} --smartcard-cert --smartcard-username=card ${SCA} --smartcard-pin-file=pin.txt --pq-key=alice_pq --pq-key-passphrase-file=a_pp.txt --non-interactive --stdout c2.enc 2>>${logFILE} | cmp -s - data.bin
	check $? "a hybrid card user added from the exported cert file opens the file"
	printf 'smartcard:card=card_cert.pem,pq=bob_pq.pub.pem\n' | ${FC} ${A} --rekey c2.enc >>${logFILE} 2>&1
	${FD} --smartcard-cert --smartcard-username=card ${SCA} --smartcard-pin-file=pin.txt --pq-key=bob_pq --pq-key-passphrase-file=b_pp.txt --non-interactive --stdout c2.enc 2>>${logFILE} | cmp -s - data.bin
	check $? "a rekey gives the hybrid card user a new ML-KEM key"
    fi
fi

# ---- Older releases (2026.102 and later) ----
for d in ${OLD_DIRS}; do
    v=$(${d}/fcrypt --version 2>/dev/null | grep -o "version 20[0-9.]*" | head -1)
    # 2026.102 to 2026.105 have no --password-file or --non-interactive
    if ${d}/fdecrypt --help 2>&1 | grep -q -- "--password-file"; then OA="${A}"; ONI="--non-interactive"
    else OA="--password=Known-Pass#2026"; ONI=""; fi
    newfile o1
    addh o1.enc alice alice_pq.pub.pem
    ${FC} ${A} --add-rsa-key=bob.pub --rsa-key-username=bob o1.enc >>${logFILE} 2>&1
    ${d}/fdecrypt ${OA} --stdout o1.enc 2>>${logFILE} | cmp -s - data.bin
    check $? "${v}: decrypts a file with a hybrid user with the password"
    ${d}/fdecrypt --rsa-key=bob.pem --rsa-key-username=bob ${ONI} --stdout o1.enc 2>>${logFILE} | cmp -s - data.bin
    check $? "${v}: an RSA-only user next to a hybrid user still opens the file"
    ${d}/fdecrypt --list-users o1.enc > out.txt 2>&1
    [ $? -eq 0 ] && grep -q "Username: bob" out.txt
    check $? "${v}: --list-users works on a file with a hybrid user"
    ${d}/fdecrypt --rsa-key=alice.pem --rsa-key-username=alice ${ONI} --stdout o1.enc >/dev/null 2>&1
    [ $? -ne 0 ]
    check $? "${v}: refuses to open as the hybrid user"
    ${d}/fcrypt ${OA} --add-rsa-key=carol.pub --rsa-key-username=carol o1.enc >>${logFILE} 2>&1
    openh o1.enc alice alice_pq a_pp.txt ${FD} && ${FD} --rsa-key=carol.pem --rsa-key-username=carol --non-interactive --stdout o1.enc 2>>${logFILE} | cmp -s - data.bin
    check $? "${v}: adding an RSA user keeps the hybrid user working"
    if ${d}/fcrypt --help 2>&1 | grep -q -- "--remove-user"; then
	${d}/fcrypt ${OA} --remove-user=bob o1.enc >>${logFILE} 2>&1
	openh o1.enc alice alice_pq a_pp.txt ${FD}
	check $? "${v}: --remove-user of another user keeps the hybrid user working"
	before=$(sum o1.enc)
	printf 'rsa:carol=carol.pub\n' | ${d}/fcrypt ${OA} --rekey o1.enc >>${logFILE} 2>&1
	rv=$?
	if [ ${rv} -eq 0 ]; then
	    openh o1.enc alice alice_pq a_pp.txt ${FD}
	    check $? "${v}: a rekey keeps the hybrid user working"
	else
	    [ "$(sum o1.enc)" = "${before}" ]
	    check $? "${v}: a rekey it cannot complete leaves the file as it was (no silent drop of the hybrid user)"
	fi
    fi
done

echo "" | tee -a ${logFILE}
echo "${passed} passed, ${failed} failed" | tee -a ${logFILE}
echo "Logged output to: ${logFILE}"
if [ ${failed} -ne 0 ]; then exit 1; fi
exit 0
