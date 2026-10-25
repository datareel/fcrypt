#!/bin/bash
# Security regression tests for fcrypt and fdecrypt.
#
# Checks that fdecrypt rejects forged, modified and truncated files,
# never writes outside the output directory unless asked to, never
# overwrites files without -o, and leaves no output behind on failure.
#
# Usage: ./run_security_tests.sh [old_build_dir [2026.101_build_dir]]
#
# The 2026102 format tests always run. The old format tests need old
# build directories, since this build only writes the 2026102 format.
# The first old fdecrypt is also run on the forged file, to show the
# test reproduces the original problem, so use 2023.107 or older. The
# old format truncation and reordering tests need files from 2026.101,
# the first release that adds an integrity record to old format files.
#
# To run the tests in FIPS mode, set FCRYPT_FIPS=1, or point
# OPENSSL_CONF at a configuration that turns on FIPS mode. The old
# format tests then decrypt with --no-fips.

NEW_DIR=$(cd $(dirname $0) && pwd)
FCRYPT=${NEW_DIR}/fcrypt
FDECRYPT=${NEW_DIR}/fdecrypt
OLD_DIR=$1
OLD_DIR2=$2
OLD_ENV="env -u OPENSSL_CONF -u OPENSSL_MODULES -u FCRYPT_FIPS"
testDIR=${HOME}/tmp/fcrypt_security_testing_$(date +%Y_%m_%d_%H%M%S)
logFILE=${testDIR}/fcrypt_security_testing.log
PW=--password=security_test_password
passed=0
failed=0

if [ ! -f ${FCRYPT} ] || [ ! -f ${FDECRYPT} ]; then
    echo "ERROR: Missing binaries in ${NEW_DIR}"
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is needed to build the test files"
    exit 1
fi

mkdir -p ${testDIR}
cat /dev/null > ${logFILE}
cd ${testDIR}

# Old format files need --no-fips when this build runs in FIPS mode
LEGACY_FDECRYPT=${FDECRYPT}
if ${FDECRYPT} --version 2>&1 | grep -q "FIPS mode on"; then
    LEGACY_FDECRYPT="${FDECRYPT} --no-fips"
fi
if [ -n "${OLD_DIR}" ]; then
    OLD_DIR=$(cd ${OLD_DIR} && pwd)
    OLD_FCRYPT="${OLD_ENV} ${OLD_DIR}/fcrypt"
    OLD_FDECRYPT="${OLD_ENV} ${OLD_DIR}/fdecrypt"
fi
if [ -n "${OLD_DIR2}" ]; then
    OLD_DIR2=$(cd ${OLD_DIR2} && pwd)
    OLD_FCRYPT2="${OLD_ENV} ${OLD_DIR2}/fcrypt"
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
    caseDIR=${testDIR}/case_$1
    rm -rf ${caseDIR}
    mkdir -p ${caseDIR}
    cd ${caseDIR}
}

# File layout: static data header (276 bytes), static data area,
# encrypted file header (844 bytes), then data blocks of 844 bytes
# with a shorter last block.
cat > ${testDIR}/enctool.py <<'EOF'
import struct, sys

SD_HDR_LEN = 276
HDR_BLOCK = 844
DATA_BLOCK = 844

def split(path):
    d = open(path, 'rb').read()
    static_len = struct.unpack('<I', d[8:12])[0]
    start = SD_HDR_LEN + static_len + HDR_BLOCK
    head = d[:start]
    data = d[start:]
    blocks = [data[i:i+DATA_BLOCK] for i in range(0, len(data), DATA_BLOCK)]
    return head, blocks

def join(path, head, blocks):
    open(path, 'wb').write(head + b''.join(blocks))

cmd = sys.argv[1]
if cmd == 'forge':
    # A file with all-zero mode bytes in every block. Older fdecrypt
    # versions accepted it under any password.
    out, name, text = sys.argv[2], sys.argv[3].encode(), sys.argv[4].encode()
    static_len = 16384
    sd = struct.pack('<IIII', 2023103, 0xABAB, static_len, SD_HDR_LEN)
    sd += b'\0' * 256 + struct.pack('<I', 0xFEFE)
    hdr = struct.pack('<IIII', 2023103, 0xFEFE, 0, len(name)) + name.ljust(256, b'\0') + b'\0' * 32
    hdr = (b'\0' * 4 + hdr).ljust(HDR_BLOCK, b'\0')
    data = b'\0' * 4 + text
    open(out, 'wb').write(sd + b'\0' * static_len + hdr + data)
elif cmd == 'drop-last':
    head, blocks = split(sys.argv[2])
    join(sys.argv[2], head, blocks[:-1])
elif cmd == 'swap':
    head, blocks = split(sys.argv[2])
    blocks[0], blocks[1] = blocks[1], blocks[0]
    join(sys.argv[2], head, blocks)
elif cmd == 'splice':
    # Replace block 1 of the first file with block 1 of the second file
    head, blocks = split(sys.argv[2])
    head2, blocks2 = split(sys.argv[3])
    blocks[1] = blocks2[1]
    join(sys.argv[2], head, blocks)
elif cmd == 'append':
    head, blocks = split(sys.argv[2])
    head2, blocks2 = split(sys.argv[3])
    blocks.insert(len(blocks)-1, blocks2[0])
    join(sys.argv[2], head, blocks)
elif cmd == 'zero-mode-block':
    # Replace block 0 with an all-zero mode block holding plaintext
    head, blocks = split(sys.argv[2])
    blocks[0] = b'\0' * 4 + b'INJECTED WITHOUT KEY\n'.ljust(DATA_BLOCK - 4, b'X')
    join(sys.argv[2], head, blocks)
elif cmd == 'flip':
    d = bytearray(open(sys.argv[2], 'rb').read())
    pos = int(sys.argv[3])
    d[pos] ^= 0x01
    open(sys.argv[2], 'wb').write(bytes(d))
elif cmd == 'bad-username-len':
    # A static data block with a username length far past the area
    d = bytearray(open(sys.argv[2], 'rb').read())
    p = SD_HDR_LEN
    blk = struct.pack('<IIIIIII', 2023103, 0xFEFE, 1, 1, 300, 256, 6000) + b'\0' * 32
    d[p:p+len(blk)] = blk
    open(sys.argv[2], 'wb').write(bytes(d))
EOF
TOOL="python3 -I ${testDIR}/enctool.py"

# 2026102 format layout: 128 byte header, key slot area (length at
# offset 36), 32 byte header MAC, then records of a 4 byte length, a 16
# byte IV, the ciphertext and a 32 byte tag. Record 0 is the file name.
cat > ${testDIR}/newtool.py <<'EOF'
import struct, sys

def split(path):
    d = open(path, 'rb').read()
    slot_len = struct.unpack('<I', d[36:40])[0]
    start = 128 + slot_len + 32
    head = d[:start]
    recs = []
    p = start
    while p < len(d):
        n = struct.unpack('<I', d[p:p+4])[0]
        recs.append(d[p:p+4+16+n+32])
        p += 4 + 16 + n + 32
    return head, recs

def join(path, head, recs):
    open(path, 'wb').write(head + b''.join(recs))

cmd, path = sys.argv[1], sys.argv[2]
head, recs = split(path)
slot_len = struct.unpack('<I', head[36:40])[0]
if cmd == 'drop-last':
    recs = recs[:-1]
elif cmd == 'drop-data':
    recs = recs[:1]
elif cmd == 'swap':
    recs[1], recs[2] = recs[2], recs[1]
elif cmd == 'dup':
    recs.insert(2, recs[1])
elif cmd == 'append':
    recs.append(recs[1])
elif cmd == 'splice':
    # Record 1 from another file encrypted with the same password
    head2, recs2 = split(sys.argv[3])
    recs[1] = recs2[1]
elif cmd == 'swap-name':
    # The file name record from another file
    head2, recs2 = split(sys.argv[3])
    recs[0] = recs2[0]
elif cmd == 'header-from':
    # The header, key slots and header MAC from another file
    head2, recs2 = split(sys.argv[3])
    head = head2
elif cmd == 'slots-from':
    # The key slot area from another file, keeping this header MAC
    head2, recs2 = split(sys.argv[3])
    head = head[:128] + head2[128:128+slot_len] + head[128+slot_len:]
elif cmd == 'big-len':
    recs[1] = struct.pack('<I', 0xFFFFFFF0) + recs[1][4:]
elif cmd == 'truncate':
    recs[-1] = recs[-1][:-10]
elif cmd == 'remove-slot':
    # Clear every key slot after the first, removing a user without the key
    h = bytearray(head)
    first = struct.unpack('<I', h[132:136])[0]
    h[128+first:128+slot_len] = b'\0' * (slot_len - first)
    head = bytes(h)
elif cmd.startswith('flip-'):
    # flip-header:N flips byte N of the header area, flip-rec:N:M flips
    # byte M of record N
    what = cmd[5:].split(':')
    if what[0] == 'header':
        h = bytearray(head)
        h[int(what[1])] ^= 0x01
        head = bytes(h)
    else:
        r = bytearray(recs[int(what[1])])
        r[int(what[2])] ^= 0x01
        recs[int(what[1])] = bytes(r)
elif cmd == 'mac-offset':
    print(128 + slot_len)
    sys.exit(0)
join(path, head, recs)
EOF
NTOOL="python3 -I ${testDIR}/newtool.py"

echo "Starting tests at $(date)" | tee -a ${logFILE}
echo "$(${FDECRYPT} --version 2>&1 | grep "FIPS mode")" | tee -a ${logFILE}

echo "" | tee -a ${logFILE}
echo "2026102 format tests" | tee -a ${logFILE}

# Normal round trip, private file mode
new_case_dir roundtrip
head -c 100003 /dev/urandom > big.bin; cp big.bin orig.bin
must_pass ${FCRYPT} -r ${PW} big.bin && must_pass ${FDECRYPT} ${PW} big.enc && cmp -s big.bin orig.bin
result "round trip" $?
[ "$(head -c 8 big.enc | od -An -c | tr -d ' ')" = "FCRYPT032004" ]; result "new files use the 2026102 format" $?
[ "$(stat -c %a big.bin)" = "600" ]; result "decrypted file is created with mode 600" $?
[ "$(stat -c %a big.enc)" = "600" ]; result "encrypted file is created with mode 600" $?
ls big.bin.fdecrypt_* .fcrypt_* &>/dev/null; [ $? -ne 0 ]; result "no temp files left after encrypt and decrypt" $?
printf "" > empty.bin
must_pass ${FCRYPT} -r ${PW} empty.bin && must_pass ${FDECRYPT} ${PW} empty.enc && [ -f empty.bin ] && [ ! -s empty.bin ]
result "empty file round trip" $?
seq 1 100 > s.txt
must_pass ${FCRYPT} ${PW} s.txt && ${FDECRYPT} ${PW} --stdout s.enc 2>/dev/null | cmp -s - s.txt
result "--stdout writes the decrypted data" $?

# Wrong password
must_fail ${FDECRYPT} --password=wrong_password_123 -o big.enc
result "wrong password fails" $?

# Overwrite protection
echo "keep me" > keep.txt
must_fail ${FDECRYPT} ${PW} --outfile=keep.txt big.enc
r=$?; [ $r -eq 0 ] && grep -q "keep me" keep.txt; result "existing file is not overwritten without -o" $?
must_pass ${FDECRYPT} -o ${PW} --outfile=keep.txt big.enc && cmp -s keep.txt orig.bin
result "-o overwrites an existing file" $?
echo "keep me" > keep.enc; echo "data" > keep.bin
must_pass ${FCRYPT} ${PW} keep.bin
r=$?; [ $r -eq 0 ] && grep -q "keep me" keep.enc; result "fcrypt does not overwrite an existing enc file" $?

# Truncation, reordering, splicing, extra records and bit flips. The
# test files have one name record and four data records.
new_case_dir integrity
head -c 200000 /dev/urandom > a.bin; head -c 200000 /dev/urandom > b.bin; cp a.bin a.orig
must_pass ${FCRYPT} ${PW} a.bin; must_pass ${FCRYPT} ${PW} --decrypted-outfile=other.bin b.bin; rm a.bin b.bin
MAC=$(${NTOOL} mac-offset a.enc)
for t in drop-last drop-data swap dup append splice swap-name header-from slots-from big-len truncate \
    flip-header:0 flip-header:24 flip-header:36 flip-header:50 flip-header:80 flip-header:100 \
    flip-header:140 flip-header:${MAC} flip-rec:0:30 flip-rec:1:2 flip-rec:1:10 flip-rec:1:100 flip-rec:2:-1 flip-rec:4:-1; do
    cp a.enc t.enc
    case $t in
	splice|swap-name|header-from|slots-from) ${NTOOL} $t t.enc b.enc ;;
	*) ${NTOOL} $t t.enc ;;
    esac
    must_fail ${FDECRYPT} ${PW} --outfile=t.out t.enc
    r=$?; [ $r -eq 0 ] && [ ! -e t.out ]; result "modified file (${t}) is rejected, no output left" $?
done
cp a.enc t.enc; ${NTOOL} drop-last t.enc
must_fail ${FDECRYPT} ${PW} --stdout t.enc
result "truncated file fails with --stdout" $?
must_pass ${FDECRYPT} ${PW} a.enc && cmp -s a.bin a.orig; result "unmodified file still decrypts" $?

# Key slots
new_case_dir slots
openssl_plain() { ${OLD_ENV} openssl "$@"; }
openssl_plain genrsa -out user1.pem 2048 &>> ${logFILE}
openssl_plain rsa -in user1.pem -pubout -out user1.pub &>> ${logFILE}
openssl_plain genrsa -out user3.pem 2048 &>> ${logFILE}
openssl_plain genrsa -out small.pem 1024 &>> ${logFILE}
openssl_plain rsa -in small.pem -pubout -out small.pub &>> ${logFILE}
head -c 70000 /dev/urandom > k.bin; cp k.bin k.orig
must_pass ${FCRYPT} -r ${PW} k.bin
must_pass ${FCRYPT} ${PW} --add-rsa-key=user1.pub --rsa-key-username=user1 k.enc
must_pass ${FDECRYPT} --rsa-key=user1.pem --rsa-key-username=user1 k.enc && cmp -s k.bin k.orig
result "RSA key round trip" $?
rm -f k.bin
must_fail ${FDECRYPT} --rsa-key=user3.pem --rsa-key-username=user1 k.enc
r=$?; [ $r -eq 0 ] && [ ! -e k.bin ]; result "another RSA key fails for user1" $?
must_fail ${FDECRYPT} --rsa-key=user1.pem --rsa-key-username=user9 k.enc
result "unknown RSA user fails" $?
must_fail ${FCRYPT} ${PW} --add-rsa-key=user1.pub --rsa-key-username=user1 k.enc
result "the same RSA user cannot be added twice" $?
must_fail ${FCRYPT} --password=wrong_password_123 --add-rsa-key=user1.pub --rsa-key-username=user2 k.enc
result "adding an RSA key needs the file password" $?
must_fail ${FCRYPT} ${PW} --add-rsa-key=small.pub --rsa-key-username=small k.enc
result "RSA keys under 2048 bits are refused" $?
${FDECRYPT} --list-users k.enc 2>&1 | grep -q "Username: user1"; result "--list-users shows user1" $?
cp k.enc t.enc; ${NTOOL} remove-slot t.enc
must_fail ${FDECRYPT} ${PW} --outfile=t.out t.enc
r=$?; [ $r -eq 0 ] && [ ! -e t.out ]; result "removing a key slot is detected" $?
must_fail ${FDECRYPT} --rsa-key=user1.pem --rsa-key-username=user1 --outfile=t.out t.enc
result "RSA user removed from the slot area cannot decrypt" $?

# Stored path handling
new_case_dir paths
mkdir -p src/sub out
echo "abs" > src/sub/abs.txt
must_pass ${FCRYPT} ${PW} ${caseDIR}/src/sub/abs.txt
mv src/sub/abs.enc abs_path.enc
must_pass ${FCRYPT} ${PW} --decrypted-outfile=../escape.txt src/sub/abs.txt
mv src/sub/abs.enc dotdot.enc
must_pass ${FCRYPT} ${PW} --decrypted-outfile='C:\Users\test\win.txt' src/sub/abs.txt
mv src/sub/abs.enc win.enc
rm src/sub/abs.txt

must_pass ${FDECRYPT} ${PW} --outdir=out abs_path.enc
r=$?; [ $r -eq 0 ] && [ -f out/${caseDIR#/}/src/sub/abs.txt ] && [ ! -e src/sub/abs.txt ]
result "absolute stored path is restored under the output DIR by default" $?
must_pass ${FDECRYPT} ${PW} --no-path --outdir=out abs_path.enc
[ -f out/abs.txt ]; result "--no-path restores the file name only" $?
must_pass ${FDECRYPT} ${PW} --absolute-path abs_path.enc
[ -f src/sub/abs.txt ]; result "--absolute-path restores the exact stored path" $?
must_fail ${FDECRYPT} ${PW} --absolute-path --outdir=out abs_path.enc
result "--absolute-path with --outdir is refused" $?
must_fail ${FDECRYPT} ${PW} dotdot.enc
r=$?; [ $r -eq 0 ] && [ ! -e ../escape.txt ]; result "stored path with .. is rejected" $?
must_pass ${FDECRYPT} ${PW} --no-path dotdot.enc
[ -f escape.txt ]; result "--no-path restores a stored path with .. as the file name" $?
must_pass ${FDECRYPT} ${PW} win.enc
[ -f Users/test/win.txt ]; result "Windows stored path is restored relative on Linux" $?
${FDECRYPT} ${PW} -l win.enc 2>&1 | grep -q 'Decrypted name: C:\\Users\\test\\win.txt'
result "-l lists the stored name" $?

# Long file names, stored with a path since a single file name cannot
# be longer than 255 bytes
new_case_dir names
d=$(printf 'd%.0s' $(seq 1 200))
n300=${d}/$(printf 'n%.0s' $(seq 1 95)).txt
long=$(for i in $(seq 1 25); do printf '%s/' ${d}; done)x.txt
echo "long" > x.txt
must_pass ${FCRYPT} ${PW} --decrypted-outfile=${n300} x.txt && rm x.txt && must_pass ${FDECRYPT} ${PW} x.enc
[ -f ${n300} ]; result "300 byte stored name round trip" $?
echo "long" > y.txt
must_fail ${FCRYPT} ${PW} --decrypted-outfile=${long} y.txt
r=$?; [ $r -eq 0 ] && [ ! -e y.enc ]; result "stored name over 4096 bytes is refused" $?

# Options that would weaken the file
new_case_dir options
echo "iter" > i.txt
must_fail ${FCRYPT} ${PW} --iter=999 i.txt
result "--iter below 1000 is refused" $?
must_fail ${FCRYPT} -0 ${PW} i.txt
result "-0 (no encryption) is refused" $?
must_pass ${FCRYPT} ${PW} --iter=1000 i.txt && rm i.txt && must_pass ${FDECRYPT} ${PW} i.enc
result "fdecrypt reads the iteration count from the file" $?

# Old format files, from releases before 2026.102
echo "" | tee -a ${logFILE}
echo "Old format tests" | tee -a ${logFILE}

# C1: forged file with all-zero mode bytes
new_case_dir forged
${TOOL} forge forged.enc ${caseDIR}/pwned.txt "written without the key"
must_fail ${LEGACY_FDECRYPT} --password=wrong_password_123 forged.enc
r=$?; [ $r -eq 0 ] && [ ! -e pwned.txt ] ; result "forged file with zero mode bytes is rejected" $?
if [ -n "${OLD_DIR}" ]; then
    must_pass ${OLD_FDECRYPT} --password=wrong_password_123 forged.enc
    [ -e pwned.txt ]; result "old fdecrypt accepts the forged file (test reproduces the bug)" $?
fi

if [ -z "${OLD_DIR}" ]; then
    echo "Skipping the rest of the old format tests, no old build directory given" | tee -a ${logFILE}
else
    # C1: zero mode block injected into a real file
    new_case_dir inject
    seq 1 2000 > text.txt; cp text.txt orig.txt
    must_pass ${OLD_FCRYPT} -r ${PW} text.txt
    ${TOOL} zero-mode-block text.enc
    must_fail ${LEGACY_FDECRYPT} ${PW} text.enc
    r=$?; [ $r -eq 0 ] && [ ! -e text.txt ]; result "injected zero mode block is rejected, no output left" $?

    # H2: corrupt RSA user area
    new_case_dir rsa_area
    echo "data" > r.txt
    must_pass ${OLD_FCRYPT} ${PW} r.txt
    ${TOOL} bad-username-len r.enc
    must_fail ${LEGACY_FDECRYPT} --list-users r.enc
    r=$?; [ $r -eq 0 ]; result "bad username length is rejected without a crash" $?
    must_fail ${LEGACY_FDECRYPT} --rsa-key=/dev/null --rsa-key-username=user1 r.enc
    r=$?; [ $r -eq 0 ]; result "RSA decrypt with a bad user area fails cleanly" $?

    # L5: mode 0 files
    new_case_dir mode0
    echo "plain" > p.txt; cp p.txt p.orig
    must_pass ${OLD_FCRYPT} -0 -r ${PW} p.txt
    must_fail ${LEGACY_FDECRYPT} ${PW} p.enc
    r=$?; [ $r -eq 0 ] && [ ! -e p.txt ]; result "mode 0 file needs --allow-unencrypted" $?
    must_pass ${LEGACY_FDECRYPT} ${PW} --allow-unencrypted p.enc && cmp -s p.txt p.orig
    result "--allow-unencrypted decrypts a mode 0 file" $?
fi

if [ -z "${OLD_DIR2}" ]; then
    echo "Skipping the old format integrity tests, no 2026.101 build directory given" | tee -a ${logFILE}
else
    # H1: truncation, reordering, splicing and extra blocks
    new_case_dir integrity_old
    seq 1 3000 > a.txt; seq 5000 9000 > b.txt; cp a.txt a.orig
    must_pass ${OLD_FCRYPT2} ${PW} a.txt; must_pass ${OLD_FCRYPT2} ${PW} b.txt; rm a.txt b.txt
    for t in drop-last swap splice append flip; do
	cp a.enc t.enc
	case $t in
	    splice|append) ${TOOL} $t t.enc b.enc ;;
	    flip) ${TOOL} flip t.enc 30000 ;;
	    *) ${TOOL} $t t.enc ;;
	esac
	must_fail ${LEGACY_FDECRYPT} ${PW} --outfile=t.out t.enc
	r=$?; [ $r -eq 0 ] && [ ! -e t.out ]; result "modified old file (${t}) is rejected, no output left" $?
    done
    must_pass ${LEGACY_FDECRYPT} ${PW} a.enc && cmp -s a.txt a.orig; result "unmodified old file still decrypts" $?

fi

echo "" | tee -a ${logFILE}
echo "${passed} passed, ${failed} failed" | tee -a ${logFILE}
echo "Logged output to: ${logFILE}"
if [ ${failed} -ne 0 ]; then exit 1; fi
exit 0
