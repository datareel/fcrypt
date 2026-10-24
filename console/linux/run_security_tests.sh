#!/bin/bash
# Security regression tests for fcrypt and fdecrypt.
#
# Checks that fdecrypt rejects forged, modified and truncated files,
# never writes outside the output directory unless asked to, never
# overwrites files without -o, and leaves no output behind on failure.
#
# Usage: ./run_security_tests.sh [/path/to/old/console/linux]
#
# With an old build directory the forged file test is also run against
# the old fdecrypt, to show the test reproduces the original problem.

NEW_DIR=$(cd $(dirname $0) && pwd)
FCRYPT=${NEW_DIR}/fcrypt
FDECRYPT=${NEW_DIR}/fdecrypt
OLD_DIR=$1
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

echo "Starting tests at $(date)" | tee -a ${logFILE}

# C1: forged file with all-zero mode bytes
new_case_dir forged
${TOOL} forge forged.enc ${caseDIR}/pwned.txt "written without the key"
must_fail ${FDECRYPT} --password=wrong_password_123 forged.enc
r=$?; [ $r -eq 0 ] && [ ! -e pwned.txt ] ; result "forged file with zero mode bytes is rejected" $?
if [ -n "${OLD_DIR}" ]; then
    must_pass ${OLD_DIR}/fdecrypt --password=wrong_password_123 forged.enc
    [ -e pwned.txt ]; result "old fdecrypt accepts the forged file (test reproduces the bug)" $?
fi

# C1: zero mode block injected into a real file
new_case_dir inject
seq 1 2000 > text.txt; cp text.txt orig.txt
must_pass ${FCRYPT} -r ${PW} text.txt
${TOOL} zero-mode-block text.enc
must_fail ${FDECRYPT} ${PW} text.enc
r=$?; [ $r -eq 0 ] && [ ! -e text.txt ]; result "injected zero mode block is rejected, no output left" $?

# Normal round trip, private file mode
new_case_dir roundtrip
head -c 100003 /dev/urandom > big.bin; cp big.bin orig.bin
must_pass ${FCRYPT} -r ${PW} big.bin && must_pass ${FDECRYPT} ${PW} big.enc && cmp -s big.bin orig.bin
result "round trip" $?
[ "$(stat -c %a big.bin)" = "600" ]; result "decrypted file is created with mode 600" $?
ls big.bin.fdecrypt_* &>/dev/null; [ $? -ne 0 ]; result "no temp files left after decrypt" $?

# Wrong password
must_fail ${FDECRYPT} --password=wrong_password_123 -o big.enc
result "wrong password fails" $?

# Overwrite protection
echo "keep me" > keep.txt
cp big.enc keep.enc
must_fail ${FDECRYPT} ${PW} --outfile=keep.txt big.enc
r=$?; [ $r -eq 0 ] && grep -q "keep me" keep.txt; result "existing file is not overwritten without -o" $?
must_pass ${FDECRYPT} -o ${PW} --outfile=keep.txt big.enc && cmp -s keep.txt orig.bin
result "-o overwrites an existing file" $?

# H1: truncation, reordering, splicing and extra blocks
new_case_dir integrity
seq 1 3000 > a.txt; seq 5000 9000 > b.txt; cp a.txt a.orig
must_pass ${FCRYPT} ${PW} a.txt; must_pass ${FCRYPT} ${PW} b.txt; rm a.txt b.txt
for t in drop-last swap splice append flip; do
    cp a.enc t.enc
    case $t in
	splice|append) ${TOOL} $t t.enc b.enc ;;
	flip) ${TOOL} flip t.enc 30000 ;;
	*) ${TOOL} $t t.enc ;;
    esac
    must_fail ${FDECRYPT} ${PW} --outfile=t.out t.enc
    r=$?; [ $r -eq 0 ] && [ ! -e t.out ]; result "modified file (${t}) is rejected, no output left" $?
done
must_pass ${FDECRYPT} ${PW} a.enc && cmp -s a.txt a.orig; result "unmodified file still decrypts" $?

# C2: stored path handling
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

# H6: long file names, stored with a path since a single file name
# cannot be longer than 255 bytes
new_case_dir names
d=$(printf 'd%.0s' $(seq 1 200))
n280=${d}/$(printf 'n%.0s' $(seq 1 75)).txt
n300=${d}/$(printf 'n%.0s' $(seq 1 95)).txt
mkdir ${d}
echo "long" > x.txt
must_pass ${FCRYPT} ${PW} --decrypted-outfile=${n280} x.txt && rm x.txt && must_pass ${FDECRYPT} ${PW} x.enc
[ -f ${n280} ]; result "280 byte stored name round trip" $?
if [ -n "${OLD_DIR}" ]; then
    rm -f ${n280}
    must_pass ${OLD_DIR}/fdecrypt ${PW} x.enc
    [ -f ${n280} ]; result "old fdecrypt reads a 280 byte stored name" $?
fi
echo "long" > y.txt
must_fail ${FCRYPT} ${PW} --decrypted-outfile=${n300} y.txt
r=$?; [ $r -eq 0 ] && [ ! -e y.enc ]; result "stored name over 288 bytes is refused" $?

# H2: corrupt RSA user area
new_case_dir rsa_area
echo "data" > r.txt
must_pass ${FCRYPT} ${PW} r.txt
${TOOL} bad-username-len r.enc
must_fail ${FDECRYPT} --list-users r.enc
r=$?; [ $r -eq 0 ]; result "bad username length is rejected without a crash" $?
must_fail ${FDECRYPT} --rsa-key=/dev/null --rsa-key-username=user1 r.enc
r=$?; [ $r -eq 0 ]; result "RSA decrypt with a bad user area fails cleanly" $?

# L5: mode 0 files
new_case_dir mode0
echo "plain" > p.txt; cp p.txt p.orig
must_pass ${FCRYPT} -0 -r ${PW} p.txt
must_fail ${FDECRYPT} ${PW} p.enc
r=$?; [ $r -eq 0 ] && [ ! -e p.txt ]; result "mode 0 file needs --allow-unencrypted" $?
must_pass ${FDECRYPT} ${PW} --allow-unencrypted p.enc && cmp -s p.txt p.orig
result "--allow-unencrypted decrypts a mode 0 file" $?

# L4: weak iteration counts
new_case_dir iter
echo "iter" > i.txt
must_fail ${FCRYPT} ${PW} --iter=1 i.txt
result "--iter below 1000 is refused" $?

echo "" | tee -a ${logFILE}
echo "${passed} passed, ${failed} failed" | tee -a ${logFILE}
echo "Logged output to: ${logFILE}"
if [ ${failed} -ne 0 ]; then exit 1; fi
exit 0
