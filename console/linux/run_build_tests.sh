#!/bin/bash

testDIR=${HOME}/tmp/fcrypt_testing_$(date +%Y_%m_%d_%H%M%S)
logFILE=${testDIR}/fcrypt_decrypt_testing.log

FCRYPT=./fcrypt
FDECRYPT=./fdecrypt

echo "Testing fcrypt and decrypt build"
echo "Creating testing directory and test files"

mkdir -pv ${testDIR}
cat /dev/null > ${logFILE}

echo "Starting tests at $(date)" | tee -a ${logFILE}

if [ ! -f ${FCRYPT} ] || [ ! -f ${FDECRYPT} ]; then
    echo "ERROR: Missing binaries ${FCRYPT} and/or ${FDECRYPT}" | tee -a ${logFILE}
    exit 1
fi

cat /dev/null > ${testDIR}/testfile.txt
echo "Start of text" >> ${testDIR}/testfile.txt
echo "------------" >> ${testDIR}/testfile.txt
x=1
while [ $x -le 50 ]; do
    echo "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG 0123456789" >> ${testDIR}/testfile.txt
    echo "the quick brown fox jumps over the lazy dog 0123456789" >> ${testDIR}/testfile.txt
    x=$(( $x + 1 ))
done
echo "----------" >> ${testDIR}/testfile.txt
echo "End of text" >> ${testDIR}/testfile.txt

echo "Testing encryption using a password" | tee -a ${logFILE}
${FCRYPT} -v --debug=5 --password=password ${testDIR}/testfile.txt &>> ${logFILE}
if [ $? -ne 0 ]; then
    echo "ERROR: Password encryption test failed"
    echo "ERROR: See log ${logFILE}"
    exit 1
fi
echo "Passed" | tee -a ${logFILE}
echo "" | tee -a ${logFILE}

echo "Testing decryption using a password" | tee -a ${logFILE}
${FDECRYPT} -v --debug=5 --password=password ${testDIR}/testfile.enc &>> ${logFILE}
if [ $? -ne 0 ]; then
    echo "ERROR: Password decryption test failed"
    echo "ERROR: See log ${logFILE}"
    exit 1
fi
echo "Passed" | tee -a ${logFILE}
echo "" | tee -a ${logFILE}

/bin/rm -fv ${testDIR}/testfile.enc &>> ${logFILE}

echo "Testing encryption using a master key" | tee -a ${logFILE}

dd if=/dev/urandom of=${testDIR}/master.key bs=1 count=128 &>> ${logFILE}
chmod 600 ${testDIR}/master.key &>> ${logFILE}

${FCRYPT} -v --debug=5 --key=${testDIR}/master.key ${testDIR}/testfile.txt &>> ${logFILE}
if [ $? -ne 0 ]; then
    echo "ERROR: Master key encryption test failed"
    echo "ERROR: See log ${logFILE}"
    exit 1
fi
echo "Passed" | tee -a ${logFILE}
echo "" | tee -a ${logFILE}

echo "Testing decryption using a master key" | tee -a ${logFILE}
${FDECRYPT} -v --debug=5 --key=${testDIR}/master.key ${testDIR}/testfile.enc &>> ${logFILE}
if [ $? -ne 0 ]; then
    echo "ERROR: Master key decryption test failed"
    echo "ERROR: See log ${logFILE}"
    exit 1
fi
echo "Passed" | tee -a ${logFILE}
echo "" | tee -a ${logFILE}

echo "Tesing multi user access using an RSA key" | tee -a ${logFILE}
openssl genrsa -out ${testDIR}/testuser1_private_key.pem 2048 &>> ${logFILE}
chmod 600 ${testDIR}/testuser1_private_key.pem &>> ${logFILE}
openssl rsa -in ${testDIR}/testuser1_private_key.pem -outform PEM -pubout -out ${testDIR}/testuser1_public_key.pem &>> ${logFILE}
echo "Adding RSA key for testuser1" | tee -a ${logFILE}
${FCRYPT} -v --debug=5 --key=${testDIR}/master.key --add-rsa-key=${testDIR}/testuser1_public_key.pem --rsa-key-username=testuser1 ${testDIR}/testfile.enc &>> ${logFILE}
if [ $? -ne 0 ]; then
    echo "ERROR: Error adding RSA key for testuser1"
    echo "ERROR: See log ${logFILE}"
    exit 1
fi

echo "Passed" | tee -a ${logFILE}
echo "" | tee -a ${logFILE}

echo "Testing decryption RSA private key for testuser1" | tee -a ${logFILE}
${FDECRYPT} -v --debug=5 --rsa-key=${testDIR}/testuser1_private_key.pem ${testDIR}/testfile.enc &>> ${logFILE}
if [ $? -ne 0 ]; then
    echo "ERROR: RSA private key decryption test failed"
    echo "ERROR: See log ${logFILE}"
    exit 1
fi
echo "Passed" | tee -a ${logFILE}
echo "" | tee -a ${logFILE}

echo "All testing complete" | tee -a ${logFILE}
echo "Logged output to: ${logFILE}"
echo "Exiting script" | tee -a ${logFILE}
exit 0
