#!/bin/bash

RHEL_VERSION=0

# Check for rhel6
/bin/cat /etc/redhat-release | grep -i Santiago >/dev/null 2>&1
if [ $? -eq 0 ]; then RHEL_VERSION=6; fi

# Check for rhel7
/bin/cat /etc/redhat-release | grep -i Maipo >/dev/null 2>&1
if [ $? -eq 0 ]; then RHEL_VERSION=7; fi

# Check for rhel8
/bin/cat /etc/redhat-release | grep -i Ootpa >/dev/null 2>&1
if [ $? -eq 0 ]; then RHEL_VERSION=8; fi

# Check for rhel9
/bin/cat /etc/redhat-release | grep -i Plow >/dev/null 2>&1
if [ $? -eq 0 ]; then RHEL_VERSION=9; fi

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
echo "${FCRYPT} -v --debug=5 --password=password ${testDIR}/testfile.txt" >> ${logFILE}
${FCRYPT} -v --debug=5 --password=password ${testDIR}/testfile.txt &>> ${logFILE}
if [ $? -ne 0 ]; then
    echo "ERROR: Password encryption test failed" | tee -a ${logFILE}
    echo "ERROR: See log ${logFILE}"
    exit 1
fi
echo "Passed" | tee -a ${logFILE}
echo "" | tee -a ${logFILE}

echo "Testing decryption using a password" | tee -a ${logFILE}
echo "${FDECRYPT} -v --debug=5 --password=password ${testDIR}/testfile.enc" >> ${logFILE}
${FDECRYPT} -v --debug=5 --password=password ${testDIR}/testfile.enc &>> ${logFILE}
if [ $? -ne 0 ]; then
    echo "ERROR: Password decryption test failed" | tee -a ${logFILE}
    echo "ERROR: See log ${logFILE}"
    exit 1
fi
echo "Passed" | tee -a ${logFILE}
echo "" | tee -a ${logFILE}

/bin/rm -fv ${testDIR}/testfile.enc &>> ${logFILE}

echo "Testing encryption using a master key" | tee -a ${logFILE}

echo "dd if=/dev/urandom of=${testDIR}/master.key bs=1 count=128" >> ${logFILE}
dd if=/dev/urandom of=${testDIR}/master.key bs=1 count=128 &>> ${logFILE}
chmod 600 ${testDIR}/master.key &>> ${logFILE}

echo "${FCRYPT} -v --debug=5 --key=${testDIR}/master.key ${testDIR}/testfile.txt" >> ${logFILE}
${FCRYPT} -v --debug=5 --key=${testDIR}/master.key ${testDIR}/testfile.txt &>> ${logFILE}
if [ $? -ne 0 ]; then
    echo "ERROR: Master key encryption test failed" | tee -a ${logFILE}
    echo "ERROR: See log ${logFILE}"
    exit 1
fi
echo "Passed" | tee -a ${logFILE}
echo "" | tee -a ${logFILE}

echo "Testing decryption using a master key" | tee -a ${logFILE}
echo "${FDECRYPT} -v --debug=5 --key=${testDIR}/master.key ${testDIR}/testfile.enc" >> ${logFILE}
${FDECRYPT} -v --debug=5 --key=${testDIR}/master.key ${testDIR}/testfile.enc &>> ${logFILE}
if [ $? -ne 0 ]; then
    echo "ERROR: Master key decryption test failed" | tee -a ${logFILE}
    echo "ERROR: See log ${logFILE}"
    exit 1
fi
echo "Passed" | tee -a ${logFILE}
echo "" | tee -a ${logFILE}

USERNAME="testuser1"
echo "Tesing multi user access using an RSA key" | tee -a ${logFILE}
echo "openssl genrsa -out ${testDIR}/${USERNAME}_private_key.pem 2048" >> ${logFILE}
openssl genrsa -out ${testDIR}/${USERNAME}_private_key.pem 2048 &>> ${logFILE}
chmod 600 ${testDIR}/${USERNAME}_private_key.pem &>> ${logFILE}
echo "openssl rsa -in ${testDIR}/${USERNAME}_private_key.pem -outform PEM -pubout -out ${testDIR}/${USERNAME}_public_key.pem" >> ${logFILE}
openssl rsa -in ${testDIR}/${USERNAME}_private_key.pem -outform PEM -pubout -out ${testDIR}/${USERNAME}_public_key.pem &>> ${logFILE}
echo "Adding RSA key for ${USERNAME}" | tee -a ${logFILE}
echo "${FCRYPT} -v --debug=5 --key=${testDIR}/master.key --add-rsa-key=${testDIR}/${USERNAME}_public_key.pem --rsa-key-username=${USERNAME} ${testDIR}/testfile.enc" >> ${logFILE}
${FCRYPT} -v --debug=5 --key=${testDIR}/master.key --add-rsa-key=${testDIR}/${USERNAME}_public_key.pem --rsa-key-username=${USERNAME} ${testDIR}/testfile.enc &>> ${logFILE}
if [ $? -ne 0 ]; then
    echo "ERROR: Error adding RSA key for ${USERNAME}" | tee -a ${logFILE}
    echo "ERROR: See log ${logFILE}"
    exit 1
fi

echo "Passed" | tee -a ${logFILE}
echo "" | tee -a ${logFILE}

echo "Testing decryption RSA private key for ${USERNAME}" | tee -a ${logFILE}
echo "${FDECRYPT} -v --debug=5 --rsa-key=${testDIR}/${USERNAME}_private_key.pem ${testDIR}/testfile.enc" >> ${logFILE}
${FDECRYPT} -v --debug=5 --rsa-key=${testDIR}/${USERNAME}_private_key.pem ${testDIR}/testfile.enc &>> ${logFILE}
if [ $? -ne 0 ]; then
    echo "ERROR: RSA private key decryption test failed" | tee -a ${logFILE}
    echo "ERROR: See log ${logFILE}"
    exit 1
fi
echo "Passed" | tee -a ${logFILE}
echo "" | tee -a ${logFILE}

# NOTE: The ssh-keygen -m option is not in RHEL 6 and below
if [ ${RHEL_VERSION} -ne 6 ]; then
    USERNAME="testuser2"
    echo "Testing multi user access using an SSH-RSA key" | tee -a ${logFILE}
    echo "ssh-keygen -t rsa -f ${testDIR}/${USERNAME}_id_rsa -N 'password'" >> ${logFILE}
    ssh-keygen -t rsa -f ${testDIR}/${USERNAME}_id_rsa -N 'password' &>> ${logFILE}
    echo "ssh-keygen -p -P password -N password -f ${testDIR}/${USERNAME}_id_rsa -e -m PEM" >> ${logFILE}
    ssh-keygen -p -P password -N password -f ${testDIR}/${USERNAME}_id_rsa -e -m PEM &>> ${logFILE}
    echo "Adding SSH-RSA key for ${USERNAME}" | tee -a ${logFILE}
    echo "ssh-keygen -f ${testDIR}/${USERNAME}_id_rsa.pub -m 'PKCS8' -e | ${FCRYPT} -v --debug=5 --key=${testDIR}/master.key --add-rsa-key --rsa-key-username=${USERNAME} ${testDIR}/testfile.enc" >> ${logFILE}
    ssh-keygen -f ${testDIR}/${USERNAME}_id_rsa.pub -m 'PKCS8' -e | ${FCRYPT} -v --debug=5 --key=${testDIR}/master.key --add-rsa-key --rsa-key-username=${USERNAME} ${testDIR}/testfile.enc &>> ${logFILE}
    if [ $? -ne 0 ]; then
	echo "ERROR: Error adding SSH-RSA key for ${USERNAME}" | tee -a ${logFILE}
	echo "ERROR: See log ${logFILE}"
	exit 1
    fi
    echo "Passed" | tee -a ${logFILE}
    echo "" | tee -a ${logFILE}
    
    echo "Testing decryption SSH-RSA private key for ${USERNAME}" | tee -a ${logFILE}
    echo "${FDECRYPT} -v --debug=5 --rsa-key=${testDIR}/${USERNAME}_id_rsa --rsa-key-passphrase=password ${testDIR}/testfile.enc" >> ${logFILE}
    ${FDECRYPT} -v --debug=5 --rsa-key=${testDIR}/${USERNAME}_id_rsa --rsa-key-passphrase=password ${testDIR}/testfile.enc &>> ${logFILE}
    if [ $? -ne 0 ]; then
	echo "ERROR: SSH-RSA private key decryption test failed"
	echo "ERROR: See log ${logFILE}"
	exit 1
    fi
    echo "Passed" | tee -a ${logFILE}
    echo "" | tee -a ${logFILE}
fi

echo "All testing complete" | tee -a ${logFILE}
echo "Logged output to: ${logFILE}"
echo "Exiting script" | tee -a ${logFILE}
exit 0
