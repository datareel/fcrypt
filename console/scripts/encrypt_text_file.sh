#!/bin/bash

FCRYPT=../linux/fcrypt
FDECRYPT=../linux/fdecrypt

if [ "${1}" == "" ]; then
    echo "ERROR: You must provide a source file name to encrypt"
    echo "USEAGE: ${0} plaintext_filename encrypted_filename"
    exit 1
fi

if [ "${2}" == "" ]; then
    echo "ERROR: You must provide a destination file name for the encrypted output"
    echo "USEAGE: ${0} plaintext_filename encrypted_filename"
    exit 1
fi

FILE_TO_ENCRYPT="${1}"
ENCRYPTED_FILE_NAME="${2}"
ENCRYPTED_FILE_NAME_tmp=$(basename ${ENCRYPTED_FILE_NAME})

if [ ! -f  ${FILE_TO_ENCRYPT} ]; then
    echo "ERROR: File to encrypt does not exist:  ${FILE_TO_ENCRYPT}"
fi

PUBKEY_DB="rsa_key_access_db"
VARdir="${HOME}/var";
PUBKEY_FILES="${VARdir}/public_keys"

SYMMETRIC_KEY="${VARdir}/.keys/temp.key"

mkdir -pv ${PUBKEY_FILES} ${VARdir}/.keys
chmod 700 ${VARdir}/.keys


if [ ! -f ${PUBKEY_DB} ]; then 
    echo "ERROR - Missing file ${PUBKEY_DB}"
    exit 1
fi

dd if=/dev/urandom of=${SYMMETRIC_KEY} bs=1 count=128
chmod 400 ${SYMMETRIC_KEY}

$FCRYPT -v --debug=5 --key=${SYMMETRIC_KEY} --outfile=${VARdir}/${ENCRYPTED_FILE_NAME_tmp} --decrypted-outfile=stdout ${FILE_TO_ENCRYPT}
if [ $? -ne 0 ]; then
    echo "ERROR: Error encrypting file: ${FILE_TO_ENCRYPT}"
    exit 1
fi

rsa_pubkey_list=$(cat ${PUBKEY_DB} | grep '_pubrsa='  | grep -v -E '^#' | grep -v -E '^$' | sort)

SAVEIFS=$IFS
IFS=$(echo -en "\n\b")
for k in ${rsa_pubkey_list}; do
    kname=$(echo "${k}" | awk -F= '{ print $1 }')
    username=$(echo "${kname}" | sed s/'_local_pubrsa'//g)
    key=$(echo "${k}" | sed s/"${kname}="//)
    echo ${key} > ${PUBKEY_FILES}/${username}_id_rsa.pub
    chmod 400 ${PUBKEY_FILES}/${username}_id_rsa.pub
    echo "Adding key for user ${username}"
    ssh-keygen -f ${PUBKEY_FILES}/${username}_id_rsa.pub -m 'PKCS8' -e | $FCRYPT -v --debug=5 --key=${SYMMETRIC_KEY} --add-rsa-key --rsa-key-username=${username} ${VARdir}/${ENCRYPTED_FILE_NAME_tmp}
    if [ $? -ne 0 ]; then
	echo "ERROR: Error adding RSA key for ${username} to encrypted file: ${VARdir}/${ENCRYPTED_FILE_NAME_tmp}"
	rm -fv ${VARdir}/${ENCRYPTED_FILE_NAME_tmp}
	exit 1
    fi
done
IFS=$SAVEIFS

if [ -f ${ENCRYPTED_FILE_NAME} ]; then
    echo "Removing previous file  ${ENCRYPTED_FILE_NAME}"
    rm -rfv  ${ENCRYPTED_FILE_NAME}
fi

mv -fv ${VARdir}/${ENCRYPTED_FILE_NAME_tmp} ${ENCRYPTED_FILE_NAME}

# NOTE: If you need to keep the symmetric encryption key comment out the line below
rm -fv ${SYMMETRIC_KEY}

echo "File encryption complete"
echo "You can remove the plaintext file: ${FILE_TO_ENCRYPT}"

exit 0
