#!/bin/bash

FCRYPT=../linux/fcrypt
FDECRYPT=../linux/fdecrypt

FILE_TO_DECRYPT="${1}"

if [ "${1}" == "" ]; then
    echo "ERROR: You must provide a source file name to decrypt"
    echo "USEAGE: ${0} encrypted_filename"
    exit 1
fi

if [ ! -f  ${FILE_TO_DECRYPT} ]; then
    echo "ERROR: File to encrypt does not exist: ${FILE_TO_DECRYPT}"
fi

${FDECRYPT} -v --debug=5 --rsa-key=${HOME}/.ssh/id_rsa ${FILE_TO_DECRYPT}
if [ $? -ne 0 ]; then
    echo "ERROR: Error decrypting file: ${FILE_TO_DECRYPT}"
    exit 1
fi
