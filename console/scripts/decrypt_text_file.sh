#!/bin/bash

FCRYPT=../linux/fcrypt
FDECRYPT=../linux/fdecrypt

FILE_TO_DECRYPT="${1}"
USERNAME="$(whoami)"

if [ "${1}" == "" ]; then
    echo "ERROR: You must provide a source file name to decrypt"
    echo "USEAGE: ${0} encrypted_filename"
    exit 1
fi

if [ "${2}" != "" ]; then USERNAME="${2}"; fi

if [ ! -f  ${FILE_TO_DECRYPT} ]; then
    echo "ERROR: File to decrypt does not exist: ${FILE_TO_DECRYPT}"
    exit 1
fi

${FDECRYPT} -v --debug=5 --rsa-key=${HOME}/.ssh/id_rsa ${FILE_TO_DECRYPT} --rsa-key-username=${USERNAME}
if [ $? -ne 0 ]; then
    echo "ERROR: Error decrypting file: ${FILE_TO_DECRYPT}"
    exit 1
fi
