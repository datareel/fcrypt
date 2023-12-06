#!/bin/bash

if [ -z ${1} ]; then
    echo "ERROR: Enter the file name of the program to build"
    exit 1
fi

g++ -Wall ${1} -lssl -lcrypto
