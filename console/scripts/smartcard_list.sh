#!/bin/bash
# Lists the smart card readers, the cards in them (label, maker, model,
# PIN flags) and the certs and keys on each card (ID, label, RSA or EC)
# with the OpenSC pkcs11-tool. No login is made and no PIN is used.
#
# Usage: ./smartcard_list.sh [pkcs11_module]
#   The default module is /usr/lib64/opensc-pkcs11.so
#
# Use the slot ID in parentheses ("Slot 0 (0x4)") with --smartcard-slot
# and the ID of the encryption cert ("Certificate for Key Management",
# usually 03) with --smartcard-cert-id.

MODULE=${1:-/usr/lib64/opensc-pkcs11.so}
if ! command -v pkcs11-tool >/dev/null 2>&1; then
    echo "ERROR: pkcs11-tool not found, install OpenSC: sudo dnf install opensc pcsc-lite pcsc-lite-ccid"
    exit 1
fi
if [ ! -f "${MODULE}" ]; then
    echo "ERROR: PKCS#11 module ${MODULE} not found"
    exit 1
fi
SLOTS=$(pkcs11-tool --module "${MODULE}" --list-token-slots 2>&1)
echo "${SLOTS}"
for id in $(echo "${SLOTS}" | sed -n 's/^Slot [0-9]* (\(0x[0-9a-fA-F]*\)).*/\1/p'); do
    echo ""
    echo "---- Certs and keys in slot ID ${id} (--smartcard-slot=${id}), read without a PIN:"
    pkcs11-tool --module "${MODULE}" --slot ${id} --list-objects 2>&1
done
echo ""
echo "No login was made and no PIN was used."
if echo "${SLOTS}" | grep -i "token flags" | grep -qiE "PIN locked|final try|count low"; then
    echo "WARNING: a card reports a locked PIN, one PIN try left or low PIN tries"
fi
