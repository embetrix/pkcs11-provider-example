#!/bin/sh -e
#

export PKCS11_MODULE_PATH=/usr/lib/softhsm/libsofthsm2.so
export PKCS11_PROVIDER_MODULE_PATH=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
#export PKCS11_PROVIDER_DEBUG=1
export PIN="12345"
export SO_PIN="1234"
export SOFTHSM2_CONF=$PWD/.softhsm/softhsm2.conf
export TOKEN_NAME="MyToken"

rm -rf .softhsm
mkdir -p .softhsm/tokens
echo "directories.tokendir = $PWD/.softhsm/tokens" > .softhsm/softhsm2.conf
pkcs11-tool --pin $PIN --module $PKCS11_MODULE_PATH --slot-index=0 --init-token --label=$TOKEN_NAME --so-pin $SO_PIN --init-pin 
pkcs11-tool --pin $PIN --module $PKCS11_MODULE_PATH  --keypairgen --key-type RSA:2048      --label "testRSAKey" --id 2
pkcs11-tool --pin $PIN --module $PKCS11_MODULE_PATH  --keypairgen --key-type EC:prime256v1 --label "testECCKey" --id 3

./pkcs11-provider-example "pkcs11:object=testRSAKey;type=private?pin-value=12345"
./pkcs11-provider-example "pkcs11:object=testECCKey;type=private" "12345"
