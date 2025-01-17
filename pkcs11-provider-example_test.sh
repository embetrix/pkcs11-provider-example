#!/bin/sh -e
#
# Copyright (c) 2025
# Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com
# 


export PKCS11_MODULE_PATH=/usr/lib/softhsm/libsofthsm2.so
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
./pkcs11-provider-example "pkcs11:object=testECCKey" "12345"
./pkcs11-provider-example "pkcs11:object=testECCKey;type=public"

export OPENSSL_CONF=$PWD/openssl.cnf
dd if=/dev/urandom of=data.bin bs=1M count=1 > /dev/null 2>&1
openssl dgst -sha256 -sign   "pkcs11:object=testRSAKey;type=private?pin-value=12345" -out data.bin.sig data.bin
openssl dgst -sha256 -verify "pkcs11:object=testRSAKey;type=public" -signature data.bin.sig data.bin
openssl dgst -sha256 -sign   "pkcs11:object=testECCKey;type=private?pin-value=12345" -out data.bin.sig data.bin
openssl dgst -sha256 -verify "pkcs11:object=testECCKey;type=public" -signature data.bin.sig data.bin
