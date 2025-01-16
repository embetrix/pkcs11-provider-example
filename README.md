# PKCS#11 Provider Example

This project demonstrates how to use the OpenSSL pkcs11-provider API in C to access PKCS#11 tokens and read private keys.


## Install Dependencies

#### Ubuntu

```sh
sudo apt-get update
sudo apt-get install -y openssl libssl-dev softhsm2 opensc pkcs11-provider
```

## Build

```sh
cmake .
make
```

## Test

```sh
pkcs11-provider-example_test.sh
```
