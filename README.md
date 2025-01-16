# PKCS#11 Provider Example

This project demonstrates how to use the OpenSSL `OSSL_STORE` API to access PKCS#11 tokens and read private keys. It includes an example of how to specify the PKCS#11 module path and provide a PIN for accessing the token.

## Prerequisites

- OpenSSL 3.0 or later
- A PKCS#11 module (e.g., SoftHSM)
- C compiler
- OpenSC tools (for managing PKCS#11 tokens)

## Installation

### Install OpenSSL

Ensure you have OpenSSL 3.0 or later installed on your system. You can download and build it from the [OpenSSL website](https://www.openssl.org/source/).

### Install SoftHSM

SoftHSM is a software implementation of a Hardware Security Module (HSM). You can install it using the following command:

```sh
sudo apt-get install softhsm2