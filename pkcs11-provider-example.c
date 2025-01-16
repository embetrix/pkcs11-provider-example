#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/store.h>
#include <openssl/core_names.h>

int main(int argc, char *argv[]) {
    OSSL_PROVIDER *pkcs11_provider = NULL;
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_STORE_CTX *store = NULL;
    OSSL_STORE_INFO *store_info = NULL;
    EVP_PKEY *pkey = NULL;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pkcs11-uri>", argv[0]);
        return 1;
    }

    const char *pkcs11_uri = argv[1];
    /* Load the default provider */
    default_provider = OSSL_PROVIDER_load(NULL, "default");
    if (!default_provider) {
        fprintf(stderr, "Failed to load default provider");
        return 1;
    }

    /* Load the PKCS#11 provider */
    pkcs11_provider = OSSL_PROVIDER_load(NULL, "pkcs11");
    if (!pkcs11_provider) {
        fprintf(stderr, "Failed to load PKCS#11 provider");
        OSSL_PROVIDER_unload(default_provider);
        return 1;
    }

    store = OSSL_STORE_open_ex(pkcs11_uri, NULL, "provider=pkcs11", NULL, NULL, NULL, NULL, NULL);
    if (!store) {
        fprintf(stderr, "Failed to open OSSL_STORE (check URI or provider setup)");
        goto cleanup;
    }

    while ((store_info = OSSL_STORE_load(store)) != NULL) {
        int info_type = OSSL_STORE_INFO_get_type(store_info);

        if (info_type == OSSL_STORE_INFO_PKEY) {
            /* Extract the key */
            pkey = OSSL_STORE_INFO_get1_PKEY(store_info);
            if (pkey) {
                /* Determine key type (RSA, EC, etc.) */
                int base_id = EVP_PKEY_base_id(pkey);
                if (base_id == EVP_PKEY_RSA) {
                    printf("Loaded an RSA private key.\n");
                } else if (base_id == EVP_PKEY_EC) {
                    printf("Loaded an ECC private key.\n");
                } else {
                    fprintf(stderr, "Loaded a private key of unknown type (base_id=%d).\n", base_id);
                }
                EVP_PKEY_free(pkey);
                pkey = NULL;
            }
        }

        OSSL_STORE_INFO_free(store_info);
        store_info = NULL;
    }

    if (!OSSL_STORE_eof(store)) {
        fprintf(stderr, "Did not reach end of store.");
    }

cleanup:
    if (store) {
        OSSL_STORE_close(store);
    }

    if (pkcs11_provider) {
        OSSL_PROVIDER_unload(pkcs11_provider);
    }
    if (default_provider) {
        OSSL_PROVIDER_unload(default_provider);
    }

    return 0;
}
