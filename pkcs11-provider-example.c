#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/store.h>
#include <openssl/core_names.h>
#include <openssl/ui.h>

int ui_get_pin(UI *ui, UI_STRING *uis) {
    const char *pin = (const char *)UI_get0_user_data(ui);
    if (pin == NULL) {
        return -1;
    }
    int ret = UI_set_result(ui, uis, pin);
    return (ret == 0) ? 1 : -1;
}

EVP_PKEY *load_key_provider(const char *pkcs11_uri, const char *pin) {
    OSSL_PROVIDER *pkcs11_provider = NULL;
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_STORE_CTX *store = NULL;
    OSSL_STORE_INFO *store_info = NULL;
    EVP_PKEY *pkey = NULL;
    UI_METHOD *ui_method = NULL;

    /* Load the default provider */
    default_provider = OSSL_PROVIDER_load(NULL, "default");
    if (!default_provider) {
        fprintf(stderr, "Failed to load default provider\n");
        goto cleanup;
    }

    /* Load the PKCS#11 provider */
    pkcs11_provider = OSSL_PROVIDER_load(NULL, "pkcs11");
    if (!pkcs11_provider) {
        fprintf(stderr, "Failed to load PKCS#11 provider\n");
        goto cleanup;
    }

    ui_method = UI_create_method("PIN reader");
    if (!ui_method) {
        fprintf(stderr, "Failed to create UI method\n");
        goto cleanup;
    } else {
        UI_method_set_reader(ui_method, ui_get_pin);
    }

    store = OSSL_STORE_open_ex(pkcs11_uri, NULL, "provider=pkcs11", ui_method, (void *)pin, NULL, NULL, NULL);
    if (!store) {
        fprintf(stderr, "Failed to open OSSL_STORE (check URI or provider setup)\n");
        goto cleanup;
    }

    while ((store_info = OSSL_STORE_load(store)) != NULL) {
        int info_type = OSSL_STORE_INFO_get_type(store_info);

        if (info_type == OSSL_STORE_INFO_PKEY) {
            /* Extract the key */
            pkey = OSSL_STORE_INFO_get1_PKEY(store_info);
            if (pkey) {
                break;
            }
        }
        OSSL_STORE_INFO_free(store_info);
        store_info = NULL;
    }

    if (!pkey) {
        fprintf(stderr, "Failed to load private key\n");
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
    if (ui_method) {
        UI_destroy_method(ui_method);
    }

    return pkey;
}

int main(int argc, char *argv[]) {
    const char *pin = NULL;
    int ret = -1;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <pkcs11-uri> [pkcs11-pin]\n", argv[0]);
        return ret;
    }

    const char *pkcs11_uri = argv[1];
    if (argc == 3) {
        pin = argv[2];
    }

    EVP_PKEY *key = load_key_provider(pkcs11_uri, pin);
    if (key) {
        int key_type = EVP_PKEY_base_id(key);
        if (key_type == EVP_PKEY_RSA) {
            printf("Loaded an RSA private key.\n");
        } else if (key_type == EVP_PKEY_EC) {
            printf("Loaded an ECC private key.\n");
        } else {
            fprintf(stderr, "Loaded a private key of unknown type (base_id=%d).\n", key_type);
        }
        EVP_PKEY_free(key);
        ret = 0;
    } else {
        fprintf(stderr, "Failed to read private key\n");
    }

    return ret;
}
