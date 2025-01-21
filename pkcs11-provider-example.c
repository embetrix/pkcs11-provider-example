// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * (C) Copyright 2025
 * Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 3 of
 * the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 */

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/store.h>
#include <openssl/ui.h>

int ui_get_pin(UI *ui, UI_STRING *uis) {
    const char *pin = (const char *)UI_get0_user_data(ui);
    if (pin == NULL) {
        return -1;
    }
    int ret = UI_set_result(ui, uis, pin);
    return (ret == 0) ? 1 : 0;
}

EVP_PKEY *provider_load_private_key(const char *pkcs11_uri, const char *pin) {
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

EVP_PKEY *provider_load_public_key(const char *pkcs11_uri) {
    OSSL_PROVIDER *pkcs11_provider = NULL;
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_STORE_CTX *store = NULL;
    OSSL_STORE_INFO *store_info = NULL;
    EVP_PKEY *pubkey = NULL;

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

    store = OSSL_STORE_open(pkcs11_uri, NULL, NULL, NULL, NULL);
    if (!store) {
        fprintf(stderr, "Failed to open OSSL_STORE (check URI or provider setup)\n");
        goto cleanup;
    }

    while ((store_info = OSSL_STORE_load(store)) != NULL) {
        int info_type = OSSL_STORE_INFO_get_type(store_info);

        if (info_type == OSSL_STORE_INFO_PUBKEY) {
            /* Extract the key */
            pubkey = OSSL_STORE_INFO_get1_PUBKEY(store_info);
            if (pubkey) {
                break;
            }
        }
        OSSL_STORE_INFO_free(store_info);
        store_info = NULL;
    }

    if (!pubkey) {
        fprintf(stderr, "Failed to load public key\n");
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

    return pubkey;
}

X509 *provider_load_cert(const char *pkcs11_uri) {
    OSSL_PROVIDER *pkcs11_provider = NULL;
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_STORE_CTX *store = NULL;
    OSSL_STORE_INFO *store_info = NULL;
    X509 *cert = NULL;

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

    store = OSSL_STORE_open(pkcs11_uri, NULL, NULL, NULL, NULL);
    if (!store) {
        fprintf(stderr, "Failed to open OSSL_STORE (check URI or provider setup)\n");
        goto cleanup;
    }

    if (OSSL_STORE_expect(store, OSSL_STORE_INFO_CERT) != 1) {
        fprintf(stderr, "Failed to expect certificate\n");
        goto cleanup;
    }

    while ((store_info = OSSL_STORE_load(store)) != NULL) {
        int info_type = OSSL_STORE_INFO_get_type(store_info);
        if (info_type == OSSL_STORE_INFO_CERT) {
            /* Extract the certificate */
            cert = OSSL_STORE_INFO_get1_CERT(store_info);
            if (cert) {
                break;
            }
        }
        OSSL_STORE_INFO_free(store_info);
        store_info = NULL;
    }

    if (!cert) {
        fprintf(stderr, "Failed to load certificate\n");
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

    return cert;
}

int main(int argc, char *argv[]) {
    const char *pkcs11_uri = NULL;
    const char *pin = NULL;
    EVP_PKEY *key = NULL;
    X509 *cert = NULL;
    int ret = -1;
    int is_private = 1;
    int is_cert = 0;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <pkcs11-uri> [pkcs11-pin]\n", argv[0]);
        return ret;
    }

    pkcs11_uri = argv[1];
    if (pkcs11_uri == NULL || strlen(pkcs11_uri) == 0) {
        fprintf(stderr, "The pkcs11-uri cannot be empty\n");
        return ret;
    }
    if (strstr(pkcs11_uri, "type=cert") != NULL) {
        is_cert = 1;
    }
    if (strstr(pkcs11_uri, "type=public") != NULL) {
        is_private = 0;
    }

    if (argc == 3) {
        pin = argv[2];
    }

    if (is_cert) {
        cert = provider_load_cert(pkcs11_uri);
        if (cert) {
            X509_NAME *subject_name = X509_get_subject_name(cert);
            if (subject_name) {
                char *subject = X509_NAME_oneline(subject_name, NULL, 0);
                if (subject) {
                    printf("Certificate Subject: %s\n", subject);
                    OPENSSL_free(subject);
                } else {
                    fprintf(stderr, "Failed to get certificate subject\n");
                }
            } else {
                fprintf(stderr, "Failed to get subject name from certificate\n");
            }
        } else {
            fprintf(stderr, "Failed to read certificate\n");
        }
    }

    else {
        if (is_private) {
            key = provider_load_private_key(pkcs11_uri, pin);
        } else {
            key = provider_load_public_key(pkcs11_uri);
        }
        if (key) {
            int key_type = EVP_PKEY_base_id(key);
            if (key_type == EVP_PKEY_RSA) {
                printf("Loaded an RSA %s key.\n", is_private ? "private" : "public");
            } else if (key_type == EVP_PKEY_EC) {
                printf("Loaded an ECC %s key.\n", is_private ? "private" : "public");
            } else {
                fprintf(stderr, "Loaded a %s key of unknown type (base_id=%d).\n", is_private ? "private" : "public", key_type);
            }
        } else {
            fprintf(stderr, "Failed to read %s key\n", is_private ? "private" : "public");
        }
    }

    if (key || cert) {
        ret = 0;
    }

    if (key) {
        EVP_PKEY_free(key);
    }

    if (cert) {
        X509_free(cert);
    }

    // Clean up sensitive data
    if (pin)
        OPENSSL_cleanse((void *)pin, strlen(pin));
    if (pkcs11_uri)
        OPENSSL_cleanse((void *)pkcs11_uri, strlen(pkcs11_uri));

    return ret;
}
