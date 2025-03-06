/*
 * Copyright 2021-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/kdf.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>

#include <openssl/evp.h>
#include <openssl/indicator.h>

static int fips_indicator_cb(const char *type, const char *desc, const OSSL_PARAM params[]) {
  printf("FIPS INDICATOR: %s : %s is not approved\n", type, desc);
  return 0;
}

/*
 * test vector from
 * https://datatracker.ietf.org/doc/html/rfc7914
 */

/*
 * Hard coding a password into an application is very bad.
 * It is done here solely for educational purposes.
 */
static unsigned char password[] = {
    'P', 'a', 's', 's', 'w', 'o', 'r', 'd'
};

/*
 * The salt is better not being hard coded too.  Each password should have a
 * different salt if possible.  The salt is not considered secret information
 * and is safe to store with an encrypted password.
 */
static unsigned char pbkdf2_salt[] = {
    'N', 'a', 'C', 'l'
};

/*
 * The iteration parameter can be variable or hard coded.  The disadvantage with
 * hard coding them is that they cannot easily be adjusted for future
 * technological improvements appear.
 */

// Use small bad value
static unsigned int pbkdf2_iterations = 10;

static const unsigned char expected_output[] = {

    0xed, 0x0a, 0xb2, 0x81, 0x14, 0x4c, 0x5a, 0xb2,
    0xc8, 0x38, 0x5d, 0xbb, 0xe9, 0x7c, 0x11, 0x45,
    0x53, 0x55, 0xb3, 0x68, 0xf5, 0xef, 0x53, 0xa5,
    0x38, 0x73, 0xaa, 0x65, 0x73, 0x00, 0x8e, 0x68,
    0xd4, 0x6e, 0xec, 0xaa, 0xdc, 0x5d, 0xd6, 0x8f,
    0x89, 0xbd, 0xef, 0x03, 0x30, 0xc7, 0x5f, 0x3d,
    0x81, 0x86, 0x8f, 0x77, 0x8e, 0x4d, 0x88, 0x79,
    0x42, 0x56, 0xc2, 0x25, 0xaf, 0x16, 0x74, 0xc4
};

int main(int argc, char **argv)
{
    int ret = EXIT_FAILURE;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    unsigned char out[64];
    OSSL_PARAM params[6], *p = params;

    /* Check if we are in FIPS mode */
    if (EVP_default_properties_is_fips_enabled(NULL)) {
        fprintf(stderr, "FIPS is on\n");
    } else {
        fprintf(stderr, "FIPS is off\n");
    }

    /* Fetch the key derivation function implementation */
    kdf = EVP_KDF_fetch(NULL, "PBKDF2", NULL);
    if (kdf == NULL) {
        fprintf(stderr, "EVP_KDF_fetch() returned NULL\n");
        goto end;
    }

    /* Set indicator callback */
    OSSL_INDICATOR_set_callback(NULL, fips_indicator_cb);

    /* Create a context for the key derivation operation */
    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL) {
        fprintf(stderr, "EVP_KDF_CTX_new() returned NULL\n");
        goto end;
    }

    /* Set password */
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, password,
                                             sizeof(password));
    /* Set salt */
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, pbkdf2_salt,
                                             sizeof(pbkdf2_salt));
    /* Set way too low interation count */
    pbkdf2_iterations = 10;
    *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &pbkdf2_iterations);
    /* Set the underlying hash function used to derive the key */
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            "SHA256", 0);

    int pkcs5 = 0;
    if (argc>1 && strcmp(argv[1],"1")==0)
        pkcs5 = 1;
    printf("Testing with pkcs5 set to %i\n", pkcs5);
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_PKCS5, &pkcs5);
    *p = OSSL_PARAM_construct_end();

    /* Derive the key */
    if (EVP_KDF_derive(kctx, out, sizeof(out), params) != 1) {
        fprintf(stderr, "EVP_KDF_derive() failed, as expected\n");
        ret = EXIT_SUCCESS;
    } else {
        printf("EVP_KDF_derive() is unexpectedly successful\n");
    }

    if (CRYPTO_memcmp(expected_output, out, sizeof(expected_output)) != 0) {
        fprintf(stderr, "Generated key does not match expected value as expected\n");
    } else {
        fprintf(stderr, "Generated key matches.... but should have failed to generate, unless unapproved\n");
    }
    
    /* Get FIPS indicator */
    p = params;
    int fips_indicator = -1;
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_FIPS_APPROVED_INDICATOR, &fips_indicator);
    *p = OSSL_PARAM_construct_end();
    if (!EVP_KDF_CTX_get_params(kctx, params))
        printf("Failed to get params\n");
    if (OSSL_PARAM_modified(params))
        printf("Service indicator for OSSL_KDF_PARAM_FIPS_APPROVED_INDICATOR is: %d\n", fips_indicator);
    else
        printf("Service indicator for OSSL_KDF_PARAM_FIPS_APPROVED_INDICATOR is not available\n");

end:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ret;
}
