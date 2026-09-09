/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>

#include <openssl/ssl.h>
#ifdef DIRECT_CRYPTO_CALLS
#include <openssl/crypto.h>
#include <openssl/provider.h>
#endif

int main(void)
{
    SSL_CTX *ctx = NULL;
#ifdef DIRECT_CRYPTO_CALLS
    /* Exercise libcrypto directly */
    printf("Linked against %s\n", OpenSSL_version(OPENSSL_VERSION));
#endif

    /* Exercise libssl */
    ctx = SSL_CTX_new(TLS_method());
    if (ctx == NULL) {
        fprintf(stderr, "SSL_CTX_new() failed\n");
        return EXIT_FAILURE;
    }
    SSL_CTX_free(ctx);

#if defined(DIRECT_CRYPTO_CALLS) && defined(TEST_LEGACY_PROVIDER)
    /*
     * Exercise the provider module search path.  This relies on
     * OPENSSL_MODULES being set appropriately in the environment.
     */
    {
        OSSL_PROVIDER *legacy = NULL;
        OSSL_PROVIDER *def = NULL;

        legacy = OSSL_PROVIDER_load(NULL, "legacy");
        if (legacy == NULL) {
            fprintf(stderr, "OSSL_PROVIDER_load(\"legacy\") failed\n");
            return EXIT_FAILURE;
        }
        def = OSSL_PROVIDER_load(NULL, "default");
        if (def == NULL) {
            fprintf(stderr, "OSSL_PROVIDER_load(\"default\") failed\n");
            OSSL_PROVIDER_unload(legacy);
            return EXIT_FAILURE;
        }
        OSSL_PROVIDER_unload(def);
        OSSL_PROVIDER_unload(legacy);
    }
#endif

    return EXIT_SUCCESS;
}
