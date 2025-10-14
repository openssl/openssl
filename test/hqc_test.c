/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include "internal/nelem.h"
#include "testutil.h"

static int hqc_generate_and_validate_key(int idx)
{
    const char *alg_name[] = { "HQC-128", "HQC-192", "HQC-256" };
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int ret = 0;

    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name[idx], NULL))
        || !TEST_int_eq(EVP_PKEY_keygen_init(ctx), 1)
        || !TEST_int_eq(EVP_PKEY_generate(ctx, &pkey), 1))
        goto err;

    EVP_PKEY_CTX_free(ctx);
    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new(pkey, NULL))
        || !EVP_PKEY_private_check(ctx)
        || !EVP_PKEY_public_check(ctx))
        goto err;

    ret = 1;
err:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(hqc_generate_and_validate_key, 3);
    return 1;
}
