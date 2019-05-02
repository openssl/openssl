/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal/nelem.h"
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include "testutil.h"

static int pkey_param_types[] = {
#ifndef OPENSSL_NO_DH
    EVP_PKEY_DH,
#endif
#ifndef OPENSSL_NO_DSA
    EVP_PKEY_DSA,
#endif
#ifndef OPENSSL_NO_EC
    EVP_PKEY_EC
#endif
};

#if !defined(OPENSSL_NO_DH) || !defined(OPENSSL_NO_DSA) || !defined(OPENSSL_NO_EC)

static int params_bio_test(int id)
{
    int ret;
    BIO *mem_bio = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *params_key = NULL, *out_key = NULL;
    int type = pkey_param_types[id];

    ret =
        TEST_ptr(mem_bio = BIO_new(BIO_s_mem()))
        && TEST_ptr(ctx = EVP_PKEY_CTX_new_id(type, NULL))
        && TEST_int_gt(EVP_PKEY_paramgen_init(ctx), 0)
        && (type != EVP_PKEY_EC
           || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp256k1) > 0)
        && TEST_int_gt(EVP_PKEY_paramgen(ctx, &params_key), 0)
        && TEST_int_gt(i2d_KeyParams_bio(mem_bio, params_key), 0)
        && TEST_ptr(d2i_KeyParams_bio(type, &out_key, mem_bio))
        && TEST_int_gt(EVP_PKEY_cmp_parameters(out_key, params_key), 0);

    BIO_free(mem_bio);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(params_key);
    EVP_PKEY_free(out_key);
    return ret;
}
#endif

int setup_tests(void)
{
#if defined(OPENSSL_NO_DH) && defined(OPENSSL_NO_DSA) && defined(OPENSSL_NO_EC)
    TEST_note("No DH/DSA/EC support");
#else
    ADD_ALL_TESTS(params_bio_test, OSSL_NELEM(pkey_param_types));
#endif
    return 1;
}
