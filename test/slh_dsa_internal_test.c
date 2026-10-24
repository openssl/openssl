/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/evp.h>
#include "crypto/slh_dsa/slh_dsa_local.h"
#include "crypto/slh_dsa/slh_dsa_key.h"
#include "testutil.h"

static const char *slh_test_algorithms[] = {
    "SLH-DSA-SHA2-128s",
    "SLH-DSA-SHA2-192f",
    "SLH-DSA-SHAKE-256f"
};

static int test_hash_prefix(int idx)
{
    SLH_DSA_KEY key = { 0 };
    EVP_MD_CTX *mdctx = NULL;
    SLH_DSA_HASH_CTX *ctx = NULL, *dup = NULL;
    unsigned char input[128 + SLH_ADRSC_SIZE + 2144];
    unsigned char out[32], digest[64];
    size_t n, prefix, adrs_len, len, i, rep, sample;
    int is_shake;
    int ret = 0;

    if (!TEST_ptr(mdctx = EVP_MD_CTX_new()))
        goto end;
    key.params = ossl_slh_dsa_params_get(slh_test_algorithms[idx]);
    if (!TEST_ptr(key.params))
        goto end;
    n = key.params->n;
    is_shake = key.params->is_shake;
    prefix = is_shake ? n : n == 16 ? 64 : 128;
    adrs_len = is_shake ? SLH_ADRS_SIZE : SLH_ADRSC_SIZE;
    key.pub = key.priv + 2 * n;
    key.hash_func = ossl_slh_get_hash_fn(is_shake, key.params->security_category);
    for (sample = 0; sample < 3; sample++) {
        for (i = 0; i < n; i++)
            key.pub[i] = (unsigned char)(i * 37 + sample * 61);
        memset(input, 0, prefix);
        memcpy(input, key.pub, n);
        for (i = prefix; i < sizeof(input); i++)
            input[i] = (unsigned char)(i * 43 + sample * 71);
        if (!TEST_ptr(ctx = ossl_slh_dsa_hash_ctx_new(&key))
            || !TEST_ptr(dup = ossl_slh_dsa_hash_ctx_dup(ctx)))
            goto end;
        ossl_slh_dsa_hash_ctx_free(ctx);
        ctx = NULL;
        for (rep = 0; rep < 4; rep++) {
            len = rep == 0 ? 0 : rep == 1 ? n : rep == 2 ? 2 * n : SLH_WOTS_LEN(n) * n;
            input[prefix] ^= (unsigned char)(rep + 1);
            if (is_shake) {
                if (!TEST_true(EVP_DigestInit_ex(mdctx, EVP_shake256(), NULL))
                    || !TEST_true(EVP_DigestUpdate(mdctx, input, prefix + adrs_len + len))
                    || !TEST_true(EVP_DigestFinalXOF(mdctx, digest, n)))
                    goto end;
            } else if (!TEST_true(EVP_Q_digest(NULL, n == 16 ? "SHA256" : "SHA512",
                           NULL, input, prefix + adrs_len + len, digest, NULL))) {
                goto end;
            }
            if (!TEST_true(key.hash_func->T(dup, key.pub, input + prefix,
                    input + prefix + adrs_len, len, out, n))
                || !TEST_mem_eq(out, n, digest, n))
                goto end;
            if (len == 2 * n
                && (!TEST_true(key.hash_func->H(dup, key.pub, input + prefix,
                        input + prefix + adrs_len,
                        input + prefix + adrs_len + n, out, n))
                    || !TEST_mem_eq(out, n, digest, n)))
                goto end;
        }
        ossl_slh_dsa_hash_ctx_free(dup);
        dup = NULL;
    }
    ret = 1;
end:
    EVP_MD_CTX_free(mdctx);
    ossl_slh_dsa_hash_ctx_free(ctx);
    ossl_slh_dsa_hash_ctx_free(dup);
    return ret;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_hash_prefix, OSSL_NELEM(slh_test_algorithms));
    return 1;
}
