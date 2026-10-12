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

static int test_sha2_prefix(int idx)
{
    static const char *names[] = {
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
        "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f"
    };
    SLH_DSA_KEY key = { 0 };
    SLH_DSA_HASH_CTX *ctx = NULL, *dup = NULL;
    unsigned char input[128 + SLH_ADRSC_SIZE + 2144];
    unsigned char out[32], digest[64];
    size_t n, prefix, len, i, rep, sample;
    int ret = 0;

    key.params = ossl_slh_dsa_params_get(names[idx]);
    if (!TEST_ptr(key.params))
        goto end;
    n = key.params->n;
    prefix = n == 16 ? 64 : 128;
    key.pub = key.priv + 2 * n;
    key.hash_func = ossl_slh_get_hash_fn(0, key.params->security_category);
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
            if (!TEST_true(EVP_Q_digest(NULL, n == 16 ? "SHA256" : "SHA512",
                    NULL, input, prefix + SLH_ADRSC_SIZE + len, digest, NULL))
                || !TEST_true(key.hash_func->T(dup, key.pub, input + prefix,
                    input + prefix + SLH_ADRSC_SIZE, len, out, n))
                || !TEST_mem_eq(out, n, digest, n))
                goto end;
            if (len == 2 * n
                && (!TEST_true(key.hash_func->H(dup, key.pub, input + prefix,
                        input + prefix + SLH_ADRSC_SIZE,
                        input + prefix + SLH_ADRSC_SIZE + n, out, n))
                    || !TEST_mem_eq(out, n, digest, n)))
                goto end;
        }
        ossl_slh_dsa_hash_ctx_free(dup);
        dup = NULL;
    }
    ret = 1;
end:
    ossl_slh_dsa_hash_ctx_free(ctx);
    ossl_slh_dsa_hash_ctx_free(dup);
    return ret;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_sha2_prefix, 6);
    return 1;
}
