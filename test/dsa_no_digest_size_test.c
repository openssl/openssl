/*
 * Copyright 2018-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * DSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <stdlib.h>
#include <string.h>

#include "testutil.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#include "helpers/predefined_dsaparams.h"

static DSA *dsakey;

static int genkeys(void)
{
    if (!TEST_ptr(dsakey = load_dsa_params()))
        return 0;

    if (!TEST_int_eq(DSA_generate_key(dsakey), 1))
        return 0;

    return 1;
}

static int sign_and_verify(int len)
{
    /*
     * Per FIPS 186-4, the hash is recommended to be the same length as q.
     * If the hash is longer than q, the leftmost N bits are used; if the hash
     * is shorter, then we left-pad (see appendix C.2.1).
     */
    size_t sigLength;
    int digestlen = BN_num_bytes(DSA_get0_q(dsakey));
    int ok = 0;

    unsigned char *dataToSign = OPENSSL_malloc(len);
    unsigned char *paddedData = OPENSSL_malloc(digestlen);
    unsigned char *signature = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    if (!TEST_ptr(dataToSign) || !TEST_ptr(paddedData) || !TEST_int_eq(RAND_bytes(dataToSign, len), 1))
        goto end;

    memset(paddedData, 0, digestlen);
    if (len > digestlen)
        memcpy(paddedData, dataToSign, digestlen);
    else
        memcpy(paddedData + digestlen - len, dataToSign, len);

    if (!TEST_ptr(pkey = EVP_PKEY_new()))
        goto end;
    EVP_PKEY_set1_DSA(pkey, dsakey);

    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new(pkey, NULL)))
        goto end;
    if (!TEST_int_eq(EVP_PKEY_sign_init(ctx), 1))
        goto end;

    if (EVP_PKEY_sign(ctx, NULL, &sigLength, dataToSign, len) != 1) {
        TEST_error("Failed to get signature length, len=%d", len);
        goto end;
    }

    if (!TEST_ptr(signature = OPENSSL_malloc(sigLength)))
        goto end;

    if (EVP_PKEY_sign(ctx, signature, &sigLength, dataToSign, len) != 1) {
        TEST_error("Failed to sign, len=%d", len);
        goto end;
    }

    /* Check that the signature is okay via the EVP interface */
    if (!TEST_int_eq(EVP_PKEY_verify_init(ctx), 1))
        goto end;

    /* ... using the same data we just signed */
    if (EVP_PKEY_verify(ctx, signature, sigLength, dataToSign, len) != 1) {
        TEST_error("EVP verify with unpadded length %d failed\n", len);
        goto end;
    }

    /* ... padding/truncating the data to the appropriate digest size */
    if (EVP_PKEY_verify(ctx, signature, sigLength, paddedData, digestlen) != 1) {
        TEST_error("EVP verify with length %d failed\n", len);
        goto end;
    }

    /* Verify again using the raw DSA interface */
    if (DSA_verify(0, dataToSign, len, signature, (int)sigLength, dsakey) != 1) {
        TEST_error("Verification with unpadded data failed, len=%d", len);
        goto end;
    }

    if (DSA_verify(0, paddedData, digestlen, signature, (int)sigLength, dsakey) != 1) {
        TEST_error("verify with length %d failed\n", len);
        goto end;
    }

    ok = 1;
end:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    OPENSSL_free(signature);
    OPENSSL_free(paddedData);
    OPENSSL_free(dataToSign);

    return ok;
}

static int dsa_exact_size_test(void)
{
    /*
     * For a 2048-bit p, q should be either 224 or 256 bits per the table in
     * FIPS 186-4 4.2.
     */

    return sign_and_verify(224 / 8) && sign_and_verify(256 / 8);
}

static int dsa_small_digest_test(void)
{
    return sign_and_verify(16) && sign_and_verify(1);
}

static int dsa_large_digest_test(void)
{
    return sign_and_verify(33) && sign_and_verify(64);
}

void cleanup_tests(void)
{
    DSA_free(dsakey);
}

#endif /* OPENSSL_NO_DSA */

int setup_tests(void)
{
#ifndef OPENSSL_NO_DSA
    if (!genkeys())
        return 0;

    ADD_TEST(dsa_exact_size_test);
    ADD_TEST(dsa_small_digest_test);
    ADD_TEST(dsa_large_digest_test);
#endif
    return 1;
}
