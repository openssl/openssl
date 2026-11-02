/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

/*
 * Regression test for https://github.com/openssl/openssl/issues/33399
 *
 * ossl_method_store_do_all() copies the algorithm list under the store read
 * lock but calls the user callbacks after releasing it.  If a provider is
 * unloaded concurrently, provider_remove_store_methods() frees the
 * implementations that were just copied out, and the callbacks operate on
 * freed memory (observed as a SIGSEGV in OSSL_PROVIDER_get0_provider_ctx()
 * from OSSL_DECODER_CTX_new_for_pkey(), with the provider pointer holding
 * garbage).
 *
 * The test runs decoder threads doing OSSL_DECODER_CTX_new_for_pkey() plus
 * OSSL_DECODER_from_data() concurrently with threads that repeatedly load and
 * unload the default provider.  Without the fix this crashes under
 * sanitizers (and intermittently in release builds).
 */

#include <string.h>
#include <openssl/decoder.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/x509.h>

#include "internal/tsan_assist.h"
#include "testutil.h"
#include "threadstest.h"

/* An EC P-384 public key in SubjectPublicKeyInfo (DER) form */
static const unsigned char ec_spki_der[] = {
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0x1f, 0x4f, 0x33, 0x87, 0x33, 0x29, 0x8a, 0xa1,
    0x84, 0xde, 0xcb, 0xc7, 0x21, 0x58, 0x41, 0x89, 0xea, 0x56, 0x9d, 0x2b, 0x4b, 0x85, 0xc6, 0x1d,
    0x4c, 0x27, 0xbc, 0x7f, 0x26, 0x51, 0x72, 0x6f, 0xe2, 0x9f, 0xd6, 0xa3, 0xca, 0xcc, 0x45, 0x14,
    0x46, 0x8b, 0xad, 0xef, 0x7e, 0x86, 0x8c, 0xec, 0xb1, 0x7e, 0x2f, 0xff, 0xa9, 0x71, 0x9d, 0x18,
    0x84, 0x45, 0x04, 0x41, 0x55, 0x6e, 0x2b, 0xea, 0x26, 0x7f, 0xbb, 0x90, 0x01, 0xe3, 0x4b, 0x19,
    0xba, 0xe4, 0x54, 0x96, 0x45, 0x09, 0xb1, 0xd5, 0x6c, 0x91, 0x44, 0xad, 0x84, 0x13, 0x8e, 0x9a,
    0x8c, 0x0d, 0x80, 0x0c, 0x32, 0xf6, 0xe0, 0x27
};

#define N_DECODER_THREADS   4
#define N_PROVIDER_THREADS  2
#define DECODER_ITERATIONS  30000
#define PROVIDER_CYCLES     200000

/*
 * Counts successful decodes.  Individual decode attempts may legitimately
 * fail while the provider is being loaded and unloaded concurrently (there
 * may be no decoder available at that moment), so only the aggregate is
 * checked.  The primary failure mode this test detects is a crash.
 */
static TSAN_QUALIFIER unsigned int decoded_ok = 0;
static TSAN_QUALIFIER int load_failed = 0;

static void decoder_thread_fn(void)
{
    int i;

    for (i = 0; i < DECODER_ITERATIONS; i++) {
        EVP_PKEY *pkey = NULL;
        OSSL_DECODER_CTX *dctx;
        const unsigned char *p = ec_spki_der;
        size_t len = sizeof(ec_spki_der);

        dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", "SubjectPublicKeyInfo",
                                             "id-ecPublicKey", EVP_PKEY_PUBLIC_KEY,
                                             NULL, NULL);
        if (dctx != NULL) {
            if (OSSL_DECODER_from_data(dctx, &p, &len))
                tsan_store(&decoded_ok, tsan_load(&decoded_ok) + 1);
            OSSL_DECODER_CTX_free(dctx);
        }
        EVP_PKEY_free(pkey);
    }
}

static void provider_thread_fn(void)
{
    int i;

    for (i = 0; i < PROVIDER_CYCLES; i++) {
        OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, "default");

        if (prov == NULL) {
            tsan_store(&load_failed, 1);
            return;
        }
        OSSL_PROVIDER_unload(prov);
    }
}

static int test_decoder_unload_race(void)
{
    thread_t dthreads[N_DECODER_THREADS];
    thread_t pthreads[N_PROVIDER_THREADS];
    int i, ok = 1;

    for (i = 0; i < N_PROVIDER_THREADS; i++)
        ok &= TEST_true(run_thread(&pthreads[i], provider_thread_fn));
    for (i = 0; i < N_DECODER_THREADS; i++)
        ok &= TEST_true(run_thread(&dthreads[i], decoder_thread_fn));
    for (i = 0; i < N_DECODER_THREADS; i++)
        ok &= TEST_true(wait_for_thread(dthreads[i]));
    for (i = 0; i < N_PROVIDER_THREADS; i++)
        ok &= TEST_true(wait_for_thread(pthreads[i]));

    ok &= TEST_int_eq(tsan_load(&load_failed), 0);
    ok &= TEST_uint_gt(tsan_load(&decoded_ok), 0);
    return ok;
}

int setup_tests(void)
{
    ADD_TEST(test_decoder_unload_race);
    return 1;
}
