/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Regression test for https://github.com/openssl/openssl/issues/33399
 *
 * OSSL_DECODER_do_all_provided() walks a copy of the method store taken
 * under the store lock, but runs its callbacks after the lock is released.
 * If a provider is unloaded at that moment, the implementations in the copy
 * must not be freed under the walker.
 *
 * Run decoder construction and decoding concurrently with threads that keep
 * loading and unloading the default provider.  A failure shows up as a crash
 * or, in sanitizer builds, as a use-after-free report.
 */

#include <openssl/decoder.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/x509.h>

#include "testutil.h"
#include "threadstest.h"

/* An EC P-384 public key in SubjectPublicKeyInfo (DER) form */
static const unsigned char ec_spki_der[] = {
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04,
    0x1f, 0x4f, 0x33, 0x87, 0x33, 0x29, 0x8a, 0xa1, 0x84, 0xde, 0xcb, 0xc7,
    0x21, 0x58, 0x41, 0x89, 0xea, 0x56, 0x9d, 0x2b, 0x4b, 0x85, 0xc6, 0x1d,
    0x4c, 0x27, 0xbc, 0x7f, 0x26, 0x51, 0x72, 0x6f, 0xe2, 0x9f, 0xd6, 0xa3,
    0xca, 0xcc, 0x45, 0x14, 0x46, 0x8b, 0xad, 0xef, 0x7e, 0x86, 0x8c, 0xec,
    0xb1, 0x7e, 0x2f, 0xff, 0xa9, 0x71, 0x9d, 0x18, 0x84, 0x45, 0x04, 0x41,
    0x55, 0x6e, 0x2b, 0xea, 0x26, 0x7f, 0xbb, 0x90, 0x01, 0xe3, 0x4b, 0x19,
    0xba, 0xe4, 0x54, 0x96, 0x45, 0x09, 0xb1, 0xd5, 0x6c, 0x91, 0x44, 0xad,
    0x84, 0x13, 0x8e, 0x9a, 0x8c, 0x0d, 0x80, 0x0c, 0x32, 0xf6, 0xe0, 0x27
};

#define NUM_DECODER_THREADS 4
#define NUM_PROVIDER_THREADS 2
#define DECODER_ITERATIONS 2000
#define PROVIDER_ITERATIONS 20000

static void decoder_thread(void)
{
    int i;

    for (i = 0; i < DECODER_ITERATIONS; i++) {
        EVP_PKEY *pkey = NULL;
        OSSL_DECODER_CTX *dctx;
        const unsigned char *p = ec_spki_der;
        size_t len = sizeof(ec_spki_der);

        /*
         * Neither call is checked: with the provider being unloaded
         * concurrently there may legitimately be no decoder available.
         */
        dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", "SubjectPublicKeyInfo",
            "id-ecPublicKey",
            EVP_PKEY_PUBLIC_KEY, NULL, NULL);
        if (dctx != NULL) {
            (void)OSSL_DECODER_from_data(dctx, &p, &len);
            OSSL_DECODER_CTX_free(dctx);
        }
        EVP_PKEY_free(pkey);
    }
}

static void provider_thread(void)
{
    int i;

    for (i = 0; i < PROVIDER_ITERATIONS; i++) {
        OSSL_PROVIDER *prov = OSSL_PROVIDER_load(NULL, "default");

        if (prov != NULL)
            OSSL_PROVIDER_unload(prov);
    }
}

static int test_decoder_unload_race(void)
{
    thread_t dthreads[NUM_DECODER_THREADS];
    thread_t pthreads[NUM_PROVIDER_THREADS];
    int i, testresult = 1;

    for (i = 0; i < NUM_PROVIDER_THREADS; i++)
        if (!TEST_true(run_thread(&pthreads[i], provider_thread)))
            testresult = 0;
    for (i = 0; i < NUM_DECODER_THREADS; i++)
        if (!TEST_true(run_thread(&dthreads[i], decoder_thread)))
            testresult = 0;
    for (i = 0; i < NUM_DECODER_THREADS; i++)
        if (!TEST_true(wait_for_thread(dthreads[i])))
            testresult = 0;
    for (i = 0; i < NUM_PROVIDER_THREADS; i++)
        if (!TEST_true(wait_for_thread(pthreads[i])))
            testresult = 0;

    return testresult;
}

int setup_tests(void)
{
    ADD_TEST(test_decoder_unload_race);
    return 1;
}
