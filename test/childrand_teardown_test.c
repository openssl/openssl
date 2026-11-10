/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Test that a child libctx's RAND thread state is torn down safely when
 * it outlives the parent libctx's method store.
 *
 * p_childrand creates a child libctx and instantiates its public DRBG in
 * the child's thread state; the DRBG's cipher is cached in the parent
 * libctx's method store.  Freeing the parent libctx tears down the
 * method store while the child-owning provider's real free is deferred
 * (a reference from the child libctx keeps it alive), so the child libctx
 * and its RAND thread state survive.  The thread state is freed by
 * OPENSSL_thread_stop() from the cleanup destructor at process exit, and
 * must not touch the cipher that died with the method store.
 *
 * A failure manifests as a crash (e.g. SIGSEGV in drbg_ctr_free via
 * EVP_CIPHER_CTX_free on the freed cipher) at process exit, i.e. after
 * the test itself has reported success.
 */

#include <openssl/crypto.h>
#include <openssl/provider.h>

#include "testutil.h"

/*
 * The provider handles are held in file scope deliberately: the
 * surviving references defer the providers' free past the libctx
 * teardown below - that deferral is the scenario under test.  Being
 * reachable at process exit also keeps LeakSanitizer quiet; the
 * resources are cleaned up by the exit-time teardown.
 */
static OSSL_PROVIDER *defprov = NULL;
static OSSL_PROVIDER *childprov = NULL;

static int test_childrand_teardown(void)
{
    int ret = 0;
    OSSL_LIB_CTX *libctx = OSSL_LIB_CTX_new();

    if (!TEST_ptr(libctx)
        || !TEST_ptr(defprov = OSSL_PROVIDER_load(libctx, "default"))
        || !TEST_ptr(childprov = OSSL_PROVIDER_load(libctx, "p_childrand")))
        goto err;

    ret = 1;
err:
    OSSL_LIB_CTX_free(libctx);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_childrand_teardown);
    return 1;
}
