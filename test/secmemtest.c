/*
 * Copyright 2015-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>

#include "testutil.h"

static int test_sec_mem(void)
{
#if defined(OPENSSL_SYS_LINUX) || defined(OPENSSL_SYS_UNIX)
    int testresult = 0;
    char *p = NULL, *q = NULL, *r = NULL, *s = NULL;

    r = OPENSSL_secure_malloc(20);
    /* r = non-secure 20 */
    if (!TEST_ptr(r)
        || !TEST_true(CRYPTO_secure_malloc_init(4096, 32))
        || !TEST_false(CRYPTO_secure_allocated(r)))
        goto end;
    p = OPENSSL_secure_malloc(20);
    if (!TEST_ptr(p)
        /* r = non-secure 20, p = secure 20 */
        || !TEST_true(CRYPTO_secure_allocated(p))
        /* 20 secure -> 32-byte minimum allocaton unit */
        || !TEST_size_t_eq(CRYPTO_secure_used(), 32))
        goto end;
    q = OPENSSL_malloc(20);
    if (!TEST_ptr(q))
        goto end;
    /* r = non-secure 20, p = secure 20, q = non-secure 20 */
    if (!TEST_false(CRYPTO_secure_allocated(q)))
        goto end;
    s = OPENSSL_secure_malloc(20);
    if (!TEST_ptr(s)
        /* r = non-secure 20, p = secure 20, q = non-secure 20, s = secure 20 */
        || !TEST_true(CRYPTO_secure_allocated(s))
        /* 2 * 20 secure -> 64 bytes allocated */
        || !TEST_size_t_eq(CRYPTO_secure_used(), 64))
        goto end;
    OPENSSL_secure_free(p);
    p = NULL;
    /* 20 secure -> 32 bytes allocated */
    if (!TEST_size_t_eq(CRYPTO_secure_used(), 32))
        goto end;
    OPENSSL_free(q);
    q = NULL;
    /* should not complete, as secure memory is still allocated */
    if (!TEST_false(CRYPTO_secure_malloc_done())
        || !TEST_true(CRYPTO_secure_malloc_initialized()))
        goto end;
    OPENSSL_secure_free(s);
    s = NULL;
    /* secure memory should now be 0, so done should complete */
    if (!TEST_size_t_eq(CRYPTO_secure_used(), 0)
        || !TEST_true(CRYPTO_secure_malloc_done())
        || !TEST_false(CRYPTO_secure_malloc_initialized()))
        goto end;

    TEST_info("Possible infinite loop: allocate more than available");
    if (!TEST_true(CRYPTO_secure_malloc_init(32768, 16)))
        goto end;
    TEST_ptr_null(OPENSSL_secure_malloc((size_t)-1));
    TEST_true(CRYPTO_secure_malloc_done());

    TEST_info("Possible infinite loop: small arena");
    if (!TEST_false(CRYPTO_secure_malloc_init(16, 16)))
        goto end;
    TEST_false(CRYPTO_secure_malloc_initialized());
    TEST_ptr_null(OPENSSL_secure_malloc((size_t)-1));
    TEST_true(CRYPTO_secure_malloc_done());

    if (sizeof(size_t) > 4) {
        TEST_info("Possible infinite loop: 1<<31 limit");
        if (!TEST_true(CRYPTO_secure_malloc_init((size_t)1<<34, (size_t)1<<4) != 0))
            goto end;
        TEST_true(CRYPTO_secure_malloc_done());
    }
    
    /* this can complete - it was not really secure */
    testresult = 1;
 end:
    OPENSSL_secure_free(p);
    OPENSSL_free(q);
    OPENSSL_secure_free(r);
    OPENSSL_secure_free(s);
    return testresult;
#else
    /* Should fail. */
    return TEST_false(CRYPTO_secure_malloc_init(4096, 32));
#endif
}

void register_tests(void)
{
    ADD_TEST(test_sec_mem);
}
