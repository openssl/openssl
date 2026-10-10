/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Regression test for allocation failures during the lazy initialisation of
 * the error string table (do_err_strings_init() in crypto/err/err.c).
 *
 * Reporting such an allocation failure creates the thread's error state,
 * which in turn requests the loading of the crypto error strings.  That used
 * to re-enter the error string CRYPTO_ONCE from inside its own init routine,
 * deadlocking (or aborting, depending on the platform).
 *
 * The error string table is initialised only once per process, so the
 * scenario is run from global_init(), before the test framework itself has
 * done anything that might initialise it.  The index of the (single)
 * allocation to fail, counted from the start of the call to
 * ERR_reason_error_string(), is taken from the ERR_STRING_INIT_FAIL_AT
 * environment variable; the recipe runs this program once per index.
 *
 * If ERR_STRING_INIT_FAIL_PERSIST is set, that allocation and all later ones
 * fail.  Reporting each failure then fails to allocate as well, which used to
 * recurse until the stack was exhausted.
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include "testutil.h"

#if !defined(OPENSSL_SYS_WINDOWS)
#include <signal.h>
#include <unistd.h>

/* Turn a deadlock into a prompt failure rather than a hung test run */
#define SCENARIO_TIMEOUT 30
#endif

static int armed = 0;
static int fail_at = -1;
static int persist = 0;
static int alloc_count = 0;
static int injected = 0;
static int scenario_done = 0;

static int should_fail(void)
{
    int n;

    if (!armed)
        return 0;
    n = alloc_count++;
    if (n == fail_at || (persist && fail_at >= 0 && n > fail_at)) {
        injected = 1;
        return 1;
    }
    return 0;
}

static void *test_malloc(size_t num, const char *file, int line)
{
    if (should_fail())
        return NULL;
    return malloc(num);
}

static void *test_realloc(void *addr, size_t num, const char *file, int line)
{
    if (should_fail())
        return NULL;
    return realloc(addr, num);
}

static void test_free(void *addr, const char *file, int line)
{
    free(addr);
}

static int test_err_string_init_alloc_failure(void)
{
    if (!TEST_true(scenario_done))
        return 0;
    TEST_info("allocation %d%s of %d %s", fail_at, persist ? " onwards" : "",
        alloc_count, injected ? "failed" : "not reached");

    /* Error reporting must still work afterwards */
    ERR_clear_error();
    ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
    if (!TEST_int_eq(ERR_GET_REASON(ERR_peek_error()), ERR_R_INTERNAL_ERROR))
        return 0;
    ERR_clear_error();
    return 1;
}

int setup_tests(void)
{
    ADD_TEST(test_err_string_init_alloc_failure);
    return 1;
}

int global_init(void)
{
    const char *e = getenv("ERR_STRING_INIT_FAIL_AT");

    if (e != NULL && *e != '\0')
        fail_at = atoi(e);
    e = getenv("ERR_STRING_INIT_FAIL_PERSIST");
    persist = e != NULL && *e != '\0';

    if (!CRYPTO_set_mem_functions(test_malloc, test_realloc, test_free))
        return 0;

    /*
     * Make sure the base initialisation is done before arming the failure
     * injection, this does not touch the error strings.  (Passing no options
     * at all would return early without doing any initialisation.)
     */
    if (!OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL))
        return 0;

#if !defined(OPENSSL_SYS_WINDOWS)
    alarm(SCENARIO_TIMEOUT);
#endif
    armed = 1;
    /* The result may be NULL if initialisation failed, we only must return */
    (void)ERR_reason_error_string(ERR_R_MALLOC_FAILURE);
    armed = 0;
#if !defined(OPENSSL_SYS_WINDOWS)
    alarm(0);
#endif
    scenario_done = 1;

    return 1;
}
