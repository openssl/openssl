/*
 * Copyright 2011-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* We need to use some deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

#include <string.h>
#include "internal/nelem.h"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/core_names.h>
#include <stdint.h>
#include "../crypto/rand/rand_local.h"
#include "../include/crypto/rand.h"
#include "../include/crypto/evp.h"
#include "../providers/implementations/include/prov/drbg.h"
#include "../crypto/evp/evp_local.h"

#if defined(_WIN32)
#include <windows.h>
#endif

#if defined(OPENSSL_SYS_UNIX)
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "testutil.h"

/*
 * DRBG generate wrappers
 */
static int gen_bytes(EVP_RAND_CTX *drbg, unsigned char *buf, int num)
{
#ifndef OPENSSL_NO_DEPRECATED_3_0
    const RAND_METHOD *meth = RAND_get_rand_method();

    if (meth != NULL && meth != RAND_OpenSSL()) {
        if (meth->bytes != NULL)
            return meth->bytes(buf, num);
        return -1;
    }
#endif

    if (drbg != NULL)
        return EVP_RAND_generate(drbg, buf, num, 0, 0, NULL, 0);
    return 0;
}

static int rand_bytes(unsigned char *buf, int num)
{
    return gen_bytes(RAND_get0_public(NULL), buf, num);
}

static int rand_priv_bytes(unsigned char *buf, int num)
{
    return gen_bytes(RAND_get0_private(NULL), buf, num);
}

/* size of random output generated in test_drbg_reseed() */
#define RANDOM_SIZE 16

/*
 * DRBG query functions
 */
static int state(EVP_RAND_CTX *drbg)
{
    return EVP_RAND_get_state(drbg);
}

static unsigned int query_rand_uint(EVP_RAND_CTX *drbg, const char *name)
{
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    unsigned int n;

    *params = OSSL_PARAM_construct_uint(name, &n);
    if (EVP_RAND_CTX_get_params(drbg, params))
        return n;
    return 0;
}

#define DRBG_UINT(name)                          \
    static unsigned int name(EVP_RAND_CTX *drbg) \
    {                                            \
        return query_rand_uint(drbg, #name);     \
    }
DRBG_UINT(reseed_counter)

static PROV_DRBG *prov_rand(EVP_RAND_CTX *drbg)
{
    return (PROV_DRBG *)drbg->algctx;
}

static void set_reseed_counter(EVP_RAND_CTX *drbg, unsigned int n)
{
    PROV_DRBG *p = prov_rand(drbg);

    p->reseed_counter = n;
}

static void inc_reseed_counter(EVP_RAND_CTX *drbg)
{
    set_reseed_counter(drbg, reseed_counter(drbg) + 1);
}

static time_t reseed_time(EVP_RAND_CTX *drbg)
{
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    time_t t;

    *params = OSSL_PARAM_construct_time_t(OSSL_DRBG_PARAM_RESEED_TIME, &t);
    if (EVP_RAND_CTX_get_params(drbg, params))
        return t;
    return 0;
}

/*
 * When building the FIPS module, it isn't possible to disable the continuous
 * RNG tests.  Tests that require this are skipped and this means a detection
 * mechanism for the FIPS provider being in use.
 */
static int using_fips_rng(void)
{
    EVP_RAND_CTX *primary = RAND_get0_primary(NULL);
    const OSSL_PROVIDER *prov;
    const char *name;

    if (!TEST_ptr(primary))
        return 0;

    prov = EVP_RAND_get0_provider(EVP_RAND_CTX_get0_rand(primary));
    if (!TEST_ptr(prov))
        return 0;
    name = OSSL_PROVIDER_get0_name(prov);
    return strstr(name, "FIPS Provider") != NULL;
}

/*
 * Disable CRNG testing if it is enabled.
 * This stub remains to indicate the calling locations where it is necessary.
 * Once the RNG infrastructure is able to disable these tests, it should be
 * reconstituted.
 */
static int disable_crngt(EVP_RAND_CTX *drbg)
{
    return 1;
}

/*
 * Generates random output using rand_bytes() and rand_priv_bytes()
 * and checks whether the three shared DRBGs were reseeded as
 * expected.
 *
 * |expect_success|: expected outcome (as reported by RAND_status())
 * |primary|, |public|, |private|: pointers to the three shared DRBGs
 * |public_random|, |private_random|: generated random output
 * |expect_xxx_reseed| =
 *       1:  it is expected that the specified DRBG is reseeded
 *       0:  it is expected that the specified DRBG is not reseeded
 *      -1:  don't check whether the specified DRBG was reseeded or not
 * |reseed_when|: if nonzero, used instead of time(NULL) to set the
 *                |before_reseed| time.
 */
static int test_drbg_reseed(int expect_success,
    EVP_RAND_CTX *primary,
    EVP_RAND_CTX *public,
    EVP_RAND_CTX *private,
    unsigned char *public_random,
    unsigned char *private_random,
    int expect_primary_reseed,
    int expect_public_reseed,
    int expect_private_reseed,
    time_t reseed_when)
{
    time_t before_reseed, after_reseed;
    int expected_state = (expect_success ? EVP_RAND_STATE_READY : EVP_RAND_STATE_ERROR);
    unsigned int primary_reseed, public_reseed, private_reseed;
    unsigned char dummy[RANDOM_SIZE];

    if (public_random == NULL)
        public_random = dummy;

    if (private_random == NULL)
        private_random = dummy;

    /*
     * step 1: check preconditions
     */

    /* Test whether seed propagation is enabled */
    if (!TEST_int_ne(primary_reseed = reseed_counter(primary), 0)
        || !TEST_int_ne(public_reseed = reseed_counter(public), 0)
        || !TEST_int_ne(private_reseed = reseed_counter(private), 0))
        return 0;

    /*
     * step 2: generate random output
     */

    if (reseed_when == 0)
        reseed_when = time(NULL);

    /* Generate random output from the public and private DRBG */
    before_reseed = expect_primary_reseed == 1 ? reseed_when : 0;
    if (!TEST_int_eq(rand_bytes((unsigned char *)public_random,
                         RANDOM_SIZE),
            expect_success)
        || !TEST_int_eq(rand_priv_bytes((unsigned char *)private_random,
                            RANDOM_SIZE),
            expect_success))
        return 0;
    after_reseed = time(NULL);

    /*
     * step 3: check postconditions
     */

    /* Test whether reseeding succeeded as expected */
    if (!TEST_int_eq(state(primary), expected_state)
        || !TEST_int_eq(state(public), expected_state)
        || !TEST_int_eq(state(private), expected_state))
        return 0;

    if (expect_primary_reseed >= 0) {
        /* Test whether primary DRBG was reseeded as expected */
        if (!TEST_int_ge(reseed_counter(primary), primary_reseed))
            return 0;
    }

    if (expect_public_reseed >= 0) {
        /* Test whether public DRBG was reseeded as expected */
        if (!TEST_int_ge(reseed_counter(public), public_reseed)
            || !TEST_uint_ge(reseed_counter(public),
                reseed_counter(primary)))
            return 0;
    }

    if (expect_private_reseed >= 0) {
        /* Test whether public DRBG was reseeded as expected */
        if (!TEST_int_ge(reseed_counter(private), private_reseed)
            || !TEST_uint_ge(reseed_counter(private),
                reseed_counter(primary)))
            return 0;
    }

    if (expect_success == 1) {
        /* Test whether reseed time of primary DRBG is set correctly */
        if (!TEST_time_t_le(before_reseed, reseed_time(primary))
            || !TEST_time_t_le(reseed_time(primary), after_reseed))
            return 0;

        /* Test whether reseed times of child DRBGs are synchronized with primary */
        if (!TEST_time_t_ge(reseed_time(public), reseed_time(primary))
            || !TEST_time_t_ge(reseed_time(private), reseed_time(primary)))
            return 0;
    } else {
        ERR_clear_error();
    }

    return 1;
}

#if defined(OPENSSL_SYS_UNIX) && !defined(OPENSSL_RAND_SEED_EGD)
/* number of children to fork */
#define DRBG_FORK_COUNT 9
/* two results per child, two for the parent */
#define DRBG_FORK_RESULT_COUNT (2 * (DRBG_FORK_COUNT + 1))

typedef struct drbg_fork_result_st {

    unsigned char random[RANDOM_SIZE]; /* random output */

    int pindex; /* process index (0: parent, 1,2,3...: children)*/
    pid_t pid; /* process id */
    int private; /* true if the private drbg was used */
    char name[10]; /* 'parent' resp. 'child 1', 'child 2', ... */
} drbg_fork_result;

/*
 * Sort the drbg_fork_result entries in lexicographical order
 *
 * This simplifies finding duplicate random output and makes
 * the printout in case of an error more readable.
 */
static int compare_drbg_fork_result(const void *left, const void *right)
{
    int result;
    const drbg_fork_result *l = left;
    const drbg_fork_result *r = right;

    /* separate public and private results */
    result = l->private - r->private;

    if (result == 0)
        result = memcmp(l->random, r->random, RANDOM_SIZE);

    if (result == 0)
        result = l->pindex - r->pindex;

    return result;
}

/*
 * Sort two-byte chunks of random data
 *
 * Used for finding collisions in two-byte chunks
 */
static int compare_rand_chunk(const void *left, const void *right)
{
    return memcmp(left, right, 2);
}

/*
 * Test whether primary, public and private DRBG are reseeded
 * in the child after forking the process. Collect the random
 * output of the public and private DRBG and send it back to
 * the parent process.
 */
static int test_drbg_reseed_in_child(EVP_RAND_CTX *primary,
    EVP_RAND_CTX *public,
    EVP_RAND_CTX *private,
    drbg_fork_result result[2])
{
    int rv = 0, status;
    int fd[2];
    pid_t pid;
    unsigned char random[2 * RANDOM_SIZE];

    if (!TEST_int_ge(pipe(fd), 0))
        return 0;

    if (!TEST_int_ge(pid = fork(), 0)) {
        close(fd[0]);
        close(fd[1]);
        return 0;
    } else if (pid > 0) {

        /* I'm the parent; close the write end */
        close(fd[1]);

        /* wait for children to terminate and collect their random output */
        if (TEST_int_eq(waitpid(pid, &status, 0), pid)
            && TEST_int_eq(status, 0)
            && TEST_true(read(fd[0], &random[0], sizeof(random))
                == sizeof(random))) {

            /* random output of public drbg */
            result[0].pid = pid;
            result[0].private = 0;
            memcpy(result[0].random, &random[0], RANDOM_SIZE);

            /* random output of private drbg */
            result[1].pid = pid;
            result[1].private = 1;
            memcpy(result[1].random, &random[RANDOM_SIZE], RANDOM_SIZE);

            rv = 1;
        }

        /* close the read end */
        close(fd[0]);

        return rv;

    } else {

        /* I'm the child; close the read end */
        close(fd[0]);

        /* check whether all three DRBGs reseed and send output to parent */
        if (TEST_true(test_drbg_reseed(1, primary, public, private,
                &random[0], &random[RANDOM_SIZE],
                1, 1, 1, 0))
            && TEST_true(write(fd[1], random, sizeof(random))
                == sizeof(random))) {

            rv = 1;
        }

        /* close the write end */
        close(fd[1]);

        /* convert boolean to exit code */
        exit(rv == 0);
    }
}

static int test_rand_reseed_on_fork(EVP_RAND_CTX *primary,
    EVP_RAND_CTX *public,
    EVP_RAND_CTX *private)
{
    unsigned int i;
    pid_t pid = getpid();
    int verbose = (getenv("V") != NULL);
    int success = 1;
    int duplicate[2] = { 0, 0 };
    unsigned char random[2 * RANDOM_SIZE];
    unsigned char sample[DRBG_FORK_RESULT_COUNT * RANDOM_SIZE];
    unsigned char *psample = &sample[0];
    drbg_fork_result result[DRBG_FORK_RESULT_COUNT];
    drbg_fork_result *presult = &result[2];

    memset(&result, 0, sizeof(result));

    for (i = 1; i <= DRBG_FORK_COUNT; ++i) {

        presult[0].pindex = presult[1].pindex = i;

        snprintf(presult[0].name, sizeof(presult[0].name), "child %d", i);
        strcpy(presult[1].name, presult[0].name);

        /* collect the random output of the children */
        if (!TEST_true(test_drbg_reseed_in_child(primary,
                public,
                private,
                presult)))
            return 0;

        presult += 2;
    }

    /* collect the random output of the parent */
    if (!TEST_true(test_drbg_reseed(1,
            primary, public, private,
            &random[0], &random[RANDOM_SIZE],
            0, 0, 0, 0)))
        return 0;

    strcpy(result[0].name, "parent");
    strcpy(result[1].name, "parent");

    /* output of public drbg */
    result[0].pid = pid;
    result[0].private = 0;
    memcpy(result[0].random, &random[0], RANDOM_SIZE);

    /* output of private drbg */
    result[1].pid = pid;
    result[1].private = 1;
    memcpy(result[1].random, &random[RANDOM_SIZE], RANDOM_SIZE);

    /* collect all sampled random data in a single buffer */
    for (i = 0; i < DRBG_FORK_RESULT_COUNT; ++i) {
        memcpy(psample, &result[i].random[0], RANDOM_SIZE);
        psample += RANDOM_SIZE;
    }

    /* sort the results... */
    qsort(result, DRBG_FORK_RESULT_COUNT, sizeof(drbg_fork_result),
        compare_drbg_fork_result);

    /* ...and count duplicate prefixes by looking at the first byte only */
    for (i = 1; i < DRBG_FORK_RESULT_COUNT; ++i) {
        if (result[i].random[0] == result[i - 1].random[0]) {
            /* count public and private duplicates separately */
            ++duplicate[result[i].private];
        }
    }

    if (duplicate[0] >= DRBG_FORK_COUNT - 1) {
        /* just too many duplicates to be a coincidence */
        TEST_note("ERROR: %d duplicate prefixes in public random output", duplicate[0]);
        success = 0;
    }

    if (duplicate[1] >= DRBG_FORK_COUNT - 1) {
        /* just too many duplicates to be a coincidence */
        TEST_note("ERROR: %d duplicate prefixes in private random output", duplicate[1]);
        success = 0;
    }

    duplicate[0] = 0;

    /* sort the two-byte chunks... */
    qsort(sample, sizeof(sample) / 2, 2, compare_rand_chunk);

    /* ...and count duplicate chunks */
    for (i = 2, psample = sample + 2; i < sizeof(sample); i += 2, psample += 2) {
        if (compare_rand_chunk(psample - 2, psample) == 0)
            ++duplicate[0];
    }

    if (duplicate[0] >= DRBG_FORK_COUNT - 1) {
        /* just too many duplicates to be a coincidence */
        TEST_note("ERROR: %d duplicate chunks in random output", duplicate[0]);
        success = 0;
    }

    if (verbose || !success) {

        for (i = 0; i < DRBG_FORK_RESULT_COUNT; ++i) {
            char *rand_hex = OPENSSL_buf2hexstr(result[i].random, RANDOM_SIZE);

            TEST_note("    random: %s, pid: %d (%s, %s)",
                rand_hex,
                result[i].pid,
                result[i].name,
                result[i].private ? "private" : "public");

            OPENSSL_free(rand_hex);
        }
    }

    return success;
}

static int test_rand_fork_safety(int i)
{
    int success = 1;
    unsigned char random[1];
    EVP_RAND_CTX *primary, *public, *private;

    /* All three DRBGs should be non-null */
    if (!TEST_ptr(primary = RAND_get0_primary(NULL))
        || !TEST_ptr(public = RAND_get0_public(NULL))
        || !TEST_ptr(private = RAND_get0_private(NULL)))
        return 0;

    /* run the actual test */
    if (!TEST_true(test_rand_reseed_on_fork(primary, public, private)))
        success = 0;

    /* request a single byte from each of the DRBGs before the next run */
    if (!TEST_int_gt(RAND_bytes(random, 1), 0) || !TEST_int_gt(RAND_priv_bytes(random, 1), 0))
        success = 0;

    return success;
}
#endif

/*
 * Test whether the default rand_method (RAND_OpenSSL()) is
 * setup correctly, in particular whether reseeding works
 * as designed.
 */
static int test_rand_reseed(void)
{
    EVP_RAND_CTX *primary, *public, *private;
    unsigned char rand_add_buf[256];
    int rv = 0;
    time_t before_reseed;

    if (using_fips_rng())
        return TEST_skip("CRNGT cannot be disabled");

#ifndef OPENSSL_NO_DEPRECATED_3_0
    /* Check whether RAND_OpenSSL() is the default method */
    if (!TEST_ptr_eq(RAND_get_rand_method(), RAND_OpenSSL()))
        return 0;
#endif

    /* All three DRBGs should be non-null */
    if (!TEST_ptr(primary = RAND_get0_primary(NULL))
        || !TEST_ptr(public = RAND_get0_public(NULL))
        || !TEST_ptr(private = RAND_get0_private(NULL)))
        return 0;

    /* There should be three distinct DRBGs, two of them chained to primary */
    if (!TEST_ptr_ne(public, private)
        || !TEST_ptr_ne(public, primary)
        || !TEST_ptr_ne(private, primary)
        || !TEST_ptr_eq(prov_rand(public)->parent, prov_rand(primary))
        || !TEST_ptr_eq(prov_rand(private)->parent, prov_rand(primary)))
        return 0;

    /* Disable CRNG testing for the primary DRBG */
    if (!TEST_true(disable_crngt(primary)))
        return 0;

    /* uninstantiate the three global DRBGs */
    EVP_RAND_uninstantiate(primary);
    EVP_RAND_uninstantiate(private);
    EVP_RAND_uninstantiate(public);

    /*
     * Test initial seeding of shared DRBGs
     */
    if (!TEST_true(test_drbg_reseed(1,
            primary, public, private,
            NULL, NULL,
            1, 1, 1, 0)))
        goto error;

    /*
     * Test initial state of shared DRBGs
     */
    if (!TEST_true(test_drbg_reseed(1,
            primary, public, private,
            NULL, NULL,
            0, 0, 0, 0)))
        goto error;

    /*
     * Test whether the public and private DRBG are both reseeded when their
     * reseed counters differ from the primary's reseed counter.
     */
    inc_reseed_counter(primary);
    if (!TEST_true(test_drbg_reseed(1,
            primary, public, private,
            NULL, NULL,
            0, 1, 1, 0)))
        goto error;

    /*
     * Test whether the public DRBG is reseeded when its reseed counter differs
     * from the primary's reseed counter.
     */
    inc_reseed_counter(primary);
    inc_reseed_counter(private);
    if (!TEST_true(test_drbg_reseed(1,
            primary, public, private,
            NULL, NULL,
            0, 1, 0, 0)))
        goto error;

    /*
     * Test whether the private DRBG is reseeded when its reseed counter differs
     * from the primary's reseed counter.
     */
    inc_reseed_counter(primary);
    inc_reseed_counter(public);
    if (!TEST_true(test_drbg_reseed(1,
            primary, public, private,
            NULL, NULL,
            0, 0, 1, 0)))
        goto error;

    /* fill 'randomness' buffer with some arbitrary data */
    memset(rand_add_buf, 'r', sizeof(rand_add_buf));

    /*
     * Test whether all three DRBGs are reseeded by RAND_add().
     * The before_reseed time has to be measured here and passed into the
     * test_drbg_reseed() test, because the primary DRBG gets already reseeded
     * in RAND_add(), whence the check for the condition
     * before_reseed <= reseed_time(primary) will fail if the time value happens
     * to increase between the RAND_add() and the test_drbg_reseed() call.
     */
    before_reseed = time(NULL);
    RAND_add(rand_add_buf, sizeof(rand_add_buf), sizeof(rand_add_buf));
    if (!TEST_true(test_drbg_reseed(1,
            primary, public, private,
            NULL, NULL,
            1, 1, 1,
            before_reseed)))
        goto error;

    rv = 1;

error:
    return rv;
}

#if defined(OPENSSL_THREADS)
static int multi_thread_rand_bytes_succeeded = 1;
static int multi_thread_rand_priv_bytes_succeeded = 1;

static int set_reseed_time_interval(EVP_RAND_CTX *drbg, int t)
{
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_int(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL,
        &t);
    params[1] = OSSL_PARAM_construct_end();
    return EVP_RAND_CTX_set_params(drbg, params);
}

static void run_multi_thread_test(void)
{
    unsigned char buf[256];
    time_t start = time(NULL);
    EVP_RAND_CTX *public = NULL, *private = NULL;

    if (!TEST_ptr(public = RAND_get0_public(NULL))
        || !TEST_ptr(private = RAND_get0_private(NULL))
        || !TEST_true(set_reseed_time_interval(private, 1))
        || !TEST_true(set_reseed_time_interval(public, 1))) {
        multi_thread_rand_bytes_succeeded = 0;
        return;
    }

    do {
        if (rand_bytes(buf, sizeof(buf)) <= 0)
            multi_thread_rand_bytes_succeeded = 0;
        if (rand_priv_bytes(buf, sizeof(buf)) <= 0)
            multi_thread_rand_priv_bytes_succeeded = 0;
    } while (time(NULL) - start < 5);
}

#if defined(OPENSSL_SYS_WINDOWS)

typedef HANDLE thread_t;

static DWORD WINAPI thread_run(LPVOID arg)
{
    run_multi_thread_test();
    /*
     * Because we're linking with a static library, we must stop each
     * thread explicitly, or so says OPENSSL_thread_stop(3)
     */
    OPENSSL_thread_stop();
    return 0;
}

static int run_thread(thread_t *t)
{
    *t = CreateThread(NULL, 0, thread_run, NULL, 0, NULL);
    return *t != NULL;
}

static int wait_for_thread(thread_t thread)
{
    return WaitForSingleObject(thread, INFINITE) == 0;
}

#else

typedef pthread_t thread_t;

static void *thread_run(void *arg)
{
    run_multi_thread_test();
    /*
     * Because we're linking with a static library, we must stop each
     * thread explicitly, or so says OPENSSL_thread_stop(3)
     */
    OPENSSL_thread_stop();
    return NULL;
}

static int run_thread(thread_t *t)
{
    return pthread_create(t, NULL, thread_run, NULL) == 0;
}

static int wait_for_thread(thread_t thread)
{
    return pthread_join(thread, NULL) == 0;
}

#endif

/*
 * The main thread will also run the test, so we'll have THREADS+1 parallel
 * tests running
 */
#define THREADS 3

static int test_multi_thread(void)
{
    thread_t t[THREADS];
    int i;

    for (i = 0; i < THREADS; i++)
        run_thread(&t[i]);
    run_multi_thread_test();
    for (i = 0; i < THREADS; i++)
        wait_for_thread(t[i]);

    if (!TEST_true(multi_thread_rand_bytes_succeeded))
        return 0;
    if (!TEST_true(multi_thread_rand_priv_bytes_succeeded))
        return 0;

    return 1;
}
#endif

static EVP_RAND_CTX *new_drbg(EVP_RAND_CTX *parent)
{
    OSSL_PARAM params[2];
    EVP_RAND *rand = NULL;
    EVP_RAND_CTX *drbg = NULL;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER,
        "AES-256-CTR", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (!TEST_ptr(rand = EVP_RAND_fetch(NULL, "CTR-DRBG", NULL))
        || !TEST_ptr(drbg = EVP_RAND_CTX_new(rand, parent))
        || !TEST_true(EVP_RAND_CTX_set_params(drbg, params))) {
        EVP_RAND_CTX_free(drbg);
        drbg = NULL;
    }
    EVP_RAND_free(rand);
    return drbg;
}

static int test_rand_prediction_resistance(void)
{
    EVP_RAND_CTX *x = NULL, *y = NULL, *z = NULL;
    unsigned char buf1[51], buf2[sizeof(buf1)];
    int ret = 0, xreseed, yreseed, zreseed;

    if (using_fips_rng())
        return TEST_skip("CRNGT cannot be disabled");

    /* Initialise a three long DRBG chain */
    if (!TEST_ptr(x = new_drbg(NULL))
        || !TEST_true(disable_crngt(x))
        || !TEST_true(EVP_RAND_instantiate(x, 0, 0, NULL, 0, NULL))
        || !TEST_ptr(y = new_drbg(x))
        || !TEST_true(EVP_RAND_instantiate(y, 0, 0, NULL, 0, NULL))
        || !TEST_ptr(z = new_drbg(y))
        || !TEST_true(EVP_RAND_instantiate(z, 0, 0, NULL, 0, NULL)))
        goto err;

    /*
     * During a normal reseed, only the last DRBG in the chain should
     * be reseeded.
     */
    inc_reseed_counter(y);
    xreseed = reseed_counter(x);
    yreseed = reseed_counter(y);
    zreseed = reseed_counter(z);
    if (!TEST_true(EVP_RAND_reseed(z, 0, NULL, 0, NULL, 0))
        || !TEST_int_eq(reseed_counter(x), xreseed)
        || !TEST_int_eq(reseed_counter(y), yreseed)
        || !TEST_int_gt(reseed_counter(z), zreseed))
        goto err;

    /*
     * When prediction resistance is requested, the request should be
     * propagated to the primary, so that the entire DRBG chain reseeds.
     */
    zreseed = reseed_counter(z);
    if (!TEST_true(EVP_RAND_reseed(z, 1, NULL, 0, NULL, 0))
        || !TEST_int_gt(reseed_counter(x), xreseed)
        || !TEST_int_gt(reseed_counter(y), yreseed)
        || !TEST_int_gt(reseed_counter(z), zreseed))
        goto err;

    /*
     * During a normal generate, only the last DRBG should be reseed */
    inc_reseed_counter(y);
    xreseed = reseed_counter(x);
    yreseed = reseed_counter(y);
    zreseed = reseed_counter(z);
    if (!TEST_true(EVP_RAND_generate(z, buf1, sizeof(buf1), 0, 0, NULL, 0))
        || !TEST_int_eq(reseed_counter(x), xreseed)
        || !TEST_int_eq(reseed_counter(y), yreseed)
        || !TEST_int_gt(reseed_counter(z), zreseed))
        goto err;

    /*
     * When a prediction resistant generate is requested, the request
     * should be propagated to the primary, reseeding the entire DRBG chain.
     */
    zreseed = reseed_counter(z);
    if (!TEST_true(EVP_RAND_generate(z, buf2, sizeof(buf2), 0, 1, NULL, 0))
        || !TEST_int_gt(reseed_counter(x), xreseed)
        || !TEST_int_gt(reseed_counter(y), yreseed)
        || !TEST_int_gt(reseed_counter(z), zreseed)
        || !TEST_mem_ne(buf1, sizeof(buf1), buf2, sizeof(buf2)))
        goto err;

    /* Verify that a normal reseed still only reseeds the last DRBG */
    inc_reseed_counter(y);
    xreseed = reseed_counter(x);
    yreseed = reseed_counter(y);
    zreseed = reseed_counter(z);
    if (!TEST_true(EVP_RAND_reseed(z, 0, NULL, 0, NULL, 0))
        || !TEST_int_eq(reseed_counter(x), xreseed)
        || !TEST_int_eq(reseed_counter(y), yreseed)
        || !TEST_int_gt(reseed_counter(z), zreseed))
        goto err;

    ret = 1;
err:
    EVP_RAND_CTX_free(z);
    EVP_RAND_CTX_free(y);
    EVP_RAND_CTX_free(x);
    return ret;
}

#if defined(__linux__) && !defined(FIPS_MODULE) && defined(__GNUC__)
/*
 * A regular file laid out like the VMClock page stands in for the device
 * (OPENSSL_VMCLOCK is set to it in setup_tests, before any DRBG runs). Bumping
 * the generation counter in it must reseed the public and private DRBGs, and
 * the primary through them, on their next generate call; leaving it alone must
 * not.
 */
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/provider.h>

#define VMCLOCK_TEST_SIZE 4096

static char vmclock_test_path[4096];
static int vmclock_test_created;
static uint8_t *vmclock_test_page;
static uint32_t vmclock_test_seq = 2;
static uint64_t vmclock_test_generation;

static int vmclock_test_setup(void)
{
    static const uint8_t header[32] = {
        'V', 'C', 'L', 'K', 112, 0, 0, 0, 1, 0, 1, 0, 2, 0, 0, 0, /* magic, size, version, ids, seq */
        0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 /* marker, flags = GEN_COUNTER_PRESENT */
    };
    static uint8_t page[VMCLOCK_TEST_SIZE];
    const char *dir = getenv("TMPDIR");
    int fd;

    if (dir == NULL || *dir == '\0')
        dir = "/tmp";
    if (BIO_snprintf(vmclock_test_path, sizeof(vmclock_test_path),
            "%s/openssl-vmclock-test-XXXXXX", dir)
        <= 0)
        return 0;
    memcpy(page, header, sizeof(header));
    if ((fd = mkstemp(vmclock_test_path)) < 0)
        return 0;
    vmclock_test_created = 1;
    if (write(fd, page, sizeof(page)) != (ssize_t)sizeof(page)) {
        close(fd);
        return 0;
    }
    vmclock_test_page = mmap(NULL, sizeof(page), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (vmclock_test_page == MAP_FAILED) {
        vmclock_test_page = NULL;
        return 0;
    }
    return setenv("OPENSSL_VMCLOCK", vmclock_test_path, 1) == 0;
}

/* Every field of the page is little-endian. */
static void vmclock_test_put(size_t off, uint64_t v, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++)
        vmclock_test_page[off + i] = (uint8_t)(v >> (8 * i));
}

/* The readers load seq_count in one access, so it is stored in one. */
static void vmclock_test_set_seq(uint32_t seq)
{
    uint8_t b[4];
    uint32_t raw;
    int i;

    for (i = 0; i < 4; i++)
        b[i] = (uint8_t)(seq >> (8 * i));
    memcpy(&raw, b, sizeof(raw));
    __atomic_store_n((uint32_t *)(vmclock_test_page + 12), raw, __ATOMIC_SEQ_CST);
}

/* Bump the generation counter as a hypervisor does, holding the page odd for |hold_us|. */
static void vmclock_test_bump(unsigned int hold_us)
{
    vmclock_test_set_seq(++vmclock_test_seq); /* odd: update in progress */
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    vmclock_test_put(104, ++vmclock_test_generation, 8);
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    if (hold_us > 0)
        usleep(hold_us);
    vmclock_test_set_seq(++vmclock_test_seq);
}

static unsigned int vmclock_reseed_counter(EVP_RAND_CTX *drbg)
{
    unsigned int n = 0;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_uint(OSSL_DRBG_PARAM_RESEED_COUNTER, &n);
    params[1] = OSSL_PARAM_construct_end();
    if (!EVP_RAND_CTX_get_params(drbg, params))
        return 0;
    return n;
}

static int test_rand_reseed_on_vmclock(void)
{
    EVP_RAND_CTX *primary, *public, *private;
    unsigned char buf[32];
    unsigned int pri, pub, pri2, pub2;

    if (using_fips_rng())
        return TEST_skip("FIPS provider DRBGs do not read VMClock");
    if (!TEST_ptr(primary = RAND_get0_primary(NULL))
        || !TEST_ptr(public = RAND_get0_public(NULL))
        || !TEST_ptr(private = RAND_get0_private(NULL)))
        return 0;
    if (!TEST_true(RAND_bytes(buf, sizeof(buf))) || !TEST_true(RAND_priv_bytes(buf, sizeof(buf))))
        return 0;
    pri = vmclock_reseed_counter(primary);
    pub = vmclock_reseed_counter(public);

    /* nothing changed: no reseed */
    if (!TEST_true(RAND_bytes(buf, sizeof(buf)))
        || !TEST_uint_eq(vmclock_reseed_counter(public), pub)
        || !TEST_uint_eq(vmclock_reseed_counter(primary), pri))
        return 0;

    /* the generation counter moved: the public DRBG reseeds, and the primary with it */
    vmclock_test_bump(0);
    if (!TEST_true(RAND_bytes(buf, sizeof(buf))))
        return 0;
    pub2 = vmclock_reseed_counter(public);
    pri2 = vmclock_reseed_counter(primary);
    if (!TEST_uint_eq(pub2, pub + 1) || !TEST_uint_eq(pri2, pri + 1))
        return 0;
    /* and the private DRBG on its next call, once */
    if (!TEST_true(RAND_priv_bytes(buf, sizeof(buf)))
        || !TEST_true(RAND_priv_bytes(buf, sizeof(buf)))
        || !TEST_uint_eq(vmclock_reseed_counter(primary), pri2))
        return 0;
    return 1;
}

/*
 * A seed source that moves the counter while a DRBG takes seed from it, that
 * is, after the DRBG's check before generating and before its check after.
 * It records the prediction resistance asked of each seed request.
 */
static int vmclock_seed_bumps, vmclock_seed_requests, vmclock_seed_pr[4];

static void *vmclock_seed_newctx(ossl_unused void *provctx,
    ossl_unused void *parent, ossl_unused const OSSL_DISPATCH *pd)
{
    int *state = OPENSSL_zalloc(sizeof(*state));

    if (state != NULL)
        *state = EVP_RAND_STATE_UNINITIALISED;
    return state;
}

static void vmclock_seed_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static int vmclock_seed_instantiate(void *vctx, ossl_unused unsigned int strength,
    ossl_unused int prediction_resistance, ossl_unused const unsigned char *pstr,
    ossl_unused size_t pstr_len, ossl_unused const OSSL_PARAM params[])
{
    *(int *)vctx = EVP_RAND_STATE_READY;
    return 1;
}

static int vmclock_seed_uninstantiate(void *vctx)
{
    *(int *)vctx = EVP_RAND_STATE_UNINITIALISED;
    return 1;
}

static int vmclock_seed_generate(ossl_unused void *vctx, unsigned char *out,
    size_t outlen, ossl_unused unsigned int strength,
    ossl_unused int prediction_resistance, ossl_unused const unsigned char *adin,
    ossl_unused size_t adinlen)
{
    memset(out, 0x5a, outlen);
    return 1;
}

static size_t vmclock_seed_get_seed(ossl_unused void *vctx, unsigned char **pout,
    int entropy, size_t min_len, size_t max_len, int prediction_resistance,
    ossl_unused const unsigned char *adin, ossl_unused size_t adinlen)
{
    size_t len = entropy > 0 ? ((size_t)entropy + 7) / 8 : 0;

    if (len < min_len)
        len = min_len;
    if (len > max_len)
        len = max_len;
    if (len == 0 || (*pout = OPENSSL_malloc(len)) == NULL)
        return 0;
    memset(*pout, 0x5a + vmclock_seed_requests, len);
    if (vmclock_seed_requests < (int)OSSL_NELEM(vmclock_seed_pr))
        vmclock_seed_pr[vmclock_seed_requests] = prediction_resistance;
    vmclock_seed_requests++;
    if (vmclock_seed_bumps > 0) {
        vmclock_seed_bumps--;
        vmclock_test_bump(0);
    }
    return len;
}

static void vmclock_seed_clear_seed(ossl_unused void *vctx, unsigned char *out,
    size_t outlen)
{
    OPENSSL_clear_free(out, outlen);
}

static int vmclock_seed_enable_locking(ossl_unused void *vctx)
{
    return 1;
}

static int vmclock_seed_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STATE);
    if (p != NULL && !OSSL_PARAM_set_int(p, *(int *)vctx))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_STRENGTH);
    if (p != NULL && !OSSL_PARAM_set_uint(p, 256))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_RAND_PARAM_MAX_REQUEST);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 1 << 16))
        return 0;
    return 1;
}

static const OSSL_PARAM *vmclock_seed_gettable_ctx_params(ossl_unused void *vctx,
    ossl_unused void *provctx)
{
    static const OSSL_PARAM known[] = {
        OSSL_PARAM_int(OSSL_RAND_PARAM_STATE, NULL),
        OSSL_PARAM_uint(OSSL_RAND_PARAM_STRENGTH, NULL),
        OSSL_PARAM_size_t(OSSL_RAND_PARAM_MAX_REQUEST, NULL),
        OSSL_PARAM_END
    };

    return known;
}

static const OSSL_DISPATCH vmclock_seed_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void (*)(void))vmclock_seed_newctx },
    { OSSL_FUNC_RAND_FREECTX, (void (*)(void))vmclock_seed_freectx },
    { OSSL_FUNC_RAND_INSTANTIATE, (void (*)(void))vmclock_seed_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void (*)(void))vmclock_seed_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void (*)(void))vmclock_seed_generate },
    { OSSL_FUNC_RAND_ENABLE_LOCKING, (void (*)(void))vmclock_seed_enable_locking },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
        (void (*)(void))vmclock_seed_gettable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void (*)(void))vmclock_seed_get_ctx_params },
    { OSSL_FUNC_RAND_GET_SEED, (void (*)(void))vmclock_seed_get_seed },
    { OSSL_FUNC_RAND_CLEAR_SEED, (void (*)(void))vmclock_seed_clear_seed },
    OSSL_DISPATCH_END
};

static const OSSL_ALGORITHM vmclock_seed_rand[] = {
    { "VMCLOCK-SEED", "provider=vmclock-seed", vmclock_seed_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *vmclock_seed_query(ossl_unused void *provctx,
    int operation_id, int *no_cache)
{
    *no_cache = 0;
    return operation_id == OSSL_OP_RAND ? vmclock_seed_rand : NULL;
}

static const OSSL_DISPATCH vmclock_seed_method[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))vmclock_seed_query },
    OSSL_DISPATCH_END
};

static int vmclock_seed_provider_init(ossl_unused const OSSL_CORE_HANDLE *handle,
    ossl_unused const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
    void **provctx)
{
    *provctx = NULL;
    *out = vmclock_seed_method;
    return 1;
}

/*
 * The counter moves before a call, which the check before generating sees,
 * and again while the DRBG reseeds for that call, which only the check after
 * generating can see: the DRBG must reseed a second time, with the prediction
 * resistance the caller asked for, and then be settled.
 */
static int test_rand_vmclock_recheck(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *dflt = NULL, *seed = NULL;
    EVP_RAND *rand = NULL;
    EVP_RAND_CTX *parent = NULL, *drbg = NULL;
    OSSL_PARAM params[2];
    unsigned char buf[32];
    unsigned int n;
    int ret = 0;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER,
        (char *)"AES-256-CTR", 0);
    params[1] = OSSL_PARAM_construct_end();
    if (!TEST_ptr(ctx = OSSL_LIB_CTX_new())
        || !TEST_ptr(dflt = OSSL_PROVIDER_load(ctx, "default"))
        || !TEST_true(OSSL_PROVIDER_add_builtin(ctx, "vmclock-seed",
            vmclock_seed_provider_init))
        || !TEST_ptr(seed = OSSL_PROVIDER_load(ctx, "vmclock-seed"))
        || !TEST_ptr(rand = EVP_RAND_fetch(ctx, "VMCLOCK-SEED", NULL))
        || !TEST_ptr(parent = EVP_RAND_CTX_new(rand, NULL))
        || !TEST_true(EVP_RAND_instantiate(parent, 0, 0, NULL, 0, NULL)))
        goto err;
    EVP_RAND_free(rand);
    if (!TEST_ptr(rand = EVP_RAND_fetch(ctx, "CTR-DRBG", NULL))
        || !TEST_ptr(drbg = EVP_RAND_CTX_new(rand, parent))
        || !TEST_true(EVP_RAND_instantiate(drbg, 256, 0, NULL, 0, params))
        || !TEST_true(EVP_RAND_generate(drbg, buf, sizeof(buf), 256, 0, NULL, 0)))
        goto err;
    n = vmclock_reseed_counter(drbg);

    vmclock_seed_requests = 0;
    vmclock_seed_bumps = 1;
    vmclock_test_bump(0);
    if (!TEST_true(EVP_RAND_generate(drbg, buf, sizeof(buf), 256, 1, NULL, 0))
        || !TEST_uint_eq(vmclock_reseed_counter(drbg), n + 2)
        || !TEST_int_eq(vmclock_seed_requests, 2)
        || !TEST_int_eq(vmclock_seed_pr[0], 1)
        || !TEST_int_eq(vmclock_seed_pr[1], 1))
        goto err;

    n = vmclock_reseed_counter(drbg);
    if (!TEST_true(EVP_RAND_generate(drbg, buf, sizeof(buf), 256, 0, NULL, 0))
        || !TEST_uint_eq(vmclock_reseed_counter(drbg), n))
        goto err;
    ret = 1;
err:
    vmclock_seed_bumps = 0;
    EVP_RAND_CTX_free(drbg);
    EVP_RAND_CTX_free(parent);
    EVP_RAND_free(rand);
    OSSL_PROVIDER_unload(seed);
    OSSL_PROVIDER_unload(dflt);
    OSSL_LIB_CTX_free(ctx);
    return ret;
}

/*
 * A page left odd, as if the hypervisor stopped in the middle of an update:
 * the read gives up after a bounded number of looks, the call succeeds and
 * reseeds, and once the page is consistent again without a change, the DRBGs
 * stop reseeding. This test and the next run in their own library context,
 * so that their many reseeds stay out of the counts of the default one, which
 * the other tests compare; the page is shared, so the default DRBGs reseed
 * once more at their next call.
 */
static int test_rand_vmclock_stuck(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    EVP_RAND_CTX *public;
    unsigned char buf[32];
    unsigned int pub;
    int ret = 0;

    if (using_fips_rng())
        return TEST_skip("FIPS provider DRBGs do not read VMClock");
    if (!TEST_ptr(ctx = OSSL_LIB_CTX_new())
        || !TEST_true(RAND_bytes_ex(ctx, buf, sizeof(buf), 0))
        || !TEST_ptr(public = RAND_get0_public(ctx)))
        goto err;
    pub = vmclock_reseed_counter(public);

    /*
     * A read that gives up counts as a change: the public DRBG reseeds at the
     * check before generating and again at the one after.
     */
    vmclock_test_set_seq(++vmclock_test_seq);
    if (!TEST_true(RAND_bytes_ex(ctx, buf, sizeof(buf), 0))
        || !TEST_uint_eq(vmclock_reseed_counter(public), pub + 2))
        goto err;
    vmclock_test_set_seq(++vmclock_test_seq);

    if (!TEST_true(RAND_bytes_ex(ctx, buf, sizeof(buf), 0)))
        goto err;
    pub = vmclock_reseed_counter(public);
    if (!TEST_true(RAND_bytes_ex(ctx, buf, sizeof(buf), 0))
        || !TEST_uint_eq(vmclock_reseed_counter(public), pub))
        goto err;
    ret = 1;
err:
    if ((vmclock_test_seq & 1) != 0)
        vmclock_test_set_seq(++vmclock_test_seq);
    OSSL_LIB_CTX_free(ctx);
    return ret;
}

#if defined(OPENSSL_THREADS)
#include <pthread.h>

/*
 * Threads draw from their public and private DRBGs, and so from the shared
 * primary, while the counter moves under them, now and then with the page
 * held odd. This checks that the calls succeed and end in a settled state; it
 * cannot force any particular interleaving. Afterwards one more bump must
 * reseed the primary exactly once and every thread's public DRBG on its next
 * call, and once all have seen it, a further call must not reseed.
 */
#define VMCLOCK_THREADS 4
#define VMCLOCK_BUMPS 2000

static int vmclock_stop, vmclock_phases;
static pthread_barrier_t vmclock_barrier;
static OSSL_LIB_CTX *vmclock_ctx;

static void *vmclock_thread(void *arg)
{
    int *ok = arg;
    unsigned char buf[32];
    EVP_RAND_CTX *public;
    unsigned int before;

    *ok = 1;
    while (!__atomic_load_n(&vmclock_stop, __ATOMIC_ACQUIRE))
        if (!RAND_bytes_ex(vmclock_ctx, buf, sizeof(buf), 0)
            || !RAND_priv_bytes_ex(vmclock_ctx, buf, sizeof(buf), 0))
            *ok = 0;
    if (!vmclock_phases)
        goto end;
    if ((public = RAND_get0_public(vmclock_ctx)) == NULL)
        *ok = 0;
    before = public == NULL ? 0 : vmclock_reseed_counter(public);
    pthread_barrier_wait(&vmclock_barrier); /* the main thread bumps */
    pthread_barrier_wait(&vmclock_barrier);
    if (!RAND_bytes_ex(vmclock_ctx, buf, sizeof(buf), 0)
        || public == NULL || vmclock_reseed_counter(public) == before)
        *ok = 0;
    pthread_barrier_wait(&vmclock_barrier); /* every thread has drawn once */
    before = public == NULL ? 0 : vmclock_reseed_counter(public);
    if (!RAND_bytes_ex(vmclock_ctx, buf, sizeof(buf), 0)
        || public == NULL || vmclock_reseed_counter(public) != before)
        *ok = 0;
end:
    OPENSSL_thread_stop();
    return NULL;
}

static int test_rand_vmclock_threads(void)
{
    pthread_t t[VMCLOCK_THREADS];
    int ok[VMCLOCK_THREADS];
    EVP_RAND_CTX *primary = NULL;
    unsigned int pri = 0;
    int i, n, ret = 1;

    if (using_fips_rng())
        return TEST_skip("FIPS provider DRBGs do not read VMClock");
    if (!TEST_ptr(vmclock_ctx = OSSL_LIB_CTX_new())
        || !TEST_ptr(primary = RAND_get0_primary(vmclock_ctx))) {
        OSSL_LIB_CTX_free(vmclock_ctx);
        vmclock_ctx = NULL;
        return 0;
    }
    for (n = 0; n < VMCLOCK_THREADS; n++)
        if (pthread_create(&t[n], NULL, vmclock_thread, &ok[n]) != 0)
            break;
    /* the threads look at vmclock_phases only after vmclock_stop is set */
    vmclock_phases = TEST_int_eq(n, VMCLOCK_THREADS)
        && TEST_int_eq(pthread_barrier_init(&vmclock_barrier, NULL, n + 1), 0);
    for (i = 0; i < VMCLOCK_BUMPS; i++) {
        vmclock_test_bump(i % 100 == 0 ? 200 : 0);
        usleep(20);
    }
    __atomic_store_n(&vmclock_stop, 1, __ATOMIC_RELEASE);
    if (vmclock_phases) {
        pthread_barrier_wait(&vmclock_barrier);
        pri = vmclock_reseed_counter(primary);
        vmclock_test_bump(0);
        pthread_barrier_wait(&vmclock_barrier);
        pthread_barrier_wait(&vmclock_barrier);
    }
    for (i = 0; i < n; i++) {
        pthread_join(t[i], NULL);
        if (!TEST_true(ok[i]))
            ret = 0;
    }
    if (vmclock_phases) {
        pthread_barrier_destroy(&vmclock_barrier);
        if (!TEST_uint_eq(vmclock_reseed_counter(primary), pri + 1))
            ret = 0;
    }
    OSSL_LIB_CTX_free(vmclock_ctx);
    vmclock_ctx = NULL;
    return vmclock_phases && ret;
}
#endif
#endif

int setup_tests(void)
{
#if defined(__linux__) && !defined(FIPS_MODULE) && defined(__GNUC__)
    if (vmclock_test_setup()) {
        ADD_TEST(test_rand_reseed_on_vmclock);
        ADD_TEST(test_rand_vmclock_recheck);
        ADD_TEST(test_rand_vmclock_stuck);
#if defined(OPENSSL_THREADS)
        ADD_TEST(test_rand_vmclock_threads);
#endif
    } else {
        TEST_note("no file to stand in for the VMClock page; its tests are skipped");
    }
#endif
    ADD_TEST(test_rand_reseed);
#if defined(OPENSSL_SYS_UNIX) && !defined(OPENSSL_RAND_SEED_EGD)
    ADD_ALL_TESTS(test_rand_fork_safety, RANDOM_SIZE);
#endif
    ADD_TEST(test_rand_prediction_resistance);
#if defined(OPENSSL_THREADS)
    ADD_TEST(test_multi_thread);
#endif
    return 1;
}

void cleanup_tests(void)
{
#if defined(__linux__) && !defined(FIPS_MODULE) && defined(__GNUC__)
    if (vmclock_test_page != NULL)
        munmap(vmclock_test_page, VMCLOCK_TEST_SIZE);
    if (vmclock_test_created)
        unlink(vmclock_test_path);
#endif
}
