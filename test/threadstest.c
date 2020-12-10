/*
 * Copyright 2016-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if defined(_WIN32)
# include <windows.h>
#endif

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include "testutil.h"

static int dofips = 0;

#if !defined(OPENSSL_THREADS) || defined(CRYPTO_TDEBUG)

typedef unsigned int thread_t;

static int run_thread(thread_t *t, void (*f)(void))
{
    f();
    return 1;
}

static int wait_for_thread(thread_t thread)
{
    return 1;
}

#elif defined(OPENSSL_SYS_WINDOWS)

typedef HANDLE thread_t;

static DWORD WINAPI thread_run(LPVOID arg)
{
    void (*f)(void);

    *(void **) (&f) = arg;

    f();
    return 0;
}

static int run_thread(thread_t *t, void (*f)(void))
{
    *t = CreateThread(NULL, 0, thread_run, *(void **) &f, 0, NULL);
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
    void (*f)(void);

    *(void **) (&f) = arg;

    f();
    return NULL;
}

static int run_thread(thread_t *t, void (*f)(void))
{
    return pthread_create(t, NULL, thread_run, *(void **) &f) == 0;
}

static int wait_for_thread(thread_t thread)
{
    return pthread_join(thread, NULL) == 0;
}

#endif

static int test_lock(void)
{
    CRYPTO_RWLOCK *lock = CRYPTO_THREAD_lock_new();

    if (!TEST_true(CRYPTO_THREAD_read_lock(lock))
        || !TEST_true(CRYPTO_THREAD_unlock(lock)))
        return 0;

    CRYPTO_THREAD_lock_free(lock);

    return 1;
}

static CRYPTO_ONCE once_run = CRYPTO_ONCE_STATIC_INIT;
static unsigned once_run_count = 0;

static void once_do_run(void)
{
    once_run_count++;
}

static void once_run_thread_cb(void)
{
    CRYPTO_THREAD_run_once(&once_run, once_do_run);
}

static int test_once(void)
{
    thread_t thread;

    if (!TEST_true(run_thread(&thread, once_run_thread_cb))
        || !TEST_true(wait_for_thread(thread))
        || !CRYPTO_THREAD_run_once(&once_run, once_do_run)
        || !TEST_int_eq(once_run_count, 1))
        return 0;
    return 1;
}

static CRYPTO_THREAD_LOCAL thread_local_key;
static unsigned destructor_run_count = 0;
static int thread_local_thread_cb_ok = 0;

static void thread_local_destructor(void *arg)
{
    unsigned *count;

    if (arg == NULL)
        return;

    count = arg;

    (*count)++;
}

static void thread_local_thread_cb(void)
{
    void *ptr;

    ptr = CRYPTO_THREAD_get_local(&thread_local_key);
    if (!TEST_ptr_null(ptr)
        || !TEST_true(CRYPTO_THREAD_set_local(&thread_local_key,
                                              &destructor_run_count)))
        return;

    ptr = CRYPTO_THREAD_get_local(&thread_local_key);
    if (!TEST_ptr_eq(ptr, &destructor_run_count))
        return;

    thread_local_thread_cb_ok = 1;
}

static int test_thread_local(void)
{
    thread_t thread;
    void *ptr = NULL;

    if (!TEST_true(CRYPTO_THREAD_init_local(&thread_local_key,
                                            thread_local_destructor)))
        return 0;

    ptr = CRYPTO_THREAD_get_local(&thread_local_key);
    if (!TEST_ptr_null(ptr)
        || !TEST_true(run_thread(&thread, thread_local_thread_cb))
        || !TEST_true(wait_for_thread(thread))
        || !TEST_int_eq(thread_local_thread_cb_ok, 1))
        return 0;

#if defined(OPENSSL_THREADS) && !defined(CRYPTO_TDEBUG)

    ptr = CRYPTO_THREAD_get_local(&thread_local_key);
    if (!TEST_ptr_null(ptr))
        return 0;

# if !defined(OPENSSL_SYS_WINDOWS)
    if (!TEST_int_eq(destructor_run_count, 1))
        return 0;
# endif
#endif

    if (!TEST_true(CRYPTO_THREAD_cleanup_local(&thread_local_key)))
        return 0;
    return 1;
}

static int test_atomic(void)
{
    int val = 0, ret = 0, testresult = 0;
    uint64_t val64 = 1, ret64 = 0;
    CRYPTO_RWLOCK *lock = CRYPTO_THREAD_lock_new();

    if (!TEST_ptr(lock))
        return 0;

    if (CRYPTO_atomic_add(&val, 1, &ret, NULL)) {
        /* This succeeds therefore we're on a platform with lockless atomics */
        if (!TEST_int_eq(val, 1) || !TEST_int_eq(val, ret))
            goto err;
    } else {
        /* This failed therefore we're on a platform without lockless atomics */
        if (!TEST_int_eq(val, 0) || !TEST_int_eq(val, ret))
            goto err;
    }
    val = 0;
    ret = 0;

    if (!TEST_true(CRYPTO_atomic_add(&val, 1, &ret, lock)))
        goto err;
    if (!TEST_int_eq(val, 1) || !TEST_int_eq(val, ret))
        goto err;

    if (CRYPTO_atomic_or(&val64, 2, &ret64, NULL)) {
        /* This succeeds therefore we're on a platform with lockless atomics */
        if (!TEST_uint_eq((unsigned int)val64, 3)
                || !TEST_uint_eq((unsigned int)val64, (unsigned int)ret64))
            goto err;
    } else {
        /* This failed therefore we're on a platform without lockless atomics */
        if (!TEST_uint_eq((unsigned int)val64, 1)
                || !TEST_int_eq((unsigned int)ret64, 0))
            goto err;
    }
    val64 = 1;
    ret64 = 0;

    if (!TEST_true(CRYPTO_atomic_or(&val64, 2, &ret64, lock)))
        goto err;

    if (!TEST_uint_eq((unsigned int)val64, 3)
            || !TEST_uint_eq((unsigned int)val64, (unsigned int)ret64))
        goto err;

    ret64 = 0;
    if (CRYPTO_atomic_load(&val64, &ret64, NULL)) {
        /* This succeeds therefore we're on a platform with lockless atomics */
        if (!TEST_uint_eq((unsigned int)val64, 3)
                || !TEST_uint_eq((unsigned int)val64, (unsigned int)ret64))
            goto err;
    } else {
        /* This failed therefore we're on a platform without lockless atomics */
        if (!TEST_uint_eq((unsigned int)val64, 3)
                || !TEST_int_eq((unsigned int)ret64, 0))
            goto err;
    }

    ret64 = 0;
    if (!TEST_true(CRYPTO_atomic_load(&val64, &ret64, lock)))
        goto err;

    if (!TEST_uint_eq((unsigned int)val64, 3)
            || !TEST_uint_eq((unsigned int)val64, (unsigned int)ret64))
        goto err;

    testresult = 1;
 err:
    CRYPTO_THREAD_lock_free(lock);
    return testresult;
}

static OSSL_LIB_CTX *multilibctx = NULL;
static int multisuccess;

static void thread_multi_worker(void)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_MD *md = EVP_MD_fetch(multilibctx, "SHA2-256", NULL);
    EVP_CIPHER_CTX *cipherctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER *ciph = EVP_CIPHER_fetch(multilibctx, "AES-128-CBC", NULL);
    const char *message = "Hello World";
    size_t messlen = strlen(message);
    /* Should be big enough for encryption output too */
    unsigned char out[EVP_MAX_MD_SIZE];
    const unsigned char key[AES_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };
    const unsigned char iv[AES_BLOCK_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };
    unsigned int mdoutl;
    int ciphoutl;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    int testresult = 0;
    int i, isfips;

    isfips = OSSL_PROVIDER_available(multilibctx, "fips");

    if (!TEST_ptr(mdctx)
            || !TEST_ptr(md)
            || !TEST_ptr(cipherctx)
            || !TEST_ptr(ciph))
        goto err;

    /* Do some work */
    for (i = 0; i < 5; i++) {
        if (!TEST_true(EVP_DigestInit_ex(mdctx, md, NULL))
                || !TEST_true(EVP_DigestUpdate(mdctx, message, messlen))
                || !TEST_true(EVP_DigestFinal(mdctx, out, &mdoutl)))
            goto err;
    }
    for (i = 0; i < 5; i++) {
        if (!TEST_true(EVP_EncryptInit_ex(cipherctx, ciph, NULL, key, iv))
                || !TEST_true(EVP_EncryptUpdate(cipherctx, out, &ciphoutl,
                                                (unsigned char *)message,
                                                messlen))
                || !TEST_true(EVP_EncryptFinal(cipherctx, out, &ciphoutl)))
            goto err;
    }

    pctx = EVP_PKEY_CTX_new_from_name(multilibctx, "RSA", NULL);
    if (!TEST_ptr(pctx)
            || !TEST_int_gt(EVP_PKEY_keygen_init(pctx), 0)
               /*
                * We want the test to run quickly - not securely. Therefore we
                * use an insecure bit length where we can (512). In the FIPS
                * module though we must use a longer length.
                */
            || !TEST_int_gt(EVP_PKEY_CTX_set_rsa_keygen_bits(pctx,
                                                             isfips ? 2048 : 512),
                                                             0)
            || !TEST_int_gt(EVP_PKEY_keygen(pctx, &pkey), 0))
        goto err;


    testresult = 1;
 err:
    EVP_MD_CTX_free(mdctx);
    EVP_MD_free(md);
    EVP_CIPHER_CTX_free(cipherctx);
    EVP_CIPHER_free(ciph);
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkey);
    if (!testresult)
        multisuccess = 0;
}

/*
 * Do work in multiple worker threads at the same time.
 * Test 0: Use the default provider
 * Test 1: Use the fips provider
 */
static int test_multi(int idx)
{
    thread_t thread1, thread2;
    int testresult = 0;
    OSSL_PROVIDER *prov = NULL;

    if (idx == 1 && !dofips)
        return TEST_skip("FIPS not supported");

    multisuccess = 1;
    multilibctx = OSSL_LIB_CTX_new();
    if (!TEST_ptr(multilibctx))
        goto err;
    prov = OSSL_PROVIDER_load(multilibctx, (idx == 0) ? "default" : "fips");
    if (!TEST_ptr(prov))
        goto err;

    if (!TEST_true(run_thread(&thread1, thread_multi_worker))
            || !TEST_true(run_thread(&thread2, thread_multi_worker)))
        goto err;

    thread_multi_worker();

    if (!TEST_true(wait_for_thread(thread1))
            || !TEST_true(wait_for_thread(thread2))
            || !TEST_true(multisuccess))
        goto err;

    testresult = 1;

 err:
    OSSL_PROVIDER_unload(prov);
    OSSL_LIB_CTX_free(multilibctx);
    return testresult;
}

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_FIPS,
    OPT_TEST_ENUM
} OPTION_CHOICE;

const OPTIONS *test_get_options(void)
{
    static const OPTIONS options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "fips", OPT_FIPS, '-', "Test the FIPS provider" },
        { NULL }
    };
    return options;
}

int setup_tests(void)
{
    OPTION_CHOICE o;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_FIPS:
            dofips = 1;
            break;
        case OPT_TEST_CASES:
            break;
        default:
            return 0;
        }
    }

    ADD_TEST(test_lock);
    ADD_TEST(test_once);
    ADD_TEST(test_thread_local);
    ADD_TEST(test_atomic);
    ADD_ALL_TESTS(test_multi, 2);
    return 1;
}
