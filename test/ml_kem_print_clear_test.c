/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Check that printing an ML-KEM private key as text does not leave the key
 * in memory handed back to the allocator.  A free hook looks at every block
 * before it is released and counts the blocks that still hold the whole
 * seed or the whole decapsulation key.
 */

#include <string.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include "testutil.h"

#define HDR 16

static unsigned char seed[64], dk[4096];
static size_t seed_len, dk_len;
static int watching;
static int leaks;
static const char *leak_file[16];
static int leak_line[16];

static int contains(const unsigned char *p, size_t n,
    const unsigned char *s, size_t s_len)
{
    size_t i;

    if (s_len == 0 || n < s_len)
        return 0;
    for (i = 0; i + s_len <= n; i++)
        if (memcmp(p + i, s, s_len) == 0)
            return 1;
    return 0;
}

static int holds_secret(const unsigned char *p, size_t n)
{
    return contains(p, n, seed, seed_len) || contains(p, n, dk, dk_len);
}

static void *hook_malloc(size_t num, const char *file, int line)
{
    size_t *p = malloc(num + HDR);

    if (p == NULL)
        return NULL;
    p[0] = num;
    return (unsigned char *)p + HDR;
}

static void hook_free(void *addr, const char *file, int line)
{
    unsigned char *base;

    if (addr == NULL)
        return;
    base = (unsigned char *)addr - HDR;
    /* Only record here: printing could allocate and re-enter the hook. */
    if (watching && holds_secret(addr, *(size_t *)base)) {
        if (leaks < (int)OSSL_NELEM(leak_file)) {
            leak_file[leaks] = file;
            leak_line[leaks] = line;
        }
        leaks++;
    }
    free(base);
}

static void *hook_realloc(void *addr, size_t num, const char *file, int line)
{
    void *ret;
    size_t old;

    if (addr == NULL)
        return hook_malloc(num, file, line);
    old = *(size_t *)((unsigned char *)addr - HDR);
    if ((ret = hook_malloc(num, file, line)) == NULL)
        return NULL;
    memcpy(ret, addr, old < num ? old : num);
    hook_free(addr, file, line);
    return ret;
}

int global_init(void)
{
    return CRYPTO_set_mem_functions(hook_malloc, hook_realloc, hook_free);
}

#ifndef OPENSSL_NO_ML_KEM
static const char *key_types[] = {
    "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"
};

static int set_secret(const EVP_PKEY *pkey)
{
    dk_len = sizeof(dk);
    return TEST_true(EVP_PKEY_get_octet_string_param(pkey,
               OSSL_PKEY_PARAM_ML_KEM_SEED, seed, sizeof(seed), &seed_len))
        && TEST_true(EVP_PKEY_get_raw_private_key(pkey, dk, &dk_len));
}

static void watch(void)
{
    leaks = 0;
    watching = 1;
}

static int report_leaks(const char *type)
{
    int i;

    watching = 0;
    if (TEST_int_eq(leaks, 0))
        return 1;
    for (i = 0; i < leaks && i < (int)OSSL_NELEM(leak_file); i++)
        TEST_info("%s: private key bytes freed uncleared at %s:%d", type,
            leak_file[i], leak_line[i]);
    return 0;
}

/* Printing the private key as text */
static int test_print_key(int idx)
{
    const char *type = key_types[idx];
    EVP_PKEY *pkey = NULL;
    BIO *mem = NULL;
    int ret = 0;

    if (!TEST_ptr(pkey = EVP_PKEY_Q_keygen(NULL, NULL, type))
        || !set_secret(pkey)
        || !TEST_ptr(mem = BIO_new(BIO_s_mem())))
        goto end;

    watch();
    if (!TEST_true(EVP_PKEY_print_private(mem, pkey, 0, NULL)))
        goto end;
    ret = report_leaks(type);
end:
    watching = 0;
    EVP_PKEY_free(pkey);
    BIO_free(mem);
    return ret;
}
#endif

int setup_tests(void)
{
#ifdef OPENSSL_NO_ML_KEM
    return TEST_skip("ML-KEM is disabled");
#else
    ADD_ALL_TESTS(test_print_key, OSSL_NELEM(key_types));
    return 1;
#endif
}
