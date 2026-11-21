/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include "../testutil.h"
#include "tu_local.h"

/*
 * Blocks allocated while watching.  The table is fixed so that the hooks
 * below never allocate themselves.
 */
static struct {
    void *ptr;
    size_t size;
} watched[1024];
static size_t nwatched;
static int watching, overflow, nfound;
static const unsigned char *watch_secret;
static size_t watch_secret_len;
/*
 * The allocator the test program started with: the mfail hooks on master,
 * otherwise the library default.
 */
static int base_known;
static CRYPTO_malloc_fn base_malloc;
static CRYPTO_realloc_fn base_realloc;
static CRYPTO_free_fn base_free;
/* Where the hooks pass allocations on to; NULL means the C library */
static CRYPTO_malloc_fn next_malloc;
static CRYPTO_realloc_fn next_realloc;
static CRYPTO_free_fn next_free;

static int holds_secret(const unsigned char *p, size_t size)
{
    size_t i;

    for (i = 0; i + watch_secret_len <= size; i++)
        if (memcmp(p + i, watch_secret, watch_secret_len) == 0)
            return 1;
    return 0;
}

static void watch_add(void *ptr, size_t size)
{
    if (ptr == NULL)
        return;
    if (nwatched == sizeof(watched) / sizeof(watched[0])) {
        overflow = 1;
        return;
    }
    watched[nwatched].ptr = ptr;
    watched[nwatched].size = size;
    nwatched++;
}

static void watch_remove(void *ptr, int search)
{
    size_t i;

    for (i = 0; i < nwatched; i++) {
        if (watched[i].ptr != ptr)
            continue;
        if (search && holds_secret(ptr, watched[i].size))
            nfound++;
        watched[i] = watched[--nwatched];
        return;
    }
}

static void *next_malloc_fn(size_t num, const char *file, int line)
{
    if (next_malloc != NULL)
        return next_malloc(num, file, line);
    return num == 0 ? NULL : malloc(num);
}

static void *next_realloc_fn(void *ptr, size_t num, const char *file,
    int line)
{
    if (next_realloc != NULL)
        return next_realloc(ptr, num, file, line);
    if (ptr == NULL)
        return num == 0 ? NULL : malloc(num);
    if (num == 0) {
        free(ptr);
        return NULL;
    }
    return realloc(ptr, num);
}

static void next_free_fn(void *ptr, const char *file, int line)
{
    if (next_free != NULL)
        next_free(ptr, file, line);
    else
        free(ptr);
}

static void *watch_malloc(size_t num, const char *file, int line)
{
    void *ret = next_malloc_fn(num, file, line);

    if (watching)
        watch_add(ret, num);
    return ret;
}

static void *watch_realloc(void *ptr, size_t num, const char *file, int line)
{
    void *ret = next_realloc_fn(ptr, num, file, line);

    if (watching) {
        if (ptr != NULL && (ret != NULL || num == 0))
            watch_remove(ptr, 0);
        watch_add(ret, num);
    }
    return ret;
}

static void watch_free(void *ptr, const char *file, int line)
{
    if (watching && ptr != NULL)
        watch_remove(ptr, 1);
    next_free_fn(ptr, file, line);
}

static void note_base(void)
{
    if (base_known)
        return;
    CRYPTO_get_mem_functions(&base_malloc, &base_realloc, &base_free);
    base_known = 1;
}

static int hooks_installed(void)
{
    CRYPTO_malloc_fn m;
    CRYPTO_realloc_fn r;
    CRYPTO_free_fn f;

    CRYPTO_get_mem_functions(&m, &r, &f);
    return m == watch_malloc && r == watch_realloc && f == watch_free;
}

/*
 * Put the hooks in front of the allocator the program started with.  Tests
 * such as quic_stream_test and dtlsssllistenertest replace the allocator and
 * restore it afterwards, which can take the hooks out again, so look at what
 * is installed each time rather than remembering that this was done.
 *
 * The hooks pass every call on to the mfail hooks if those are the starting
 * allocator.  If it is the library default, they call the C library directly,
 * as mfail does, because the library's functions would call back into the
 * hooks.  If anything else is installed, such as a test's own allocator that
 * may itself call the hooks, return -1 rather than guess what to pass on to.
 *
 * The allocator can only be replaced before the first allocation, unless
 * another allocator was installed before that: on master the test driver
 * installs mfail first, elsewhere the hooks have to go in at startup (see
 * test_watch_freed_init()).  Return 0 if it cannot be replaced.
 */
static int watch_install(void)
{
    CRYPTO_malloc_fn m;
    CRYPTO_realloc_fn r;
    CRYPTO_free_fn f;

    note_base();
    CRYPTO_get_mem_functions(&m, &r, &f);
    if (m == watch_malloc && r == watch_realloc && f == watch_free)
        return 1;
    if (m != base_malloc || r != base_realloc || f != base_free)
        return -1;
    next_malloc = m == CRYPTO_malloc ? NULL : m;
    next_realloc = r == CRYPTO_realloc ? NULL : r;
    next_free = f == CRYPTO_free ? NULL : f;
    if (!CRYPTO_set_mem_functions(watch_malloc, watch_realloc, watch_free))
        return 0;
    return 1;
}

int test_watch_freed_init(void)
{
    const char *e = getenv("OPENSSL_TEST_WATCH_FREED");

    note_base();
    if (e == NULL || *e == '\0' || strcmp(e, "0") == 0)
        return 0;
    return watch_install() == 1 ? 1 : -1;
}

int test_watch_freed_start(const void *secret, size_t secret_len)
{
    int ret;

    if (watching || secret == NULL || secret_len == 0)
        return -1;
    if ((ret = watch_install()) != 1)
        return ret;
    nwatched = 0;
    overflow = 0;
    nfound = 0;
    watch_secret = secret;
    watch_secret_len = secret_len;
    watching = 1;
    return 1;
}

int test_watch_freed_stop(void)
{
    if (!watching)
        return -1;
    watching = 0;
    /* If the hooks were taken out, blocks freed meanwhile were not searched */
    if (overflow || !hooks_installed())
        return -1;
    return nfound;
}
