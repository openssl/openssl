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
static int installed;
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

/*
 * Put the hooks in front of the allocator.  The library's own functions call
 * back into whatever is installed, so unless the mfail hooks are there to
 * pass allocations on to, the hooks use the C library directly, as mfail
 * does.  The allocator can only be replaced before the first allocation,
 * unless another allocator was installed before that: on master the test
 * driver installs mfail first, elsewhere test_watch_freed_init() has to run
 * at startup.
 */
static int watch_install(void)
{
    if (installed)
        return 1;
    if (mfail_is_installed()) {
        CRYPTO_get_mem_functions(&next_malloc, &next_realloc, &next_free);
    } else {
        next_malloc = NULL;
        next_realloc = NULL;
        next_free = NULL;
    }
    if (!CRYPTO_set_mem_functions(watch_malloc, watch_realloc, watch_free))
        return 0;
    installed = 1;
    return 1;
}

int test_watch_freed_init(void)
{
    const char *e = getenv("OPENSSL_TEST_WATCH_FREED");

    if (e == NULL || *e == '\0' || strcmp(e, "0") == 0)
        return 0;
    return watch_install() ? 1 : -1;
}

int test_watch_freed_start(const void *secret, size_t secret_len)
{
    if (watching || secret == NULL || secret_len == 0 || !watch_install())
        return 0;
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
    return overflow ? -1 : nfound;
}
