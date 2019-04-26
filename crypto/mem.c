/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"
#include "internal/cryptlib.h"
#include "internal/cryptlib_int.h"
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <openssl/crypto.h>
#if !defined(OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE) && !defined(FIPS_MODE)
# include <execinfo.h>
#endif

typedef void *(*OSSL_REALLOC)(void *, size_t, const char *, int);
typedef void *(*OSSL_MALLOC)(size_t, const char *, int);
typedef void (*OSSL_FREE)(void *, const char *, int);

static void *simple_malloc(size_t n, const char *file, int line)
{
    (void)file; (void)line;
    if (n == 0)
        return NULL;
    return malloc(n);
}
static void *simple_realloc(void *p, size_t n, const char *file, int line)
{
    (void)file; (void)line;
    return realloc(p, n);
}
static void simple_free(void *p, const char *file, int line)
{
    (void)file; (void)line;
    free(p);
}

/*
 * the following pointers may be changed as long as 'allow_customize' is set
 */
static int allow_customize = 1;

static OSSL_MALLOC malloc_impl = simple_malloc;
static OSSL_REALLOC realloc_impl = simple_realloc;
static OSSL_FREE free_impl = simple_free;

#if !defined(OPENSSL_NO_CRYPTO_MPROTECT) && !defined(FIPS_MODE)
/*
 * OPENSSL EXTENDED MALLOC SUPPORT
 *
 * OpenSSL allocates an extra 4*sizeof(void*) bytes to protect and help track memory
 * allocations. A broad assumption is that sizeof(size_t) <= sizeof(void*), which
 * is a reasonable assumption for 32-bit+ systems supported by OpenSSL.
 *
 * +----------+---------+------+---------+-------------------     +---------+
 * | self-ptr | size    | free | realloc | guard | allocation ... | guard   |
 * +----------+---------+------+---------+-------------------     +---------+
 *
 * Each field is sizeof(void*) in size:
 * self-ptr:  is a pointer to the allocation itself, used as an indicator of
 *            legal OpenSSL memory
 * size:      size of the allocation (n)
 * free:      a pointer to free function
 * realloc:   a pointer to the realloc function
 * guard:     guard bytes at the beginning and end of data
 * The trailing guard is accessed as bytes, to avoid alignment issues
 */

#define GUARD_SIZE            sizeof(void*)
#define EXTRA_ALLOC           (sizeof(OSSL_MEM_HEADER) + GUARD_SIZE)
#define OUT_PTR(x)            ((OSSL_MEM_HEADER*)x + 1)
#define IN_PTR(x)             ((OSSL_MEM_HEADER*)x - 1)
#define SELF_VAL(x)           ((OSSL_MEM_HEADER*)x)->self
#define SIZE_VAL(x)           ((OSSL_MEM_HEADER*)x)->size
#define HEAD_GUARD_PTR(x)     ((OSSL_MEM_HEADER*)x)->guard
#define TAIL_GUARD_PTR(x, n)  ((void*)((char*)OUT_PTR(x) + n))

typedef struct ossl_mem_header_st {
    void* self;
    size_t size;
    unsigned char guard[GUARD_SIZE];
} OSSL_MEM_HEADER;

/* Will work until there are 128-bit systems */
static uint8_t guard[] = { 'O', 'p', 'e', 'n', 'S', 'S', 'L', '!' };

/* assumes |n| is original allocation request size */
static void *protect_mem(void *p, size_t n)
{
    if (p == NULL || n == 0)
        return p;
    SELF_VAL(p) = p;
    SIZE_VAL(p) = n;
    memcpy(HEAD_GUARD_PTR(p), guard, GUARD_SIZE);
    memcpy(TAIL_GUARD_PTR(p, n), guard, GUARD_SIZE);
    return OUT_PTR(p);
}

static void *check_mem(void *p, size_t *num, const char *file, int line)
{
    if (p == NULL)
        return p;
    p = IN_PTR(p);

    if (SELF_VAL(p) == NULL)
        OPENSSL_die("check_mem: possible double-free", file, line);
    if (SELF_VAL(p) != p)
        OPENSSL_die("check_mem: bad pointer", file, line);
    if (memcmp(HEAD_GUARD_PTR(p), guard, GUARD_SIZE))
        OPENSSL_die("check_mem: bad head guard", file, line);
    if (memcmp(TAIL_GUARD_PTR(p, SIZE_VAL(p)), guard, GUARD_SIZE))
        OPENSSL_die("check_mem: bad tail guard", file, line);

    if (num != NULL)
        *num += EXTRA_ALLOC;

    SELF_VAL(p) = NULL;
    return p;
}
#else
static void *protect_mem(void *p, size_t n)
{
    (void)n;
    return p;
}
static void *check_mem(void *p, size_t *num, const char *file, int line)
{
    (void)num; (void)file; (void)line;
    return p;
}
#define EXTRA_ALLOC 0
#endif

#if !defined(OPENSSL_NO_CRYPTO_MDEBUG) && !defined(FIPS_MODE)
# include "internal/tsan_assist.h"

static TSAN_QUALIFIER int malloc_count;
static TSAN_QUALIFIER int realloc_count;
static TSAN_QUALIFIER int free_count;

# define INCREMENT(x) tsan_counter(&(x))

static char *md_failstring;
static char *md_failstring_orig;
static long md_count;
static int md_fail_percent = 0;
static int md_tracefd = -1;
static int call_malloc_debug = 1;

static void parseit(void);
static int shouldfail(void);

# define FAILTEST() if (shouldfail()) return NULL

#else
static int call_malloc_debug = 0;

# define INCREMENT(x) /* empty */
# define FAILTEST() /* empty */
#endif

int CRYPTO_set_mem_functions(
        void *(*m)(size_t, const char *, int),
        void *(*r)(void *, size_t, const char *, int),
        void (*f)(void *, const char *, int))
{
    if (!allow_customize)
        return 0;

    if (m == CRYPTO_malloc)
        malloc_impl = simple_malloc;
    else if (m != NULL)
        malloc_impl = m;

    if (r == CRYPTO_realloc)
        realloc_impl = simple_realloc;
    else if (r != NULL)
        realloc_impl = r;

    if (f == CRYPTO_free)
        free_impl = simple_free;
    else if (f != NULL)
        free_impl = f;

    return 1;
}

int CRYPTO_set_mem_debug(int flag)
{
    if (!allow_customize)
        return 0;
    call_malloc_debug = flag;
    return 1;
}

void CRYPTO_get_mem_functions(
        void *(**m)(size_t, const char *, int),
        void *(**r)(void *, size_t, const char *, int),
        void (**f)(void *, const char *, int))
{
    if (m != NULL)
        *m = malloc_impl;
    if (r != NULL)
        *r = realloc_impl;
    if (f != NULL)
        *f = free_impl;
}

#if !defined(OPENSSL_NO_CRYPTO_MDEBUG) && !defined(FIPS_MODE)
void CRYPTO_get_alloc_counts(int *mcount, int *rcount, int *fcount)
{
    if (mcount != NULL)
        *mcount = tsan_load(&malloc_count);
    if (rcount != NULL)
        *rcount = tsan_load(&realloc_count);
    if (fcount != NULL)
        *fcount = tsan_load(&free_count);
}

/*
 * Parse a "malloc failure spec" string.  This likes like a set of fields
 * separated by semicolons.  Each field has a count and an optional failure
 * percentage.  For example:
 *          100@0;100@25;0@0
 *    or    100;100@25;0
 * This means 100 mallocs succeed, then next 100 fail 25% of the time, and
 * all remaining (count is zero) succeed.
 */
static void parseit(void)
{
    char *semi = strchr(md_failstring, ';');
    char *atsign;

    if (semi != NULL)
        *semi++ = '\0';

    /* Get the count (atol will stop at the @ if there), and percentage */
    md_count = atol(md_failstring);
    atsign = strchr(md_failstring, '@');
    md_fail_percent = atsign == NULL ? 0 : atoi(atsign + 1);

    if (semi != NULL)
        md_failstring = semi;
}

/*
 * Windows doesn't have random(), but it has rand()
 * Some rand() implementations aren't good, but we're not
 * dealing with secure randomness here.
 */
# ifdef _WIN32
#  define random() rand()
# endif
/*
 * See if the current malloc should fail.
 */
static int shouldfail(void)
{
    int roll = (int)(random() % 100);
    int shoulditfail = roll < md_fail_percent;
# ifndef _WIN32
/* suppressed on Windows as POSIX-like file descriptors are non-inheritable */
    int len;
    char buff[80];

    if (md_tracefd > 0) {
        BIO_snprintf(buff, sizeof(buff),
                     "%c C%ld %%%d R%d\n",
                     shoulditfail ? '-' : '+', md_count, md_fail_percent, roll);
        len = strlen(buff);
        if (write(md_tracefd, buff, len) != len)
            perror("shouldfail write failed");
#  ifndef OPENSSL_NO_CRYPTO_MDEBUG_BACKTRACE
        if (shoulditfail) {
            void *addrs[30];
            int num = backtrace(addrs, OSSL_NELEM(addrs));

            backtrace_symbols_fd(addrs, num, md_tracefd);
        }
#  endif
    }
# endif

    if (md_count) {
        /* If we used up this one, go to the next. */
        if (--md_count == 0)
            parseit();
    }

    return shoulditfail;
}

void ossl_malloc_setup_failures(void)
{
    const char *cp = getenv("OPENSSL_MALLOC_FAILURES");

    if (cp != NULL && (md_failstring_orig = md_failstring = strdup(cp)) != NULL)
        parseit();
    if ((cp = getenv("OPENSSL_MALLOC_FD")) != NULL)
        md_tracefd = atoi(cp);
}
#endif

void *CRYPTO_malloc(size_t num, const char *file, int line)
{
    void *ret = NULL;
    size_t new_num = num;

    INCREMENT(malloc_count);
    FAILTEST();
    if (allow_customize) {
        /*
         * Disallow customization after the first allocation. We only set this
         * if necessary to avoid a store to the same cache line on every
         * allocation.
         */
        allow_customize = 0;
    }

    if (num != 0)
        new_num += EXTRA_ALLOC;

#if !defined(OPENSSL_NO_CRYPTO_MDEBUG) && !defined(FIPS_MODE)
    if (call_malloc_debug && new_num != 0)
        CRYPTO_mem_debug_malloc(NULL, new_num, 0, file, line);
#endif
    ret = malloc_impl(new_num, file, line);
#if !defined(OPENSSL_NO_CRYPTO_MDEBUG) && !defined(FIPS_MODE)
    if (call_malloc_debug && new_num != 0)
        CRYPTO_mem_debug_malloc(ret, new_num, 1, file, line);
#endif

    return protect_mem(ret, num);
}

void *CRYPTO_zalloc(size_t num, const char *file, int line)
{
    void *ret = CRYPTO_malloc(num, file, line);

    if (ret != NULL)
        memset(ret, 0, num);
    return ret;
}

void *CRYPTO_realloc(void *str, size_t num, const char *file, int line)
{
    void *ret;
    size_t new_num = num;

    if (str == NULL)
        return CRYPTO_malloc(num, file, line);

    if (num == 0) {
        CRYPTO_free(str, file, line);
        return NULL;
    }

    INCREMENT(realloc_count);
    FAILTEST();

    new_num = num;
    str = check_mem(str, &new_num, file, line);

#if !defined(OPENSSL_NO_CRYPTO_MDEBUG) && !defined(FIPS_MODE)
    if (call_malloc_debug)
        CRYPTO_mem_debug_realloc(str, NULL, new_num, 0, file, line);
#endif
    ret = realloc_impl(str, new_num, file, line);
#if !defined(OPENSSL_NO_CRYPTO_MDEBUG) && !defined(FIPS_MODE)
    if (call_malloc_debug)
        CRYPTO_mem_debug_realloc(str, ret, new_num, 1, file, line);
#endif

    return protect_mem(ret, num);
}

void *CRYPTO_clear_realloc(void *str, size_t old_len, size_t num,
                           const char *file, int line)
{
    void *ret = NULL;

    if (str == NULL)
        return CRYPTO_malloc(num, file, line);

    if (num == 0) {
        CRYPTO_clear_free(str, old_len, file, line);
        return NULL;
    }

    /* Can't shrink the buffer since memcpy below copies |old_len| bytes. */
    if (num < old_len) {
        OPENSSL_cleanse((char*)str + num, old_len - num);
        return str;
    }

    ret = CRYPTO_malloc(num, file, line);
    if (ret != NULL) {
        memcpy(ret, str, old_len);
        CRYPTO_clear_free(str, old_len, file, line);
    }
    return ret;
}

void CRYPTO_free(void *str, const char *file, int line)
{
    INCREMENT(free_count);
    str = check_mem(str, NULL, file, line);

#if !defined(OPENSSL_NO_CRYPTO_MDEBUG) && !defined(FIPS_MODE)
    if (call_malloc_debug)
        CRYPTO_mem_debug_free(str, 0, file, line);
#endif
    free_impl(str, file, line);
#if !defined(OPENSSL_NO_CRYPTO_MDEBUG) && !defined(FIPS_MODE)
    if (call_malloc_debug)
        CRYPTO_mem_debug_free(str, 1, file, line);
#endif
}

void CRYPTO_clear_free(void *str, size_t num, const char *file, int line)
{
    if (str == NULL)
        return;
    if (num)
        OPENSSL_cleanse(str, num);
    CRYPTO_free(str, file, line);
}
