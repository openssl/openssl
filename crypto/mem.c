/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <openssl/crypto.h>
#include "internal/cryptlib.h"

/*
 * the following pointers may be changed as long as 'allow_customize' is set
 */
static int allow_customize = 1;

static void *(*malloc_wrapper)(size_t, const char *, int)
    = CRYPTO_malloc;
static void *(*realloc_wrapper)(void *, size_t, const char *, int)
    = CRYPTO_realloc;
static void (*free_wrapper)(void *)
    = CRYPTO_free;

#ifndef OPENSSL_NO_CRYPTO_MDEBUG
static int call_malloc_debug = 1;
#else
static int call_malloc_debug = 0;
#endif

int CRYPTO_set_mem_functions(
        void *(*m)(size_t, const char *, int),
        void *(*r)(void *, size_t, const char *, int),
        void (*f)(void *))
{
    if (!allow_customize)
        return 0;
    if (m)
        malloc_wrapper = m;
    if (r)
        realloc_wrapper = r;
    if (f)
        free_wrapper = f;
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
        void (**f)(void *))
{
    if (m != NULL)
        *m = malloc_wrapper;
    if (r != NULL)
        *r = realloc_wrapper;
    if (f != NULL)
        *f = free_wrapper;
}

void *CRYPTO_malloc(size_t num, const char *file, int line)
{
    void *ret = NULL;

    if (num <= 0)
        return NULL;

    allow_customize = 0;
#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (call_malloc_debug) {
        CRYPTO_mem_debug_malloc(NULL, num, 0, file, line);
        ret = malloc(num);
        CRYPTO_mem_debug_malloc(ret, num, 1, file, line);
    } else {
        ret = malloc(num);
    }
#else
    (void)file;
    (void)line;
    ret = malloc(num);
#endif

#ifndef OPENSSL_CPUID_OBJ
    /*
     * Create a dependency on the value of 'cleanse_ctr' so our memory
     * sanitisation function can't be optimised out. NB: We only do this for
     * >2Kb so the overhead doesn't bother us.
     */
    if (ret && (num > 2048)) {
        extern unsigned char cleanse_ctr;
        ((unsigned char *)ret)[0] = cleanse_ctr;
    }
#endif

    return ret;
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
    if (str == NULL)
        return CRYPTO_malloc(num, file, line);

    if (num == 0) {
        CRYPTO_free(str);
        return NULL;
    }

    allow_customize = 0;
#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (call_malloc_debug) {
        void *ret;
        CRYPTO_mem_debug_realloc(str, NULL, num, 0, file, line);
        ret = realloc(str, num);
        CRYPTO_mem_debug_realloc(str, ret, num, 1, file, line);
        return ret;
    }
#else
    (void)file;
    (void)line;
#endif
    return realloc(str, num);

}

void *CRYPTO_clear_realloc(void *str, size_t old_len, size_t num,
                           const char *file, int line)
{
    void *ret = NULL;

    if (str == NULL)
        return CRYPTO_malloc(num, file, line);

    if (num == 0) {
        CRYPTO_clear_free(str, old_len);
        return NULL;
    }

    /* Can't shrink the buffer since memcpy below copies |old_len| bytes. */
    if (num < old_len) {
        memset((char*)str + num, 0, old_len - num);
        return str;
    }

    /* Allocate new memory.  Call malloc and do a copy, so that we can
     * cleanse the old buffer. */
#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (call_malloc_debug) {
        CRYPTO_mem_debug_realloc(str, NULL, num, 0, file, line);
        ret = malloc(num);
        CRYPTO_mem_debug_realloc(str, ret, num, 1, file, line);
    } else {
        ret = malloc(num);
    }
#else
    (void)file;
    (void)line;
    ret = malloc(num);
#endif

    if (ret)
        memcpy(ret, str, old_len);
    CRYPTO_clear_free(str, old_len);
    return ret;
}

void CRYPTO_free(void *str)
{
#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (call_malloc_debug) {
        CRYPTO_mem_debug_free(str, 0);
        free(str);
        CRYPTO_mem_debug_free(str, 1);
    } else {
        free(str);
    }
#else
    free(str);
#endif
}

void CRYPTO_clear_free(void *str, size_t num)
{
    if (str == NULL)
        return;
    if (num)
        OPENSSL_cleanse(str, num);
    CRYPTO_free(str);
}
