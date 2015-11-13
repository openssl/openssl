/* crypto/async/arch/async_win.c */
/*
 * Written by Matt Caswell (matt@openssl.org) for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 2015 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

#include "async_win.h"

#ifdef ASYNC_WIN

# include <windows.h>
# include "internal/cryptlib.h"

struct winpool {
    STACK_OF(ASYNC_JOB) *pool;
    size_t curr_size;
    size_t max_size;
};

void async_start_func(void);

int async_fibre_init_dispatcher(async_fibre *fibre)
{
    LPVOID dispatcher;

    dispatcher =
        (LPVOID) CRYPTO_get_thread_local(CRYPTO_THREAD_LOCAL_ASYNC_DISPATCH);
    if (dispatcher == NULL) {
        fibre->fibre = ConvertThreadToFiber(NULL);
        CRYPTO_set_thread_local(CRYPTO_THREAD_LOCAL_ASYNC_DISPATCH,
                                (void *)fibre->fibre);
    } else {
        fibre->fibre = dispatcher;
    }
    return 1;
}

VOID CALLBACK async_start_func_win(PVOID unused)
{
    async_start_func();
}

int async_pipe(OSSL_ASYNC_FD *pipefds)
{
    if (CreatePipe(&pipefds[0], &pipefds[1], NULL, 256) == 0)
        return 0;

    return 1;
}

int async_write1(OSSL_ASYNC_FD fd, const void *buf)
{
    DWORD numwritten = 0;

    if (WriteFile(fd, buf, 1, &numwritten, NULL) && numwritten == 1)
        return 1;

    return 0;
}

int async_read1(OSSL_ASYNC_FD fd, void *buf)
{
    DWORD numread = 0;

    if (ReadFile(fd, buf, 1, &numread, NULL) && numread == 1)
        return 1;

    return 0;
}

STACK_OF(ASYNC_JOB) *async_get_pool(void)
{
    struct winpool *pool;
    pool = (struct winpool *)
            CRYPTO_get_thread_local(CRYPTO_THREAD_LOCAL_ASYNC_POOL);
    return pool->pool;
}


int async_set_pool(STACK_OF(ASYNC_JOB) *poolin, size_t curr_size,
                    size_t max_size)
{
    struct winpool *pool;
    pool = OPENSSL_malloc(sizeof *pool);
    if (pool == NULL)
        return 0;

    pool->pool = poolin;
    pool->curr_size = curr_size;
    pool->max_size = max_size;
    CRYPTO_set_thread_local(CRYPTO_THREAD_LOCAL_ASYNC_POOL, (void *)pool);
    return 1;
}

void async_increment_pool_size(void)
{
    struct winpool *pool;
    pool = (struct winpool *)
            CRYPTO_get_thread_local(CRYPTO_THREAD_LOCAL_ASYNC_POOL);
    pool->curr_size++;
}

void async_release_job_to_pool(ASYNC_JOB *job)
{
    struct winpool *pool;
    pool = (struct winpool *)
            CRYPTO_get_thread_local(CRYPTO_THREAD_LOCAL_ASYNC_POOL);
    sk_ASYNC_JOB_push(pool->pool, job);
}

size_t async_pool_max_size(void)
{
    struct winpool *pool;
    pool = (struct winpool *)
            CRYPTO_get_thread_local(CRYPTO_THREAD_LOCAL_ASYNC_POOL);
    return pool->max_size;
}

void async_release_pool(void)
{
    struct winpool *pool;
    pool = (struct winpool *)
            CRYPTO_get_thread_local(CRYPTO_THREAD_LOCAL_ASYNC_POOL);
    sk_ASYNC_JOB_free(pool->pool);
    OPENSSL_free(pool);
    CRYPTO_set_thread_local(CRYPTO_THREAD_LOCAL_ASYNC_POOL, NULL);
}

int async_pool_can_grow(void)
{
    struct winpool *pool;
    pool = (struct winpool *)
            CRYPTO_get_thread_local(CRYPTO_THREAD_LOCAL_ASYNC_POOL);
    return (pool->max_size == 0) || (pool->curr_size < pool->max_size);
}

#endif
