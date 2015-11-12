/* crypto/async/arch/async_posix.c */
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

#include "../async_locl.h"
#include <openssl/async.h>

#ifdef ASYNC_POSIX
# include <stddef.h>
# include <ucontext.h>
# include <unistd.h>
# include <openssl/crypto.h>
# include <openssl/async.h>

__thread async_ctx *sysvctx;

#define STACKSIZE       32768

extern __thread size_t posixpool_max_size;
extern __thread size_t posixpool_curr_size;
extern __thread STACK_OF(ASYNC_JOB) *posixpool;
__thread size_t posixpool_max_size = 0;
__thread size_t posixpool_curr_size = 0;
__thread STACK_OF(ASYNC_JOB) *posixpool = NULL;

int async_fibre_init(async_fibre *fibre)
{
    void *stack = NULL;

    stack = OPENSSL_malloc(STACKSIZE);
    if (stack == NULL) {
        return 0;
    }

    fibre->fibre.uc_stack.ss_sp = stack;
    fibre->fibre.uc_stack.ss_size = STACKSIZE;
    fibre->fibre.uc_link = NULL;
    fibre->env_init = 0;

    return 1;
}

void async_fibre_free(async_fibre *fibre)
{
    if (fibre->fibre.uc_stack.ss_sp)
        OPENSSL_free(fibre->fibre.uc_stack.ss_sp);
}

int async_pipe(int *pipefds)
{
    if (pipe(pipefds) == 0)
        return 1;

    return 0;
}

int async_write1(int fd, const void *buf)
{
    if (write(fd, buf, 1) > 0)
        return 1;

    return 0;
}

int async_read1(int fd, void *buf)
{
    if (read(fd, buf, 1) > 0)
        return 1;

    return 0;
}

STACK_OF(ASYNC_JOB) *async_get_pool(void)
{
    return posixpool;
}

int async_set_pool(STACK_OF(ASYNC_JOB) *poolin, size_t curr_size,
                    size_t max_size)
{
    posixpool = poolin;
    posixpool_curr_size = curr_size;
    posixpool_max_size = max_size;
    return 1;
}

void async_increment_pool_size(void)
{
    posixpool_curr_size++;
}

void async_release_job_to_pool(ASYNC_JOB *job)
{
    sk_ASYNC_JOB_push(posixpool, job);
}

size_t async_pool_max_size(void)
{
    return posixpool_max_size;
}

void async_release_pool(void)
{
    sk_ASYNC_JOB_free(posixpool);
    posixpool = NULL;
}

int async_pool_can_grow(void)
{
    return (posixpool_max_size == 0)
        || (posixpool_curr_size < posixpool_max_size);
}

#endif
