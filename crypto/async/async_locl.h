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

/*
 * Must do this before including any header files, because on MacOS/X <stlib.h>
 * includes <signal.h> which includes <ucontext.h>
 */
#if defined(__APPLE__) && defined(__MACH__) && !defined(_XOPEN_SOURCE)
# define _XOPEN_SOURCE          /* Otherwise incomplete ucontext_t structure */
# pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <internal/async.h>
#include <openssl/crypto.h>

typedef struct async_ctx_st async_ctx;
typedef struct async_pool_st async_pool;

#include "arch/async_win.h"
#include "arch/async_posix.h"
#include "arch/async_null.h"

struct async_ctx_st {
    async_fibre dispatcher;
    ASYNC_JOB *currjob;
    unsigned int blocked;
};

struct async_job_st {
    async_fibre fibrectx;
    int (*func) (void *);
    void *funcargs;
    int ret;
    int status;
    ASYNC_WAIT_CTX *waitctx;
};

struct fd_lookup_st {
    const void *key;
    OSSL_ASYNC_FD fd;
    void *custom_data;
    void (*cleanup)(ASYNC_WAIT_CTX *, const void *, OSSL_ASYNC_FD, void *);
    int add;
    int del;
    struct fd_lookup_st *next;
};

struct async_wait_ctx_st {
    struct fd_lookup_st *fds;
    size_t numadd;
    size_t numdel;
};

DEFINE_STACK_OF(ASYNC_JOB)

struct async_pool_st {
    STACK_OF(ASYNC_JOB) *jobs;
    size_t curr_size;
    size_t max_size;
};

int async_global_init(void);
void async_local_cleanup(void);
void async_global_cleanup(void);
void async_start_func(void);

void async_wait_ctx_reset_counts(ASYNC_WAIT_CTX *ctx);

