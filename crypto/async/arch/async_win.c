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

/* This must be the first #include file */
#include "../async_locl.h"

#ifdef ASYNC_WIN

# include <windows.h>
# include "internal/cryptlib.h"

struct winpool {
    STACK_OF(ASYNC_JOB) *pool;
    size_t curr_size;
    size_t max_size;
};

static DWORD asyncwinpool = 0;
static DWORD asyncwinctx = 0;
static DWORD asyncwindispatch = 0;


void async_start_func(void);

int async_global_init(void)
{
    asyncwinpool = TlsAlloc();
    asyncwinctx = TlsAlloc();
    asyncwindispatch = TlsAlloc();
    if (asyncwinpool == TLS_OUT_OF_INDEXES || asyncwinctx == TLS_OUT_OF_INDEXES
            || asyncwindispatch == TLS_OUT_OF_INDEXES) {
        if (asyncwinpool != TLS_OUT_OF_INDEXES) {
            TlsFree(asyncwinpool);
        }
        if (asyncwinctx != TLS_OUT_OF_INDEXES) {
            TlsFree(asyncwinctx);
        }
        if (asyncwindispatch != TLS_OUT_OF_INDEXES) {
            TlsFree(asyncwindispatch);
        }
        return 0;
    }
    return 1;
}

int async_local_init(void)
{
    return (TlsSetValue(asyncwinpool, NULL) != 0)
        && (TlsSetValue(asyncwinctx, NULL) != 0)
        && (TlsSetValue(asyncwindispatch, NULL) != 0);
}

void async_local_cleanup(void)
{
    async_ctx *ctx = async_get_ctx();
    if (ctx != NULL) {
        async_fibre *fibre = &ctx->dispatcher;
        if(fibre != NULL && fibre->fibre != NULL && fibre->converted) {
            ConvertFiberToThread();
            fibre->fibre = NULL;
        }
    }
}

void async_global_cleanup(void)
{
    TlsFree(asyncwinpool);
    TlsFree(asyncwinctx);
    TlsFree(asyncwindispatch);
    asyncwinpool = 0;
    asyncwinctx = 0;
    asyncwindispatch = 0;
}

int async_fibre_init_dispatcher(async_fibre *fibre)
{
    LPVOID dispatcher;

    dispatcher = (LPVOID)TlsGetValue(asyncwindispatch);
    if (dispatcher == NULL) {
        fibre->fibre = ConvertThreadToFiber(NULL);
        if (fibre->fibre == NULL) {
            fibre->converted = 0;
            fibre->fibre = GetCurrentFiber();
            if (fibre->fibre == NULL)
                return 0;
        } else {
            fibre->converted = 1;
        }
        if (TlsSetValue(asyncwindispatch, (LPVOID)fibre->fibre) == 0)
            return 0;
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

int async_close_fd(OSSL_ASYNC_FD fd)
{
    if (CloseHandle(fd) == 0)
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

async_pool *async_get_pool(void)
{
    return (async_pool *)TlsGetValue(asyncwinpool);
}


int async_set_pool(async_pool *pool)
{
    return TlsSetValue(asyncwinpool, (LPVOID)pool) != 0;
}

async_ctx *async_get_ctx(void)
{
    return (async_ctx *)TlsGetValue(asyncwinctx);
}

int async_set_ctx(async_ctx *ctx)
{
    return TlsSetValue(asyncwinctx, (LPVOID)ctx) != 0;
}

#endif
