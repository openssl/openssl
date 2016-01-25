/*
 * Written by Matt Caswell (matt@openssl.org) for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 2016 The OpenSSL Project.  All rights reserved.
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
#include "async_locl.h"

#include <openssl/err.h>

ASYNC_WAIT_CTX *ASYNC_WAIT_CTX_new(void)
{
    return OPENSSL_zalloc(sizeof(ASYNC_WAIT_CTX));
}

void ASYNC_WAIT_CTX_free(ASYNC_WAIT_CTX *ctx)
{
    struct fd_lookup_st *curr;

    if (ctx == NULL)
        return;

    curr = ctx->fds;
    while (curr != NULL) {
        if (curr->del) {
            /* This one has already been deleted so do nothing */
            curr = curr->next;
            continue;
        }
        if (curr->cleanup != NULL)
            curr->cleanup(ctx, curr->key, curr->fd, curr->custom_data);
        curr = curr->next;
    }

    OPENSSL_free(ctx);
}
int ASYNC_WAIT_CTX_set_wait_fd(ASYNC_WAIT_CTX *ctx, const void *key,
                               OSSL_ASYNC_FD fd, void *custom_data,
                               void (*cleanup)(ASYNC_WAIT_CTX *, const void *,
                                               OSSL_ASYNC_FD, void *))
{
    struct fd_lookup_st *fdlookup;

    fdlookup = OPENSSL_zalloc(sizeof *fdlookup);
    if (fdlookup == NULL)
        return 0;

    fdlookup->key = key;
    fdlookup->fd = fd;
    fdlookup->custom_data = custom_data;
    fdlookup->cleanup = cleanup;
    fdlookup->add = 1;
    fdlookup->next = ctx->fds;
    ctx->fds = fdlookup;
    ctx->numadd++;
    return 1;
}

int ASYNC_WAIT_CTX_get_fd(ASYNC_WAIT_CTX *ctx, const void *key,
                          OSSL_ASYNC_FD *fd, void **custom_data)
{
    struct fd_lookup_st *curr;

    curr = ctx->fds;
    while (curr != NULL) {
        if (curr->del) {
            /* This one has been marked deleted so do nothing */
            curr = curr->next;
            continue;
        }
        if (curr->key == key) {
            *fd = curr->fd;
            *custom_data = curr->custom_data;
            return 1;
        }
        curr = curr->next;
    }
    return 0;
}

int ASYNC_WAIT_CTX_get_all_fds(ASYNC_WAIT_CTX *ctx, OSSL_ASYNC_FD *fd,
                               size_t *numfds)
{
    struct fd_lookup_st *curr;

    curr = ctx->fds;
    *numfds = 0;
    while (curr != NULL) {
        if (curr->del) {
            /* This one has been marked deleted so do nothing */
            curr = curr->next;
            continue;
        }
        if (fd != NULL) {
            *fd = curr->fd;
            fd++;
        }
        (*numfds)++;
        curr = curr->next;
    }
    return 1;
}

int ASYNC_WAIT_CTX_get_changed_fds(ASYNC_WAIT_CTX *ctx, OSSL_ASYNC_FD *addfd,
                                   size_t *numaddfds, OSSL_ASYNC_FD *delfd,
                                   size_t *numdelfds)
{
    struct fd_lookup_st *curr;

    *numaddfds = ctx->numadd;
    *numdelfds = ctx->numdel;
    if (addfd == NULL && delfd == NULL)
        return 1;

    curr = ctx->fds;

    while (curr != NULL) {
        /* We ignore fds that have been marked as both added and deleted */
        if (curr->del && !curr->add && (delfd != NULL)) {
            *delfd = curr->fd;
            delfd++;
        }
        if (curr->add && !curr->del && (addfd != NULL)) {
            *addfd = curr->fd;
            addfd++;
        }
        curr = curr->next;
    }

    return 1;
}

int ASYNC_WAIT_CTX_clear_fd(ASYNC_WAIT_CTX *ctx, const void *key)
{
    struct fd_lookup_st *curr;

    curr = ctx->fds;
    while (curr != NULL) {
        if (curr->del) {
            /* This one has been marked deleted already so do nothing */
            curr = curr->next;
            continue;
        }
        if (curr->key == key) {
            /*
             * Mark it as deleted. We don't call cleanup if explicitly asked
             * to clear an fd. We assume the caller is going to do that
             */
            curr->del = 1;
            ctx->numdel++;
            return 1;
        }
        curr = curr->next;
    }
    return 0;
}

void async_wait_ctx_reset_counts(ASYNC_WAIT_CTX *ctx)
{
    struct fd_lookup_st *curr, *prev = NULL;

    ctx->numadd = 0;
    ctx->numdel = 0;

    curr = ctx->fds;

    while (curr != NULL) {
        if (curr->del) {
            if (prev == NULL)
                ctx->fds = curr->next;
            else
                prev->next = curr->next;
            OPENSSL_free(curr);
            if (prev == NULL)
                curr = ctx->fds;
            else
                curr = prev->next;
            continue;
        }
        if (curr->add) {
            curr->add = 0;
        }
        prev = curr;
        curr = curr->next;
    }
}
