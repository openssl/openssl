/* ====================================================================
 * Copyright (c) 1999-2015 The OpenSSL Project.  All rights reserved.
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
 *    openssl-core@OpenSSL.org.
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
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/objects.h>
#include <openssl/comp.h>
#include "comp_lcl.h"

COMP_CTX *COMP_CTX_new(COMP_METHOD *meth)
{
    COMP_CTX *ret;

    if ((ret = OPENSSL_zalloc(sizeof(*ret))) == NULL)
        return (NULL);
    ret->meth = meth;
    if ((ret->meth->init != NULL) && !ret->meth->init(ret)) {
        OPENSSL_free(ret);
        ret = NULL;
    }
    return (ret);
}

const COMP_METHOD *COMP_CTX_get_method(const COMP_CTX *ctx)
{
    return ctx->meth;
}

int COMP_get_type(const COMP_METHOD *meth)
{
    return meth->type;
}

const char *COMP_get_name(const COMP_METHOD *meth)
{
    return meth->name;
}

void COMP_CTX_free(COMP_CTX *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->meth->finish != NULL)
        ctx->meth->finish(ctx);

    OPENSSL_free(ctx);
}

int COMP_compress_block(COMP_CTX *ctx, unsigned char *out, int olen,
                        unsigned char *in, int ilen)
{
    int ret;
    if (ctx->meth->compress == NULL) {
        return (-1);
    }
    ret = ctx->meth->compress(ctx, out, olen, in, ilen);
    if (ret > 0) {
        ctx->compress_in += ilen;
        ctx->compress_out += ret;
    }
    return (ret);
}

int COMP_expand_block(COMP_CTX *ctx, unsigned char *out, int olen,
                      unsigned char *in, int ilen)
{
    int ret;

    if (ctx->meth->expand == NULL) {
        return (-1);
    }
    ret = ctx->meth->expand(ctx, out, olen, in, ilen);
    if (ret > 0) {
        ctx->expand_in += ilen;
        ctx->expand_out += ret;
    }
    return (ret);
}

int COMP_CTX_get_type(const COMP_CTX* comp)
{
    return comp->meth ? comp->meth->type : NID_undef;
}
