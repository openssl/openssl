/*
 * Written by Diego F. Aranha (d@miracl.com) and contributed to the
 * the OpenSSL project.
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
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/*
 * ====================================================================
 * Copyright 2016 MIRACL UK Ltd., All Rights Reserved. Portions of the
 * attached software ("Contribution") are developed by MIRACL UK LTD., and
 * are contributed to the OpenSSL project. The Contribution is licensed
 * pursuant to the OpenSSL open source license provided above.
 */

#include <openssl/ec.h>

#include "bp_lcl.h"

GT_ELEM *GT_ELEM_new(const BP_GROUP *group)
{
    GT_ELEM *ret;

    if ((ret = OPENSSL_malloc(sizeof(*ret))) == NULL)
        return NULL;

    ret->f = FP12_new();
    if (ret->f == NULL) {
        FP12_free(ret->f);
        return NULL;
    }
    return (ret);
}

void GT_ELEM_free(GT_ELEM *a)
{
    if (a == NULL)
        return;
    FP12_free(a->f);
    OPENSSL_free(a);
}

void GT_clear_free(GT_ELEM *a)
{
    if (a == NULL)
        return;
    FP12_clear_free(a->f);
    OPENSSL_free(a);
}

int GT_ELEM_copy(GT_ELEM *a, const GT_ELEM *b)
{
    return FP12_copy(a->f, b->f);
}

GT_ELEM *GT_ELEM_dup(const GT_ELEM *a, const BP_GROUP *group)
{
    GT_ELEM *t;

    if (a == NULL)
        return NULL;
    t = GT_ELEM_new(group);
    if (t == NULL)
        return NULL;
    if (!GT_ELEM_copy(t, a)) {
        GT_ELEM_free(t);
        return NULL;
    }
    return t;
}

int GT_ELEM_zero(GT_ELEM *a)
{
    return FP12_zero(a->f);
}

int GT_ELEM_is_zero(GT_ELEM *a)
{
    return FP12_is_zero(a->f);
}

int GT_ELEM_set_to_unity(const BP_GROUP *group, GT_ELEM *a)
{
    if (!FP12_zero(a->f))
        return 0;
    return BN_copy(a->f->f[0]->f[0]->f[0], group->one) != NULL;
}

int GT_ELEM_is_unity(const BP_GROUP *group, const GT_ELEM *a)
{
    if (FP6_is_zero(a->f->f[1]) == 0)
        return 0;
    if (FP2_is_zero(a->f->f[0]->f[1]) == 0)
        return 0;
    if (FP2_is_zero(a->f->f[0]->f[2]) == 0)
        return 0;
    if (BN_is_zero(a->f->f[0]->f[0]->f[1]) == 0)
        return 0;
    if (!BN_cmp(a->f->f[0]->f[0]->f[0], group->one) == 0)
        return 0;
    return 1;
}

size_t GT_ELEM_elem2oct(const BP_GROUP *group, const GT_ELEM *a,
                        unsigned char *buf, size_t len, BN_CTX *ctx)
{
    size_t ret;
    BN_CTX *new_ctx = NULL;
    int used_ctx = 0;
    BIGNUM *f;
    size_t field_len, i, j, k, l, skip;

    /*
     * ret := required output buffer length
     */
    field_len = BN_num_bytes(group->field);
    ret = 12 * field_len;

    /*
     * if 'buf' is NULL, just return required length
     */
    if (buf != NULL) {
        if (len < ret)
            goto err;

        if (ctx == NULL && (ctx = new_ctx = BN_CTX_new()) == NULL)
            return 0;

        BN_CTX_start(ctx);
        used_ctx = 1;
        if ((f = BN_CTX_get(ctx)) == NULL)
            goto err;

        l = 0;
        for (i = 0; i < 2; i++) {
            for (j = 0; j < 3; j++) {
                for (k = 0; k < 2; k++) {
                    if (!BN_from_montgomery(f, a->f->f[i]->f[j]->f[k],
                                            group->mont, ctx))
                        goto err;
                    skip = field_len - BN_num_bytes(f);
                    if (skip > field_len)
                        goto err;
                    while (skip > 0) {
                        buf[l++] = 0;
                        skip--;
                    }
                    skip = BN_bn2bin(f, buf + l);
                    l += skip;
                    if (l != (i * 6 + j * 2 + k + 1) * field_len)
                        goto err;
                }
            }
        }

        if (l != ret)
            goto err;
    }

    if (used_ctx)
        BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;

 err:
    if (used_ctx)
        BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return 0;
}

int GT_ELEM_oct2elem(const BP_GROUP *group, GT_ELEM *a,
                     const unsigned char *buf, size_t len, BN_CTX *ctx)
{
    BN_CTX *new_ctx = NULL;
    BIGNUM *f;
    size_t field_len, enc_len;
    int i, j, k, ret = 0;

    if (len == 0)
        return 0;

    field_len = BN_num_bytes(group->field);
    enc_len = 12 * field_len;

    if (len != enc_len)
        return 0;

    if (ctx == NULL && (ctx = new_ctx = BN_CTX_new()) == NULL)
        return 0;

    BN_CTX_start(ctx);
    if ((f = BN_CTX_get(ctx)) == NULL)
        goto err;

    for (i = 0; i < 2; i++) {
        for (j = 0; j < 3; j++) {
            for (k = 0; k < 2; k++) {
                if (!BN_bin2bn(buf, field_len, f))
                    goto err;
                if (BN_ucmp(f, group->field) >= 0)
                    goto err;
                if (!BN_to_montgomery(a->f->f[i]->f[j]->f[k], f,
                                      group->mont, ctx))
                    goto err;
                buf += field_len;
            }
        }
    }

    ret = 1;

 err:
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);
    return ret;
}

int GT_ELEM_add(const BP_GROUP *group, GT_ELEM *r, const GT_ELEM *a,
                const GT_ELEM *b, BN_CTX *ctx)
{
    return FP12_add(group, r->f, a->f, b->f);
}

int GT_ELEM_sub(const BP_GROUP *group, GT_ELEM *r, const GT_ELEM *a,
                const GT_ELEM *b, BN_CTX *ctx)
{
    return FP12_sub(group, r->f, a->f, b->f);
}

int GT_ELEM_sqr(const BP_GROUP *group, GT_ELEM *r, const GT_ELEM *a,
                BN_CTX *ctx)
{
    return FP12_sqr(group, r->f, a->f, ctx);
}

int GT_ELEM_mul(const BP_GROUP *group, GT_ELEM *r, GT_ELEM *a, GT_ELEM *b,
                BN_CTX *ctx)
{
    return FP12_mul(group, r->f, a->f, b->f, ctx);
}

int GT_ELEM_inv(const BP_GROUP *group, GT_ELEM *r, GT_ELEM *a, BN_CTX *ctx)
{
    return FP12_inv(group, r->f, a->f, ctx);
}

int GT_ELEM_cmp(const GT_ELEM *a, const GT_ELEM *b)
{
    return FP12_cmp(a->f, b->f);
}

int GT_ELEM_exp(const BP_GROUP *group, GT_ELEM *r, const GT_ELEM *a,
                const BIGNUM *b, BN_CTX *ctx)
{
    return FP12_exp_cyclotomic(group, r->f, a->f, b, ctx);
}
