/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifdef OPENSSL_NO_CT
# error "CT is disabled"
#endif

#include <openssl/ct.h>
#include <openssl/err.h>

#include "ct_locl.h"

CT_POLICY_EVAL_CTX *CT_POLICY_EVAL_CTX_new(void)
{
    CT_POLICY_EVAL_CTX *ctx = OPENSSL_zalloc(sizeof(CT_POLICY_EVAL_CTX));

    if (ctx == NULL) {
        CTerr(CT_F_CT_POLICY_EVAL_CTX_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    return ctx;
}

void CT_POLICY_EVAL_CTX_free(CT_POLICY_EVAL_CTX *ctx)
{
    OPENSSL_free(ctx);
}

void CT_POLICY_EVAL_CTX_set0_cert(CT_POLICY_EVAL_CTX *ctx, X509 *cert)
{
    ctx->cert = cert;
}

void CT_POLICY_EVAL_CTX_set0_issuer(CT_POLICY_EVAL_CTX *ctx, X509 *issuer)
{
    ctx->issuer = issuer;
}

void CT_POLICY_EVAL_CTX_set0_log_store(CT_POLICY_EVAL_CTX *ctx,
                                       CTLOG_STORE *log_store)
{
    ctx->log_store = log_store;
}

const X509 *CT_POLICY_EVAL_CTX_get0_cert(const CT_POLICY_EVAL_CTX *ctx)
{
    return ctx->cert;
}

const X509 *CT_POLICY_EVAL_CTX_get0_issuer(const CT_POLICY_EVAL_CTX *ctx)
{
    return ctx->issuer;
}

const CTLOG_STORE *CT_POLICY_EVAL_CTX_get0_log_store(const CT_POLICY_EVAL_CTX *ctx)
{
    return ctx->log_store;
}

