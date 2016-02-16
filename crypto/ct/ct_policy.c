/*
* Implementations of Certificate Transparency SCT policies.
* Written by Rob Percival (robpercival@google.com) for the OpenSSL project.
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
    ctx->good_scts = sk_SCT_new_null();
    ctx->bad_scts = sk_SCT_new_null();
    return ctx;
}

void CT_POLICY_EVAL_CTX_free(CT_POLICY_EVAL_CTX *ctx)
{
    sk_SCT_free(ctx->good_scts);
    sk_SCT_free(ctx->bad_scts);
    OPENSSL_free(ctx);
}

int CT_POLICY_EVAL_CTX_set0_cert(CT_POLICY_EVAL_CTX *ctx, X509 *cert)
{
    if (ctx == NULL) {
        CTerr(CT_F_CT_POLICY_EVAL_CTX_SET0_CERT, ERR_R_PASSED_NULL_PARAMETER);
        return -1;
    }

    ctx->cert = cert;
    return 1;
}

int CT_POLICY_EVAL_CTX_set0_issuer(CT_POLICY_EVAL_CTX *ctx, X509 *issuer)
{
    if (ctx == NULL) {
        CTerr(CT_F_CT_POLICY_EVAL_CTX_SET0_ISSUER, ERR_R_PASSED_NULL_PARAMETER);
        return -1;
    }

    ctx->issuer = issuer;
    return 1;
}

int CT_POLICY_EVAL_CTX_set0_log_store(CT_POLICY_EVAL_CTX *ctx,
    CTLOG_STORE *log_store)
{
    if (ctx == NULL) {
        CTerr(CT_F_CT_POLICY_EVAL_CTX_SET0_LOG_STORE, ERR_R_PASSED_NULL_PARAMETER);
        return -1;
    }

    ctx->log_store = log_store;
    return 1;
}

int CT_POLICY_EVAL_CTX_set0_good_scts(CT_POLICY_EVAL_CTX *ctx,
    STACK_OF(SCT) *scts)
{
    if (ctx == NULL) {
        CTerr(CT_F_CT_POLICY_EVAL_CTX_SET0_GOOD_SCTS, ERR_R_PASSED_NULL_PARAMETER);
        return -1;
    }

    ctx->good_scts = scts;
    return 1;
}

int CT_POLICY_EVAL_CTX_set0_bad_scts(CT_POLICY_EVAL_CTX *ctx,
    STACK_OF(SCT) *scts)
{
    if (ctx == NULL) {
        CTerr(CT_F_CT_POLICY_EVAL_CTX_SET0_BAD_SCTS, ERR_R_PASSED_NULL_PARAMETER);
        return -1;
    }

    ctx->bad_scts = scts;
    return 1;
}

X509* CT_POLICY_EVAL_CTX_get0_cert(CT_POLICY_EVAL_CTX *ctx)
{
    if (ctx == NULL) {
        CTerr(CT_F_CT_POLICY_EVAL_CTX_GET0_CERT, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    return ctx->cert;
}

X509* CT_POLICY_EVAL_CTX_get0_issuer(CT_POLICY_EVAL_CTX *ctx)
{
    if (ctx == NULL) {
        CTerr(CT_F_CT_POLICY_EVAL_CTX_GET0_ISSUER, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    return ctx->issuer;
}

CTLOG_STORE *CT_POLICY_EVAL_CTX_get0_log_store(CT_POLICY_EVAL_CTX *ctx)
{
    if (ctx == NULL) {
        CTerr(CT_F_CT_POLICY_EVAL_CTX_GET0_LOG_STORE, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    return ctx->log_store;
}

STACK_OF(SCT) *CT_POLICY_EVAL_CTX_get0_good_scts(CT_POLICY_EVAL_CTX *ctx)
{
    if (ctx == NULL) {
        CTerr(CT_F_CT_POLICY_EVAL_CTX_GET0_GOOD_SCTS, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    return ctx->good_scts;
}

STACK_OF(SCT) *CT_POLICY_EVAL_CTX_get0_bad_scts(CT_POLICY_EVAL_CTX *ctx)
{
    if (ctx == NULL) {
        CTerr(CT_F_CT_POLICY_EVAL_CTX_GET0_BAD_SCTS, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    return ctx->bad_scts;
}
