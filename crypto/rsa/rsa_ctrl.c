/*
 * Copyright 1995-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * RSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/err.h>
#include "crypto/evp.h"
#include "crypto/rsa.h"

#define LEGACY_SET_RSA_KEYGEN2_CTRL(_ctx, _cmd, _p1, _p2)                      \
EVP_PKEY_CTX_ctrl(_ctx, EVP_PKEY_RSA, EVP_PKEY_OP_KEYGEN, _cmd, _p1, _p2)

#define LEGACY_SET_RSA_KEYGEN(_ctx, _cmd, _p1, _p2)                            \
LEGACY_EVP_PKEY_CTX_CTRL(_ctx->op.keymgmt.genctx == NULL, _ctx,                \
                         EVP_PKEY_RSA, EVP_PKEY_OP_KEYGEN, _cmd, _p1, _p2)

#define LEGACY_SET_RSA_SIG_OR_ASYM(_ctx, _ktype, _op, _cmd, _p1, _p2)          \
LEGACY_EVP_PKEY_CTX_CTRL(                                                      \
    (EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(_ctx) && _ctx->op.ciph.ciphprovctx == NULL)\
    || (EVP_PKEY_CTX_IS_SIGNATURE_OP(_ctx) && _ctx->op.sig.sigprovctx == NULL),\
    _ctx, _ktype, _op, _cmd, _p1, _p2)

int EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad_mode)
{
    OSSL_PARAM pad_params[2], *p = pad_params;

    if (ctx == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA or RSA-PSS return error */
    if (ctx->pmeth != NULL
            && ctx->pmeth->pkey_id != EVP_PKEY_RSA
            && ctx->pmeth->pkey_id != EVP_PKEY_RSA_PSS)
        return -1;

    LEGACY_SET_RSA_SIG_OR_ASYM(ctx, -1, -1,
                               EVP_PKEY_CTRL_RSA_PADDING, pad_mode, NULL);

    *p++ = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_PAD_MODE, &pad_mode);
    *p = OSSL_PARAM_construct_end();

    return EVP_PKEY_CTX_set_params(ctx, pad_params);
}

int EVP_PKEY_CTX_get_rsa_padding(EVP_PKEY_CTX *ctx, int *pad_mode)
{
    OSSL_PARAM pad_params[2], *p = pad_params;

    if (ctx == NULL || pad_mode == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA or RSA-PSS return error */
    if (ctx->pmeth != NULL
            && ctx->pmeth->pkey_id != EVP_PKEY_RSA
            && ctx->pmeth->pkey_id != EVP_PKEY_RSA_PSS)
        return -1;

    LEGACY_SET_RSA_SIG_OR_ASYM(ctx, -1, -1,
                               EVP_PKEY_CTRL_GET_RSA_PADDING, 0, pad_mode);

    *p++ = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_PAD_MODE, pad_mode);
    *p = OSSL_PARAM_construct_end();

    if (!EVP_PKEY_CTX_get_params(ctx, pad_params))
        return 0;

    return 1;

}

int EVP_PKEY_CTX_set_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)
{
    const char *name;

    if (ctx == NULL || !EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA return error */
    if (ctx->pmeth != NULL && ctx->pmeth->pkey_id != EVP_PKEY_RSA)
        return -1;

    LEGACY_EVP_PKEY_CTX_CTRL(ctx->op.ciph.ciphprovctx == NULL, ctx,
                             EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,
                             EVP_PKEY_CTRL_RSA_OAEP_MD, 0, (void *)md);

    name = (md == NULL) ? "" : EVP_MD_name(md);

    return EVP_PKEY_CTX_set_rsa_oaep_md_name(ctx, name, NULL);
}

int EVP_PKEY_CTX_set_rsa_oaep_md_name(EVP_PKEY_CTX *ctx, const char *mdname,
                                      const char *mdprops)
{
    OSSL_PARAM rsa_params[3], *p = rsa_params;

    if (ctx == NULL || !EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA return error */
    if (ctx->pmeth != NULL && ctx->pmeth->pkey_id != EVP_PKEY_RSA)
        return -1;


    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
                                            /*
                                             * Cast away the const. This is read
                                             * only so should be safe
                                             */
                                            (char *)mdname, 0);
    if (mdprops != NULL) {
        *p++ = OSSL_PARAM_construct_utf8_string(
                    OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS,
                    /*
                     * Cast away the const. This is read
                     * only so should be safe
                     */
                    (char *)mdprops, 0);
    }
    *p = OSSL_PARAM_construct_end();

    return EVP_PKEY_CTX_set_params(ctx, rsa_params);
}

int EVP_PKEY_CTX_get_rsa_oaep_md_name(EVP_PKEY_CTX *ctx, char *name,
                                      size_t namelen)
{
    OSSL_PARAM rsa_params[2], *p = rsa_params;

    if (ctx == NULL || !EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA return error */
    if (ctx->pmeth != NULL && ctx->pmeth->pkey_id != EVP_PKEY_RSA)
        return -1;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
                                            name, namelen);
    *p = OSSL_PARAM_construct_end();

    if (!EVP_PKEY_CTX_get_params(ctx, rsa_params))
        return -1;

    return 1;
}

int EVP_PKEY_CTX_get_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD **md)
{
    /* 80 should be big enough */
    char name[80] = "";

    if (ctx == NULL || md == NULL || !EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA return error */
    if (ctx->pmeth != NULL && ctx->pmeth->pkey_id != EVP_PKEY_RSA)
        return -1;

    LEGACY_EVP_PKEY_CTX_CTRL(ctx->op.ciph.ciphprovctx == NULL, ctx,
                             EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,
                             EVP_PKEY_CTRL_GET_RSA_OAEP_MD, 0, (void *)md);

    if (EVP_PKEY_CTX_get_rsa_oaep_md_name(ctx, name, sizeof(name)) <= 0)
        return -1;

    /* May be NULL meaning "unknown" */
    *md = evp_get_digestbyname_ex(ctx->libctx, name);

    return 1;
}

static int int_set_rsa_mgf1_md(EVP_PKEY_CTX *ctx,
                               /* For EVP_PKEY_CTX_ctrl() */
                               int keytype, int optype, int cmd,
                               const EVP_MD *md,
                               /* For EVP_PKEY_CTX_set_params() */
                               const char *mdname, const char *mdprops)
{
    OSSL_PARAM rsa_params[3], *p = rsa_params;

    if (ctx == NULL || (ctx->operation & optype) == 0) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA return error */
    if (ctx->pmeth != NULL
        && (keytype == -1
            ? (ctx->pmeth->pkey_id != EVP_PKEY_RSA
               && ctx->pmeth->pkey_id != EVP_PKEY_RSA_PSS)
            : ctx->pmeth->pkey_id != keytype))
        return -1;

    if (cmd != -1) {
        LEGACY_EVP_PKEY_CTX_CTRL(
            (EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)
             && ctx->op.ciph.ciphprovctx == NULL)
            || (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx)
                && ctx->op.sig.sigprovctx == NULL)
            || (EVP_PKEY_CTX_IS_GEN_OP(ctx)
                && ctx->op.keymgmt.genctx == NULL),
            ctx, keytype, optype, cmd, 0, (void *)md);
        mdname = (md == NULL) ? "" : EVP_MD_name(md);
    }

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_MGF1_DIGEST,
                                            /*
                                             * Cast away the const. This is
                                             * read only so should be safe
                                             */
                                            (char *)mdname, 0);
    if (mdprops != NULL) {
        *p++ =
            OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_MGF1_PROPERTIES,
                                             /*
                                              * Cast away the const. This is
                                              * read only so should be safe
                                              */
                                             (char *)mdprops, 0);
    }
    *p = OSSL_PARAM_construct_end();

    return EVP_PKEY_CTX_set_params(ctx, rsa_params);
}

int EVP_PKEY_CTX_set_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)
{
    return int_set_rsa_mgf1_md(ctx, -1,
                               EVP_PKEY_OP_TYPE_CRYPT | EVP_PKEY_OP_TYPE_SIG,
                               EVP_PKEY_CTRL_RSA_MGF1_MD, md, NULL, NULL);
}

int EVP_PKEY_CTX_set_rsa_mgf1_md_name(EVP_PKEY_CTX *ctx, const char *mdname,
                                      const char *mdprops)
{
    return int_set_rsa_mgf1_md(ctx, -1,
                               EVP_PKEY_OP_TYPE_CRYPT | EVP_PKEY_OP_TYPE_SIG,
                               -1, NULL, mdname, mdprops);
}

int EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)
{
    return int_set_rsa_mgf1_md(ctx, EVP_PKEY_RSA_PSS,
                               EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_RSA_MGF1_MD,
                               md, NULL, NULL);
}

int EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(EVP_PKEY_CTX *ctx,
                                                 const char *mdname)
{
    return int_set_rsa_mgf1_md(ctx, EVP_PKEY_RSA_PSS,
                               EVP_PKEY_OP_TYPE_CRYPT | EVP_PKEY_OP_TYPE_SIG,
                               -1, NULL, mdname, NULL);
}

int EVP_PKEY_CTX_get_rsa_mgf1_md_name(EVP_PKEY_CTX *ctx, char *name,
                                      size_t namelen)
{
    OSSL_PARAM rsa_params[2], *p = rsa_params;

    if (ctx == NULL
            || (!EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)
                && !EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx))) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA or RSA-PSS return error */
    if (ctx->pmeth != NULL
            && ctx->pmeth->pkey_id != EVP_PKEY_RSA
            && ctx->pmeth->pkey_id != EVP_PKEY_RSA_PSS)
        return -1;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_MGF1_DIGEST,
                                            name, namelen);
    *p = OSSL_PARAM_construct_end();

    if (!EVP_PKEY_CTX_get_params(ctx, rsa_params))
        return -1;

    return 1;
}

int EVP_PKEY_CTX_get_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD **md)
{
    /* 80 should be big enough */
    char name[80] = "";

    if (ctx == NULL
            || (!EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)
                && !EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx))) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA or RSA-PSS return error */
    if (ctx->pmeth != NULL
            && ctx->pmeth->pkey_id != EVP_PKEY_RSA
            && ctx->pmeth->pkey_id != EVP_PKEY_RSA_PSS)
        return -1;

    LEGACY_SET_RSA_SIG_OR_ASYM(ctx, -1,
                               EVP_PKEY_OP_TYPE_SIG | EVP_PKEY_OP_TYPE_CRYPT,
                               EVP_PKEY_CTRL_GET_RSA_MGF1_MD, 0, (void *)md);

    if (EVP_PKEY_CTX_get_rsa_mgf1_md_name(ctx, name, sizeof(name)) <= 0)
        return -1;

    /* May be NULL meaning "unknown" */
    *md = evp_get_digestbyname_ex(ctx->libctx, name);

    return 1;
}

int EVP_PKEY_CTX_set0_rsa_oaep_label(EVP_PKEY_CTX *ctx, void *label, int llen)
{
    OSSL_PARAM rsa_params[2], *p = rsa_params;

    if (ctx == NULL || !EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA return error */
    if (ctx->pmeth != NULL && ctx->pmeth->pkey_id != EVP_PKEY_RSA)
        return -1;

    LEGACY_EVP_PKEY_CTX_CTRL(ctx->op.ciph.ciphprovctx == NULL, ctx,
                             EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,
                             EVP_PKEY_CTRL_RSA_OAEP_LABEL, llen, (void *)label);

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL,
                                             /*
                                              * Cast away the const. This is
                                              * read only so should be safe
                                              */
                                             (void *)label,
                                             (size_t)llen);
    *p = OSSL_PARAM_construct_end();

    if (!EVP_PKEY_CTX_set_params(ctx, rsa_params))
        return 0;

    OPENSSL_free(label);
    return 1;
}

int EVP_PKEY_CTX_get0_rsa_oaep_label(EVP_PKEY_CTX *ctx, unsigned char **label)
{
    OSSL_PARAM rsa_params[3], *p = rsa_params;
    size_t labellen;

    if (ctx == NULL || !EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA return error */
    if (ctx->pmeth != NULL && ctx->pmeth->pkey_id != EVP_PKEY_RSA)
        return -1;

    LEGACY_EVP_PKEY_CTX_CTRL(ctx->op.ciph.ciphprovctx == NULL, ctx,
                             EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,
                             EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL, 0, (void *)label);

    *p++ = OSSL_PARAM_construct_octet_ptr(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL,
                                          (void **)label, 0);
    *p++ = OSSL_PARAM_construct_size_t(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL_LEN,
                                       &labellen);
    *p = OSSL_PARAM_construct_end();

    if (!EVP_PKEY_CTX_get_params(ctx, rsa_params))
        return -1;

    if (labellen > INT_MAX)
        return -1;

    return (int)labellen;
}

static int int_set_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int saltlen,
                                   int keytype, int optype)
{
    OSSL_PARAM pad_params[2], *p = pad_params;

    if (ctx == NULL || (ctx->operation & optype) == 0) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA or RSA-PSS return error */
    if (ctx->pmeth != NULL
        && (keytype == -1
            ? (ctx->pmeth->pkey_id != EVP_PKEY_RSA
               && ctx->pmeth->pkey_id != EVP_PKEY_RSA_PSS)
            : ctx->pmeth->pkey_id != keytype))
        return -1;

    LEGACY_EVP_PKEY_CTX_CTRL(
        (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx) && ctx->op.sig.sigprovctx == NULL)
        || (EVP_PKEY_CTX_IS_GEN_OP(ctx) && ctx->op.keymgmt.genctx == NULL),
        ctx, keytype, optype, EVP_PKEY_CTRL_RSA_PSS_SALTLEN, saltlen, NULL);

    *p++ =
        OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, &saltlen);
    *p = OSSL_PARAM_construct_end();

    return EVP_PKEY_CTX_set_params(ctx, pad_params);
}

int EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int saltlen)
{
    return int_set_rsa_pss_saltlen(ctx, saltlen, -1, EVP_PKEY_OP_TYPE_SIG);
}

int EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(EVP_PKEY_CTX *ctx, int saltlen)
{
    return int_set_rsa_pss_saltlen(ctx, saltlen, EVP_PKEY_RSA_PSS,
                                   EVP_PKEY_OP_KEYGEN);
}

int EVP_PKEY_CTX_get_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int *saltlen)
{
    OSSL_PARAM pad_params[2], *p = pad_params;

    if (ctx == NULL || saltlen == NULL || !EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA or RSA-PSS return error */
    if (ctx->pmeth != NULL
            && ctx->pmeth->pkey_id != EVP_PKEY_RSA
            && ctx->pmeth->pkey_id != EVP_PKEY_RSA_PSS)
        return -1;

    LEGACY_EVP_PKEY_CTX_CTRL(ctx->op.sig.sigprovctx == NULL, ctx, -1, -1,
                             EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN, 0, saltlen);

    *p++ =
        OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, saltlen);
    *p = OSSL_PARAM_construct_end();

    if (!EVP_PKEY_CTX_get_params(ctx, pad_params))
        return 0;

    return 1;

}

int EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX *ctx, int bits)
{
    OSSL_PARAM params[2], *p = params;
    size_t bits2 = bits;

    if (ctx == NULL || !EVP_PKEY_CTX_IS_GEN_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA return error */
    if (ctx->pmeth != NULL && ctx->pmeth->pkey_id != EVP_PKEY_RSA)
        return -1;

    LEGACY_SET_RSA_KEYGEN(ctx, EVP_PKEY_CTRL_RSA_KEYGEN_BITS, bits, NULL);

    *p++ = OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_RSA_BITS, &bits2);
    *p = OSSL_PARAM_construct_end();

    if (!EVP_PKEY_CTX_set_params(ctx, params))
        return 0;

    return 1;
}

static int evp_pkey_ctx_set_rsa_keygen_pubexp_intern(EVP_PKEY_CTX *ctx,
                                                     BIGNUM *pubexp,
                                                     int copy)
{
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params;
    int ret;

    if (ctx == NULL || !EVP_PKEY_CTX_IS_GEN_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA return error */
    if (ctx->pmeth != NULL && ctx->pmeth->pkey_id != EVP_PKEY_RSA)
        return -1;

    if (ctx->op.keymgmt.genctx == NULL) {
        if (copy == 1)
            pubexp = BN_dup(pubexp);
        ret = LEGACY_SET_RSA_KEYGEN2_CTRL(ctx, EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP,
                                          0, pubexp);
        if ((copy == 1) && (ret <= 0))
            BN_free(pubexp);
        return ret;
    }

    if ((tmpl = OSSL_PARAM_BLD_new()) == NULL)
        return 0;
    if (!OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_E, pubexp)
        || (params = OSSL_PARAM_BLD_to_param(tmpl)) == NULL) {
        OSSL_PARAM_BLD_free(tmpl);
        return 0;
    }
    OSSL_PARAM_BLD_free(tmpl);

    ret = EVP_PKEY_CTX_set_params(ctx, params);
    OSSL_PARAM_BLD_free_params(params);

    /*
     * Satisfy memory semantics for pre-3.0 callers of
     * EVP_PKEY_CTX_set_rsa_keygen_pubexp(): their expectation is that input
     * pubexp BIGNUM becomes managed by the EVP_PKEY_CTX on success.
     */
    if ((copy == 0) && (ret > 0))
        ctx->rsa_pubexp = pubexp;

    return ret;
}

int EVP_PKEY_CTX_set_rsa_keygen_pubexp(EVP_PKEY_CTX *ctx, BIGNUM *pubexp)
{
    return evp_pkey_ctx_set_rsa_keygen_pubexp_intern(ctx, pubexp, 0);
}

int EVP_PKEY_CTX_set1_rsa_keygen_pubexp(EVP_PKEY_CTX *ctx, BIGNUM *pubexp)
{
    return evp_pkey_ctx_set_rsa_keygen_pubexp_intern(ctx, pubexp, 1);
}

int EVP_PKEY_CTX_set_rsa_keygen_primes(EVP_PKEY_CTX *ctx, int primes)
{
    OSSL_PARAM params[2], *p = params;
    size_t primes2 = primes;

    if (ctx == NULL || !EVP_PKEY_CTX_IS_GEN_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA return error */
    if (ctx->pmeth != NULL && ctx->pmeth->pkey_id != EVP_PKEY_RSA)
        return -1;

    LEGACY_SET_RSA_KEYGEN(ctx, EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES, primes, NULL);

    *p++ = OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, &primes2);
    *p = OSSL_PARAM_construct_end();

    if (!EVP_PKEY_CTX_set_params(ctx, params))
        return 0;

    return 1;
}
