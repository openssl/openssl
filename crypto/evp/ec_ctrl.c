/*
 * Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/deprecated.h"

#include <string.h>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include "crypto/evp.h"
#include "crypto/ec.h"

/*
 * This file is meant to contain functions to provide EVP_PKEY support for EC
 * keys.
 */

static ossl_inline
int evp_pkey_ctx_getset_ecdh_param_checks(const EVP_PKEY_CTX *ctx)
{
    if (ctx == NULL || !EVP_PKEY_CTX_IS_DERIVE_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not EC return error */
    if (ctx->pmeth != NULL && ctx->pmeth->pkey_id != EVP_PKEY_EC)
        return -1;

    return 1;
}

int EVP_PKEY_CTX_set_ecdh_cofactor_mode(EVP_PKEY_CTX *ctx, int cofactor_mode)
{
    int ret;
    OSSL_PARAM params[2], *p = params;

    ret = evp_pkey_ctx_getset_ecdh_param_checks(ctx);
    if (ret != 1)
        return ret;

    /*
     * Valid input values are:
     *  * 0 for disable
     *  * 1 for enable
     *  * -1 for reset to default for associated priv key
     */
    if (cofactor_mode < -1 || cofactor_mode > 1) {
        /* Uses the same return value of pkey_ec_ctrl() */
        return -2;
    }

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.kex.exchprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
                                 EVP_PKEY_OP_DERIVE,
                                 EVP_PKEY_CTRL_EC_ECDH_COFACTOR,
                                 cofactor_mode, NULL);

    *p++ = OSSL_PARAM_construct_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE,
                                    &cofactor_mode);
    *p++ = OSSL_PARAM_construct_end();

    ret = evp_pkey_ctx_set_params_strict(ctx, params);
    if (ret == -2) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    return ret;
}

int EVP_PKEY_CTX_get_ecdh_cofactor_mode(EVP_PKEY_CTX *ctx)
{
    int ret, mode;
    OSSL_PARAM params[2], *p = params;

    ret = evp_pkey_ctx_getset_ecdh_param_checks(ctx);
    if (ret != 1)
        return ret;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.kex.exchprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
                                 EVP_PKEY_OP_DERIVE,
                                 EVP_PKEY_CTRL_EC_ECDH_COFACTOR, -2, NULL);

    *p++ = OSSL_PARAM_construct_int(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE,
                                    &mode);
    *p++ = OSSL_PARAM_construct_end();

    ret = evp_pkey_ctx_get_params_strict(ctx, params);
    if (ret == -2) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    } else if (ret != 1) {
        return -1;
    }

    if (mode < 0 || mode > 1) {
        /*
         * The provider should return either 0 or 1, any other value is a
         * provider error.
         */
        return -1;
    }

    return mode;
}

int EVP_PKEY_CTX_set_ecdh_kdf_type(EVP_PKEY_CTX *ctx, int kdf)
{
    int ret;
    const char *kdf_type;
    OSSL_PARAM params[2], *p = params;

    ret = evp_pkey_ctx_getset_ecdh_param_checks(ctx);
    if (ret != 1)
        return ret;

    switch (kdf) {
        case EVP_PKEY_ECDH_KDF_NONE:
            kdf_type = "";
            break;
        case EVP_PKEY_ECDH_KDF_X9_63:
            kdf_type = OSSL_KDF_NAME_X963KDF;
            break;
        default:
            return -2;
    }

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.kex.exchprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
                                 EVP_PKEY_OP_DERIVE,
                                 EVP_PKEY_CTRL_EC_KDF_TYPE, kdf, NULL);

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE,
                                            /*
                                             * Cast away the const. This is read
                                             * only so should be safe
                                             */
                                            (char *)kdf_type, 0);
    *p++ = OSSL_PARAM_construct_end();

    ret = evp_pkey_ctx_set_params_strict(ctx, params);
    if (ret == -2) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    return ret;
}

int EVP_PKEY_CTX_get_ecdh_kdf_type(EVP_PKEY_CTX *ctx)
{
    int ret;
    /* 80 should be big enough */
    char kdf_type[80];
    OSSL_PARAM params[2], *p = params;

    ret = evp_pkey_ctx_getset_ecdh_param_checks(ctx);
    if (ret != 1)
        return ret;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.kex.exchprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
                                 EVP_PKEY_OP_DERIVE,
                                 EVP_PKEY_CTRL_EC_KDF_TYPE, -2, NULL);

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE,
                                            kdf_type, sizeof(kdf_type));
    *p++ = OSSL_PARAM_construct_end();

    ret = evp_pkey_ctx_get_params_strict(ctx, params);
    if (ret == -2) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    } else if (ret != 1) {
        return -1;
    }

    if (kdf_type[0] == '\0')
        return EVP_PKEY_ECDH_KDF_NONE;
    else if (strcmp(kdf_type, OSSL_KDF_NAME_X963KDF) == 0)
        return EVP_PKEY_ECDH_KDF_X9_63;

    return -1;
}

int EVP_PKEY_CTX_set_ecdh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)
{
    int ret;
    OSSL_PARAM params[2], *p = params;
    const char *md_name = NULL;

    ret = evp_pkey_ctx_getset_ecdh_param_checks(ctx);
    if (ret != 1)
        return ret;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.kex.exchprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
                                 EVP_PKEY_OP_DERIVE,
                                 EVP_PKEY_CTRL_EC_KDF_MD, 0, (void *)(md));

    md_name = (md == NULL) ? "" : EVP_MD_name(md);

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST,
                                            /*
                                             * Cast away the const. This is read
                                             * only so should be safe
                                             */
                                            (char *)md_name, 0);
    *p++ = OSSL_PARAM_construct_end();

    ret = evp_pkey_ctx_set_params_strict(ctx, params);
    if (ret == -2) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }
    return ret;
}

int EVP_PKEY_CTX_get_ecdh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD **pmd)
{
    /* 80 should be big enough */
    char name[80] = "";
    int ret;
    OSSL_PARAM params[2], *p = params;

    ret = evp_pkey_ctx_getset_ecdh_param_checks(ctx);
    if (ret != 1)
        return ret;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.kex.exchprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
                                 EVP_PKEY_OP_DERIVE,
                                 EVP_PKEY_CTRL_GET_EC_KDF_MD, 0, (void *)(pmd));

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST,
                                            name, sizeof(name));
    *p++ = OSSL_PARAM_construct_end();

    ret = evp_pkey_ctx_get_params_strict(ctx, params);
    if (ret == -2) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    } else if (ret != 1) {
        return -1;
    }

    /* May be NULL meaning "unknown" */
    *pmd = EVP_get_digestbyname(name);

    return 1;
}

int EVP_PKEY_CTX_set_ecdh_kdf_outlen(EVP_PKEY_CTX *ctx, int in)
{
    int ret;
    size_t len = in;
    OSSL_PARAM params[2], *p = params;

    ret = evp_pkey_ctx_getset_ecdh_param_checks(ctx);
    if (ret != 1)
        return ret;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.kex.exchprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
                                 EVP_PKEY_OP_DERIVE,
                                 EVP_PKEY_CTRL_EC_KDF_OUTLEN, in, NULL);

    if (in <= 0) {
        /*
         * This would ideally be -1 or 0, but we have to retain compatibility
         * with legacy behaviour of EVP_PKEY_CTX_ctrl() which returned -2 if
         * in <= 0
         */
        return -2;
    }

    *p++ = OSSL_PARAM_construct_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
                                       &len);
    *p++ = OSSL_PARAM_construct_end();

    ret = evp_pkey_ctx_set_params_strict(ctx, params);
    if (ret == -2) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }
    return ret;
}

int EVP_PKEY_CTX_get_ecdh_kdf_outlen(EVP_PKEY_CTX *ctx, int *plen)
{
    size_t len = UINT_MAX;
    int ret;
    OSSL_PARAM params[2], *p = params;

    ret = evp_pkey_ctx_getset_ecdh_param_checks(ctx);
    if (ret != 1)
        return ret;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.kex.exchprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
                                 EVP_PKEY_OP_DERIVE,
                                 EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN, 0,
                                 (void *)(plen));

    *p++ = OSSL_PARAM_construct_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
                                       &len);
    *p++ = OSSL_PARAM_construct_end();

    ret = evp_pkey_ctx_get_params_strict(ctx, params);
    if (ret == -2) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    } else if (ret != 1) {
        return -1;
    }

    if (len > INT_MAX)
        return -1;

    *plen = (int)len;

    return 1;
}

int EVP_PKEY_CTX_set0_ecdh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char *ukm, int len)
{
    int ret;
    OSSL_PARAM params[2], *p = params;

    ret = evp_pkey_ctx_getset_ecdh_param_checks(ctx);
    if (ret != 1)
        return ret;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.kex.exchprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
                                 EVP_PKEY_OP_DERIVE,
                                 EVP_PKEY_CTRL_EC_KDF_UKM, len, (void *)(ukm));

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM,
                                            /*
                                             * Cast away the const. This is read
                                             * only so should be safe
                                             */
                                            (void *)ukm,
                                            (size_t)len);
    *p++ = OSSL_PARAM_construct_end();

    ret = evp_pkey_ctx_set_params_strict(ctx, params);
    if (ret == -2) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }
    if (ret == 1)
        OPENSSL_free(ukm);
    return ret;
}

int EVP_PKEY_CTX_get0_ecdh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char **pukm)
{
    size_t ukmlen;
    int ret;
    OSSL_PARAM params[2], *p = params;

    ret = evp_pkey_ctx_getset_ecdh_param_checks(ctx);
    if (ret != 1)
        return ret;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.kex.exchprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
                                 EVP_PKEY_OP_DERIVE,
                                 EVP_PKEY_CTRL_GET_EC_KDF_UKM, 0,
                                 (void *)(pukm));

    *p++ = OSSL_PARAM_construct_octet_ptr(OSSL_EXCHANGE_PARAM_KDF_UKM,
                                          (void **)pukm, 0);
    *p++ = OSSL_PARAM_construct_end();

    ret = evp_pkey_ctx_get_params_strict(ctx, params);
    if (ret == -2) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    } else if (ret != 1) {
        return -1;
    }

    ukmlen = params[0].return_size;
    if (ukmlen > INT_MAX)
        return -1;

    return (int)ukmlen;
}

#ifndef FIPS_MODULE
int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid)
{
    if (ctx == NULL || !EVP_PKEY_CTX_IS_GEN_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* Legacy: if key type not EC return error */
    if (ctx->pmeth != NULL
        && EVP_PKEY_type(ctx->pmeth->pkey_id) != EVP_PKEY_EC)
        return -1;

    if (ctx->op.keymgmt.genctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
                                 EVP_PKEY_OP_PARAMGEN|EVP_PKEY_OP_KEYGEN,
                                 EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID,
                                 nid, NULL);

    return EVP_PKEY_CTX_set_group_name(ctx, OBJ_nid2sn(nid));
}

int evp_pkey_ctx_set_ec_param_enc_prov(EVP_PKEY_CTX *ctx, int param_enc)
{
    const char *enc = NULL;
    OSSL_PARAM params[2], *p = params;
    int ret = -2;                /* Assume unsupported */

    if (ctx == NULL
        || !EVP_PKEY_CTX_IS_GEN_OP(ctx)
        || ctx->op.keymgmt.genctx == NULL)
        goto end;

    switch (param_enc) {
    case OPENSSL_EC_EXPLICIT_CURVE:
        enc = OSSL_PKEY_EC_ENCODING_EXPLICIT;
        break;
    case OPENSSL_EC_NAMED_CURVE:
        enc = OSSL_PKEY_EC_ENCODING_GROUP;
        break;
    default:
        goto end;
    }

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_EC_ENCODING,
                                            (char *)enc, 0);
    *p = OSSL_PARAM_construct_end();

    ret = evp_pkey_ctx_set_params_strict(ctx, params);
 end:
    if (ret == -2)
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
    return ret;
}

int EVP_PKEY_CTX_set_ec_param_enc(EVP_PKEY_CTX *ctx, int param_enc)
{
    return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC,
                             EVP_PKEY_OP_PARAMGEN|EVP_PKEY_OP_KEYGEN,
                             EVP_PKEY_CTRL_EC_PARAM_ENC, param_enc, NULL);
}
#endif
