/*
 * Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include "crypto/dh.h"
#include "crypto/evp.h"

static int dh_paramgen_check(EVP_PKEY_CTX *ctx)
{
    if (ctx == NULL || !EVP_PKEY_CTX_IS_GEN_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }
    /* If key type not DH return error */
    if (ctx->pmeth != NULL
        && ctx->pmeth->pkey_id != EVP_PKEY_DH
        && ctx->pmeth->pkey_id != EVP_PKEY_DHX)
        return -1;
    return 1;
}

static int dh_param_derive_check(EVP_PKEY_CTX *ctx)
{
    if (ctx == NULL || !EVP_PKEY_CTX_IS_DERIVE_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }
    /* If key type not DH return error */
    if (ctx->pmeth != NULL
        && ctx->pmeth->pkey_id != EVP_PKEY_DH
        && ctx->pmeth->pkey_id != EVP_PKEY_DHX)
        return -1;
    return 1;
}

int EVP_PKEY_CTX_set_dh_paramgen_gindex(EVP_PKEY_CTX *ctx, int gindex)
{
    int ret;
    OSSL_PARAM params[2], *p = params;

    if ((ret = dh_paramgen_check(ctx)) <= 0)
        return ret;

    *p++ = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_FFC_GINDEX, &gindex);
    *p = OSSL_PARAM_construct_end();

    return EVP_PKEY_CTX_set_params(ctx, params);
}

int EVP_PKEY_CTX_set_dh_paramgen_seed(EVP_PKEY_CTX *ctx,
                                      const unsigned char *seed,
                                      size_t seedlen)
{
    int ret;
    OSSL_PARAM params[2], *p = params;

    if ((ret = dh_paramgen_check(ctx)) <= 0)
        return ret;

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_FFC_SEED,
                                             (void *)seed, seedlen);
    *p = OSSL_PARAM_construct_end();

    return EVP_PKEY_CTX_set_params(ctx, params);
}

int EVP_PKEY_CTX_set_dh_paramgen_type(EVP_PKEY_CTX *ctx, int typ)
{
    int ret;
    OSSL_PARAM params[2], *p = params;
    const char *name;

    if ((ret = dh_paramgen_check(ctx)) <= 0)
        return ret;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.keymgmt.genctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN,
                                 EVP_PKEY_CTRL_DH_PARAMGEN_TYPE, typ, NULL);

    name = dh_gen_type_id2name(typ);
    if (name == NULL)
        return 0;
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_FFC_TYPE,
                                            (char *) name, 0);
    *p = OSSL_PARAM_construct_end();

    return EVP_PKEY_CTX_set_params(ctx, params);
}

int EVP_PKEY_CTX_set_dh_paramgen_prime_len(EVP_PKEY_CTX *ctx, int pbits)
{
    int ret;
    OSSL_PARAM params[2], *p = params;
    size_t bits = pbits;

    if ((ret = dh_paramgen_check(ctx)) <= 0)
        return ret;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.keymgmt.genctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN,
                                 EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN, pbits,
                                 NULL);
    *p++ = OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_FFC_PBITS, &bits);
    *p = OSSL_PARAM_construct_end();
    return EVP_PKEY_CTX_set_params(ctx, params);
}

int EVP_PKEY_CTX_set_dh_paramgen_subprime_len(EVP_PKEY_CTX *ctx, int qbits)
{
    int ret;
    OSSL_PARAM params[2], *p = params;
    size_t bits2 = qbits;

    if ((ret = dh_paramgen_check(ctx)) <= 0)
        return ret;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.keymgmt.genctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN,
                                 EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN, qbits,
                                 NULL);
    *p++ = OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_FFC_QBITS, &bits2);
    *p = OSSL_PARAM_construct_end();

    return EVP_PKEY_CTX_set_params(ctx, params);
}

int EVP_PKEY_CTX_set_dh_paramgen_generator(EVP_PKEY_CTX *ctx, int gen)
{
    int ret;
    OSSL_PARAM params[2], *p = params;

    if ((ret = dh_paramgen_check(ctx)) <= 0)
        return ret;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.keymgmt.genctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN,
                                 EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR, gen, NULL);
    *p++ = OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_DH_GENERATOR, &gen);
    *p = OSSL_PARAM_construct_end();

    return EVP_PKEY_CTX_set_params(ctx, params);
}

int EVP_PKEY_CTX_set_dh_rfc5114(EVP_PKEY_CTX *ctx, int gen)
{
    int ret;
    OSSL_PARAM params[2], *p = params;
    const char *name;

    if ((ret = dh_paramgen_check(ctx)) <= 0)
        return ret;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.keymgmt.genctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_PARAMGEN,
                                 EVP_PKEY_CTRL_DH_RFC5114, gen, NULL);
    name = ossl_ffc_named_group_get_name(ossl_ffc_uid_to_dh_named_group(gen));
    if (name == NULL)
        return 0;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                            (void *)name, 0);
    *p = OSSL_PARAM_construct_end();
    return EVP_PKEY_CTX_set_params(ctx, params);
}

int EVP_PKEY_CTX_set_dhx_rfc5114(EVP_PKEY_CTX *ctx, int gen)
{
    return EVP_PKEY_CTX_set_dh_rfc5114(ctx, gen);
}

int EVP_PKEY_CTX_set_dh_nid(EVP_PKEY_CTX *ctx, int nid)
{
    int ret;
    OSSL_PARAM params[2], *p = params;
    const char *name;

    if ((ret = dh_paramgen_check(ctx)) <= 0)
        return ret;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.keymgmt.genctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH,
                                 EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN,
                                 EVP_PKEY_CTRL_DH_NID, nid, NULL);
    name = ossl_ffc_named_group_get_name(ossl_ffc_uid_to_dh_named_group(nid));
    if (name == NULL)
        return 0;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                            (void *)name, 0);
    *p = OSSL_PARAM_construct_end();
    return EVP_PKEY_CTX_set_params(ctx, params);
}

int EVP_PKEY_CTX_set_dh_pad(EVP_PKEY_CTX *ctx, int pad)
{
    OSSL_PARAM dh_pad_params[2];
    unsigned int upad = pad;

    /* We use EVP_PKEY_CTX_ctrl return values */
    if (ctx == NULL || !EVP_PKEY_CTX_IS_DERIVE_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        return -2;
    }

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.kex.exchprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_DERIVE,
                                 EVP_PKEY_CTRL_DH_PAD, pad, NULL);

    dh_pad_params[0] = OSSL_PARAM_construct_uint(OSSL_EXCHANGE_PARAM_PAD, &upad);
    dh_pad_params[1] = OSSL_PARAM_construct_end();

    return EVP_PKEY_CTX_set_params(ctx, dh_pad_params);
}

int EVP_PKEY_CTX_set_dh_kdf_type(EVP_PKEY_CTX *ctx, int kdf)
{
    int ret;
    const char *kdf_type;
    OSSL_PARAM params[2], *p = params;

    ret = dh_param_derive_check(ctx);
    if (ret != 1)
        return ret;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.kex.exchprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE,
                                 EVP_PKEY_CTRL_DH_KDF_TYPE, kdf, NULL);
    switch (kdf) {
        case EVP_PKEY_DH_KDF_NONE:
            kdf_type = "";
            break;
        case EVP_PKEY_DH_KDF_X9_42:
            kdf_type = OSSL_KDF_NAME_X942KDF_ASN1;
            break;
        default:
            return -2;
    }
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE,
                                            /*
                                             * Cast away the const. This is read
                                             * only so should be safe
                                             */
                                            (char *)kdf_type, 0);
    *p = OSSL_PARAM_construct_end();

    ret = evp_pkey_ctx_set_params_strict(ctx, params);
    if (ret == -2) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    return ret;
}

int EVP_PKEY_CTX_get_dh_kdf_type(EVP_PKEY_CTX *ctx)
{
    int ret;
    char kdf_type[80]; /* 80 should be big enough */
    OSSL_PARAM params[2], *p = params;

    ret = dh_param_derive_check(ctx);
    if (ret != 1)
        return ret;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.kex.exchprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE,
                                 EVP_PKEY_CTRL_DH_KDF_TYPE, -2, NULL);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_TYPE,
                                            kdf_type, sizeof(kdf_type));
    *p = OSSL_PARAM_construct_end();

    ret = evp_pkey_ctx_get_params_strict(ctx, params);
    if (ret == -2) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    } else if (ret != 1) {
        return -1;
    }

    if (kdf_type[0] == '\0')
        return EVP_PKEY_DH_KDF_NONE;
    else if (strcmp(kdf_type, OSSL_KDF_NAME_X942KDF_ASN1) == 0)
        return EVP_PKEY_DH_KDF_X9_42;

    return -1;
}

int EVP_PKEY_CTX_set0_dh_kdf_oid(EVP_PKEY_CTX *ctx, ASN1_OBJECT *oid)
{
    int ret;
    OSSL_PARAM params[2], *p = params;
    const char *oid_name;

    ret = dh_param_derive_check(ctx);
    if (ret != 1)
        return ret;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.kex.exchprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE,
                                 EVP_PKEY_CTRL_DH_KDF_OID, 0, (void *)(oid));
    oid_name = OBJ_nid2sn(OBJ_obj2nid(oid));

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CEK_ALG,
                                            (char *)oid_name, 0);
    *p = OSSL_PARAM_construct_end();
    ret = evp_pkey_ctx_set_params_strict(ctx, params);
    if (ret == -2) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    return ret;
}

int EVP_PKEY_CTX_get0_dh_kdf_oid(EVP_PKEY_CTX *ctx, ASN1_OBJECT **oid)
{
    int ret, nid;
    OSSL_PARAM params[2], *p = params;
    char oid_name[80]; /* 80 should be big enough */

    ret = dh_param_derive_check(ctx);
    if (ret != 1)
        return ret;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.kex.exchprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE,
                                 EVP_PKEY_CTRL_GET_DH_KDF_OID, 0, (void *)(oid));
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CEK_ALG,
                                            oid_name, sizeof(oid_name));
    *p = OSSL_PARAM_construct_end();

    ret = evp_pkey_ctx_get_params_strict(ctx, params);
    if (ret == -2) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    } else if (ret != 1) {
        return -1;
    }
    nid = OBJ_sn2nid(oid_name);
    if (nid == NID_undef)
        nid = OBJ_ln2nid(oid_name);
    *oid = (nid == NID_undef ? NULL : OBJ_nid2obj(nid));
    return *oid != NULL;
}

int EVP_PKEY_CTX_set_dh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)
{
    int ret;
    OSSL_PARAM params[2], *p = params;
    const char *md_name = NULL;

    ret = dh_param_derive_check(ctx);
    if (ret != 1)
        return ret;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.kex.exchprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE,
                                 EVP_PKEY_CTRL_DH_KDF_MD, 0, (void *)(md));
    md_name = (md == NULL) ? "" : EVP_MD_name(md);

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST,
                                            /*
                                             * Cast away the const. This is read
                                             * only so should be safe
                                             */
                                            (char *)md_name, 0);
    *p = OSSL_PARAM_construct_end();

    ret = evp_pkey_ctx_set_params_strict(ctx, params);
    if (ret == -2) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }
    return ret;
}

int EVP_PKEY_CTX_get_dh_kdf_md(EVP_PKEY_CTX *ctx, const EVP_MD **pmd)
{
    int ret;
    char name[80] = "";  /* 80 should be big enough */
    OSSL_PARAM params[2], *p = params;

    ret = dh_param_derive_check(ctx);
    if (ret != 1)
        return ret;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.kex.exchprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE,
                                 EVP_PKEY_CTRL_GET_DH_KDF_MD, 0, (void *)(pmd));
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_EXCHANGE_PARAM_KDF_DIGEST,
                                            name, sizeof(name));
    *p = OSSL_PARAM_construct_end();

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

int EVP_PKEY_CTX_set_dh_kdf_outlen(EVP_PKEY_CTX *ctx, int inlen)
{
    int ret;
    size_t len = inlen;
    OSSL_PARAM params[2], *p = params;

    ret = dh_param_derive_check(ctx);
    if (ret != 1)
        return ret;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.kex.exchprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE,
                                 EVP_PKEY_CTRL_DH_KDF_OUTLEN, inlen, NULL);
    if (inlen <= 0) {
        /*
         * This would ideally be -1 or 0, but we have to retain compatibility
         * with legacy behaviour of EVP_PKEY_CTX_ctrl() which returned -2 if
         * in <= 0
         */
        return -2;
    }

    *p++ = OSSL_PARAM_construct_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
                                       &len);
    *p = OSSL_PARAM_construct_end();

    ret = evp_pkey_ctx_set_params_strict(ctx, params);
    if (ret == -2) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }
    return ret;
}

int EVP_PKEY_CTX_get_dh_kdf_outlen(EVP_PKEY_CTX *ctx, int *plen)
{
    int ret;
    size_t len = UINT_MAX;
    OSSL_PARAM params[2], *p = params;

    ret = dh_param_derive_check(ctx);
    if (ret != 1)
        return ret;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.kex.exchprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE,
                                 EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN, 0,
                                 (void *)(plen));
    *p++ = OSSL_PARAM_construct_size_t(OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
                                       &len);
    *p = OSSL_PARAM_construct_end();

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

int EVP_PKEY_CTX_set0_dh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char *ukm, int len)
{
    int ret;
    OSSL_PARAM params[2], *p = params;

    if (len < 0)
        return -1;

    ret = dh_param_derive_check(ctx);
    if (ret != 1)
        return ret;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.kex.exchprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE,
                                 EVP_PKEY_CTRL_DH_KDF_UKM, len, (void *)(ukm));

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_EXCHANGE_PARAM_KDF_UKM,
                                            /*
                                             * Cast away the const. This is read
                                             * only so should be safe
                                             */
                                            (void *)ukm,
                                            (size_t)len);
    *p = OSSL_PARAM_construct_end();

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

int EVP_PKEY_CTX_get0_dh_kdf_ukm(EVP_PKEY_CTX *ctx, unsigned char **pukm)
{
    int ret;
    size_t ukmlen;
    OSSL_PARAM params[2], *p = params;

    ret = dh_param_derive_check(ctx);
    if (ret != 1)
        return ret;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.kex.exchprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE,
                                 EVP_PKEY_CTRL_GET_DH_KDF_UKM, 0, (void *)(pukm));

    *p++ = OSSL_PARAM_construct_octet_ptr(OSSL_EXCHANGE_PARAM_KDF_UKM,
                                          (void **)pukm, 0);
    *p = OSSL_PARAM_construct_end();

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
