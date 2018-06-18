/*
 * Copyright 2006-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include "internal/evp_int.h"
#include "internal/sm2.h"
#include "internal/sm2err.h"

/* EC pkey context structure */

typedef struct {
    /* Key and paramgen group */
    EC_GROUP *gen_group;
    /* message digest */
    const EVP_MD *md;
} SM2_PKEY_CTX;

static int pkey_sm2_init(EVP_PKEY_CTX *ctx)
{
    SM2_PKEY_CTX *dctx;

    if ((dctx = OPENSSL_zalloc(sizeof(*dctx))) == NULL) {
        SM2err(SM2_F_PKEY_SM2_INIT, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    ctx->data = dctx;
    return 1;
}

static void pkey_sm2_cleanup(EVP_PKEY_CTX *ctx)
{
    SM2_PKEY_CTX *dctx = ctx->data;

    if (dctx != NULL) {
        EC_GROUP_free(dctx->gen_group);
        OPENSSL_free(dctx);
        ctx->data = NULL;
    }
}

static int pkey_sm2_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
    SM2_PKEY_CTX *dctx, *sctx;

    if (!pkey_sm2_init(dst))
        return 0;
    sctx = src->data;
    dctx = dst->data;
    if (sctx->gen_group != NULL) {
        dctx->gen_group = EC_GROUP_dup(sctx->gen_group);
        if (dctx->gen_group == NULL) {
            pkey_sm2_cleanup(dst);
            return 0;
        }
    }
    dctx->md = sctx->md;

    return 1;
}

static int pkey_sm2_sign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen,
                         const unsigned char *tbs, size_t tbslen)
{
    int ret;
    unsigned int sltmp;
    EC_KEY *ec = ctx->pkey->pkey.ec;
    const int sig_sz = ECDSA_size(ctx->pkey->pkey.ec);

    if (sig_sz <= 0) {
        return 0;
    }

    if (sig == NULL) {
        *siglen = (size_t)sig_sz;
        return 1;
    }

    if (*siglen < (size_t)sig_sz) {
        SM2err(SM2_F_PKEY_SM2_SIGN, SM2_R_BUFFER_TOO_SMALL);
        return 0;
    }

    ret = sm2_sign(tbs, tbslen, sig, &sltmp, ec);

    if (ret <= 0)
        return ret;
    *siglen = (size_t)sltmp;
    return 1;
}

static int pkey_sm2_verify(EVP_PKEY_CTX *ctx,
                           const unsigned char *sig, size_t siglen,
                           const unsigned char *tbs, size_t tbslen)
{
    EC_KEY *ec = ctx->pkey->pkey.ec;

    return sm2_verify(tbs, tbslen, sig, siglen, ec);
}

static int pkey_sm2_encrypt(EVP_PKEY_CTX *ctx,
                            unsigned char *out, size_t *outlen,
                            const unsigned char *in, size_t inlen)
{
    EC_KEY *ec = ctx->pkey->pkey.ec;
    SM2_PKEY_CTX *dctx = ctx->data;
    const EVP_MD *md = (dctx->md == NULL) ? EVP_sm3() : dctx->md;

    if (out == NULL) {
        if (!sm2_ciphertext_size(ec, md, inlen, outlen))
            return -1;
        else
            return 1;
    }

    return sm2_encrypt(ec, md, in, inlen, out, outlen);
}

static int pkey_sm2_decrypt(EVP_PKEY_CTX *ctx,
                            unsigned char *out, size_t *outlen,
                            const unsigned char *in, size_t inlen)
{
    EC_KEY *ec = ctx->pkey->pkey.ec;
    SM2_PKEY_CTX *dctx = ctx->data;
    const EVP_MD *md = (dctx->md == NULL) ? EVP_sm3() : dctx->md;

    if (out == NULL) {
        if (!sm2_plaintext_size(ec, md, inlen, outlen))
            return -1;
        else
            return 1;
    }

    return sm2_decrypt(ec, md, in, inlen, out, outlen);
}

static int pkey_sm2_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    SM2_PKEY_CTX *dctx = ctx->data;
    EC_GROUP *group;

    switch (type) {
    case EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID:
        group = EC_GROUP_new_by_curve_name(p1);
        if (group == NULL) {
            SM2err(SM2_F_PKEY_SM2_CTRL, SM2_R_INVALID_CURVE);
            return 0;
        }
        EC_GROUP_free(dctx->gen_group);
        dctx->gen_group = group;
        return 1;

    case EVP_PKEY_CTRL_EC_PARAM_ENC:
        if (dctx->gen_group == NULL) {
            SM2err(SM2_F_PKEY_SM2_CTRL, SM2_R_NO_PARAMETERS_SET);
            return 0;
        }
        EC_GROUP_set_asn1_flag(dctx->gen_group, p1);
        return 1;

    case EVP_PKEY_CTRL_MD:
        dctx->md = p2;
        return 1;

    case EVP_PKEY_CTRL_GET_MD:
        *(const EVP_MD **)p2 = dctx->md;
        return 1;

    default:
        return -2;

    }
}

static int pkey_sm2_ctrl_str(EVP_PKEY_CTX *ctx,
                             const char *type, const char *value)
{
    if (strcmp(type, "ec_paramgen_curve") == 0) {
        int nid = NID_undef;

        if (((nid = EC_curve_nist2nid(value)) == NID_undef)
            && ((nid = OBJ_sn2nid(value)) == NID_undef)
            && ((nid = OBJ_ln2nid(value)) == NID_undef)) {
            SM2err(SM2_F_PKEY_SM2_CTRL_STR, SM2_R_INVALID_CURVE);
            return 0;
        }
        return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
    } else if (strcmp(type, "ec_param_enc") == 0) {
        int param_enc;

        if (strcmp(value, "explicit") == 0)
            param_enc = 0;
        else if (strcmp(value, "named_curve") == 0)
            param_enc = OPENSSL_EC_NAMED_CURVE;
        else
            return -2;
        return EVP_PKEY_CTX_set_ec_param_enc(ctx, param_enc);
    }

    return -2;
}

const EVP_PKEY_METHOD sm2_pkey_meth = {
    EVP_PKEY_SM2,
    0,
    pkey_sm2_init,
    pkey_sm2_copy,
    pkey_sm2_cleanup,

    0,
    0,

    0,
    0,

    0,
    pkey_sm2_sign,

    0,
    pkey_sm2_verify,

    0, 0,

    0, 0, 0, 0,

    0,
    pkey_sm2_encrypt,

    0,
    pkey_sm2_decrypt,

    0,
    0,
    pkey_sm2_ctrl,
    pkey_sm2_ctrl_str
};
