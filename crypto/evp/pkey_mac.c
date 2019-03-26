/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/evp.h>
#include "internal/evp_int.h"

/* MAC PKEY context structure */

typedef struct {
    EVP_MAC_CTX *ctx;

    /*
     * We know of two MAC types:
     *
     * 1. those who take a secret in raw form, i.e. raw data as a
     *    ASN1_OCTET_STRING embedded in a EVP_PKEY.  So far, that's
     *    all of them but CMAC.
     * 2. those who take a secret with associated cipher in very generic
     *    form, i.e. a complete EVP_MAC_CTX embedded in a PKEY.  So far,
     *    only CMAC does this.
     *
     * (one might wonder why the second form isn't used for all)
     */
#define MAC_TYPE_RAW    1   /* HMAC like MAC type (all but CMAC so far) */
#define MAC_TYPE_MAC    2   /* CMAC like MAC type (only CMAC known so far) */
    int type;

    /* The following is only used for MAC_TYPE_RAW implementations */
    struct {
        const EVP_MD *md;           /* temp storage of MD */
        ASN1_OCTET_STRING ktmp;     /* temp storage for key */
    } raw_data;
} MAC_PKEY_CTX;

static int pkey_mac_init(EVP_PKEY_CTX *ctx)
{
    MAC_PKEY_CTX *hctx;
    int nid = ctx->pmeth->pkey_id;

    if ((hctx = OPENSSL_zalloc(sizeof(*hctx))) == NULL) {
        EVPerr(EVP_F_PKEY_MAC_INIT, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    /* We're being smart and using the same base NIDs for PKEY and for MAC */
    hctx->ctx = EVP_MAC_CTX_new_id(nid);
    if (hctx->ctx == NULL) {
        OPENSSL_free(hctx);
        return 0;
    }

    if (nid == EVP_PKEY_CMAC) {
        hctx->type = MAC_TYPE_MAC;
    } else {
        hctx->type = MAC_TYPE_RAW;
        hctx->raw_data.ktmp.type = V_ASN1_OCTET_STRING;
    }

    EVP_PKEY_CTX_set_data(ctx, hctx);
    ctx->keygen_info_count = 0;

    return 1;
}

static void pkey_mac_cleanup(EVP_PKEY_CTX *ctx);

static int pkey_mac_copy(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src)
{
    MAC_PKEY_CTX *sctx, *dctx;

    if (!pkey_mac_init(dst))
        return 0;

    sctx = EVP_PKEY_CTX_get_data(src);
    dctx = EVP_PKEY_CTX_get_data(dst);

    if (!EVP_MAC_CTX_copy(dctx->ctx, sctx->ctx))
        goto err;

    switch (dctx->type) {
    case MAC_TYPE_RAW:
        dctx->raw_data.md = sctx->raw_data.md;
        if (ASN1_STRING_get0_data(&sctx->raw_data.ktmp) != NULL &&
            !ASN1_STRING_copy(&dctx->raw_data.ktmp, &sctx->raw_data.ktmp))
            goto err;
        break;
    case MAC_TYPE_MAC:
        /* Nothing more to do */
        break;
    default:
        /* This should be dead code */
        return 0;
    }
    return 1;
 err:
    pkey_mac_cleanup (dst);
    return 0;
}

static void pkey_mac_cleanup(EVP_PKEY_CTX *ctx)
{
    MAC_PKEY_CTX *hctx = EVP_PKEY_CTX_get_data(ctx);

    if (hctx != NULL) {
        switch (hctx->type) {
        case MAC_TYPE_RAW:
            OPENSSL_clear_free(hctx->raw_data.ktmp.data,
                               hctx->raw_data.ktmp.length);
            break;
        }
        EVP_MAC_CTX_free(hctx->ctx);
        OPENSSL_free(hctx);
        EVP_PKEY_CTX_set_data(ctx, NULL);
    }
}

static int pkey_mac_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
    MAC_PKEY_CTX *hctx = EVP_PKEY_CTX_get_data(ctx);
    int nid = ctx->pmeth->pkey_id;

    switch (hctx->type) {
    case MAC_TYPE_RAW:
        {
            ASN1_OCTET_STRING *hkey = NULL;

            if (!hctx->raw_data.ktmp.data)
                return 0;
            hkey = ASN1_OCTET_STRING_dup(&hctx->raw_data.ktmp);
            if (!hkey)
                return 0;
            EVP_PKEY_assign(pkey, nid, hkey);
        }
        break;
    case MAC_TYPE_MAC:
        {
            EVP_MAC_CTX *cmkey = EVP_MAC_CTX_new_id(nid);

            if (cmkey == NULL)
                return 0;
            if (!EVP_MAC_CTX_copy(cmkey, hctx->ctx)) {
                EVP_MAC_CTX_free(cmkey);
                return 0;
            }
            EVP_PKEY_assign(pkey, nid, cmkey);
        }
        break;
    default:
        /* This should be dead code */
        return 0;
    }

    return 1;
}

static int int_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    MAC_PKEY_CTX *hctx = EVP_PKEY_CTX_get_data(EVP_MD_CTX_pkey_ctx(ctx));

    if (!EVP_MAC_update(hctx->ctx, data, count))
        return 0;
    return 1;
}

static int pkey_mac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx)
{
    MAC_PKEY_CTX *hctx = EVP_PKEY_CTX_get_data(ctx);
    ASN1_OCTET_STRING *key = NULL;
    int rv = 1;
    /*
     * For MACs with the EVP_PKEY_FLAG_SIGCTX_CUSTOM flag set and that
     * gets the key passed as an ASN.1 OCTET STRING, we set the key here,
     * as this may be only time it's set during a DigestSign.
     *
     * MACs that pass around the key in form of EVP_MAC_CTX are setting
     * the key through other mechanisms.  (this is only CMAC for now)
     */
    int set_key =
        hctx->type == MAC_TYPE_RAW
        && (ctx->pmeth->flags & EVP_PKEY_FLAG_SIGCTX_CUSTOM) != 0;

    if (set_key) {
        if (EVP_PKEY_id(EVP_PKEY_CTX_get0_pkey(ctx))
            != EVP_MAC_nid(EVP_MAC_CTX_mac(hctx->ctx)))
            return 0;
        key = EVP_PKEY_get0(EVP_PKEY_CTX_get0_pkey(ctx));
        if (key == NULL)
            return 0;
    }

    /* Some MACs don't support this control...  that's fine */
    EVP_MAC_ctrl(hctx->ctx, EVP_MAC_CTRL_SET_FLAGS,
                 EVP_MD_CTX_test_flags(mctx, ~EVP_MD_CTX_FLAG_NO_INIT));

    EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_NO_INIT);
    EVP_MD_CTX_set_update_fn(mctx, int_update);

    if (set_key)
        rv = EVP_MAC_ctrl(hctx->ctx, EVP_MAC_CTRL_SET_KEY, key->data,
                          key->length);
    return rv > 0;
}

static int pkey_mac_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig,
                             size_t *siglen, EVP_MD_CTX *mctx)
{
    MAC_PKEY_CTX *hctx = EVP_PKEY_CTX_get_data(ctx);

    return EVP_MAC_final(hctx->ctx, sig, siglen);
}

static int pkey_mac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
    MAC_PKEY_CTX *hctx = EVP_PKEY_CTX_get_data(ctx);

    switch (type) {

    case EVP_PKEY_CTRL_CIPHER:
        switch (hctx->type) {
        case MAC_TYPE_RAW:
            return -2;       /* The raw types don't support ciphers */
        case MAC_TYPE_MAC:
            {
                int rv;

                if ((rv = EVP_MAC_ctrl(hctx->ctx, EVP_MAC_CTRL_SET_ENGINE,
                                       ctx->engine)) <= 0
                    || (rv = EVP_MAC_ctrl(hctx->ctx, EVP_MAC_CTRL_SET_CIPHER,
                                          p2)) <= 0
                    || !(rv = EVP_MAC_init(hctx->ctx)))
                    return rv;
            }
            break;
        default:
            /* This should be dead code */
            return 0;
        }
        break;

    case EVP_PKEY_CTRL_MD:
        switch (hctx->type) {
        case MAC_TYPE_RAW:
            hctx->raw_data.md = p2;
            break;
        case MAC_TYPE_MAC:
            if (ctx->pkey != NULL
                && !EVP_MAC_CTX_copy(hctx->ctx,
                                     (EVP_MAC_CTX *)ctx->pkey->pkey.ptr))
                return 0;
            if (!EVP_MAC_init(hctx->ctx))
                return 0;
            break;
        default:
            /* This should be dead code */
            return 0;
        }
        break;

    case EVP_PKEY_CTRL_SET_DIGEST_SIZE:
        return EVP_MAC_ctrl(hctx->ctx, EVP_MAC_CTRL_SET_SIZE, (size_t)p1);

    case EVP_PKEY_CTRL_SET_MAC_KEY:
        switch (hctx->type) {
        case MAC_TYPE_RAW:
            if ((!p2 && p1 > 0) || (p1 < -1))
                return 0;
            if (!ASN1_OCTET_STRING_set(&hctx->raw_data.ktmp, p2, p1))
                return 0;
            break;
        case MAC_TYPE_MAC:
            if (EVP_MAC_ctrl(hctx->ctx, EVP_MAC_CTRL_SET_KEY, p2, p1) <= 0)
                return 0;
            break;
        default:
            /* This should be dead code */
            return 0;
        }
        break;

    case EVP_PKEY_CTRL_DIGESTINIT:
        switch (hctx->type) {
        case MAC_TYPE_RAW:
            /* Ensure that we have attached the implementation */
            if (!EVP_MAC_init(hctx->ctx))
                return 0;
            {
                int rv;
                ASN1_OCTET_STRING *key =
                    (ASN1_OCTET_STRING *)ctx->pkey->pkey.ptr;

                if ((rv = EVP_MAC_ctrl(hctx->ctx, EVP_MAC_CTRL_SET_ENGINE,
                                       ctx->engine)) <= 0
                    || (rv = EVP_MAC_ctrl(hctx->ctx, EVP_MAC_CTRL_SET_MD,
                                          hctx->raw_data.md)) <= 0
                    || (rv = EVP_MAC_ctrl(hctx->ctx, EVP_MAC_CTRL_SET_KEY,
                                          key->data, key->length)) <= 0)
                    return rv;
            }
            break;
        case MAC_TYPE_MAC:
            return -2;       /* The mac types don't support ciphers */
        default:
            /* This should be dead code */
            return 0;
        }
        break;

    default:
        return -2;

    }
    return 1;
}

static int pkey_mac_ctrl_str(EVP_PKEY_CTX *ctx,
                              const char *type, const char *value)
{
    MAC_PKEY_CTX *hctx = EVP_PKEY_CTX_get_data(ctx);

    return EVP_MAC_ctrl_str(hctx->ctx, type, value);
}

const EVP_PKEY_METHOD cmac_pkey_meth = {
    EVP_PKEY_CMAC,
    EVP_PKEY_FLAG_SIGCTX_CUSTOM,
    pkey_mac_init,
    pkey_mac_copy,
    pkey_mac_cleanup,

    0, 0,

    0,
    pkey_mac_keygen,

    0, 0,

    0, 0,

    0, 0,

    pkey_mac_signctx_init,
    pkey_mac_signctx,

    0, 0,

    0, 0,

    0, 0,

    0, 0,

    pkey_mac_ctrl,
    pkey_mac_ctrl_str
};

const EVP_PKEY_METHOD hmac_pkey_meth = {
    EVP_PKEY_HMAC,
    0,
    pkey_mac_init,
    pkey_mac_copy,
    pkey_mac_cleanup,

    0, 0,

    0,
    pkey_mac_keygen,

    0, 0,

    0, 0,

    0, 0,

    pkey_mac_signctx_init,
    pkey_mac_signctx,

    0, 0,

    0, 0,

    0, 0,

    0, 0,

    pkey_mac_ctrl,
    pkey_mac_ctrl_str
};

const EVP_PKEY_METHOD siphash_pkey_meth = {
    EVP_PKEY_SIPHASH,
    EVP_PKEY_FLAG_SIGCTX_CUSTOM,
    pkey_mac_init,
    pkey_mac_copy,
    pkey_mac_cleanup,

    0, 0,

    0,
    pkey_mac_keygen,

    0, 0,

    0, 0,

    0, 0,

    pkey_mac_signctx_init,
    pkey_mac_signctx,

    0, 0,

    0, 0,

    0, 0,

    0, 0,

    pkey_mac_ctrl,
    pkey_mac_ctrl_str
};

const EVP_PKEY_METHOD poly1305_pkey_meth = {
    EVP_PKEY_POLY1305,
    EVP_PKEY_FLAG_SIGCTX_CUSTOM,
    pkey_mac_init,
    pkey_mac_copy,
    pkey_mac_cleanup,

    0, 0,

    0,
    pkey_mac_keygen,

    0, 0,

    0, 0,

    0, 0,

    pkey_mac_signctx_init,
    pkey_mac_signctx,

    0, 0,

    0, 0,

    0, 0,

    0, 0,

    pkey_mac_ctrl,
    pkey_mac_ctrl_str
};
