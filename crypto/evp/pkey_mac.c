/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include "crypto/evp.h"
#include "evp_local.h"

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

static void pkey_mac_cleanup(EVP_PKEY_CTX *ctx);

static int pkey_mac_init(EVP_PKEY_CTX *ctx)
{
    MAC_PKEY_CTX *hctx;
    /* We're being smart and using the same base NIDs for PKEY and for MAC */
    int nid = ctx->pmeth->pkey_id;
    EVP_MAC *mac = EVP_MAC_fetch(NULL, OBJ_nid2sn(nid), NULL);

    if ((hctx = OPENSSL_zalloc(sizeof(*hctx))) == NULL) {
        EVPerr(EVP_F_PKEY_MAC_INIT, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    hctx->ctx = EVP_MAC_CTX_new(mac);
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

    pkey_mac_cleanup(ctx);
    EVP_PKEY_CTX_set_data(ctx, hctx);
    ctx->keygen_info_count = 0;

    return 1;
}

static int pkey_mac_copy(EVP_PKEY_CTX *dst, const EVP_PKEY_CTX *src)
{
    MAC_PKEY_CTX *sctx, *dctx;

    sctx = EVP_PKEY_CTX_get_data(src);
    if (sctx->ctx->data == NULL)
        return 0;

    dctx = OPENSSL_zalloc(sizeof(*dctx));
    if (dctx == NULL) {
        EVPerr(EVP_F_PKEY_MAC_COPY, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    EVP_PKEY_CTX_set_data(dst, dctx);
    dst->keygen_info_count = 0;

    dctx->ctx = EVP_MAC_CTX_dup(sctx->ctx);
    if (dctx->ctx == NULL)
        goto err;

    /*
     * Normally, nothing special would be done with the MAC method.  In
     * this particular case, though, the MAC method was fetched internally
     * by pkey_mac_init() above or by EVP_PKEY_new_CMAC_key() and passed
     * via the EVP_MAC_CTX, so it is effectively like every new EVP_MAC_CTX
     * fetches the MAC method anew in this case.  Therefore, its reference
     * count must be adjusted here.
     */
    if (!EVP_MAC_up_ref(EVP_MAC_CTX_mac(dctx->ctx)))
        goto err;

    dctx->type = sctx->type;

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
    pkey_mac_cleanup(dst);
    return 0;
}

static void pkey_mac_cleanup(EVP_PKEY_CTX *ctx)
{
    /*
     * For the exact same reasons the MAC reference count is incremented
     * in pkey_mac_copy() above, it must be explicitly freed here.
     */

    MAC_PKEY_CTX *hctx = ctx == NULL ? NULL : EVP_PKEY_CTX_get_data(ctx);

    if (hctx != NULL) {
        EVP_MAC *mac = EVP_MAC_CTX_mac(hctx->ctx);

        switch (hctx->type) {
        case MAC_TYPE_RAW:
            OPENSSL_clear_free(hctx->raw_data.ktmp.data,
                               hctx->raw_data.ktmp.length);
            break;
        }
        EVP_MAC_CTX_free(hctx->ctx);
        EVP_MAC_free(mac);
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
            EVP_MAC_CTX *cmkey = EVP_MAC_CTX_dup(hctx->ctx);

            if (cmkey == NULL)
                return 0;
            if (!EVP_MAC_up_ref(EVP_MAC_CTX_mac(hctx->ctx)))
                return 0;
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
        if (!EVP_MAC_is_a(EVP_MAC_CTX_mac(hctx->ctx),
                          OBJ_nid2sn(EVP_PKEY_id(EVP_PKEY_CTX_get0_pkey(ctx)))))
            return 0;
        key = EVP_PKEY_get0(EVP_PKEY_CTX_get0_pkey(ctx));
        if (key == NULL)
            return 0;
    }

    EVP_MD_CTX_set_flags(mctx, EVP_MD_CTX_FLAG_NO_INIT);
    EVP_MD_CTX_set_update_fn(mctx, int_update);

    /* Some MACs don't support this control...  that's fine */
    {
        OSSL_PARAM params[3];
        size_t params_n = 0;
        int flags = EVP_MD_CTX_test_flags(mctx, ~EVP_MD_CTX_FLAG_NO_INIT);

        /* TODO(3.0) "flags" isn't quite right, i.e. a quick hack for now */
        params[params_n++] =
            OSSL_PARAM_construct_int(OSSL_MAC_PARAM_FLAGS, &flags);
        if (set_key)
            params[params_n++] =
                OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
                                                  key->data, key->length);
        params[params_n++] = OSSL_PARAM_construct_end();
        rv = EVP_MAC_CTX_set_params(hctx->ctx, params);
    }
    return rv;
}

static int pkey_mac_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig,
                             size_t *siglen, EVP_MD_CTX *mctx)
{
    MAC_PKEY_CTX *hctx = EVP_PKEY_CTX_get_data(ctx);

    return EVP_MAC_final(hctx->ctx, sig, siglen, EVP_MAC_size(hctx->ctx));
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
                OSSL_PARAM params[3];
                size_t params_n = 0;
                char *ciphname = (char *)OBJ_nid2sn(EVP_CIPHER_nid(p2));
#ifndef OPENSSL_NO_ENGINE
                char *engineid = (char *)ENGINE_get_id(ctx->engine);

                params[params_n++] =
                    OSSL_PARAM_construct_utf8_string("engine", engineid, 0);
#endif
                params[params_n++] =
                    OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                                                     ciphname, 0);
                params[params_n] = OSSL_PARAM_construct_end();

                if (!EVP_MAC_CTX_set_params(hctx->ctx, params)
                    || !EVP_MAC_init(hctx->ctx))
                    return 0;
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
        case MAC_TYPE_MAC: {
                EVP_MAC_CTX *new_mac_ctx;

                if (ctx->pkey == NULL)
                    return 0;
                new_mac_ctx = EVP_MAC_CTX_dup((EVP_MAC_CTX *)ctx->pkey
                                              ->pkey.ptr);
                if (new_mac_ctx == NULL)
                    return 0;
                EVP_MAC_CTX_free(hctx->ctx);
                hctx->ctx = new_mac_ctx;
            }
            break;
        default:
            /* This should be dead code */
            return 0;
        }
        break;

    case EVP_PKEY_CTRL_SET_DIGEST_SIZE:
        {
            OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
            size_t size = (size_t)p1;
            size_t verify = 0;

            /*
             * We verify that the length is actually set by getting back
             * the same parameter and checking that it matches what we
             * tried to set.
             * TODO(3.0) when we have a more direct mechanism to check if
             * a parameter was used, we must refactor this to use that.
             */

            params[0] =
                OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &size);

            if (!EVP_MAC_CTX_set_params(hctx->ctx, params))
                return 0;

            params[0] =
                OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &verify);

            if (!EVP_MAC_CTX_get_params(hctx->ctx, params))
                return 0;

            /*
             * Since EVP_MAC_CTX_{get,set}_params() returned successfully,
             * we can only assume that the size was ignored, i.e. this
             * control is unsupported.
             */
            if (verify != size)
                return -2;
        }
        break;
    case EVP_PKEY_CTRL_SET_MAC_KEY:
        switch (hctx->type) {
        case MAC_TYPE_RAW:
            if ((!p2 && p1 > 0) || (p1 < -1))
                return 0;
            if (!ASN1_OCTET_STRING_set(&hctx->raw_data.ktmp, p2, p1))
                return 0;
            break;
        case MAC_TYPE_MAC:
            {
                OSSL_PARAM params[2];
                size_t params_n = 0;

                params[params_n++] =
                    OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
                                                      p2, p1);
                params[params_n] = OSSL_PARAM_construct_end();

                return EVP_MAC_CTX_set_params(hctx->ctx, params);
            }
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
                ASN1_OCTET_STRING *key =
                    (ASN1_OCTET_STRING *)ctx->pkey->pkey.ptr;
                OSSL_PARAM params[4];
                size_t params_n = 0;
                char *mdname =
                    (char *)OBJ_nid2sn(EVP_MD_nid(hctx->raw_data.md));
#ifndef OPENSSL_NO_ENGINE
                char *engineid = ctx->engine == NULL
                    ? NULL : (char *)ENGINE_get_id(ctx->engine);

                if (engineid != NULL)
                    params[params_n++] =
                        OSSL_PARAM_construct_utf8_string("engine", engineid, 0);
#endif
                params[params_n++] =
                    OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                     mdname, 0);
                params[params_n++] =
                    OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
                                                      key->data, key->length);
                params[params_n] = OSSL_PARAM_construct_end();

                return EVP_MAC_CTX_set_params(hctx->ctx, params);
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
    const EVP_MAC *mac = EVP_MAC_CTX_mac(hctx->ctx);
    OSSL_PARAM params[2];
    int ok = 0;

    /*
     * Translation of some control names that are equivalent to a single
     * parameter name.
     *
     * "md" and "digest" are the same thing, we use the single "digest"
     *
     * "digestsize" was a setting control in siphash, but naming wise,
     * it's really the same as "size".
     */
    if (strcmp(type, "md") == 0)
        type = OSSL_MAC_PARAM_DIGEST;
    else if (strcmp(type, "digestsize") == 0)
        type = OSSL_MAC_PARAM_SIZE;

    if (!OSSL_PARAM_allocate_from_text(&params[0],
                                       EVP_MAC_settable_ctx_params(mac),
                                       type, value, strlen(value) + 1))
        return 0;
    params[1] = OSSL_PARAM_construct_end();
    ok = EVP_MAC_CTX_set_params(hctx->ctx, params);
    OPENSSL_free(params[0].data);
    return ok;
}

static const EVP_PKEY_METHOD cmac_pkey_meth = {
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

const EVP_PKEY_METHOD *cmac_pkey_method(void)
{
    return &cmac_pkey_meth;
}

static const EVP_PKEY_METHOD hmac_pkey_meth = {
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

const EVP_PKEY_METHOD *hmac_pkey_method(void)
{
    return &hmac_pkey_meth;
}

static const EVP_PKEY_METHOD siphash_pkey_meth = {
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

const EVP_PKEY_METHOD *siphash_pkey_method(void)
{
    return &siphash_pkey_meth;
}

static const EVP_PKEY_METHOD poly1305_pkey_meth = {
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

const EVP_PKEY_METHOD *poly1305_pkey_method(void)
{
    return &poly1305_pkey_meth;
}
