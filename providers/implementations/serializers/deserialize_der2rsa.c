/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
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

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/x509.h>
#include "prov/bio.h"
#include "prov/implementations.h"
#include "serializer_local.h"

static OSSL_FUNC_deserializer_newctx_fn der2rsa_newctx;
static OSSL_FUNC_deserializer_freectx_fn der2rsa_freectx;
static OSSL_FUNC_deserializer_gettable_params_fn der2rsa_gettable_params;
static OSSL_FUNC_deserializer_get_params_fn der2rsa_get_params;
static OSSL_FUNC_deserializer_settable_ctx_params_fn der2rsa_settable_ctx_params;
static OSSL_FUNC_deserializer_set_ctx_params_fn der2rsa_set_ctx_params;
static OSSL_FUNC_deserializer_deserialize_fn der2rsa_deserialize;
static OSSL_FUNC_deserializer_export_object_fn der2rsa_export_object;

/*
 * Context used for DER to RSA key deserialization.
 */
struct der2rsa_ctx_st {
    PROV_CTX *provctx;

    struct pkcs8_encrypt_ctx_st sc;
};

static void *der2rsa_newctx(void *provctx)
{
    struct der2rsa_ctx_st *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        ctx->provctx = provctx;
        /* -1 is the "whatever" indicator, i.e. the PKCS8 library default PBE */
        ctx->sc.pbe_nid = -1;
    }
    return ctx;
}

static void der2rsa_freectx(void *vctx)
{
    struct der2rsa_ctx_st *ctx = vctx;

    EVP_CIPHER_free(ctx->sc.cipher);
    OPENSSL_clear_free(ctx->sc.cipher_pass, ctx->sc.cipher_pass_length);
    OPENSSL_free(ctx);
}

static const OSSL_PARAM *der2rsa_gettable_params(void)
{
    static const OSSL_PARAM gettables[] = {
        { OSSL_DESERIALIZER_PARAM_INPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        OSSL_PARAM_END,
    };

    return gettables;
}

static int der2rsa_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DESERIALIZER_PARAM_INPUT_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "DER"))
        return 0;

    return 1;
}


static const OSSL_PARAM *der2rsa_settable_ctx_params(void)
{
    static const OSSL_PARAM settables[] = {
        OSSL_PARAM_utf8_string(OSSL_DESERIALIZER_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_DESERIALIZER_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_DESERIALIZER_PARAM_PASS, NULL, 0),
        OSSL_PARAM_END,
    };

    return settables;
}

static int der2rsa_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct der2rsa_ctx_st *ctx = vctx;
    OPENSSL_CTX *libctx = PROV_CTX_get0_library_context(ctx->provctx);
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_DESERIALIZER_PARAM_CIPHER))
        != NULL) {
        const OSSL_PARAM *propsp =
            OSSL_PARAM_locate_const(params, OSSL_DESERIALIZER_PARAM_PROPERTIES);
        const char *props = NULL;

        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        if (propsp != NULL && propsp->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        props = (propsp != NULL ? propsp->data : NULL);

        EVP_CIPHER_free(ctx->sc.cipher);
        ctx->sc.cipher = NULL;
        ctx->sc.cipher_intent = p->data != NULL;
        if (p->data != NULL
            && ((ctx->sc.cipher = EVP_CIPHER_fetch(libctx, p->data, props))
                == NULL))
            return 0;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_DESERIALIZER_PARAM_PASS))
        != NULL) {
        OPENSSL_clear_free(ctx->sc.cipher_pass, ctx->sc.cipher_pass_length);
        ctx->sc.cipher_pass = NULL;
        if (!OSSL_PARAM_get_octet_string(p, &ctx->sc.cipher_pass, 0,
                                         &ctx->sc.cipher_pass_length))
            return 0;
    }
    return 1;
}

static int der2rsa_deserialize(void *vctx, OSSL_CORE_BIO *cin,
                               OSSL_CALLBACK *data_cb, void *data_cbarg,
                               OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    struct der2rsa_ctx_st *ctx = vctx;
    void *libctx = PROV_LIBRARY_CONTEXT_OF(ctx->provctx);
    RSA *rsa = NULL;
    unsigned char *der = NULL;
    const unsigned char *derp;
    long der_len = 0;
    unsigned char *new_der = NULL;
    long new_der_len;
    EVP_PKEY *pkey = NULL;
    int ok = 0;

    ctx->sc.cb = pw_cb;
    ctx->sc.cbarg = pw_cbarg;

    if (!ossl_prov_read_der(ctx->provctx, cin, &der, &der_len))
        return 0;

    /*
     * Opportunistic attempt to decrypt.  If it doesn't work, we try to
     * decode our input unencrypted.
     */
    if (ctx->sc.cipher_intent
        && ossl_prov_der_from_p8(&new_der, &new_der_len, der, der_len,
                                 &ctx->sc)) {
        OPENSSL_free(der);
        der = new_der;
        der_len = new_der_len;
    }

    derp = der;
    if ((pkey = d2i_PrivateKey_ex(EVP_PKEY_RSA, NULL, &derp, der_len,
                                  libctx, NULL)) != NULL) {
        /* Tear out the RSA pointer from the pkey */
        rsa = EVP_PKEY_get1_RSA(pkey);
        EVP_PKEY_free(pkey);
    }

    OPENSSL_free(der);

    if (rsa != NULL) {
        OSSL_PARAM params[3];

        params[0] =
            OSSL_PARAM_construct_utf8_string(OSSL_DESERIALIZER_PARAM_DATA_TYPE,
                                             "RSA", 0);
        /* The address of the key becomes the octet string */
        params[1] =
            OSSL_PARAM_construct_octet_string(OSSL_DESERIALIZER_PARAM_REFERENCE,
                                              &rsa, sizeof(rsa));
        params[2] = OSSL_PARAM_construct_end();

        ok = data_cb(params, data_cbarg);
    }
    RSA_free(rsa);

    return ok;
}

static int der2rsa_export_object(void *vctx,
                                 const void *reference, size_t reference_sz,
                                 OSSL_CALLBACK *export_cb, void *export_cbarg)
{
    OSSL_FUNC_keymgmt_export_fn *rsa_export =
        ossl_prov_get_keymgmt_rsa_export();
    void *keydata;

    if (reference_sz == sizeof(keydata) && rsa_export != NULL) {
        /* The contents of the reference is the address to our object */
        keydata = *(RSA **)reference;

        return rsa_export(keydata, OSSL_KEYMGMT_SELECT_ALL,
                          export_cb, export_cbarg);
    }
    return 0;
}

const OSSL_DISPATCH der_to_rsa_deserializer_functions[] = {
    { OSSL_FUNC_DESERIALIZER_NEWCTX, (void (*)(void))der2rsa_newctx },
    { OSSL_FUNC_DESERIALIZER_FREECTX, (void (*)(void))der2rsa_freectx },
    { OSSL_FUNC_DESERIALIZER_GETTABLE_PARAMS,
      (void (*)(void))der2rsa_gettable_params },
    { OSSL_FUNC_DESERIALIZER_GET_PARAMS,
      (void (*)(void))der2rsa_get_params },
    { OSSL_FUNC_DESERIALIZER_SETTABLE_CTX_PARAMS,
      (void (*)(void))der2rsa_settable_ctx_params },
    { OSSL_FUNC_DESERIALIZER_SET_CTX_PARAMS,
      (void (*)(void))der2rsa_set_ctx_params },
    { OSSL_FUNC_DESERIALIZER_DESERIALIZE,
      (void (*)(void))der2rsa_deserialize },
    { OSSL_FUNC_DESERIALIZER_EXPORT_OBJECT,
      (void (*)(void))der2rsa_export_object },
    { 0, NULL }
};
