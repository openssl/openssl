/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * low level APIs are deprecated for public use, but still ok for
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

static OSSL_FUNC_deserializer_freectx_fn der2key_freectx;
static OSSL_FUNC_deserializer_gettable_params_fn der2key_gettable_params;
static OSSL_FUNC_deserializer_get_params_fn der2key_get_params;
static OSSL_FUNC_deserializer_deserialize_fn der2key_deserialize;
static OSSL_FUNC_deserializer_export_object_fn der2key_export_object;

typedef void *(extract_key_fn)(EVP_PKEY *);
typedef void (free_key_fn)(void *);
struct keytype_desc_st {
    int type;                 /* EVP key type */
    const char *name;         /* Keytype */
    const OSSL_DISPATCH *fns; /* Keymgmt (to pilfer functions from) */

    /*
     * These must be the correct EVP_PKEY_get1_{TYPE}() and {TYPE}_free()
     * function for the key.
     */
    extract_key_fn *extract_key;
    free_key_fn *free_key;
};

/*
 * Context used for DER to key deserialization.
 */
struct der2key_ctx_st {
    PROV_CTX *provctx;
    const struct keytype_desc_st *desc;
};

static struct der2key_ctx_st *
der2key_newctx(void *provctx, const struct keytype_desc_st *desc)
{
    struct der2key_ctx_st *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        ctx->provctx = provctx;
        ctx->desc = desc;
    }
    return ctx;
}

static void der2key_freectx(void *vctx)
{
    struct der2key_ctx_st *ctx = vctx;

    OPENSSL_free(ctx);
}

static const OSSL_PARAM *der2key_gettable_params(void)
{
    static const OSSL_PARAM gettables[] = {
        { OSSL_DESERIALIZER_PARAM_INPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        OSSL_PARAM_END,
    };

    return gettables;
}

static int der2key_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DESERIALIZER_PARAM_INPUT_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "DER"))
        return 0;

    return 1;
}

static int der2key_deserialize(void *vctx, OSSL_CORE_BIO *cin,
                               OSSL_CALLBACK *data_cb, void *data_cbarg,
                               OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    struct der2key_ctx_st *ctx = vctx;
    void *libctx = PROV_LIBRARY_CONTEXT_OF(ctx->provctx);
    unsigned char *der = NULL;
    const unsigned char *derp;
    long der_len = 0;
    unsigned char *new_der = NULL;
    long new_der_len;
    EVP_PKEY *pkey = NULL;
    void *key = NULL;
    int ok = 0;

    if (!ossl_prov_read_der(ctx->provctx, cin, &der, &der_len))
        return 0;

    /*
     * Opportunistic attempt to decrypt.  If it doesn't work, we try to
     * decode our input unencrypted.
     */
    if (ossl_prov_der_from_p8(&new_der, &new_der_len, der, der_len,
                              pw_cb, pw_cbarg)) {
        OPENSSL_free(der);
        der = new_der;
        der_len = new_der_len;
    }

    derp = der;
    pkey = d2i_PrivateKey_ex(ctx->desc->type, NULL, &derp, der_len,
                             libctx, NULL);
    if (pkey == NULL) {
        derp = der;
        pkey = d2i_PUBKEY(NULL, &derp, der_len);
    }

    if (pkey != NULL) {
        /*
         * Tear out the low-level key pointer from the pkey,
         * but only if it matches the expected key type.
         *
         * TODO(3.0): The check should be done with EVP_PKEY_is_a(), but
         * as long as we still have #legacy internal keys, it's safer to
         * use the type numbers in side the provider.
         */
        if (EVP_PKEY_id(pkey) == ctx->desc->type)
            key = ctx->desc->extract_key(pkey);

        /*
         * ctx->desc->extract_key() is expected to have incremented |key|'s
         * reference count, so it should be safe to free |pkey| now.
         */
        EVP_PKEY_free(pkey);
    }

    OPENSSL_free(der);

    if (key != NULL) {
        OSSL_PARAM params[3];

        params[0] =
            OSSL_PARAM_construct_utf8_string(OSSL_DESERIALIZER_PARAM_DATA_TYPE,
                                             (char *)ctx->desc->name, 0);
        /* The address of the key becomes the octet string */
        params[1] =
            OSSL_PARAM_construct_octet_string(OSSL_DESERIALIZER_PARAM_REFERENCE,
                                              &key, sizeof(key));
        params[2] = OSSL_PARAM_construct_end();

        ok = data_cb(params, data_cbarg);
    }
    ctx->desc->free_key(key);

    return ok;
}

static int der2key_export_object(void *vctx,
                                 const void *reference, size_t reference_sz,
                                 OSSL_CALLBACK *export_cb, void *export_cbarg)
{
    struct der2key_ctx_st *ctx = vctx;
    OSSL_FUNC_keymgmt_export_fn *export =
        ossl_prov_get_keymgmt_export(ctx->desc->fns);
    void *keydata;

    if (reference_sz == sizeof(keydata) && export != NULL) {
        /* The contents of the reference is the address to our object */
        keydata = *(void **)reference;

        return export(keydata, OSSL_KEYMGMT_SELECT_ALL,
                      export_cb, export_cbarg);
    }
    return 0;
}

#define IMPLEMENT_NEWCTX(KEYTYPEstr, KEYTYPE, keytype, extract, free)   \
    static const struct keytype_desc_st keytype##_desc =                \
        { EVP_PKEY_##KEYTYPE, KEYTYPEstr, keytype##_keymgmt_functions,  \
          (extract_key_fn *)extract,                                    \
          (free_key_fn *)free };                                        \
    static void *der2##keytype##_newctx(void *provctx)                  \
    {                                                                   \
        return der2key_newctx(provctx, &keytype##_desc);                \
    }                                                                   \
    const OSSL_DISPATCH der_to_##keytype##_deserializer_functions[] = { \
        { OSSL_FUNC_DESERIALIZER_NEWCTX,                                \
          (void (*)(void))der2##keytype##_newctx },                     \
        { OSSL_FUNC_DESERIALIZER_FREECTX,                               \
          (void (*)(void))der2key_freectx },                            \
        { OSSL_FUNC_DESERIALIZER_GETTABLE_PARAMS,                       \
          (void (*)(void))der2key_gettable_params },                    \
        { OSSL_FUNC_DESERIALIZER_GET_PARAMS,                            \
          (void (*)(void))der2key_get_params },                         \
        { OSSL_FUNC_DESERIALIZER_DESERIALIZE,                           \
          (void (*)(void))der2key_deserialize },                        \
        { OSSL_FUNC_DESERIALIZER_EXPORT_OBJECT,                         \
          (void (*)(void))der2key_export_object },                      \
        { 0, NULL }                                                     \
    }

#ifndef OPENSSL_NO_DH
IMPLEMENT_NEWCTX("DH", DH, dh, EVP_PKEY_get1_DH, DH_free);
#endif
#ifndef OPENSSL_NO_DSA
IMPLEMENT_NEWCTX("DSA", DSA, dsa, EVP_PKEY_get1_DSA, DSA_free);
#endif
#ifndef OPENSSL_NO_EC
IMPLEMENT_NEWCTX("EC", EC, ec, EVP_PKEY_get1_EC_KEY, EC_KEY_free);
IMPLEMENT_NEWCTX("X25519", X25519, x25519,
                 EVP_PKEY_get1_X25519, ecx_key_free);
IMPLEMENT_NEWCTX("X448", X448, x448,
                 EVP_PKEY_get1_X448, ecx_key_free);
IMPLEMENT_NEWCTX("ED25519", ED25519, ed25519,
                 EVP_PKEY_get1_ED25519, ecx_key_free);
IMPLEMENT_NEWCTX("ED448", ED448, ed448, EVP_PKEY_get1_ED448, ecx_key_free);
#endif
IMPLEMENT_NEWCTX("RSA", RSA, rsa, EVP_PKEY_get1_RSA, RSA_free);
IMPLEMENT_NEWCTX("RSA-PSS", RSA_PSS, rsapss, EVP_PKEY_get1_RSA, RSA_free);
