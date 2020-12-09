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

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/pem.h>         /* For public PVK functions */
#include <openssl/x509.h>
#include "internal/passphrase.h"
#include "crypto/pem.h"          /* For internal PVK and "blob" headers */
#include "prov/bio.h"
#include "prov/implementations.h"
#include "endecoder_local.h"

static EVP_PKEY *read_msblob(PROV_CTX *provctx, OSSL_CORE_BIO *cin, int *ispub)
{
    BIO *in = bio_new_from_core_bio(provctx, cin);
    EVP_PKEY *pkey = ossl_b2i_bio(in, ispub);

    BIO_free(in);
    return pkey;
}

static EVP_PKEY *read_pvk(PROV_CTX *provctx, OSSL_CORE_BIO *cin,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    BIO *in = NULL;
    EVP_PKEY *pkey = NULL;
    struct ossl_passphrase_data_st pwdata;

    memset(&pwdata, 0, sizeof(pwdata));
    if (!ossl_pw_set_ossl_passphrase_cb(&pwdata, pw_cb, pw_cbarg))
        return NULL;

    in = bio_new_from_core_bio(provctx, cin);
    pkey = b2i_PVK_bio(in, ossl_pw_pem_password, &pwdata);
    BIO_free(in);

    return pkey;
}

static OSSL_FUNC_decoder_freectx_fn ms2key_freectx;
static OSSL_FUNC_decoder_gettable_params_fn ms2key_gettable_params;
static OSSL_FUNC_decoder_get_params_fn msblob2key_get_params;
static OSSL_FUNC_decoder_get_params_fn pvk2key_get_params;
static OSSL_FUNC_decoder_decode_fn msblob2key_decode;
static OSSL_FUNC_decoder_decode_fn pvk2key_decode;
static OSSL_FUNC_decoder_export_object_fn ms2key_export_object;

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
 * Context used for DER to key decoding.
 */
struct ms2key_ctx_st {
    PROV_CTX *provctx;
    const struct keytype_desc_st *desc;
};

static struct ms2key_ctx_st *
ms2key_newctx(void *provctx, const struct keytype_desc_st *desc)
{
    struct ms2key_ctx_st *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        ctx->provctx = provctx;
        ctx->desc = desc;
    }
    return ctx;
}

static void ms2key_freectx(void *vctx)
{
    struct ms2key_ctx_st *ctx = vctx;

    OPENSSL_free(ctx);
}

static const OSSL_PARAM *ms2key_gettable_params(ossl_unused void *provctx)
{
    static const OSSL_PARAM gettables[] = {
        { OSSL_DECODER_PARAM_INPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        OSSL_PARAM_END,
    };

    return gettables;
}

static int msblob2key_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DECODER_PARAM_INPUT_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "MSBLOB"))
        return 0;

    return 1;
}

static int pvk2key_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DECODER_PARAM_INPUT_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "PVK"))
        return 0;

    return 1;
}

static int ms2key_post(struct ms2key_ctx_st *ctx, EVP_PKEY *pkey,
                       OSSL_CALLBACK *data_cb, void *data_cbarg)
{
    void *key = NULL;
    int ok = 0;

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
    }

    if (key != NULL) {
        OSSL_PARAM params[4];
        int object_type = OSSL_OBJECT_PKEY;

        params[0] =
            OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
        params[1] =
            OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                             (char *)ctx->desc->name, 0);
        /* The address of the key becomes the octet string */
        params[2] =
            OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                              &key, sizeof(key));
        params[3] = OSSL_PARAM_construct_end();

        ok = data_cb(params, data_cbarg);
    }
    ctx->desc->free_key(key);

    return ok;
}

static int msblob2key_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
                             OSSL_CALLBACK *data_cb, void *data_cbarg,
                             OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    struct ms2key_ctx_st *ctx = vctx;
    int ispub = -1;
    EVP_PKEY *pkey = read_msblob(ctx->provctx, cin, &ispub);
    int ok = 0;

    if (selection == 0
        || (ispub
            ? (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
            : (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0))
        ok = ms2key_post(ctx, pkey, data_cb, data_cbarg);

    EVP_PKEY_free(pkey);
    return ok;
}

static int pvk2key_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
                          OSSL_CALLBACK *data_cb, void *data_cbarg,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    struct ms2key_ctx_st *ctx = vctx;
    EVP_PKEY *pkey = read_pvk(ctx->provctx, cin, pw_cb, pw_cbarg);
    int ok = 0;

    if (selection == 0
        || (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ms2key_post(ctx, pkey, data_cb, data_cbarg);

    EVP_PKEY_free(pkey);
    return ok;
}

static int ms2key_export_object(void *vctx,
                                const void *reference, size_t reference_sz,
                                OSSL_CALLBACK *export_cb, void *export_cbarg)
{
    struct ms2key_ctx_st *ctx = vctx;
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

#define IMPLEMENT_TYPE(KEYTYPEstr, KEYTYPE, keytype, extract, free)     \
    static const struct keytype_desc_st keytype##_desc;                 \
    static OSSL_FUNC_decoder_newctx_fn ms2##keytype##_newctx;           \
    static void *ms2##keytype##_newctx(void *provctx)                   \
    {                                                                   \
        return ms2key_newctx(provctx, &keytype##_desc);                 \
    }                                                                   \
    static const struct keytype_desc_st keytype##_desc =                \
        { EVP_PKEY_##KEYTYPE, KEYTYPEstr,                               \
          ossl_##keytype##_keymgmt_functions,                           \
          (extract_key_fn *)extract,                                    \
          (free_key_fn *)free }

#define IMPLEMENT_MS(mstype, keytype)                                   \
    const OSSL_DISPATCH                                                 \
        ossl_##mstype##_to_##keytype##_decoder_functions[] = {          \
        { OSSL_FUNC_DECODER_NEWCTX,                                     \
          (void (*)(void))ms2##keytype##_newctx },                      \
        { OSSL_FUNC_DECODER_FREECTX,                                    \
          (void (*)(void))ms2key_freectx },                             \
        { OSSL_FUNC_DECODER_GETTABLE_PARAMS,                            \
          (void (*)(void))ms2key_gettable_params },                     \
        { OSSL_FUNC_DECODER_GET_PARAMS,                                 \
          (void (*)(void))mstype##2key_get_params },                    \
        { OSSL_FUNC_DECODER_DECODE,                                     \
          (void (*)(void))mstype##2key_decode },                        \
        { OSSL_FUNC_DECODER_EXPORT_OBJECT,                              \
          (void (*)(void))ms2key_export_object },                       \
        { 0, NULL }                                                     \
    }

#ifndef OPENSSL_NO_DSA
IMPLEMENT_TYPE("DSA", DSA, dsa, EVP_PKEY_get1_DSA, DSA_free);
IMPLEMENT_MS(msblob, dsa);
IMPLEMENT_MS(pvk, dsa);
#endif
IMPLEMENT_TYPE("RSA", RSA, rsa, EVP_PKEY_get1_RSA, RSA_free);
IMPLEMENT_MS(msblob, rsa);
IMPLEMENT_MS(pvk, rsa);
