/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Low level APIs are deprecated for public use, but still ok for internal use.
 */
#include "internal/deprecated.h"

#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/pem.h>         /* Functions for writing MSBLOB and PVK */
#include <openssl/dsa.h>
#include "internal/passphrase.h"
#include "crypto/rsa.h"
#include "prov/implementations.h"
#include "prov/bio.h"
#include "prov/provider_ctx.h"
#include "endecoder_local.h"

static int write_blob(void *provctx, OSSL_CORE_BIO *cout,
                      void *data, int len)
{
    BIO *out = bio_new_from_core_bio(provctx, cout);
    int ret = BIO_write(out, data, len);

    BIO_free(out);
    return ret;
}

static OSSL_FUNC_encoder_newctx_fn key2blob_newctx;
static OSSL_FUNC_encoder_freectx_fn key2blob_freectx;
static OSSL_FUNC_encoder_gettable_params_fn key2blob_gettable_params;
static OSSL_FUNC_encoder_get_params_fn key2blob_get_params;
static OSSL_FUNC_encoder_does_selection_fn key2blob_does_selection;

static void *key2blob_newctx(void *provctx)
{
    return provctx;
}

static void key2blob_freectx(void *vctx)
{
}

static const OSSL_PARAM *key2blob_gettable_params(ossl_unused void *provctx)
{
    static const OSSL_PARAM gettables[] = {
        { OSSL_ENCODER_PARAM_OUTPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        OSSL_PARAM_END,
    };

    return gettables;
}

static int key2blob_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_ENCODER_PARAM_OUTPUT_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "blob"))
        return 0;

    return 1;
}

static int key2blob_does_selection(void *vctx, int selection)
{
    return (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
        && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0;
}

static int key2blob_encode(void *vctx, const void *key, int selection,
                           OSSL_CORE_BIO *cout)
{
    int pubkey_len = 0, ok = 0;
    unsigned char *pubkey = NULL;

    pubkey_len = i2o_ECPublicKey(key, &pubkey);
    if (pubkey_len > 0 && pubkey != NULL)
        ok = write_blob(vctx, cout, pubkey, pubkey_len);
    OPENSSL_free(pubkey);
    return ok;
}

#define MAKE_BLOB_ENCODER(impl, type)                                   \
    static OSSL_FUNC_encoder_import_object_fn                           \
    impl##2blob_import_object;                                          \
    static OSSL_FUNC_encoder_free_object_fn impl##2blob_free_object;    \
    static OSSL_FUNC_encoder_encode_fn impl##2blob_encode;              \
                                                                        \
    static void *impl##2blob_import_object(void *ctx, int selection,    \
                                           const OSSL_PARAM params[])   \
    {                                                                   \
        return ossl_prov_import_key(ossl_##impl##_keymgmt_functions,    \
                                    ctx, selection, params);            \
    }                                                                   \
    static void impl##2blob_free_object(void *key)                      \
    {                                                                   \
        ossl_prov_free_key(ossl_##impl##_keymgmt_functions, key);       \
    }                                                                   \
    static int impl##2blob_encode(void *vctx, OSSL_CORE_BIO *cout,      \
                                  const void *key,                      \
                                  const OSSL_PARAM key_abstract[],      \
                                  int selection,                        \
                                  OSSL_PASSPHRASE_CALLBACK *cb,         \
                                  void *cbarg)                          \
    {                                                                   \
        /* We don't deal with abstract objects */                       \
        if (key_abstract != NULL) {                                     \
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);     \
            return 0;                                                   \
        }                                                               \
        return key2blob_encode(vctx, key, selection, cout);             \
    }                                                                   \
    const OSSL_DISPATCH ossl_##impl##_to_blob_encoder_functions[] = {   \
        { OSSL_FUNC_ENCODER_NEWCTX,                                     \
          (void (*)(void))key2blob_newctx },                            \
        { OSSL_FUNC_ENCODER_FREECTX,                                    \
          (void (*)(void))key2blob_freectx },                           \
        { OSSL_FUNC_ENCODER_GETTABLE_PARAMS,                            \
          (void (*)(void))key2blob_gettable_params },                   \
        { OSSL_FUNC_ENCODER_GET_PARAMS,                                 \
          (void (*)(void))key2blob_get_params },                        \
        { OSSL_FUNC_ENCODER_DOES_SELECTION,                             \
          (void (*)(void))key2blob_does_selection },                    \
        { OSSL_FUNC_ENCODER_IMPORT_OBJECT,                              \
          (void (*)(void))impl##2blob_import_object },                  \
        { OSSL_FUNC_ENCODER_FREE_OBJECT,                                \
          (void (*)(void))impl##2blob_free_object },                    \
        { OSSL_FUNC_ENCODER_ENCODE,                                     \
          (void (*)(void))impl##2blob_encode },                         \
        { 0, NULL }                                                     \
    }

#ifndef OPENSSL_NO_EC
MAKE_BLOB_ENCODER(ec, ec);
# ifndef OPENSSL_NO_SM2
MAKE_BLOB_ENCODER(sm2, ec);
# endif
#endif
