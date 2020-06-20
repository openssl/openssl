/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
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
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/types.h>
#include <openssl/params.h>
#include "prov/bio.h"
#include "prov/implementations.h"
#include "prov/providercommonerr.h"
#include "prov/provider_ctx.h"
#include "serializer_local.h"

static OSSL_FUNC_serializer_newctx_fn rsa_pub_newctx;
static OSSL_FUNC_serializer_freectx_fn rsa_pub_freectx;
static OSSL_FUNC_serializer_serialize_data_fn rsa_pub_der_data;
static OSSL_FUNC_serializer_serialize_object_fn rsa_pub_der;
static OSSL_FUNC_serializer_serialize_data_fn rsa_pub_pem_data;
static OSSL_FUNC_serializer_serialize_object_fn rsa_pub_pem;

static OSSL_FUNC_serializer_serialize_data_fn rsa_pub_print_data;
static OSSL_FUNC_serializer_serialize_object_fn rsa_pub_print;

/* Public key : context */

/*
 * There's no specific implementation context, so we use the provider context
 */
static void *rsa_pub_newctx(void *provctx)
{
    return provctx;
}

static void rsa_pub_freectx(void *ctx)
{
}

/* Public key : DER */
static int rsa_pub_der_data(void *ctx, const OSSL_PARAM params[],
                            OSSL_CORE_BIO *out,
                            OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    OSSL_FUNC_keymgmt_new_fn *rsa_new = ossl_prov_get_keymgmt_rsa_new();
    OSSL_FUNC_keymgmt_free_fn *rsa_free = ossl_prov_get_keymgmt_rsa_free();
    OSSL_FUNC_keymgmt_import_fn *rsa_import = ossl_prov_get_keymgmt_rsa_import();
    int ok = 0;

    if (rsa_import != NULL) {
        RSA *rsa;

        /* ctx == provctx */
        if ((rsa = rsa_new(ctx)) != NULL
            && rsa_import(rsa, OSSL_KEYMGMT_SELECT_KEYPAIR, params)
            && rsa_pub_der(ctx, rsa, out, cb, cbarg))
            ok = 1;
        rsa_free(rsa);
    }
    return ok;
}

static int rsa_pub_der(void *ctx, void *rsa, OSSL_CORE_BIO *cout,
                       OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    BIO *out = bio_new_from_core_bio(ctx, cout);
    int ret;

    if (out == NULL)
        return 0;

    ret = ossl_prov_write_pub_der_from_obj(out, rsa,
                                           ossl_prov_rsa_type_to_evp(rsa),
                                           ossl_prov_prepare_rsa_params,
                                           (i2d_of_void *)i2d_RSAPublicKey);
    BIO_free(out);

    return ret;
}

/* Public key : PEM */
static int rsa_pub_pem_data(void *ctx, const OSSL_PARAM params[],
                            OSSL_CORE_BIO *out,
                            OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    OSSL_FUNC_keymgmt_new_fn *rsa_new = ossl_prov_get_keymgmt_rsa_new();
    OSSL_FUNC_keymgmt_free_fn *rsa_free = ossl_prov_get_keymgmt_rsa_free();
    OSSL_FUNC_keymgmt_import_fn *rsa_import = ossl_prov_get_keymgmt_rsa_import();
    int ok = 0;

    if (rsa_import != NULL) {
        RSA *rsa;

        /* ctx == provctx */
        if ((rsa = rsa_new(ctx)) != NULL
            && rsa_import(rsa, OSSL_KEYMGMT_SELECT_KEYPAIR, params)
            && rsa_pub_pem(ctx, rsa, out, cb, cbarg))
            ok = 1;
        rsa_free(rsa);
    }
    return ok;
}

static int rsa_pub_pem(void *ctx, void *rsa, OSSL_CORE_BIO *cout,
                       OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    BIO *out = bio_new_from_core_bio(ctx, cout);
    int ret;

    if (out == NULL)
        return 0;

    ret = ossl_prov_write_pub_pem_from_obj(out, rsa,
                                           ossl_prov_rsa_type_to_evp(rsa),
                                           ossl_prov_prepare_rsa_params,
                                           (i2d_of_void *)i2d_RSAPublicKey);
    BIO_free(out);

    return ret;
}

static int rsa_pub_print_data(void *ctx, const OSSL_PARAM params[],
                              OSSL_CORE_BIO *out,
                              OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    OSSL_FUNC_keymgmt_new_fn *rsa_new = ossl_prov_get_keymgmt_rsa_new();
    OSSL_FUNC_keymgmt_free_fn *rsa_free = ossl_prov_get_keymgmt_rsa_free();
    OSSL_FUNC_keymgmt_import_fn *rsa_import = ossl_prov_get_keymgmt_rsa_import();
    int ok = 0;

    if (rsa_import != NULL) {
        RSA *rsa;

        /* ctx == provctx */
        if ((rsa = rsa_new(ctx)) != NULL
            && rsa_import(rsa, OSSL_KEYMGMT_SELECT_KEYPAIR, params)
            && rsa_pub_print(ctx, rsa, out, cb, cbarg))
            ok = 1;
        rsa_free(rsa);
    }
    return ok;
}

static int rsa_pub_print(void *ctx, void *rsa, OSSL_CORE_BIO *cout,
                         OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    BIO *out = bio_new_from_core_bio(ctx, cout);
    int ret;

    if (out == NULL)
        return 0;

    ret = ossl_prov_print_rsa(out, rsa, 0);
    BIO_free(out);

    return ret;
}

const OSSL_DISPATCH rsa_pub_der_serializer_functions[] = {
    { OSSL_FUNC_SERIALIZER_NEWCTX, (void (*)(void))rsa_pub_newctx },
    { OSSL_FUNC_SERIALIZER_FREECTX, (void (*)(void))rsa_pub_freectx },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_DATA, (void (*)(void))rsa_pub_der_data },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))rsa_pub_der },
    { 0, NULL }
};

const OSSL_DISPATCH rsa_pub_pem_serializer_functions[] = {
    { OSSL_FUNC_SERIALIZER_NEWCTX, (void (*)(void))rsa_pub_newctx },
    { OSSL_FUNC_SERIALIZER_FREECTX, (void (*)(void))rsa_pub_freectx },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_DATA, (void (*)(void))rsa_pub_pem_data },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))rsa_pub_pem },
    { 0, NULL }
};

const OSSL_DISPATCH rsa_pub_text_serializer_functions[] = {
    { OSSL_FUNC_SERIALIZER_NEWCTX, (void (*)(void))rsa_pub_newctx },
    { OSSL_FUNC_SERIALIZER_FREECTX, (void (*)(void))rsa_pub_freectx },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))rsa_pub_print },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_DATA,
      (void (*)(void))rsa_pub_print_data },
    { 0, NULL }
};
