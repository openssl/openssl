/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_numbers.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/dh.h>
#include <openssl/types.h>
#include <openssl/params.h>
#include "prov/bio.h"
#include "prov/implementations.h"
#include "serializer_local.h"

static OSSL_OP_serializer_newctx_fn dh_pub_newctx;
static OSSL_OP_serializer_freectx_fn dh_pub_freectx;
static OSSL_OP_serializer_serialize_data_fn dh_pub_der_data;
static OSSL_OP_serializer_serialize_object_fn dh_pub_der;
static OSSL_OP_serializer_serialize_data_fn dh_pub_pem_data;
static OSSL_OP_serializer_serialize_object_fn dh_pub_pem;

static OSSL_OP_serializer_serialize_data_fn dh_pub_print_data;
static OSSL_OP_serializer_serialize_object_fn dh_pub_print;

/* Public key : context */

/*
 * There's no specific implementation context, so we use the provider context
 */
static void *dh_pub_newctx(void *provctx)
{
    return provctx;
}

static void dh_pub_freectx(void *ctx)
{
}

/* Public key : DER */
static int dh_pub_der_data(void *ctx, const OSSL_PARAM params[], BIO *out,
                            OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    OSSL_OP_keymgmt_new_fn *dh_new = ossl_prov_get_keymgmt_dh_new();
    OSSL_OP_keymgmt_free_fn *dh_free = ossl_prov_get_keymgmt_dh_free();
    OSSL_OP_keymgmt_import_fn *dh_import = ossl_prov_get_keymgmt_dh_import();
    int ok = 0;

    if (dh_import != NULL) {
        DH *dh;

        /* ctx == provctx */
        if ((dh = dh_new(ctx)) != NULL
            && dh_import(dh, OSSL_KEYMGMT_SELECT_KEYPAIR, params)
            && dh_pub_der(ctx, dh, out, cb, cbarg))
            ok = 1;
        dh_free(dh);
    }
    return ok;
}

static int dh_pub_der(void *ctx, void *dh, BIO *out,
                       OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return ossl_prov_write_pub_der_from_obj(out, dh, EVP_PKEY_DH,
                                            ossl_prov_prepare_dh_params,
                                            ossl_prov_dh_pub_to_der);
}

/* Public key : PEM */
static int dh_pub_pem_data(void *ctx, const OSSL_PARAM params[], BIO *out,
                            OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    OSSL_OP_keymgmt_new_fn *dh_new = ossl_prov_get_keymgmt_dh_new();
    OSSL_OP_keymgmt_free_fn *dh_free = ossl_prov_get_keymgmt_dh_free();
    OSSL_OP_keymgmt_import_fn *dh_import = ossl_prov_get_keymgmt_dh_import();
    int ok = 0;

    if (dh_import != NULL) {
        DH *dh;

        /* ctx == provctx */
        if ((dh = dh_new(ctx)) != NULL
            && dh_import(dh, OSSL_KEYMGMT_SELECT_KEYPAIR, params)
            && dh_pub_pem(ctx, dh, out, cb, cbarg))
            ok = 1;
        dh_free(dh);
    }
    return ok;
}

static int dh_pub_pem(void *ctx, void *dh, BIO *out,
                       OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return ossl_prov_write_pub_pem_from_obj(out, dh, EVP_PKEY_DH,
                                            ossl_prov_prepare_dh_params,
                                            ossl_prov_dh_pub_to_der);

}

static int dh_pub_print_data(void *ctx, const OSSL_PARAM params[], BIO *out,
                              OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    OSSL_OP_keymgmt_new_fn *dh_new = ossl_prov_get_keymgmt_dh_new();
    OSSL_OP_keymgmt_free_fn *dh_free = ossl_prov_get_keymgmt_dh_free();
    OSSL_OP_keymgmt_import_fn *dh_import = ossl_prov_get_keymgmt_dh_import();
    int ok = 0;

    if (dh_import != NULL) {
        DH *dh;

        /* ctx == provctx */
        if ((dh = dh_new(ctx)) != NULL
            && dh_import(dh, OSSL_KEYMGMT_SELECT_KEYPAIR, params)
            && dh_pub_print(ctx, dh, out, cb, cbarg))
            ok = 1;
        dh_free(dh);
    }
    return ok;
}

static int dh_pub_print(void *ctx, void *dh, BIO *out,
                         OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return ossl_prov_print_dh(out, dh, 0);
}

const OSSL_DISPATCH dh_pub_der_serializer_functions[] = {
    { OSSL_FUNC_SERIALIZER_NEWCTX, (void (*)(void))dh_pub_newctx },
    { OSSL_FUNC_SERIALIZER_FREECTX, (void (*)(void))dh_pub_freectx },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_DATA, (void (*)(void))dh_pub_der_data },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))dh_pub_der },
    { 0, NULL }
};

const OSSL_DISPATCH dh_pub_pem_serializer_functions[] = {
    { OSSL_FUNC_SERIALIZER_NEWCTX, (void (*)(void))dh_pub_newctx },
    { OSSL_FUNC_SERIALIZER_FREECTX, (void (*)(void))dh_pub_freectx },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_DATA, (void (*)(void))dh_pub_pem_data },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))dh_pub_pem },
    { 0, NULL }
};

const OSSL_DISPATCH dh_pub_text_serializer_functions[] = {
    { OSSL_FUNC_SERIALIZER_NEWCTX, (void (*)(void))dh_pub_newctx },
    { OSSL_FUNC_SERIALIZER_FREECTX, (void (*)(void))dh_pub_freectx },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))dh_pub_print },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_DATA,
      (void (*)(void))dh_pub_print_data },
    { 0, NULL }
};
