/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_numbers.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/types.h>
#include <openssl/params.h>
#include "prov/bio.h"
#include "prov/implementations.h"
#include "prov/providercommonerr.h"
#include "prov/provider_ctx.h"
#include "serializer_local.h"

static OSSL_OP_serializer_newctx_fn ec_param_newctx;
static OSSL_OP_serializer_freectx_fn ec_param_freectx;
static OSSL_OP_serializer_serialize_data_fn ec_param_der_data;
static OSSL_OP_serializer_serialize_object_fn ec_param_der;
static OSSL_OP_serializer_serialize_data_fn ec_param_pem_data;
static OSSL_OP_serializer_serialize_object_fn ec_param_pem;

static OSSL_OP_serializer_serialize_data_fn ec_param_print_data;
static OSSL_OP_serializer_serialize_object_fn ec_param_print;


/* There is no specific implementation context, so use the provider context */
static void *ec_param_newctx(void *provctx)
{
    return provctx;
}

static void ec_param_freectx(void *vctx)
{
}

/* Public key : DER */
static int ec_param_der_data(void *vctx, const OSSL_PARAM params[],
                             OSSL_CORE_BIO *out,
                             OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    OSSL_OP_keymgmt_new_fn *ec_new;
    OSSL_OP_keymgmt_free_fn *ec_free;
    OSSL_OP_keymgmt_import_fn *ec_import;
    int ok = 0;

    ec_get_new_free_import(&ec_new, &ec_free, &ec_import);

    if (ec_import != NULL) {
        EC_KEY *eckey;

        /* vctx == provctx */
        if ((eckey = ec_new(vctx)) != NULL
            && ec_import(eckey, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, params)
            && ec_param_der(vctx, eckey, out, cb, cbarg))
            ok = 1;
        ec_free(eckey);
    }
    return ok;
}

static int ec_param_der(void *vctx, void *eckey, OSSL_CORE_BIO *cout,
                         OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    BIO *out = bio_new_from_core_bio(vctx, cout);
    int ret;

    if (out == NULL)
        return 0;

    ret = i2d_ECPKParameters_bio(out, EC_KEY_get0_group(eckey));
    BIO_free(out);

    return ret;
}

/* Public key : PEM */
static int ec_param_pem_data(void *vctx, const OSSL_PARAM params[],
                             OSSL_CORE_BIO *out,
                             OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    OSSL_OP_keymgmt_new_fn *ec_new;
    OSSL_OP_keymgmt_free_fn *ec_free;
    OSSL_OP_keymgmt_import_fn *ec_import;
    int ok = 0;

    ec_get_new_free_import(&ec_new, &ec_free, &ec_import);

    if (ec_import != NULL) {
        EC_KEY *eckey;

        /* vctx == provctx */
        if ((eckey = ec_new(vctx)) != NULL
            && ec_import(eckey, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, params)
            && ec_param_pem(vctx, eckey, out, cb, cbarg))
            ok = 1;
        ec_free(eckey);
    }
    return ok;
}

static int ec_param_pem(void *vctx, void *eckey, OSSL_CORE_BIO *cout,
                         OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    BIO *out = bio_new_from_core_bio(vctx, cout);
    int ret;

    if (out == NULL)
        return 0;

    ret = PEM_write_bio_ECPKParameters(out, EC_KEY_get0_group(eckey));
    BIO_free(out);

    return ret;
}

static int ec_param_print_data(void *vctx, const OSSL_PARAM params[],
                               OSSL_CORE_BIO *out,
                               OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    OSSL_OP_keymgmt_new_fn *ec_new;
    OSSL_OP_keymgmt_free_fn *ec_free;
    OSSL_OP_keymgmt_import_fn *ec_import;
    int ok = 0;

    ec_get_new_free_import(&ec_new, &ec_free, &ec_import);

    if (ec_import != NULL) {
        EC_KEY *eckey;

        /* vctx == provctx */
        if ((eckey = ec_new(vctx)) != NULL
            && ec_import(eckey, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, params)
            && ec_param_print(vctx, eckey, out, cb, cbarg))
            ok = 1;
        ec_free(eckey);
    }
    return ok;
}

static int ec_param_print(void *vctx, void *eckey, OSSL_CORE_BIO *cout,
                           OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    BIO *out = bio_new_from_core_bio(vctx, cout);
    int ret;

    if (out == NULL)
        return 0;

    ret = ossl_prov_print_eckey(out, eckey, ec_print_params);
    BIO_free(out);

    return ret;
}

const OSSL_DISPATCH ec_param_der_serializer_functions[] = {
    { OSSL_FUNC_SERIALIZER_NEWCTX, (void (*)(void))ec_param_newctx },
    { OSSL_FUNC_SERIALIZER_FREECTX, (void (*)(void))ec_param_freectx },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_DATA, (void (*)(void))ec_param_der_data },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))ec_param_der },
    { 0, NULL }
};

const OSSL_DISPATCH ec_param_pem_serializer_functions[] = {
    { OSSL_FUNC_SERIALIZER_NEWCTX, (void (*)(void))ec_param_newctx },
    { OSSL_FUNC_SERIALIZER_FREECTX, (void (*)(void))ec_param_freectx },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_DATA, (void (*)(void))ec_param_pem_data },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))ec_param_pem },
    { 0, NULL }
};

const OSSL_DISPATCH ec_param_text_serializer_functions[] = {
    { OSSL_FUNC_SERIALIZER_NEWCTX, (void (*)(void))ec_param_newctx },
    { OSSL_FUNC_SERIALIZER_FREECTX, (void (*)(void))ec_param_freectx },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))ec_param_print },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_DATA,
      (void (*)(void))ec_param_print_data },
    { 0, NULL }
};
