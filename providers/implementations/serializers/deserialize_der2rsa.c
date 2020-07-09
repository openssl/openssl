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
static OSSL_FUNC_deserializer_deserialize_fn der2rsa_deserialize;
static OSSL_FUNC_deserializer_export_object_fn der2rsa_export_object;

/*
 * Context used for DER to RSA key deserialization.
 */
struct der2rsa_ctx_st {
    PROV_CTX *provctx;

#if 0
    struct pkcs8_encrypt_ctx_st sc;
#endif
};

static void *der2rsa_newctx(void *provctx)
{
    struct der2rsa_ctx_st *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        ctx->provctx = provctx;
    }
    return ctx;
}

static void der2rsa_freectx(void *vctx)
{
    struct der2rsa_ctx_st *ctx = vctx;

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
    EVP_PKEY *pkey = NULL;
    int ok = 0;

    if (!ossl_prov_read_der(ctx->provctx, cin, &der, &der_len))
        return 0;

    derp = der;
#if 0                            /* PKCS#8 decryption coming soon */
    X509_SIG *p8 = NULL;
    if ((p8 = d2i_X509_SIG(NULL, &derp, der_len)) != NULL) {
        const X509_ALGOR *dalg = NULL;
        const ASN1_OCTET_STRING *doct = NULL;
        unsigned char *new_data = NULL;
        int new_data_len;

        /* passphrase fetching code TBA */
        X509_SIG_get0(p8, &dalg, &doct);
        if (!PKCS12_pbe_crypt(dalg, pass, strlen(pass),
                              doct->data, doct->length,
                              &new_data, &new_data_len, 0))
            goto nop8;
        OPENSSL_free(der);
        der = new_data;
        der_len = new_data_len;
    }
    X509_SIG_free(p8);
 nop8:
#endif

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
    { OSSL_FUNC_DESERIALIZER_DESERIALIZE,
      (void (*)(void))der2rsa_deserialize },
    { OSSL_FUNC_DESERIALIZER_EXPORT_OBJECT,
      (void (*)(void))der2rsa_export_object },
    { 0, NULL }
};
