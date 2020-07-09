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
#include <openssl/pem.h>
#include "prov/bio.h"
#include "prov/implementations.h"
#include "serializer_local.h"

static OSSL_FUNC_deserializer_newctx_fn pem2der_newctx;
static OSSL_FUNC_deserializer_freectx_fn pem2der_freectx;
static OSSL_FUNC_deserializer_gettable_params_fn pem2der_gettable_params;
static OSSL_FUNC_deserializer_get_params_fn pem2der_get_params;
static OSSL_FUNC_deserializer_deserialize_fn pem2der_deserialize;

static void *pem2der_newctx(void *provctx)
{
    return provctx;
}

static void pem2der_freectx(void *vctx)
{
}

static const OSSL_PARAM *pem2der_gettable_params(void)
{
    static const OSSL_PARAM gettables[] = {
        { OSSL_DESERIALIZER_PARAM_INPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        OSSL_PARAM_END,
    };

    return gettables;
}

static int pem2der_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DESERIALIZER_PARAM_INPUT_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "PEM"))
        return 0;

    return 1;
}

static int pem2der_deserialize(void *vctx, OSSL_CORE_BIO *cin,
                               OSSL_CALLBACK *data_cb, void *data_cbarg,
                               OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    PROV_CTX *ctx = vctx;
    char *pem_name = NULL, *pem_header = NULL;
    unsigned char *der = NULL;
    long der_len = 0;
    int ok = 0;

    if (ossl_prov_read_pem(ctx, cin, &pem_name, &pem_header,
                           &der, &der_len) <= 0)
        return 0;

#if 0                            /* PEM decryption coming soon */
    /*
     * 10 is the number of characters in "Proc-Type:", which
     * PEM_get_EVP_CIPHER_INFO() requires to be present.
     * If the PEM header has less characters than that, it's
     * not worth spending cycles on it.
     */
    if (strlen(*pem_header) > 10) {
        EVP_CIPHER_INFO cipher;
        struct pem_pass_data pass_data;

        if (!PEM_get_EVP_CIPHER_INFO(*pem_header, &cipher)
            || !file_fill_pem_pass_data(&pass_data, "PEM pass phrase", uri,
                                        ui_method, ui_data)
            || !PEM_do_header(&cipher, *data, len, file_get_pem_pass,
                              &pass_data))
            goto end;
    }
#endif

    {
        OSSL_PARAM params[3];

        params[0] =
            OSSL_PARAM_construct_utf8_string(OSSL_DESERIALIZER_PARAM_DATA_TYPE,
                                             pem_name, 0);
        params[1] =
            OSSL_PARAM_construct_octet_string(OSSL_DESERIALIZER_PARAM_DATA,
                                              der, der_len);
        params[2] = OSSL_PARAM_construct_end();

        ok = data_cb(params, data_cbarg);
    }

    OPENSSL_free(pem_name);
    OPENSSL_free(pem_header);
    OPENSSL_free(der);
    return ok;
}

const OSSL_DISPATCH pem_to_der_deserializer_functions[] = {
    { OSSL_FUNC_DESERIALIZER_NEWCTX, (void (*)(void))pem2der_newctx },
    { OSSL_FUNC_DESERIALIZER_FREECTX, (void (*)(void))pem2der_freectx },
    { OSSL_FUNC_DESERIALIZER_GETTABLE_PARAMS,
      (void (*)(void))pem2der_gettable_params },
    { OSSL_FUNC_DESERIALIZER_GET_PARAMS, (void (*)(void))pem2der_get_params },
    { OSSL_FUNC_DESERIALIZER_DESERIALIZE, (void (*)(void))pem2der_deserialize },
    { 0, NULL }
};
