/*
 * Copyright 1999-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/pkcs12.h>
#include <openssl/bn.h>
#include <openssl/trace.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include "internal/provider.h"

int PKCS12_key_gen_asc(const char *pass, int passlen, unsigned char *salt,
                       int saltlen, int id, int iter, int n,
                       unsigned char *out, const EVP_MD *md_type)
{
    int ret;
    unsigned char *unipass;
    int uniplen;

    if (pass == NULL) {
        unipass = NULL;
        uniplen = 0;
    } else if (!OPENSSL_asc2uni(pass, passlen, &unipass, &uniplen)) {
        ERR_raise(ERR_LIB_PKCS12, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ret = PKCS12_key_gen_uni(unipass, uniplen, salt, saltlen,
                             id, iter, n, out, md_type);
    OPENSSL_clear_free(unipass, uniplen);
    return ret > 0;
}

int PKCS12_key_gen_utf8(const char *pass, int passlen, unsigned char *salt,
                        int saltlen, int id, int iter, int n,
                        unsigned char *out, const EVP_MD *md_type)
{
    int ret;
    unsigned char *unipass;
    int uniplen;

    if (pass == NULL) {
        unipass = NULL;
        uniplen = 0;
    } else if (!OPENSSL_utf82uni(pass, passlen, &unipass, &uniplen)) {
        ERR_raise(ERR_LIB_PKCS12, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    ret = PKCS12_key_gen_uni(unipass, uniplen, salt, saltlen,
                             id, iter, n, out, md_type);
    OPENSSL_clear_free(unipass, uniplen);
    return ret > 0;
}

int PKCS12_key_gen_uni(unsigned char *pass, int passlen, unsigned char *salt,
                       int saltlen, int id, int iter, int n,
                       unsigned char *out, const EVP_MD *md_type)
{
    OSSL_PARAM params[6], *p = params;

    /* Construct the KDF params */
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            (char *)EVP_MD_name(md_type), 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                             pass, passlen);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                             salt, saltlen);
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_PKCS12_ID, &id);
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_ITER, &iter);
    *p = OSSL_PARAM_construct_end();

    OSSL_TRACE_BEGIN(PKCS12_KEYGEN) {
        BIO_printf(trc_out, "PKCS12_key_gen_uni(): ID %d, ITER %d\n", id, iter);
        BIO_printf(trc_out, "Password (length %d):\n", passlen);
        BIO_hex_string(trc_out, 0, passlen, pass, passlen);
        BIO_printf(trc_out, "\n");
        BIO_printf(trc_out, "Salt (length %d):\n", saltlen);
        BIO_hex_string(trc_out, 0, saltlen, salt, saltlen);
        BIO_printf(trc_out, "\n");
    } OSSL_TRACE_END(PKCS12_KEYGEN);

    /*
     * The parameter query isn't available but the library context can be
     * extracted from the passed digest.
     */
    return PKCS12_key_gen_ex(out, n, params, ossl_provider_libctx(EVP_MD_provider(md_type)), NULL);
}

int PKCS12_key_gen_ex(unsigned char *out, size_t outlen, OSSL_PARAM params[],
                      OSSL_LIB_CTX *ctx, const char *propq)
{
    int res = 0;
    EVP_KDF *kdf;
    EVP_KDF_CTX *kdf_ctx;

    if (outlen <= 0)
        return 0;

    kdf = EVP_KDF_fetch(ctx, "PKCS12KDF", propq);
    if (kdf == NULL)
        return 0;

    kdf_ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (kdf_ctx == NULL)
        return 0;

    if (!EVP_KDF_CTX_set_params(kdf_ctx, params))
        goto err;

    if (EVP_KDF_derive(kdf_ctx, out, outlen)) {
        res = 1;
        OSSL_TRACE_BEGIN(PKCS12_KEYGEN) {
            BIO_printf(trc_out, "Output KEY (length %d)\n", outlen);
            BIO_hex_string(trc_out, 0, outlen, out, outlen);
            BIO_printf(trc_out, "\n");
        } OSSL_TRACE_END(PKCS12_KEYGEN);
    }
 err:
    EVP_KDF_CTX_free(kdf_ctx);
    return res;
}
