/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/buffer.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/dh.h>
#include <openssl/store.h>
#include <openssl/ui.h>
#include <openssl/serializer.h>
#include "crypto/store.h"
#include "crypto/asn1.h"
#include "crypto/evp.h"
#include "pem_local.h"

int pem_check_suffix(const char *pem_str, const char *suffix);

EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb,
                                  void *u)
{
    EVP_PKEY *ret = NULL;
    OSSL_STORE_CTX *ctx = NULL;
    OSSL_STORE_INFO *info = NULL;
    UI_METHOD *ui_method = NULL;

    if ((ui_method = UI_UTIL_wrap_read_pem_callback(cb, 0)) == NULL)
        return NULL;

    if ((ctx = ossl_store_attach_pem_bio(bp, ui_method, u)) == NULL)
        goto err;
#ifndef OPENSSL_NO_SECURE_HEAP
    {
        int on = 1;
        if (!OSSL_STORE_ctrl(ctx, OSSL_STORE_C_USE_SECMEM, &on))
            goto err;
    }
#endif

    while (!OSSL_STORE_eof(ctx) && (info = OSSL_STORE_load(ctx)) != NULL) {
        if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY) {
            ret = OSSL_STORE_INFO_get1_PKEY(info);
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

    if (ret != NULL && x != NULL)
        *x = ret;

 err:
    ossl_store_detach_pem_bio(ctx);
    UI_destroy_method(ui_method);
    OSSL_STORE_INFO_free(info);
    return ret;
}

PEM_write_cb_fnsig(PrivateKey, EVP_PKEY, BIO, write_bio)
{
    IMPLEMENT_PEM_provided_write_body_vars(EVP_PKEY, PrivateKey);

    IMPLEMENT_PEM_provided_write_body_pass();
    IMPLEMENT_PEM_provided_write_body_main(EVP_PKEY, bio);

 legacy:
    if (x->ameth == NULL || x->ameth->priv_encode != NULL)
        return PEM_write_bio_PKCS8PrivateKey(out, x, enc,
                                             (const char *)kstr, klen, cb, u);
    return PEM_write_bio_PrivateKey_traditional(out, x, enc, kstr, klen, cb, u);
}

int PEM_write_bio_PrivateKey_traditional(BIO *bp, const EVP_PKEY *x,
                                         const EVP_CIPHER *enc,
                                         const unsigned char *kstr, int klen,
                                         pem_password_cb *cb, void *u)
{
    char pem_str[80];
    BIO_snprintf(pem_str, 80, "%s PRIVATE KEY", x->ameth->pem_str);
    return PEM_ASN1_write_bio((i2d_of_void *)i2d_PrivateKey,
                              pem_str, bp, x, enc, kstr, klen, cb, u);
}

EVP_PKEY *PEM_read_bio_Parameters(BIO *bp, EVP_PKEY **x)
{
    EVP_PKEY *ret = NULL;
    OSSL_STORE_CTX *ctx = NULL;
    OSSL_STORE_INFO *info = NULL;

    if ((ctx = ossl_store_attach_pem_bio(bp, UI_null(), NULL)) == NULL)
        goto err;

    while (!OSSL_STORE_eof(ctx) && (info = OSSL_STORE_load(ctx)) != NULL) {
        if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PARAMS) {
            ret = OSSL_STORE_INFO_get1_PARAMS(info);
            break;
        }
        OSSL_STORE_INFO_free(info);
    }

    if (ret != NULL && x != NULL)
        *x = ret;

 err:
    ossl_store_detach_pem_bio(ctx);
    OSSL_STORE_INFO_free(info);
    return ret;
}

PEM_write_fnsig(Parameters, EVP_PKEY, BIO, write_bio)
{
    char pem_str[80];
    IMPLEMENT_PEM_provided_write_body_vars(EVP_PKEY, Parameters);

    IMPLEMENT_PEM_provided_write_body_main(EVP_PKEY, bio);

 legacy:
    if (!x->ameth || !x->ameth->param_encode)
        return 0;

    BIO_snprintf(pem_str, 80, "%s PARAMETERS", x->ameth->pem_str);
    return PEM_ASN1_write_bio((i2d_of_void *)x->ameth->param_encode,
                              pem_str, out, x, NULL, NULL, 0, 0, NULL);
}

#ifndef OPENSSL_NO_STDIO
EVP_PKEY *PEM_read_PrivateKey(FILE *fp, EVP_PKEY **x, pem_password_cb *cb,
                              void *u)
{
    BIO *b;
    EVP_PKEY *ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        PEMerr(PEM_F_PEM_READ_PRIVATEKEY, ERR_R_BUF_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = PEM_read_bio_PrivateKey(b, x, cb, u);
    BIO_free(b);
    return ret;
}

int PEM_write_PrivateKey(FILE *fp, const EVP_PKEY *x, const EVP_CIPHER *enc,
                         const unsigned char *kstr, int klen,
                         pem_password_cb *cb, void *u)
{
    BIO *b;
    int ret;

    if ((b = BIO_new_fp(fp, BIO_NOCLOSE)) == NULL) {
        PEMerr(PEM_F_PEM_WRITE_PRIVATEKEY, ERR_R_BUF_LIB);
        return 0;
    }
    ret = PEM_write_bio_PrivateKey(b, x, enc, kstr, klen, cb, u);
    BIO_free(b);
    return ret;
}

#endif

#ifndef OPENSSL_NO_DH

/* Transparently read in PKCS#3 or X9.42 DH parameters */

DH *PEM_read_bio_DHparams(BIO *bp, DH **x, pem_password_cb *cb, void *u)
{
    DH *ret = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_STORE_CTX *ctx = NULL;
    OSSL_STORE_INFO *info = NULL;
    UI_METHOD *ui_method = NULL;

    if ((ui_method = UI_UTIL_wrap_read_pem_callback(cb, 0)) == NULL)
        return NULL;

    if ((ctx = ossl_store_attach_pem_bio(bp, ui_method, u)) == NULL)
        goto err;

    while (!OSSL_STORE_eof(ctx) && (info = OSSL_STORE_load(ctx)) != NULL) {
        if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PARAMS) {
            pkey = OSSL_STORE_INFO_get0_PARAMS(info);
            if (EVP_PKEY_id(pkey) == EVP_PKEY_DHX
                || EVP_PKEY_id(pkey) == EVP_PKEY_DH) {
                ret = EVP_PKEY_get1_DH(pkey);
                break;
            }
        }
        OSSL_STORE_INFO_free(info);
    }

    if (ret != NULL && x != NULL)
        *x = ret;

 err:
    ossl_store_detach_pem_bio(ctx);
    UI_destroy_method(ui_method);
    OSSL_STORE_INFO_free(info);
    return ret;
}

# ifndef OPENSSL_NO_STDIO
DH *PEM_read_DHparams(FILE *fp, DH **x, pem_password_cb *cb, void *u)
{
    BIO *b;
    DH *ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        PEMerr(PEM_F_PEM_READ_DHPARAMS, ERR_R_BUF_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = PEM_read_bio_DHparams(b, x, cb, u);
    BIO_free(b);
    return ret;
}
# endif

#endif
