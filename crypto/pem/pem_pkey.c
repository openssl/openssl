/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* We need to use some deprecated APIs */
#define OPENSSL_SUPPRESS_DEPRECATED

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
#include <openssl/decoder.h>
#include <openssl/ui.h>
#include "crypto/asn1.h"
#include "crypto/evp.h"
#include "pem_local.h"

int ossl_pem_check_suffix(const char *pem_str, const char *suffix);

static EVP_PKEY *pem_read_bio_key(BIO *bp, EVP_PKEY **x,
                                  pem_password_cb *cb, void *u,
                                  OSSL_LIB_CTX *libctx, const char *propq,
                                  int selection)
{
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *dctx = NULL;

    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", NULL, NULL,
                                         selection, libctx, propq);

    if (dctx == NULL)
        return NULL;

    if (cb == NULL)
        cb = PEM_def_callback;

    if (!OSSL_DECODER_CTX_set_pem_password_cb(dctx, cb, u))
        goto err;

    while (!OSSL_DECODER_from_bio(dctx, bp) || pkey == NULL)
        if (BIO_eof(bp) != 0)
            goto err;

    if (!evp_keymgmt_util_has(pkey, selection)) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
        ERR_raise(ERR_LIB_PEM, PEM_R_UNSUPPORTED_KEY_COMPONENTS);
        goto err;
    }

    if (x != NULL) {
        EVP_PKEY_free(*x);
        *x = pkey;
    }

 err:
    OSSL_DECODER_CTX_free(dctx);
    return pkey;
}

EVP_PKEY *PEM_read_bio_PUBKEY_ex(BIO *bp, EVP_PKEY **x,
                                 pem_password_cb *cb, void *u,
                                 OSSL_LIB_CTX *libctx, const char *propq)
{
    return pem_read_bio_key(bp, x, cb, u, libctx, propq,
                            EVP_PKEY_PUBLIC_KEY);
}

EVP_PKEY *PEM_read_bio_PUBKEY(BIO *bp, EVP_PKEY **x, pem_password_cb *cb,
                              void *u)
{
    return PEM_read_bio_PUBKEY_ex(bp, x, cb, u, NULL, NULL);
}

#ifndef OPENSSL_NO_STDIO
EVP_PKEY *PEM_read_PUBKEY_ex(FILE *fp, EVP_PKEY **x,
                             pem_password_cb *cb, void *u,
                             OSSL_LIB_CTX *libctx, const char *propq)
{
    BIO *b;
    EVP_PKEY *ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        ERR_raise(ERR_LIB_PEM, ERR_R_BUF_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = PEM_read_bio_PUBKEY_ex(b, x, cb, u, libctx, propq);
    BIO_free(b);
    return ret;
}

EVP_PKEY *PEM_read_PUBKEY(FILE *fp, EVP_PKEY **x, pem_password_cb *cb, void *u)
{
    return PEM_read_PUBKEY_ex(fp, x, cb, u, NULL, NULL);
}
#endif

EVP_PKEY *PEM_read_bio_PrivateKey_ex(BIO *bp, EVP_PKEY **x,
                                     pem_password_cb *cb, void *u,
                                     OSSL_LIB_CTX *libctx, const char *propq)
{
    return pem_read_bio_key(bp, x, cb, u, libctx, propq,
                            EVP_PKEY_KEYPAIR);
}

EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb,
                                  void *u)
{
    return PEM_read_bio_PrivateKey_ex(bp, x, cb, u, NULL, NULL);
}

PEM_write_cb_ex_fnsig(PrivateKey, EVP_PKEY, BIO, write_bio)
{
    IMPLEMENT_PEM_provided_write_body_vars(pkey, PrivateKey, propq);

    IMPLEMENT_PEM_provided_write_body_pass();
    IMPLEMENT_PEM_provided_write_body_main(pkey, bio);

 legacy:
    if (x->ameth == NULL || x->ameth->priv_encode != NULL)
        return PEM_write_bio_PKCS8PrivateKey(out, x, enc,
                                             (const char *)kstr, klen, cb, u);
    return PEM_write_bio_PrivateKey_traditional(out, x, enc, kstr, klen, cb, u);
}

PEM_write_cb_fnsig(PrivateKey, EVP_PKEY, BIO, write_bio)
{
    return PEM_write_bio_PrivateKey_ex(out, x, enc, kstr, klen, cb, u,
                                       NULL, NULL);
}

/*
 * Note: there is no way to tell a provided pkey encoder to use "traditional"
 * encoding.  Therefore, if the pkey is provided, we try to take a copy 
 * TODO: when #legacy keys are gone, this function will not be possible any
 * more and should be removed.
 */
int PEM_write_bio_PrivateKey_traditional(BIO *bp, const EVP_PKEY *x,
                                         const EVP_CIPHER *enc,
                                         const unsigned char *kstr, int klen,
                                         pem_password_cb *cb, void *u)
{
    char pem_str[80];
    EVP_PKEY *copy = NULL;
    int ret;

    if (evp_pkey_is_assigned(x)
        && evp_pkey_is_provided(x)
        && evp_pkey_copy_downgraded(&copy, x))
        x = copy;

    if (x->ameth == NULL || x->ameth->old_priv_encode == NULL) {
        ERR_raise(ERR_LIB_PEM, PEM_R_UNSUPPORTED_PUBLIC_KEY_TYPE);
        return 0;
    }
    BIO_snprintf(pem_str, 80, "%s PRIVATE KEY", x->ameth->pem_str);
    ret = PEM_ASN1_write_bio((i2d_of_void *)i2d_PrivateKey,
                             pem_str, bp, x, enc, kstr, klen, cb, u);

    EVP_PKEY_free(copy);
    return ret;
}

EVP_PKEY *PEM_read_bio_Parameters_ex(BIO *bp, EVP_PKEY **x,
                                     OSSL_LIB_CTX *libctx, const char *propq)
{
    return pem_read_bio_key(bp, x, NULL, NULL, libctx, propq,
                            EVP_PKEY_KEY_PARAMETERS);
}

EVP_PKEY *PEM_read_bio_Parameters(BIO *bp, EVP_PKEY **x)
{
    return PEM_read_bio_Parameters_ex(bp, x, NULL, NULL);
}

PEM_write_fnsig(Parameters, EVP_PKEY, BIO, write_bio)
{
    char pem_str[80];
    IMPLEMENT_PEM_provided_write_body_vars(pkey, Parameters, NULL);

    IMPLEMENT_PEM_provided_write_body_main(pkey, bio);

 legacy:
    if (!x->ameth || !x->ameth->param_encode)
        return 0;

    BIO_snprintf(pem_str, 80, "%s PARAMETERS", x->ameth->pem_str);
    return PEM_ASN1_write_bio((i2d_of_void *)x->ameth->param_encode,
                              pem_str, out, x, NULL, NULL, 0, 0, NULL);
}

#ifndef OPENSSL_NO_STDIO
EVP_PKEY *PEM_read_PrivateKey_ex(FILE *fp, EVP_PKEY **x, pem_password_cb *cb,
                                 void *u, OSSL_LIB_CTX *libctx,
                                 const char *propq)
{
    BIO *b;
    EVP_PKEY *ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        ERR_raise(ERR_LIB_PEM, ERR_R_BUF_LIB);
        return 0;
    }
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    ret = PEM_read_bio_PrivateKey_ex(b, x, cb, u, libctx, propq);
    BIO_free(b);
    return ret;
}

EVP_PKEY *PEM_read_PrivateKey(FILE *fp, EVP_PKEY **x, pem_password_cb *cb,
                              void *u)
{
    return PEM_read_PrivateKey_ex(fp, x, cb, u, NULL, NULL);
}

PEM_write_cb_ex_fnsig(PrivateKey, EVP_PKEY, FILE, write)
{
    BIO *b;
    int ret;

    if ((b = BIO_new_fp(out, BIO_NOCLOSE)) == NULL) {
        ERR_raise(ERR_LIB_PEM, ERR_R_BUF_LIB);
        return 0;
    }
    ret = PEM_write_bio_PrivateKey_ex(b, x, enc, kstr, klen, cb, u,
                                      libctx, propq);
    BIO_free(b);
    return ret;
}

PEM_write_cb_fnsig(PrivateKey, EVP_PKEY, FILE, write)
{
    return PEM_write_PrivateKey_ex(out, x, enc, kstr, klen, cb, u, NULL, NULL);
}
#endif
