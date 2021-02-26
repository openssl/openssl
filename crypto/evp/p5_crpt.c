/*
 * Copyright 1999-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include "internal/cryptlib.h"
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/kdf.h>

#define PKCS5_PBES1_OUTPUT_LENGTH   16
#define PKCS5_PBES1_KEY_IV_LENGTH   8

/*
 * Doesn't do anything now: Builtin PBE algorithms in static table.
 */

void PKCS5_PBE_add(void)
{
}

int PKCS5_PBE_keyivgen(EVP_CIPHER_CTX *cctx, const char *pass, int passlen,
                       ASN1_TYPE *param, const EVP_CIPHER *cipher,
                       const EVP_MD *md, int en_de)
{
    unsigned char out[PKCS5_PBES1_OUTPUT_LENGTH];
    int ivl, kl;
    PBEPARAM *pbe = NULL;
    int saltlen, iter;
    unsigned char *salt;
    int rv = 0;
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[5], *p = params;
    const char *mdname = EVP_MD_name(md);

    /* Extract useful info from parameter */
    if (param == NULL || param->type != V_ASN1_SEQUENCE ||
        param->value.sequence == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR);
        return 0;
    }

    pbe = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBEPARAM), param);
    if (pbe == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR);
        return 0;
    }

    ivl = EVP_CIPHER_iv_length(cipher);
    if (ivl != PKCS5_PBES1_KEY_IV_LENGTH) {
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_IV_LENGTH);
        goto err;
    }
    kl = EVP_CIPHER_key_length(cipher);
    if (kl != PKCS5_PBES1_KEY_IV_LENGTH) {
        ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY_LENGTH);
        goto err;
    }

    if (pbe->iter == NULL)
        iter = 1;
    else
        iter = ASN1_INTEGER_get(pbe->iter);
    salt = pbe->salt->data;
    saltlen = pbe->salt->length;

    if (pass == NULL)
        passlen = 0;
    else if (passlen == -1)
        passlen = strlen(pass);

    kdf = EVP_KDF_fetch(NULL, OSSL_KDF_NAME_PBKDF1, NULL);
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (kctx == NULL)
        goto err;
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                             (char *)pass, (size_t)passlen);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                             salt, saltlen);
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_ITER, &iter);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            (char *)mdname, 0);
    *p = OSSL_PARAM_construct_end();
    if (EVP_KDF_derive(kctx, out, PKCS5_PBES1_OUTPUT_LENGTH, params) != 1)
        goto err;

    if (!EVP_CipherInit_ex(cctx, cipher, NULL, out,
                           out + PKCS5_PBES1_KEY_IV_LENGTH, en_de))
        goto err;
    OPENSSL_cleanse(out, PKCS5_PBES1_OUTPUT_LENGTH);
    rv = 1;
 err:
    EVP_KDF_CTX_free(kctx);
    PBEPARAM_free(pbe);
    return rv;
}
