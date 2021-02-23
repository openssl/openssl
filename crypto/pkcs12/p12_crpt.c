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
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/pkcs12.h>

/* PKCS#12 PBE algorithms now in static table */

void PKCS12_PBE_add(void)
{
}

int PKCS12_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
                        ASN1_TYPE *param, const EVP_CIPHER *cipher,
                        const EVP_MD *md, int en_de)
{
    PBEPARAM *pbe;
    int saltlen, iter, ret;
    unsigned char *salt;
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    int (*pkcs12_key_gen)(const char *pass, int passlen,
                          unsigned char *salt, int slen,
                          int id, int iter, int n,
                          unsigned char *out,
                          const EVP_MD *md_type);

    pkcs12_key_gen = PKCS12_key_gen_utf8;

    if (cipher == NULL)
        return 0;

    /* Extract useful info from parameter */

    pbe = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBEPARAM), param);
    if (pbe == NULL) {
        ERR_raise(ERR_LIB_PKCS12, PKCS12_R_DECODE_ERROR);
        return 0;
    }

    if (pbe->iter == NULL)
        iter = 1;
    else
        iter = ASN1_INTEGER_get(pbe->iter);
    salt = pbe->salt->data;
    saltlen = pbe->salt->length;
    if (!(*pkcs12_key_gen)(pass, passlen, salt, saltlen, PKCS12_KEY_ID,
                           iter, EVP_CIPHER_key_length(cipher), key, md)) {
        ERR_raise(ERR_LIB_PKCS12, PKCS12_R_KEY_GEN_ERROR);
        PBEPARAM_free(pbe);
        return 0;
    }
    if (!(*pkcs12_key_gen)(pass, passlen, salt, saltlen, PKCS12_IV_ID,
                           iter, EVP_CIPHER_iv_length(cipher), iv, md)) {
        ERR_raise(ERR_LIB_PKCS12, PKCS12_R_IV_GEN_ERROR);
        PBEPARAM_free(pbe);
        return 0;
    }
    PBEPARAM_free(pbe);
    ret = EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, en_de);
    OPENSSL_cleanse(key, EVP_MAX_KEY_LENGTH);
    OPENSSL_cleanse(iv, EVP_MAX_IV_LENGTH);
    return ret;
}

int PKCS12_PBE_keygen_ex(EVP_CIPHER_CTX **ctx, OSSL_PARAM *params,
                         const char *pass, int passlen,
                         int en_de, OSSL_LIB_CTX *libctx, const char *propq)
{
    int ret;
    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    const char *ciph_name;
    const OSSL_PARAM *p;
    EVP_CIPHER *cipher;

    *ctx = EVP_CIPHER_CTX_new();
    if (*ctx == NULL)
        return 0;
    /*
     * Get the cipher to be used for the PBE enc/dec operation
     * so we can determine key and IV lengths
     */
    p = OSSL_PARAM_locate_const(params, OSSL_PBE_PARAM_CIPHER);
    if (p == NULL)
        return 0;
    if (!OSSL_PARAM_get_utf8_ptr(p, &ciph_name))
        return 0;
    cipher = EVP_CIPHER_fetch(libctx, ciph_name, propq);

    if (!PKCS12_key_gen_ex(key, EVP_CIPHER_key_length(cipher), params, libctx, propq)) {
        ERR_raise(ERR_LIB_PKCS12, PKCS12_R_KEY_GEN_ERROR);
        return 0;
    }
    if (!PKCS12_key_gen_ex(iv, EVP_CIPHER_iv_length(cipher), params, libctx, propq)) {
        ERR_raise(ERR_LIB_PKCS12, PKCS12_R_IV_GEN_ERROR);
        return 0;
    }
    ret = EVP_CipherInit_ex(*ctx, cipher, NULL, key, iv, en_de);
    OPENSSL_cleanse(key, EVP_MAX_KEY_LENGTH);
    OPENSSL_cleanse(iv, EVP_MAX_IV_LENGTH);
    return ret;
}

int PKCS12_PBE_encode(X509_ALGOR **algor, OSSL_PARAM *params)
{
    return 0;
}

int PKCS12_PBE_decode(X509_ALGOR *algor, OSSL_PARAM **params)
{
    PBEPARAM *pbe;
    unsigned int iter = 0;
    OSSL_PARAM *p;
    int pbe_nid, cipher_nid, md_nid;
    const char *cipher_name, *md_name;

    *params = OPENSSL_malloc(sizeof(OSSL_PARAM) * 5);
    p = *params;

    pbe_nid = OBJ_obj2nid(algor->algorithm);
    if (!EVP_PBE_find_ex(EVP_PBE_TYPE_OUTER, pbe_nid, &cipher_nid, &md_nid,
                         NULL, NULL, NULL, NULL)) {
        char obj_tmp[80];
        if (algor->algorithm == NULL)
            OPENSSL_strlcpy(obj_tmp, "NULL", sizeof(obj_tmp));
        else
            i2t_ASN1_OBJECT(obj_tmp, sizeof(obj_tmp), algor->algorithm);
        ERR_raise_data(ERR_LIB_EVP, EVP_R_UNKNOWN_PBE_ALGORITHM,
                       "TYPE=%s", obj_tmp);
        return 0;
    }

    /* If cipher/digest can be determined from PBE OID, set them here */
    if (cipher_nid != -1) {
        cipher_name = OBJ_nid2sn(cipher_nid);
        if (!cipher_name) {
            ERR_raise(ERR_LIB_EVP, EVP_R_UNKNOWN_CIPHER);
            return 0;
        }
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CIPHER, cipher_name, 0);
    }

    if (md_nid != -1) {
        md_name = OBJ_nid2sn(md_nid);
        if (!md_name) {
            ERR_raise(ERR_LIB_EVP, EVP_R_UNKNOWN_DIGEST);
            return 0;
        }
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, md_name, 0);
    }

    /* Extract useful info from parameter */
    pbe = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(PBEPARAM), algor->parameter);
    if (pbe == NULL) {
        ERR_raise(ERR_LIB_PKCS12, PKCS12_R_DECODE_ERROR);
        return 0;
    }

    if (pbe->iter != NULL) {
        iter = ASN1_INTEGER_get(pbe->iter);
        *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iter);
    }
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, pbe->salt->data,
                                             pbe->salt->length);
    PBEPARAM_free(pbe);
    return 1;
}

