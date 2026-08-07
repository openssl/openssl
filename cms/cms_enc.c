/*
 * Copyright 2008-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <libcms/names.h>
#include <openssl/asn1t.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/cms.h>
#include <openssl/rand.h>
#include "cms_local.h"

/* CMS EncryptedData Utilities */

/* Return BIO based on EncryptedContentInfo and key */

/*-
 * GCMParameters ::= SEQUENCE {
 *     aes-nonce   OCTET STRING,
 *     aes-ICVlen  INTEGER
 * }
 * as defined in RFC 5084 section 3.2.  CMS carries the AEAD content-cipher
 * parameters itself because the public EVP_CIPHER parameter functions do not
 * handle AEAD ciphers; this can be dropped once they do.
 */
typedef struct {
    ASN1_OCTET_STRING *nonce;
    int32_t icvlen;
} CMS_GCMParameters;

ASN1_SEQUENCE(CMS_GCMParameters) = {
    ASN1_SIMPLE(CMS_GCMParameters, nonce, ASN1_OCTET_STRING),
    ASN1_EMBED(CMS_GCMParameters, icvlen, INT32)
} static_ASN1_SEQUENCE_END(CMS_GCMParameters)

static int cms_set_aead_params(ASN1_TYPE **param, const unsigned char *iv,
    int iv_len, int tag_len)
{
    CMS_GCMParameters gcm;
    int ret = 0;

    gcm.nonce = ASN1_OCTET_STRING_new();
    if (gcm.nonce == NULL)
        return 0;
    gcm.icvlen = tag_len;
    if (ASN1_OCTET_STRING_set(gcm.nonce, iv, iv_len)
        && ASN1_TYPE_pack_sequence(ASN1_ITEM_rptr(CMS_GCMParameters), &gcm, param)
            != NULL)
        ret = 1;
    ASN1_OCTET_STRING_free(gcm.nonce);
    return ret;
}

static int cms_get_aead_params(const ASN1_TYPE *param, unsigned char *iv,
    size_t iv_max, int *iv_len)
{
    CMS_GCMParameters *gcm;
    size_t len;
    int ret = 0;

    if (param == NULL || ASN1_TYPE_get(param) != V_ASN1_SEQUENCE)
        return 0;
    gcm = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(CMS_GCMParameters), param);
    if (gcm == NULL)
        return 0;
    len = ASN1_STRING_get_length(gcm->nonce);
    if (len > 0 && len <= iv_max) {
        memcpy(iv, ASN1_STRING_get0_data(gcm->nonce), len);
        *iv_len = (int)len;
        ret = 1;
    }
    ASN1_item_free((ASN1_VALUE *)gcm, ASN1_ITEM_rptr(CMS_GCMParameters));
    return ret;
}

BIO *ossl_cms_EncryptedContent_init_bio(CMS_EncryptedContentInfo *ec,
    const CMS_CTX *cms_ctx, int auth)
{
    BIO *b;
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *fetched_ciph = NULL;
    const EVP_CIPHER *cipher = NULL;
    X509_ALGOR *calg = ec->contentEncryptionAlgorithm;
    unsigned char iv[EVP_MAX_IV_LENGTH], *piv = NULL;
    unsigned char *tkey = NULL;
    int len;
    int ivlen = 0;
    size_t tkeylen = 0;
    int ok = 0;
    int enc, keep_key = 0;
    OSSL_LIB_CTX *libctx = ossl_cms_ctx_get0_libctx(cms_ctx);
    const char *propq = ossl_cms_ctx_get0_propq(cms_ctx);

    enc = ec->cipher ? 1 : 0;

    b = BIO_new(BIO_f_cipher());
    if (b == NULL) {
        ERR_raise(ERR_LIB_CMS, ERR_R_BIO_LIB);
        return NULL;
    }

    BIO_get_cipher_ctx(b, &ctx);

    (void)ERR_set_mark();
    if (enc) {
        cipher = ec->cipher;
        /*
         * If not keeping key set cipher to NULL so subsequent calls decrypt.
         */
        if (ec->key != NULL)
            ec->cipher = NULL;
    } else {
        cipher = EVP_get_cipherbyobj(calg->algorithm);
    }
    if (cipher != NULL) {
        fetched_ciph = EVP_CIPHER_fetch(libctx, EVP_CIPHER_get0_name(cipher),
            propq);
    } else {
        char txtoid[CMS_MAX_NAME_SIZE];
        if (OBJ_obj2txt(txtoid, sizeof(txtoid), calg->algorithm, 1) > 0)
            fetched_ciph = EVP_CIPHER_fetch(libctx, txtoid, propq);
    }
    if (fetched_ciph != NULL)
        cipher = fetched_ciph;
    if (cipher == NULL) {
        (void)ERR_clear_last_mark();
        ERR_raise(ERR_LIB_CMS, CMS_R_UNKNOWN_CIPHER);
        goto err;
    }
    (void)ERR_pop_to_mark();

    if (EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, enc) <= 0) {
        ERR_raise(ERR_LIB_CMS, CMS_R_CIPHER_INITIALISATION_ERROR);
        goto err;
    }

    if (enc) {
        (void)ERR_set_mark();
        calg->algorithm = OBJ_nid2obj(EVP_CIPHER_CTX_get_type(ctx));
        (void)ERR_pop_to_mark();

        if (calg->algorithm == NULL || OBJ_obj2nid(calg->algorithm) == NID_undef)
            calg->algorithm = OBJ_txt2obj(EVP_CIPHER_get0_name(cipher), 0);

        if (calg->algorithm == NULL || OBJ_length(calg->algorithm) == 0) {
            ERR_raise(ERR_LIB_CMS, CMS_R_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM);
            goto err;
        }
        /* Generate a random IV if we need one */
        ivlen = EVP_CIPHER_CTX_get_iv_length(ctx);

        if (ivlen > 0) {
            if (RAND_bytes_ex(libctx, iv, ivlen, 0) <= 0)
                goto err;
            piv = iv;
        }
    } else if ((EVP_CIPHER_get_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER)) {
        if (!auth) {
            ERR_raise(ERR_LIB_CMS, CMS_R_CIPHER_AEAD_IN_ENVELOPED_DATA);
            goto err;
        }
        if (cms_get_aead_params(calg->parameter, iv, sizeof(iv), &ivlen) <= 0) {
            ERR_raise(ERR_LIB_CMS, CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR);
            goto err;
        }
        piv = iv;
        if (ec->taglen < 4 || ec->taglen > 16
            || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)ec->taglen,
                   (void *)ec->tag)
                <= 0) {
            ERR_raise(ERR_LIB_CMS, CMS_R_CIPHER_AEAD_SET_TAG_ERROR);
            goto err;
        }
    } else {
        if (EVP_CIPHER_asn1_to_param(ctx, calg->parameter) <= 0) {
            ERR_raise(ERR_LIB_CMS, CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR);
            goto err;
        }
        if (auth) {
            ERR_raise(ERR_LIB_CMS, CMS_R_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM);
            goto err;
        }
    }
    len = EVP_CIPHER_CTX_get_key_length(ctx);
    if (len <= 0)
        goto err;
    tkeylen = (size_t)len;

    /* Generate random session key */
    if (!enc || !ec->key) {
        tkey = OPENSSL_malloc(tkeylen);
        if (tkey == NULL)
            goto err;
        if (EVP_CIPHER_CTX_rand_key(ctx, tkey) <= 0)
            goto err;
    }

    if (!ec->key) {
        ec->key = tkey;
        ec->keylen = tkeylen;
        tkey = NULL;
        if (enc)
            keep_key = 1;
        else
            ERR_clear_error();
    }

    if (ec->keylen != tkeylen) {
        /* If necessary set key length */
        if (EVP_CIPHER_CTX_set_key_length(ctx, (int)ec->keylen) <= 0) {
            /*
             * Only reveal failure if debugging so we don't leak information
             * which may be useful in MMA.
             */
            if (enc || ec->debug) {
                ERR_raise(ERR_LIB_CMS, CMS_R_INVALID_KEY_LENGTH);
                goto err;
            } else {
                /* Use random key */
                OPENSSL_clear_free(ec->key, ec->keylen);
                ec->key = tkey;
                ec->keylen = tkeylen;
                tkey = NULL;
                ERR_clear_error();
            }
        }
    }

    if (EVP_CipherInit_ex(ctx, NULL, NULL, ec->key, piv, enc) <= 0) {
        ERR_raise(ERR_LIB_CMS, CMS_R_CIPHER_INITIALISATION_ERROR);
        goto err;
    }
    if (enc) {
        calg->parameter = ASN1_TYPE_new();
        if (calg->parameter == NULL) {
            ERR_raise(ERR_LIB_CMS, ERR_R_ASN1_LIB);
            goto err;
        }
        if (EVP_CIPHER_get_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) {
            int tag_len = EVP_CIPHER_CTX_get_tag_length(ctx);

            if (ivlen < 0 || ivlen > EVP_MAX_IV_LENGTH) {
                ERR_raise(ERR_LIB_CMS, ERR_R_EVP_LIB);
                ASN1_TYPE_free(calg->parameter);
                calg->parameter = NULL;
                goto err;
            }
            if (tag_len <= 0
                || cms_set_aead_params(&calg->parameter, piv, ivlen, tag_len)
                    <= 0) {
                ERR_raise(ERR_LIB_CMS, CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR);
                ASN1_TYPE_free(calg->parameter);
                calg->parameter = NULL;
                goto err;
            }
        } else {
            if (EVP_CIPHER_param_to_asn1(ctx, calg->parameter) <= 0) {
                ERR_raise(ERR_LIB_CMS, CMS_R_CIPHER_PARAMETER_INITIALISATION_ERROR);
                ASN1_TYPE_free(calg->parameter);
                calg->parameter = NULL;
                goto err;
            }
            /* If parameter type not set omit parameter */
            if (ASN1_TYPE_get(calg->parameter) == V_ASN1_UNDEF) {
                ASN1_TYPE_free(calg->parameter);
                calg->parameter = NULL;
            }
        }
    }
    ok = 1;

err:
    EVP_CIPHER_free(fetched_ciph);
    if (!keep_key || !ok) {
        OPENSSL_clear_free(ec->key, ec->keylen);
        ec->key = NULL;
    }
    OPENSSL_clear_free(tkey, tkeylen);
    if (ok)
        return b;
    BIO_free(b);
    return NULL;
}

int ossl_cms_EncryptedContent_init(CMS_EncryptedContentInfo *ec,
    const EVP_CIPHER *cipher,
    const unsigned char *key, size_t keylen,
    const CMS_CTX *cms_ctx)
{
    ec->cipher = cipher;
    if (key) {
        if ((ec->key = OPENSSL_malloc(keylen)) == NULL)
            return 0;
        memcpy(ec->key, key, keylen);
    }
    ec->keylen = keylen;
    if (cipher != NULL)
        ec->contentType = OBJ_nid2obj(NID_pkcs7_data);
    return 1;
}

int CMS_EncryptedData_set1_key(CMS_ContentInfo *cms, const EVP_CIPHER *ciph,
    const unsigned char *key, size_t keylen)
{
    CMS_EncryptedContentInfo *ec;

    if (!key || !keylen) {
        ERR_raise(ERR_LIB_CMS, CMS_R_NO_KEY);
        return 0;
    }
    if (ciph) {
        if ((EVP_CIPHER_get_flags(ciph) & EVP_CIPH_FLAG_AEAD_CIPHER) != 0) {
            ERR_raise(ERR_LIB_CMS, CMS_R_UNSUPPORTED_CONTENT_ENCRYPTION_ALGORITHM);
            return 0;
        }
        if (cms->d.encryptedData != NULL) {
            M_ASN1_free_of(cms->d.encryptedData, CMS_EncryptedData);
            cms->d.encryptedData = NULL;
        }
        cms->d.encryptedData = M_ASN1_new_of(CMS_EncryptedData);
        if (!cms->d.encryptedData) {
            ERR_raise(ERR_LIB_CMS, ERR_R_ASN1_LIB);
            return 0;
        }
        cms->contentType = OBJ_nid2obj(NID_pkcs7_encrypted);
        cms->d.encryptedData->version = 0;
    } else if (OBJ_obj2nid(cms->contentType) != NID_pkcs7_encrypted) {
        ERR_raise(ERR_LIB_CMS, CMS_R_NOT_ENCRYPTED_DATA);
        return 0;
    }
    ec = cms->d.encryptedData->encryptedContentInfo;
    return ossl_cms_EncryptedContent_init(ec, ciph, key, keylen,
        ossl_cms_get0_cmsctx(cms));
}

BIO *ossl_cms_EncryptedData_init_bio(const CMS_ContentInfo *cms)
{
    CMS_EncryptedData *enc = cms->d.encryptedData;

    if (enc->encryptedContentInfo->cipher && enc->unprotectedAttrs)
        enc->version = 2;
    return ossl_cms_EncryptedContent_init_bio(enc->encryptedContentInfo,
        ossl_cms_get0_cmsctx(cms), 0);
}
