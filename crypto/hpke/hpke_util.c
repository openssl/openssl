/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include "crypto/hpke.h"
#include "internal/packet.h"

/*
 * See RFC 9180 Section 7.1 and Section 7.1.3 (for the bitmask)
 */
static const OSSL_HPKE_KEM_ALG kem_alg[]= {
    { "EC",  "P-256", "HKDF", "SHA256", 0x0010, 32, 65,  32, 0xFF },
    { "EC",  "P-384", "HKDF", "SHA384", 0x0011, 48, 97,  48, 0xFF },
    { "EC",  "P-521", "HKDF", "SHA512", 0x0012, 64, 133, 66, 0x01 },
    { "X25519", NULL, "HKDF", "SHA256", 0x0020, 32, 32,  32, 0x00 },
    { "X448",   NULL, "HKDF", "SHA512", 0x0021, 64, 56,  56, 0x00 },
    { NULL, NULL, NULL, 0, 0, 0, 0, 0 }
};

/*
 * keyname must be either "EC", "X25519" or "X448"
 * curve is one of "P-256", "P-384", "P-521" or NULL,
 * kdfname is one of "HKDF" or NULL
 * kdfdigestname is one of "SHA256", SHA384", "SHA512", or NULL.
 * Returns KEM info if the combination of input names is allowed, or NULL
 * otherwise. If any of the optional params are NULL, then it will chose the
 * first one in the list that matches the given inputs.
 */
const OSSL_HPKE_KEM_ALG *ossl_hpke_get_kemalg(const char *keyname,
                                              const char *curve,
                                              const char *kdfname,
                                              const char *kdfdigestname)
{
    const OSSL_HPKE_KEM_ALG *p;

    if (keyname == NULL)
        return NULL;

     for (p = kem_alg; p->keytype != NULL; ++p) {
        if (OPENSSL_strcasecmp(keyname, p->keytype) == 0
            && (curve == NULL
                || OPENSSL_strcasecmp(curve, p->name) == 0)
            && (kdfname == NULL
                || OPENSSL_strcasecmp(kdfname, p->kdfname) == 0)
            && (kdfdigestname == NULL
                || OPENSSL_strcasecmp(kdfdigestname, p->kdfdigestname) == 0))
            return p;
    }
    return NULL;
}

/* Common code to create a HKDF ctx */
EVP_KDF_CTX *ossl_kdf_ctx_create(const char *kdfname, const char *mdname,
                                 OSSL_LIB_CTX *libctx, const char *propq)
{
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx = NULL;

    kdf = EVP_KDF_fetch(libctx, kdfname, propq);
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (kctx != NULL && mdname != NULL) {
        OSSL_PARAM params[3], *p = params;

        if (mdname != NULL)
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                    (char *)mdname, 0);
        if (propq != NULL)
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_PROPERTIES,
                                                    (char *)propq, 0);
        *p = OSSL_PARAM_construct_end();
        if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
            EVP_KDF_CTX_free(kctx);
            return NULL;
        }
    }
    return kctx;
}

/* Common code to perform a HKDF key derivation */
static int kdf_derive(EVP_KDF_CTX *kctx,
                      unsigned char *out, size_t outlen, int mode,
                      const unsigned char *salt, size_t saltlen,
                      const unsigned char *ikm, size_t ikmlen,
                      const unsigned char *info, size_t infolen)
{
    OSSL_PARAM params[5], *p = params;

    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    if (salt != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                 (char *)salt, saltlen);
    if (ikm != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                 (char *)ikm, ikmlen);
    if (info != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                 (char *)info, infolen);
    *p = OSSL_PARAM_construct_end();
    return EVP_KDF_derive(kctx, out, outlen, params) > 0;
}

/* Common code to perform a HKDF extract */
int ossl_hpke_kdf_extract(EVP_KDF_CTX *kctx,
                          unsigned char *prk, size_t prklen,
                          const unsigned char *salt, size_t saltlen,
                          const unsigned char *ikm, size_t ikmlen)
{
    return kdf_derive(kctx, prk, prklen, EVP_KDF_HKDF_MODE_EXTRACT_ONLY,
                      salt, saltlen, ikm, ikmlen, NULL, 0);
}

/* Common code to perform a HKDF expand */
int ossl_hpke_kdf_expand(EVP_KDF_CTX *kctx,
                         unsigned char *okm, size_t okmlen,
                         const unsigned char *prk, size_t prklen,
                         const unsigned char *info, size_t infolen)
{
    return kdf_derive(kctx, okm, okmlen, EVP_KDF_HKDF_MODE_EXPAND_ONLY,
                      NULL, 0, prk, prklen, info, infolen);
}

/*
 * The largest value happens inside dhkem_extract_and_expand
 * Which consists of a max dkmlen of 2*secretlen + suiteid + small label
 */
#define LABELED_EXTRACT_SIZE (10 + 12 + 2 * OSSL_HPKE_MAX_SECRET)

/*
 * The largest value happens inside dhkem_extract_and_expand
 * Which consists of a prklen of secretlen + contextlen of 2 encoded public keys
 * + suiteid + small label
 */
#define LABELED_EXPAND_SIZE (LABELED_EXTRACT_SIZE + 2 * OSSL_HPKE_MAX_PUBLIC)
static const char LABEL_HPKEV1[] = "HPKE-v1";

/*
 * See RFC 9180 Section 4 LabelExtract()
 */
int ossl_hpke_labeled_extract(EVP_KDF_CTX *kctx,
                              unsigned char *prk, size_t prklen,
                              const unsigned char *salt, size_t saltlen,
                              const unsigned char *suiteid, size_t suiteidlen,
                              const char *label,
                              const unsigned char *ikm, size_t ikmlen)
{
    int ret = 0;
    size_t labeled_ikmlen = 0;
    unsigned char labeled_ikm[LABELED_EXTRACT_SIZE];
    WPACKET pkt;

    /* labeled_ikm = concat("HPKE-v1", suiteid, label, ikm) */
    if (!WPACKET_init_static_len(&pkt, labeled_ikm, sizeof(labeled_ikm), 0)
            || !WPACKET_memcpy(&pkt, LABEL_HPKEV1, strlen(LABEL_HPKEV1))
            || !WPACKET_memcpy(&pkt, suiteid, suiteidlen)
            || !WPACKET_memcpy(&pkt, label, strlen(label))
            || !WPACKET_memcpy(&pkt, ikm, ikmlen)
            || !WPACKET_get_total_written(&pkt, &labeled_ikmlen)
            || !WPACKET_finish(&pkt))
        goto end;

    ret = ossl_hpke_kdf_extract(kctx, prk, prklen, salt, saltlen,
                                labeled_ikm, labeled_ikmlen);
end:
    WPACKET_cleanup(&pkt);
    OPENSSL_cleanse(labeled_ikm, labeled_ikmlen);
    return ret;
}

/*
 * See RFC 9180 Section 4 LabelExpand()
 */
int ossl_hpke_labeled_expand(EVP_KDF_CTX *kctx,
                             unsigned char *okm, size_t okmlen,
                             const unsigned char *prk, size_t prklen,
                             const unsigned char *suiteid, size_t suiteidlen,
                             const char *label,
                             const unsigned char *info, size_t infolen)
{
    int ret = 0;
    size_t labeled_infolen = 0;
    unsigned char labeled_info[LABELED_EXPAND_SIZE];
    WPACKET pkt;

    /* labeled_info = concat(okmlen, "HPKE-v1", suiteid, label, info) */
    if (!WPACKET_init_static_len(&pkt, labeled_info, sizeof(labeled_info), 0)
            || !WPACKET_put_bytes_u16(&pkt, okmlen)
            || !WPACKET_memcpy(&pkt, LABEL_HPKEV1, strlen(LABEL_HPKEV1))
            || !WPACKET_memcpy(&pkt, suiteid, suiteidlen)
            || !WPACKET_memcpy(&pkt, label, strlen(label))
            || !WPACKET_memcpy(&pkt, info, infolen)
            || !WPACKET_get_total_written(&pkt, &labeled_infolen)
            || !WPACKET_finish(&pkt))
        goto end;

    ret = ossl_hpke_kdf_expand(kctx, okm, okmlen,
                               prk, prklen, labeled_info, labeled_infolen);
end:
    WPACKET_cleanup(&pkt);
    return ret;
}

/*
 * The AEAD interface have been seperated out here. At some point in the
 * future there should be very similar public interfaces using EVP_AEAD
 */

EVP_CIPHER_CTX *ossl_aead_init(EVP_CIPHER *cipher, const unsigned char *key,
                               int enc)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx = NULL;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto err;

    if (!EVP_CipherInit_ex2(ctx, cipher, key, NULL, enc, NULL))
        goto err;
    ret = 1;
err:
    if (ret == 0) {
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

void ossl_aead_free(EVP_CIPHER_CTX *ctx)
{
    EVP_CIPHER_CTX_free(ctx);
}

int ossl_aead_seal(EVP_CIPHER_CTX *ctx,
                   unsigned char *ct, size_t *ctlen,
                   const unsigned char *pt, size_t ptlen,
                   const unsigned char *iv, size_t ivlen,
                   const unsigned char *aad, size_t aadlen)
{
    int ret = 0;
    int outlen, tmplen;
    OSSL_PARAM params[2];
    size_t taglen = 16;

    if (*ctlen < (ptlen + taglen))
        return 0;
    if (!EVP_EncryptInit_ex2(ctx, NULL, NULL, iv, NULL))
        goto err;
    if (!EVP_EncryptUpdate(ctx, NULL, &outlen, aad, aadlen))
        goto err;

    if (!EVP_EncryptUpdate(ctx, ct, &outlen, pt, ptlen))
        goto err;

    if (!EVP_EncryptFinal_ex(ctx, ct, &tmplen))
        goto err;

    /* Get tag */
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                  ct + outlen, taglen);
    params[1] = OSSL_PARAM_construct_end();

    if (!EVP_CIPHER_CTX_get_params(ctx, params))
        goto err;
    *ctlen = outlen + taglen;
    ret = 1;
err:
    return ret;
}

int ossl_aead_open(EVP_CIPHER_CTX *ctx,
                   unsigned char *pt, size_t *ptlen,
                   const unsigned char *ct, size_t ctlen,
                   const unsigned char *iv, size_t ivlen,
                   const unsigned char *aad, size_t aadlen)
{
    int rv = 0;
    int outlen = 0;
    OSSL_PARAM params[2];
    size_t taglen = 16;

    if (*ptlen < (ctlen - taglen))
        return 0;
    ctlen -= taglen;

    if (!EVP_DecryptInit_ex2(ctx, NULL, NULL, iv, NULL))
        goto err;

    if (!EVP_DecryptUpdate(ctx, NULL, &outlen, aad, aadlen))
        goto err;

    if (!EVP_DecryptUpdate(ctx, pt, &outlen, ct, ctlen))
        goto err;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                  (void *)(ct + ctlen),
                                                  taglen);
    params[1] = OSSL_PARAM_construct_end();

    if (!EVP_CIPHER_CTX_set_params(ctx, params))
        goto err;

    outlen = *ptlen;
    rv = EVP_DecryptFinal_ex(ctx, pt, &outlen);
    if (rv > 0)
        *ptlen = ctlen;
err:
    return rv > 0;
}
