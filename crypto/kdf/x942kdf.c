/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"

#ifndef OPENSSL_NO_CMS

# include <stdlib.h>
# include <stdarg.h>
# include <string.h>
# include <openssl/hmac.h>
# include <openssl/cms.h>
# include <openssl/evp.h>
# include <openssl/kdf.h>
# include <openssl/x509.h>
# include <openssl/obj_mac.h>
# include "internal/cryptlib.h"
# include "internal/evp_int.h"
# include "kdf_local.h"

# define X942KDF_MAX_INLEN (1 << 30)

struct evp_kdf_impl_st {
    const EVP_MD *md;
    unsigned char *secret;
    size_t secret_len;
    int cek_nid;
    unsigned char *ukm;
    size_t ukm_len;
    size_t dkm_len;
};

/* A table of allowed wrapping algorithms and the associated output lengths */
static const struct {
    int nid;
    size_t keklen; /* size in bytes */
} kek_algs[] = {
    { NID_id_smime_alg_CMS3DESwrap, 24 },
    { NID_id_smime_alg_CMSRC2wrap, 16 },
    { NID_id_aes128_wrap, 16 },
    { NID_id_aes192_wrap, 24 },
    { NID_id_aes256_wrap, 32 },
    { NID_id_camellia128_wrap, 16 },
    { NID_id_camellia192_wrap, 24 },
    { NID_id_camellia256_wrap, 32 }
};

/* Skip past an ASN1 structure: for OBJECT skip content octets too */
static int skip_asn1(unsigned char **pp, long *plen, int exptag)
{
    int i, tag, xclass;
    long tmplen;
    const unsigned char *q = *pp;

    i = ASN1_get_object(&q, &tmplen, &tag, &xclass, *plen);
    if ((i & 0x80) != 0 || tag != exptag || xclass != V_ASN1_UNIVERSAL)
        return 0;
    if (tag == V_ASN1_OBJECT)
        q += tmplen;
    *pp = (unsigned char *)q;
    *plen -= q - *pp;
    return 1;
}

/*
 * Encode the other info structure.
 *
 *  RFC2631 Section 2.1.2 Contains the following definition for otherinfo
 *
 *  OtherInfo ::= SEQUENCE {
 *      keyInfo KeySpecificInfo,
 *      partyAInfo [0] OCTET STRING OPTIONAL,
 *      suppPubInfo [2] OCTET STRING
 *  }
 *
 *  KeySpecificInfo ::= SEQUENCE {
 *      algorithm OBJECT IDENTIFIER,
 *      counter OCTET STRING SIZE (4..4)
 *  }
 *
 * |nid| is the algorithm object identifier.
 * |keylen| is the length (in bytes) of the generated KEK. It is stored into
 * suppPubInfo (in bits).
 * |ukm| is the optional user keying material that is stored into partyAInfo. It
 * can be NULL.
 * |ukmlen| is the user keying material length (in bytes).
 * |der| is the returned encoded data. It must be freed by the caller.
 * |der_len| is the returned size of the encoded data.
 * |out_ctr| returns a pointer to the counter data which is embedded inside the
 * encoded data. This allows the counter bytes to be updated without re-encoding.
 *
 * Returns: 1 if successfully encoded, or 0 otherwise.
 * Assumptions: |der|, |der_len| & |out_ctr| are not NULL.
 */
static int x942_encode_otherinfo(int nid, size_t keylen,
                                 const unsigned char *ukm, size_t ukmlen,
                                 unsigned char **der, size_t *der_len,
                                 unsigned char **out_ctr)
{
    unsigned char *p, *encoded = NULL;
    int ret = 0, encoded_len;
    long tlen;
    /* "magic" value to check offset is sane */
    static unsigned char ctr[4] = { 0x00, 0x00, 0x00, 0x01 };
    X509_ALGOR *ksi = NULL;
    ASN1_OBJECT *alg_oid = NULL;
    ASN1_OCTET_STRING *ctr_oct = NULL, *ukm_oct = NULL;

    /* set the KeySpecificInfo - which contains an algorithm oid and counter */
    ksi = X509_ALGOR_new();
    alg_oid = OBJ_dup(OBJ_nid2obj(nid));
    ctr_oct = ASN1_OCTET_STRING_new();
    if (ksi == NULL
        || alg_oid == NULL
        || ctr_oct == NULL
        || !ASN1_OCTET_STRING_set(ctr_oct, ctr, sizeof(ctr))
        || !X509_ALGOR_set0(ksi, alg_oid, V_ASN1_OCTET_STRING, ctr_oct))
        goto err;
    /* NULL these as they now belong to ksi */
    alg_oid = NULL;
    ctr_oct = NULL;

    /* Set the optional partyAInfo */
    if (ukm != NULL) {
        ukm_oct = ASN1_OCTET_STRING_new();
        if (ukm_oct == NULL)
            goto err;
        ASN1_OCTET_STRING_set(ukm_oct, (unsigned char *)ukm, ukmlen);
    }
    /* Generate the OtherInfo DER data */
    encoded_len = CMS_SharedInfo_encode(&encoded, ksi, ukm_oct, keylen);
    if (encoded_len <= 0)
        goto err;

    /* Parse the encoded data to find the offset of the counter data */
    p = encoded;
    tlen = (long)encoded_len;
    if (skip_asn1(&p, &tlen, V_ASN1_SEQUENCE)
        && skip_asn1(&p, &tlen, V_ASN1_SEQUENCE)
        && skip_asn1(&p, &tlen, V_ASN1_OBJECT)
        && skip_asn1(&p, &tlen, V_ASN1_OCTET_STRING)
        && CRYPTO_memcmp(p, ctr, 4) == 0) {
        *out_ctr = p;
        *der = encoded;
        *der_len = (size_t)encoded_len;
        ret = 1;
    }
err:
    if (ret != 1)
        OPENSSL_free(encoded);
    ASN1_OCTET_STRING_free(ctr_oct);
    ASN1_OCTET_STRING_free(ukm_oct);
    ASN1_OBJECT_free(alg_oid);
    X509_ALGOR_free(ksi);
    return ret;
}

static int x942kdf_hash_kdm(const EVP_MD *kdf_md,
                            const unsigned char *z, size_t z_len,
                            const unsigned char *other, size_t other_len,
                            unsigned char *ctr,
                            unsigned char *derived_key, size_t derived_key_len)
{
    int ret = 0, hlen;
    size_t counter, out_len, len = derived_key_len;
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned char *out = derived_key;
    EVP_MD_CTX *ctx = NULL, *ctx_init = NULL;

    if (z_len > X942KDF_MAX_INLEN || other_len > X942KDF_MAX_INLEN
            || derived_key_len > X942KDF_MAX_INLEN
            || derived_key_len == 0) {
        KDFerr(KDF_F_X942KDF_HASH_KDM, KDF_R_BAD_LENGTH);
        return 0;
    }

    hlen = EVP_MD_size(kdf_md);
    if (hlen <= 0)
        return 0;
    out_len = (size_t)hlen;

    ctx = EVP_MD_CTX_create();
    ctx_init = EVP_MD_CTX_create();
    if (ctx == NULL || ctx_init == NULL)
        goto end;

    if (!EVP_DigestInit(ctx_init, kdf_md))
        goto end;

    for (counter = 1;; counter++) {
        /* updating the ctr modifies 4 bytes in the 'other' buffer */
        ctr[0] = (unsigned char)((counter >> 24) & 0xff);
        ctr[1] = (unsigned char)((counter >> 16) & 0xff);
        ctr[2] = (unsigned char)((counter >> 8) & 0xff);
        ctr[3] = (unsigned char)(counter & 0xff);

        if (!EVP_MD_CTX_copy_ex(ctx, ctx_init)
            || !EVP_DigestUpdate(ctx, z, z_len)
            || !EVP_DigestUpdate(ctx, other, other_len))
            goto end;
        if (len >= out_len) {
            if (!EVP_DigestFinal_ex(ctx, out, NULL))
                goto end;
            out += out_len;
            len -= out_len;
            if (len == 0)
                break;
        } else {
            if (!EVP_DigestFinal_ex(ctx, mac, NULL))
                goto end;
            memcpy(out, mac, len);
            break;
        }
    }
    ret = 1;
end:
    EVP_MD_CTX_free(ctx);
    EVP_MD_CTX_free(ctx_init);
    OPENSSL_cleanse(mac, sizeof(mac));
    return ret;
}

static EVP_KDF_IMPL *x942kdf_new(void)
{
    EVP_KDF_IMPL *impl;

    if ((impl = OPENSSL_zalloc(sizeof(*impl))) == NULL)
        KDFerr(KDF_F_X942KDF_NEW, ERR_R_MALLOC_FAILURE);
    return impl;
}

static void x942kdf_reset(EVP_KDF_IMPL *impl)
{
    OPENSSL_clear_free(impl->secret, impl->secret_len);
    OPENSSL_clear_free(impl->ukm, impl->ukm_len);
    memset(impl, 0, sizeof(*impl));
}

static void x942kdf_free(EVP_KDF_IMPL *impl)
{
    x942kdf_reset(impl);
    OPENSSL_free(impl);
}

static int x942kdf_set_buffer(va_list args, unsigned char **out, size_t *out_len)
{
    const unsigned char *p;
    size_t len;

    p = va_arg(args, const unsigned char *);
    len = va_arg(args, size_t);
    if (len == 0 || p == NULL)
        return 1;

    OPENSSL_free(*out);
    *out = OPENSSL_memdup(p, len);
    if (*out == NULL)
        return 0;

    *out_len = len;
    return 1;
}

static int x942kdf_ctrl(EVP_KDF_IMPL *impl, int cmd, va_list args)
{
    const EVP_MD *md;
    char *alg_str = NULL;
    size_t i;

    switch (cmd) {
    case EVP_KDF_CTRL_SET_MD:
        md = va_arg(args, const EVP_MD *);
        if (md == NULL)
            return 0;

        impl->md = md;
        return 1;

    case EVP_KDF_CTRL_SET_KEY:
        return x942kdf_set_buffer(args, &impl->secret, &impl->secret_len);

    case EVP_KDF_CTRL_SET_UKM:
        return x942kdf_set_buffer(args, &impl->ukm, &impl->ukm_len);

    case EVP_KDF_CTRL_SET_CEK_ALG:
        alg_str = va_arg(args, char *);
        if (alg_str == NULL)
            return 0;
        impl->cek_nid = OBJ_sn2nid(alg_str);
        for (i = 0; i < (size_t)OSSL_NELEM(kek_algs); ++i) {
            if (kek_algs[i].nid == impl->cek_nid) {
                impl->dkm_len = kek_algs[i].keklen;
                return 1;
            }
        }
        KDFerr(KDF_F_X942KDF_CTRL, KDF_R_UNSUPPORTED_CEK_ALG);
        return 0;

    default:
        return -2;
    }
}

static int x942kdf_ctrl_str(EVP_KDF_IMPL *impl, const char *type,
                            const char *value)
{
    if (strcmp(type, "digest") == 0)
        return kdf_md2ctrl(impl, x942kdf_ctrl, EVP_KDF_CTRL_SET_MD, value);

    if (strcmp(type, "secret") == 0 || strcmp(type, "key") == 0)
         return kdf_str2ctrl(impl, x942kdf_ctrl, EVP_KDF_CTRL_SET_KEY,
                             value);

    if (strcmp(type, "hexsecret") == 0 || strcmp(type, "hexkey") == 0)
        return kdf_hex2ctrl(impl, x942kdf_ctrl, EVP_KDF_CTRL_SET_KEY,
                            value);

    if (strcmp(type, "ukm") == 0)
        return kdf_str2ctrl(impl, x942kdf_ctrl, EVP_KDF_CTRL_SET_UKM,
                            value);

    if (strcmp(type, "hexukm") == 0)
        return kdf_hex2ctrl(impl, x942kdf_ctrl, EVP_KDF_CTRL_SET_UKM,
                            value);

    if (strcmp(type, "cekalg") == 0)
        return kdf_str2ctrl(impl, x942kdf_ctrl, EVP_KDF_CTRL_SET_CEK_ALG,
                            value);

    return -2;
}

static size_t x942kdf_size(EVP_KDF_IMPL *impl)
{
    int len;

    if (impl->md == NULL) {
        KDFerr(KDF_F_X942KDF_SIZE, KDF_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }
    len = EVP_MD_size(impl->md);
    return (len <= 0) ? 0 : (size_t)len;
}

static int x942kdf_derive(EVP_KDF_IMPL *impl, unsigned char *key, size_t keylen)
{
    int ret = 0;
    unsigned char *ctr;
    unsigned char *der = NULL;
    size_t der_len = 0;

    if (impl->secret == NULL) {
        KDFerr(KDF_F_X942KDF_DERIVE, KDF_R_MISSING_SECRET);
        return 0;
    }
    if (impl->md == NULL) {
        KDFerr(KDF_F_X942KDF_DERIVE, KDF_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }
    if (impl->cek_nid == NID_undef) {
        KDFerr(KDF_F_X942KDF_DERIVE, KDF_R_MISSING_CEK_ALG);
        return 0;
    }
    if (impl->ukm != NULL && impl->ukm_len >= X942KDF_MAX_INLEN) {
        /*
         * Note the ukm length MUST be 512 bits.
         * For backwards compatibility the old check is being done.
         */
        KDFerr(KDF_F_X942KDF_DERIVE, KDF_R_INAVLID_UKM_LEN);
        return 0;
    }
    if (keylen != impl->dkm_len) {
        KDFerr(KDF_F_X942KDF_DERIVE, KDF_R_MISSING_CEK_ALG);
        return 0;
    }
    /* generate the otherinfo der */
    if (!x942_encode_otherinfo(impl->cek_nid, impl->dkm_len,
                               impl->ukm, impl->ukm_len,
                               &der, &der_len, &ctr)) {
        KDFerr(KDF_F_X942KDF_DERIVE, KDF_R_BAD_ENCODING);
        return 0;
    }
    ret = x942kdf_hash_kdm(impl->md, impl->secret, impl->secret_len,
                           der, der_len, ctr, key, keylen);
    OPENSSL_free(der);
    return ret;
}

const EVP_KDF x942_kdf_meth = {
    EVP_KDF_X942,
    x942kdf_new,
    x942kdf_free,
    x942kdf_reset,
    x942kdf_ctrl,
    x942kdf_ctrl_str,
    x942kdf_size,
    x942kdf_derive
};

#endif /* OPENSSL_NO_CMS */
