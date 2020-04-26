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
# include <openssl/core_names.h>
# include "internal/cryptlib.h"
# include "internal/numbers.h"
# include "crypto/evp.h"
# include "prov/provider_ctx.h"
# include "prov/providercommonerr.h"
# include "prov/implementations.h"
# include "prov/provider_util.h"

# define X942KDF_MAX_INLEN (1 << 30)

static OSSL_OP_kdf_newctx_fn x942kdf_new;
static OSSL_OP_kdf_freectx_fn x942kdf_free;
static OSSL_OP_kdf_reset_fn x942kdf_reset;
static OSSL_OP_kdf_derive_fn x942kdf_derive;
static OSSL_OP_kdf_settable_ctx_params_fn x942kdf_settable_ctx_params;
static OSSL_OP_kdf_set_ctx_params_fn x942kdf_set_ctx_params;
static OSSL_OP_kdf_gettable_ctx_params_fn x942kdf_gettable_ctx_params;
static OSSL_OP_kdf_get_ctx_params_fn x942kdf_get_ctx_params;

typedef struct {
    void *provctx;
    PROV_DIGEST digest;
    unsigned char *secret;
    size_t secret_len;
    int cek_nid;
    unsigned char *ukm;
    size_t ukm_len;
    size_t dkm_len;
} KDF_X942;

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
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
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

static void *x942kdf_new(void *provctx)
{
    KDF_X942 *ctx;

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL)
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
    ctx->provctx = provctx;
    return ctx;
}

static void x942kdf_reset(void *vctx)
{
    KDF_X942 *ctx = (KDF_X942 *)vctx;

    ossl_prov_digest_reset(&ctx->digest);
    OPENSSL_clear_free(ctx->secret, ctx->secret_len);
    OPENSSL_clear_free(ctx->ukm, ctx->ukm_len);
    memset(ctx, 0, sizeof(*ctx));
}

static void x942kdf_free(void *vctx)
{
    KDF_X942 *ctx = (KDF_X942 *)vctx;

    if (ctx != NULL) {
        x942kdf_reset(ctx);
        OPENSSL_free(ctx);
    }
}

static int x942kdf_set_buffer(unsigned char **out, size_t *out_len,
                              const OSSL_PARAM *p)
{
    if (p->data_size == 0 || p->data == NULL)
        return 1;

    OPENSSL_free(*out);
    *out = NULL;
    return OSSL_PARAM_get_octet_string(p, (void **)out, 0, out_len);
}

static size_t x942kdf_size(KDF_X942 *ctx)
{
    int len;
    const EVP_MD *md = ossl_prov_digest_md(&ctx->digest);

    if (md == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }
    len = EVP_MD_size(md);
    return (len <= 0) ? 0 : (size_t)len;
}

static int x942kdf_derive(void *vctx, unsigned char *key, size_t keylen)
{
    KDF_X942 *ctx = (KDF_X942 *)vctx;
    const EVP_MD *md = ossl_prov_digest_md(&ctx->digest);
    int ret = 0;
    unsigned char *ctr;
    unsigned char *der = NULL;
    size_t der_len = 0;

    if (ctx->secret == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SECRET);
        return 0;
    }
    if (md == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MESSAGE_DIGEST);
        return 0;
    }
    if (ctx->cek_nid == NID_undef) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_CEK_ALG);
        return 0;
    }
    if (ctx->ukm != NULL && ctx->ukm_len >= X942KDF_MAX_INLEN) {
        /*
         * Note the ukm length MUST be 512 bits.
         * For backwards compatibility the old check is being done.
         */
        ERR_raise(ERR_LIB_PROV, PROV_R_INAVLID_UKM_LENGTH);
        return 0;
    }
    if (keylen != ctx->dkm_len) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_CEK_ALG);
        return 0;
    }
    /* generate the otherinfo der */
    if (!x942_encode_otherinfo(ctx->cek_nid, ctx->dkm_len,
                               ctx->ukm, ctx->ukm_len,
                               &der, &der_len, &ctr)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        return 0;
    }
    ret = x942kdf_hash_kdm(md, ctx->secret, ctx->secret_len,
                           der, der_len, ctr, key, keylen);
    OPENSSL_free(der);
    return ret;
}

static int x942kdf_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    KDF_X942 *ctx = vctx;
    OPENSSL_CTX *provctx = PROV_LIBRARY_CONTEXT_OF(ctx->provctx);
    size_t i;

    if (!ossl_prov_digest_load_from_params(&ctx->digest, params, provctx))
        return 0;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SECRET)) != NULL
        || (p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY)) != NULL)
        if (!x942kdf_set_buffer(&ctx->secret, &ctx->secret_len, p))
            return 0;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_UKM)) != NULL)
        if (!x942kdf_set_buffer(&ctx->ukm, &ctx->ukm_len, p))
            return 0;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_CEK_ALG)) != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        ctx->cek_nid = OBJ_sn2nid(p->data);
        for (i = 0; i < OSSL_NELEM(kek_algs); i++)
            if (kek_algs[i].nid == ctx->cek_nid)
                goto cek_found;
        ERR_raise(ERR_LIB_PROV, PROV_R_UNSUPPORTED_CEK_ALG);
        return 0;
cek_found:
        ctx->dkm_len = kek_algs[i].keklen;
    }
    return 1;
}

static const OSSL_PARAM *x942kdf_settable_ctx_params(void)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SECRET, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_UKM, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_CEK_ALG, NULL, 0),
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

static int x942kdf_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    KDF_X942 *ctx = (KDF_X942 *)vctx;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE)) != NULL)
        return OSSL_PARAM_set_size_t(p, x942kdf_size(ctx));
    return -2;
}

static const OSSL_PARAM *x942kdf_gettable_ctx_params(void)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL),
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}

const OSSL_DISPATCH kdf_x942_kdf_functions[] = {
    { OSSL_FUNC_KDF_NEWCTX, (void(*)(void))x942kdf_new },
    { OSSL_FUNC_KDF_FREECTX, (void(*)(void))x942kdf_free },
    { OSSL_FUNC_KDF_RESET, (void(*)(void))x942kdf_reset },
    { OSSL_FUNC_KDF_DERIVE, (void(*)(void))x942kdf_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
      (void(*)(void))x942kdf_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS, (void(*)(void))x942kdf_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
      (void(*)(void))x942kdf_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS, (void(*)(void))x942kdf_get_ctx_params },
    { 0, NULL }
};

#endif /* OPENSSL_NO_CMS */
