/*
 * Copyright 2006-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "libcms_names.h"
#include <assert.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/rsa.h>
#include "cms_local.h"

static const EVP_MD *x509_algor_get_md(X509_ALGOR *alg)
{
    const EVP_MD *md;

    if (alg == NULL)
        return EVP_sha1();
    md = EVP_get_digestbyobj(alg->algorithm);
    if (md == NULL)
        ERR_raise(ERR_LIB_CMS, CMS_R_UNKNOWN_DIGEST_ALGORITHM);
    return md;
}

static X509_ALGOR *x509_algor_from_nid(int nid, int ptype, void *pval)
{
    ASN1_OBJECT *algo = OBJ_nid2obj(nid);
    X509_ALGOR *alg = NULL;

    if (algo == NULL)
        return NULL;
    if ((alg = X509_ALGOR_new()) == NULL)
        goto err;
    if (X509_ALGOR_set0(alg, algo, ptype, pval))
        return alg;
    alg->algorithm = NULL; /* precaution to prevent double free */
err:
    X509_ALGOR_free(alg);
    return NULL;
}

static int x509_algor_new_from_md(X509_ALGOR **palg, const EVP_MD *md)
{
    X509_ALGOR *alg;

    /* Default is SHA1 so no need to create it - still success */
    if (md == NULL || EVP_MD_is_a(md, "SHA1"))
        return 1;
    if ((alg = X509_ALGOR_new()) == NULL)
        return 0;
    if (!X509_ALGOR_set_md(alg, md)) {
        X509_ALGOR_free(alg);
        return 0;
    }
    *palg = alg;
    return 1;
}

static int x509_algor_md_to_mgf1(X509_ALGOR **palg, const EVP_MD *mgf1md)
{
    X509_ALGOR *algtmp = NULL;
    ASN1_STRING *stmp = NULL;

    *palg = NULL;
    if (mgf1md == NULL || EVP_MD_is_a(mgf1md, "SHA1"))
        return 1;
    /* need to embed algorithm ID inside another */
    if (!x509_algor_new_from_md(&algtmp, mgf1md))
        goto err;
    if (ASN1_item_pack(algtmp, ASN1_ITEM_rptr(X509_ALGOR), &stmp) == NULL)
        goto err;
    *palg = x509_algor_from_nid(NID_mgf1, V_ASN1_SEQUENCE, stmp);
    if (*palg == NULL)
        goto err;
    stmp = NULL;
err:
    ASN1_STRING_free(stmp);
    X509_ALGOR_free(algtmp);
    return *palg != NULL;
}

static X509_ALGOR *x509_algor_mgf1_decode(X509_ALGOR *alg)
{
    if (OBJ_obj2nid(alg->algorithm) != NID_mgf1)
        return NULL;
    return ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(X509_ALGOR),
        alg->parameter);
}

static RSA_OAEP_PARAMS *rsa_oaep_decode(const X509_ALGOR *alg)
{
    RSA_OAEP_PARAMS *oaep;

    oaep = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(RSA_OAEP_PARAMS),
        alg->parameter);

    if (oaep == NULL)
        return NULL;

    if (oaep->maskGenFunc != NULL) {
        oaep->maskHash = x509_algor_mgf1_decode(oaep->maskGenFunc);
        if (oaep->maskHash == NULL) {
            RSA_OAEP_PARAMS_free(oaep);
            return NULL;
        }
    }
    return oaep;
}

static int rsa_cms_decrypt(CMS_RecipientInfo *ri)
{
    EVP_PKEY_CTX *pkctx;
    X509_ALGOR *cmsalg;
    int nid;
    int rv = -1;
    const unsigned char *label = NULL;
    size_t labellen = 0;
    const EVP_MD *mgf1md = NULL, *md = NULL;
    RSA_OAEP_PARAMS *oaep;
    const ASN1_OBJECT *aoid;
    const void *parameter = NULL;
    int ptype = 0;

    pkctx = CMS_RecipientInfo_get0_pkey_ctx(ri);
    if (pkctx == NULL)
        return 0;
    if (!CMS_RecipientInfo_ktri_get0_algs(ri, NULL, NULL, &cmsalg))
        return -1;
    nid = OBJ_obj2nid(cmsalg->algorithm);
    if (nid == NID_rsaEncryption)
        return 1;
    if (nid != NID_rsaesOaep) {
        ERR_raise(ERR_LIB_CMS, CMS_R_UNSUPPORTED_ENCRYPTION_TYPE);
        return -1;
    }
    /* Decode OAEP parameters */
    oaep = rsa_oaep_decode(cmsalg);

    if (oaep == NULL) {
        ERR_raise(ERR_LIB_CMS, CMS_R_INVALID_OAEP_PARAMETERS);
        goto err;
    }

    mgf1md = x509_algor_get_md(oaep->maskHash);
    if (mgf1md == NULL)
        goto err;
    md = x509_algor_get_md(oaep->hashFunc);
    if (md == NULL)
        goto err;

    if (oaep->pSourceFunc != NULL) {
        X509_ALGOR_get0(&aoid, &ptype, &parameter, oaep->pSourceFunc);

        if (OBJ_obj2nid(aoid) != NID_pSpecified) {
            ERR_raise(ERR_LIB_CMS, CMS_R_UNSUPPORTED_LABEL_SOURCE);
            goto err;
        }
        if (ptype != V_ASN1_OCTET_STRING) {
            ERR_raise(ERR_LIB_CMS, CMS_R_INVALID_LABEL);
            goto err;
        }

        label = ASN1_STRING_get0_data(parameter);
        labellen = ASN1_STRING_get_length(parameter);
        if (labellen > INT_MAX)
            goto err;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_OAEP_PADDING) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set_rsa_oaep_md(pkctx, md) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkctx, mgf1md) <= 0)
        goto err;
    if (label != NULL) {
        unsigned char *dup_label = OPENSSL_memdup(label, labellen);

        if (dup_label == NULL)
            goto err;

        if (EVP_PKEY_CTX_set0_rsa_oaep_label(pkctx, dup_label, (int)labellen) <= 0) {
            OPENSSL_free(dup_label);
            goto err;
        }
    }
    /* Carry on */
    rv = 1;

err:
    RSA_OAEP_PARAMS_free(oaep);
    return rv;
}

static int rsa_cms_encrypt(CMS_RecipientInfo *ri)
{
    const EVP_MD *md, *mgf1md;
    RSA_OAEP_PARAMS *oaep = NULL;
    ASN1_STRING *os = NULL;
    ASN1_OCTET_STRING *los = NULL;
    X509_ALGOR *alg;
    EVP_PKEY_CTX *pkctx = CMS_RecipientInfo_get0_pkey_ctx(ri);
    int pad_mode = RSA_PKCS1_PADDING, rv = 0, labellen;
    unsigned char *label;

    if (CMS_RecipientInfo_ktri_get0_algs(ri, NULL, NULL, &alg) <= 0)
        return 0;
    if (pkctx != NULL) {
        if (EVP_PKEY_CTX_get_rsa_padding(pkctx, &pad_mode) <= 0)
            return 0;
    }
    if (pad_mode == RSA_PKCS1_PADDING)
        return X509_ALGOR_set0(alg, OBJ_nid2obj(NID_rsaEncryption),
            V_ASN1_NULL, NULL);

    /* Not supported */
    if (pad_mode != RSA_PKCS1_OAEP_PADDING)
        return 0;
    if (EVP_PKEY_CTX_get_rsa_oaep_md(pkctx, &md) <= 0)
        goto err;
    if (EVP_PKEY_CTX_get_rsa_mgf1_md(pkctx, &mgf1md) <= 0)
        goto err;
    labellen = EVP_PKEY_CTX_get0_rsa_oaep_label(pkctx, &label);
    if (labellen < 0)
        goto err;
    oaep = RSA_OAEP_PARAMS_new();
    if (oaep == NULL)
        goto err;
    if (!x509_algor_new_from_md(&oaep->hashFunc, md))
        goto err;
    if (!x509_algor_md_to_mgf1(&oaep->maskGenFunc, mgf1md))
        goto err;
    if (labellen > 0) {
        los = ASN1_OCTET_STRING_new();

        if (los == NULL)
            goto err;
        if (!ASN1_OCTET_STRING_set(los, label, labellen))
            goto err;

        oaep->pSourceFunc = x509_algor_from_nid(NID_pSpecified,
            V_ASN1_OCTET_STRING, los);
        if (oaep->pSourceFunc == NULL)
            goto err;

        los = NULL;
    }
    /* create string with oaep parameter encoding. */
    if (!ASN1_item_pack(oaep, ASN1_ITEM_rptr(RSA_OAEP_PARAMS), &os))
        goto err;
    if (!X509_ALGOR_set0(alg, OBJ_nid2obj(NID_rsaesOaep), V_ASN1_SEQUENCE, os))
        goto err;
    os = NULL;
    rv = 1;
err:
    RSA_OAEP_PARAMS_free(oaep);
    ASN1_STRING_free(os);
    ASN1_OCTET_STRING_free(los);
    return rv;
}

int ossl_cms_rsa_envelope(CMS_RecipientInfo *ri, int decrypt)
{
    assert(decrypt == 0 || decrypt == 1);

    if (decrypt == 1)
        return rsa_cms_decrypt(ri);

    if (decrypt == 0)
        return rsa_cms_encrypt(ri);

    ERR_raise(ERR_LIB_CMS, CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE);
    return 0;
}

static ASN1_STRING *rsa_cms_ctx_to_pss(EVP_PKEY_CTX *pkctx)
{
    EVP_PKEY *pk = EVP_PKEY_CTX_get0_pkey(pkctx);
    const EVP_MD *sigmd, *mgf1md;
    RSA_PSS_PARAMS *pss = NULL;
    ASN1_STRING *os = NULL;
    int saltlen, saltlen_max = -1, md_size;

    if (EVP_PKEY_CTX_get_signature_md(pkctx, &sigmd) <= 0)
        return NULL;
    md_size = EVP_MD_get_size(sigmd);
    if (md_size <= 0)
        return NULL;
    if (EVP_PKEY_CTX_get_rsa_mgf1_md(pkctx, &mgf1md) <= 0
        || EVP_PKEY_CTX_get_rsa_pss_saltlen(pkctx, &saltlen) <= 0)
        return NULL;
    if (saltlen == RSA_PSS_SALTLEN_DIGEST) {
        saltlen = md_size;
    } else if (saltlen == RSA_PSS_SALTLEN_AUTO_DIGEST_MAX) {
        /* Use at most the digest length, per FIPS 186-4 section 5.5. */
        saltlen = RSA_PSS_SALTLEN_MAX;
        saltlen_max = md_size;
    }
    if (saltlen == RSA_PSS_SALTLEN_MAX || saltlen == RSA_PSS_SALTLEN_AUTO) {
        saltlen = EVP_PKEY_get_size(pk) - md_size - 2;
        if ((EVP_PKEY_get_bits(pk) & 0x7) == 1)
            saltlen--;
        if (saltlen < 0)
            return NULL;
        if (saltlen_max >= 0 && saltlen > saltlen_max)
            saltlen = saltlen_max;
    }

    pss = RSA_PSS_PARAMS_new();
    if (pss == NULL)
        goto err;
    if (saltlen != 20) {
        pss->saltLength = ASN1_INTEGER_new();
        if (pss->saltLength == NULL
            || !ASN1_INTEGER_set(pss->saltLength, saltlen))
            goto err;
    }
    if (!x509_algor_new_from_md(&pss->hashAlgorithm, sigmd))
        goto err;
    if (mgf1md == NULL)
        mgf1md = sigmd;
    if (!x509_algor_md_to_mgf1(&pss->maskGenAlgorithm, mgf1md)
        || !x509_algor_new_from_md(&pss->maskHash, mgf1md))
        goto err;
    os = ASN1_item_pack(pss, ASN1_ITEM_rptr(RSA_PSS_PARAMS), NULL);
err:
    RSA_PSS_PARAMS_free(pss);
    return os;
}

static int rsa_cms_pss_to_ctx(EVP_PKEY_CTX *pkctx, const X509_ALGOR *alg)
{
    RSA_PSS_PARAMS *pss;
    const EVP_MD *md, *mgf1md, *checkmd;
    int saltlen, trailerfield, ret = 0;

    pss = ASN1_TYPE_unpack_sequence(ASN1_ITEM_rptr(RSA_PSS_PARAMS),
        alg->parameter);
    if (pss == NULL)
        goto err;
    if (pss->maskGenAlgorithm != NULL) {
        pss->maskHash = x509_algor_mgf1_decode(pss->maskGenAlgorithm);
        if (pss->maskHash == NULL)
            goto err;
    }
    md = x509_algor_get_md(pss->hashAlgorithm);
    mgf1md = x509_algor_get_md(pss->maskHash);
    if (md == NULL || mgf1md == NULL)
        goto err;
    saltlen = pss->saltLength != NULL ? ASN1_INTEGER_get(pss->saltLength) : 20;
    trailerfield = pss->trailerField != NULL
        ? ASN1_INTEGER_get(pss->trailerField)
        : 1;
    if (saltlen < 0) {
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_SALT_LENGTH);
        goto err;
    }
    if (trailerfield != 1) {
        ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_TRAILER);
        goto err;
    }
    if (EVP_PKEY_CTX_get_signature_md(pkctx, &checkmd) <= 0)
        goto err;
    if (EVP_MD_get_type(md) != EVP_MD_get_type(checkmd)) {
        ERR_raise(ERR_LIB_RSA, RSA_R_DIGEST_DOES_NOT_MATCH);
        goto err;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING) <= 0
        || EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, saltlen) <= 0
        || EVP_PKEY_CTX_set_rsa_mgf1_md(pkctx, mgf1md) <= 0)
        goto err;
    ret = 1;
err:
    RSA_PSS_PARAMS_free(pss);
    return ret;
}

static int rsa_cms_sign(CMS_SignerInfo *si)
{
    int pad_mode = RSA_PKCS1_PADDING;
    X509_ALGOR *alg;
    EVP_PKEY_CTX *pkctx = CMS_SignerInfo_get0_pkey_ctx(si);
    unsigned char aid[128];
    const unsigned char *pp = aid;
    size_t aid_len = 0;
    OSSL_PARAM params[2];

    CMS_SignerInfo_get0_algs(si, NULL, NULL, NULL, &alg);
    if (pkctx != NULL) {
        if (EVP_PKEY_CTX_get_rsa_padding(pkctx, &pad_mode) <= 0)
            return 0;
    }
    if (pad_mode == RSA_PKCS1_PADDING)
        return X509_ALGOR_set0(alg, OBJ_nid2obj(NID_rsaEncryption),
            V_ASN1_NULL, NULL);

    /* We don't support it */
    if (pad_mode != RSA_PKCS1_PSS_PADDING)
        return 0;

    if (EVP_PKEY_get0_provider(EVP_PKEY_CTX_get0_pkey(pkctx)) == NULL) {
        /* No provider -> we cannot query it for algorithm ID. */
        ASN1_STRING *os = rsa_cms_ctx_to_pss(pkctx);

        if (os == NULL)
            return 0;
        if (X509_ALGOR_set0(alg, OBJ_nid2obj(EVP_PKEY_RSA_PSS), V_ASN1_SEQUENCE,
                os))
            return 1;
        ASN1_STRING_free(os);
        return 0;
    }

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_SIGNATURE_PARAM_ALGORITHM_ID, aid, sizeof(aid));
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_get_params(pkctx, params) <= 0)
        return 0;
    if ((aid_len = params[0].return_size) == 0)
        return 0;
    if (d2i_X509_ALGOR(&alg, &pp, (long)aid_len) == NULL)
        return 0;
    return 1;
}

static int rsa_cms_verify(CMS_SignerInfo *si)
{
    int nid, nid2;
    X509_ALGOR *alg;
    EVP_PKEY_CTX *pkctx = CMS_SignerInfo_get0_pkey_ctx(si);
    EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(pkctx);

    CMS_SignerInfo_get0_algs(si, NULL, NULL, NULL, &alg);
    nid = OBJ_obj2nid(alg->algorithm);
    if (nid == EVP_PKEY_RSA_PSS)
        return rsa_cms_pss_to_ctx(pkctx, alg);
    /* Only PSS allowed for PSS keys */
    if (EVP_PKEY_is_a(pkey, "RSA-PSS")) {
        ERR_raise(ERR_LIB_RSA, RSA_R_ILLEGAL_OR_UNSUPPORTED_PADDING_MODE);
        return 0;
    }
    if (nid == NID_rsaEncryption)
        return 1;
    /* Workaround for some implementation that use a signature OID */
    if (OBJ_find_sigid_algs(nid, NULL, &nid2)) {
        if (nid2 == NID_rsaEncryption)
            return 1;
    }
    return 0;
}

int ossl_cms_rsa_sign(CMS_SignerInfo *si, int verify)
{
    assert(verify == 0 || verify == 1);

    if (verify == 1)
        return rsa_cms_verify(si);

    if (verify == 0)
        return rsa_cms_sign(si);

    ERR_raise(ERR_LIB_CMS, CMS_R_NOT_SUPPORTED_FOR_THIS_KEY_TYPE);
    return 0;
}
