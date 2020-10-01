/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Low level APIs are deprecated for public use, but still ok for internal use.
 */
#include "internal/deprecated.h"

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>      /* PKCS8_encrypt() */
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/ec.h>
#include "internal/passphrase.h"
#include "internal/cryptlib.h"
#include "crypto/ecx.h"
#include "crypto/rsa.h"
#include "prov/implementations.h"
#include "prov/providercommonerr.h"
#include "prov/bio.h"
#include "prov/provider_ctx.h"
#include "prov/der_rsa.h"
#include "endecoder_local.h"

struct key2any_ctx_st {
    PROV_CTX *provctx;

    /* Set to 1 if intending to encrypt/decrypt, otherwise 0 */
    int cipher_intent;

    EVP_CIPHER *cipher;

    struct ossl_passphrase_data_st pwdata;
};

typedef int check_key_type_fn(const void *key, int nid);
typedef int key_to_paramstring_fn(const void *key, int nid,
                                  void **str, int *strtype);
typedef int key_to_der_fn(BIO *out, const void *key, int key_nid,
                          key_to_paramstring_fn *p2s, i2d_of_void *k2d,
                          struct key2any_ctx_st *ctx);
typedef int write_bio_of_void_fn(BIO *bp, const void *x);

static PKCS8_PRIV_KEY_INFO *key_to_p8info(const void *key, int key_nid,
                                          void *params, int params_type,
                                          i2d_of_void *k2d)
{
    /* der, derlen store the key DER output and its length */
    unsigned char *der = NULL;
    int derlen;
    /* The final PKCS#8 info */
    PKCS8_PRIV_KEY_INFO *p8info = NULL;


    if ((p8info = PKCS8_PRIV_KEY_INFO_new()) == NULL
        || (derlen = k2d(key, &der)) <= 0
        || !PKCS8_pkey_set0(p8info, OBJ_nid2obj(key_nid), 0,
                            params_type, params, der, derlen)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        PKCS8_PRIV_KEY_INFO_free(p8info);
        OPENSSL_free(der);
        p8info = NULL;
    }

    return p8info;
}

static X509_SIG *p8info_to_encp8(PKCS8_PRIV_KEY_INFO *p8info,
                                 struct key2any_ctx_st *ctx)
{
    X509_SIG *p8 = NULL;
    char kstr[PEM_BUFSIZE];
    size_t klen = 0;

    if (ctx->cipher == NULL)
        return NULL;

    if (!ossl_pw_get_passphrase(kstr, sizeof(kstr), &klen, NULL, 1,
                                &ctx->pwdata)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_READ_KEY);
        return NULL;
    }
    /* First argument == -1 means "standard" */
    p8 = PKCS8_encrypt(-1, ctx->cipher, kstr, klen, NULL, 0, 0, p8info);
    OPENSSL_cleanse(kstr, klen);
    return p8;
}

static X509_SIG *key_to_encp8(const void *key, int key_nid,
                              void *params, int params_type,
                              i2d_of_void *k2d, struct key2any_ctx_st *ctx)
{
    PKCS8_PRIV_KEY_INFO *p8info =
        key_to_p8info(key, key_nid, params, params_type, k2d);
    X509_SIG *p8 = p8info_to_encp8(p8info, ctx);

    PKCS8_PRIV_KEY_INFO_free(p8info);
    return p8;
}

static X509_PUBKEY *key_to_pubkey(const void *key, int key_nid,
                                  void *params, int params_type,
                                  i2d_of_void k2d)
{
    /* der, derlen store the key DER output and its length */
    unsigned char *der = NULL;
    int derlen;
    /* The final X509_PUBKEY */
    X509_PUBKEY *xpk = NULL;


    if ((xpk = X509_PUBKEY_new()) == NULL
        || (derlen = k2d(key, &der)) <= 0
        || !X509_PUBKEY_set0_param(xpk, OBJ_nid2obj(key_nid),
                                   params_type, params, der, derlen)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        X509_PUBKEY_free(xpk);
        OPENSSL_free(der);
        xpk = NULL;
    }

    return xpk;
}

static int key_to_der_pkcs8_bio(BIO *out, const void *key, int key_nid,
                                key_to_paramstring_fn *p2s, i2d_of_void *k2d,
                                struct key2any_ctx_st *ctx)
{
    int ret = 0;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;

    if (p2s != NULL && !p2s(key, key_nid, &str, &strtype))
        return 0;

    if (ctx->cipher_intent) {
        X509_SIG *p8 = key_to_encp8(key, key_nid, str, strtype, k2d, ctx);

        if (p8 != NULL)
            ret = i2d_PKCS8_bio(out, p8);

        X509_SIG_free(p8);
    } else {
        PKCS8_PRIV_KEY_INFO *p8info =
            key_to_p8info(key, key_nid, str, strtype, k2d);

        if (p8info != NULL)
            ret = i2d_PKCS8_PRIV_KEY_INFO_bio(out, p8info);

        PKCS8_PRIV_KEY_INFO_free(p8info);
    }

    return ret;
}

static int key_to_pem_pkcs8_bio(BIO *out, const void *key, int key_nid,
                                key_to_paramstring_fn *p2s, i2d_of_void *k2d,
                                struct key2any_ctx_st *ctx)
{
    int ret = 0;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;

    if (p2s != NULL && !p2s(key, key_nid, &str, &strtype))
        return 0;

    if (ctx->cipher_intent) {
        X509_SIG *p8 = key_to_encp8(key, key_nid, str, strtype, k2d, ctx);

        if (p8 != NULL)
            ret = PEM_write_bio_PKCS8(out, p8);

        X509_SIG_free(p8);
    } else {
        PKCS8_PRIV_KEY_INFO *p8info =
            key_to_p8info(key, key_nid, str, strtype, k2d);

        if (p8info != NULL)
            ret = PEM_write_bio_PKCS8_PRIV_KEY_INFO(out, p8info);

        PKCS8_PRIV_KEY_INFO_free(p8info);
    }

    return ret;
}

static int key_to_der_pubkey_bio(BIO *out, const void *key, int key_nid,
                                 key_to_paramstring_fn *p2s, i2d_of_void *k2d,
                                 struct key2any_ctx_st *ctx)
{
    int ret = 0;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;
    X509_PUBKEY *xpk = NULL;

    if (p2s != NULL && !p2s(key, key_nid, &str, &strtype))
        return 0;

    xpk = key_to_pubkey(key, key_nid, str, strtype, k2d);

    if (xpk != NULL)
        ret = i2d_X509_PUBKEY_bio(out, xpk);

    /* Also frees |str| */
    X509_PUBKEY_free(xpk);
    return ret;
}

static int key_to_pem_pubkey_bio(BIO *out, const void *key, int key_nid,
                                 key_to_paramstring_fn *p2s, i2d_of_void *k2d,
                                 struct key2any_ctx_st *ctx)
{
    int ret = 0;
    void *str = NULL;
    int strtype = V_ASN1_UNDEF;
    X509_PUBKEY *xpk = NULL;

    if (p2s != NULL && !p2s(key, key_nid, &str, &strtype))
        return 0;

    xpk = key_to_pubkey(key, key_nid, str, strtype, k2d);

    if (xpk != NULL)
        ret = PEM_write_bio_X509_PUBKEY(out, xpk);

    /* Also frees |str| */
    X509_PUBKEY_free(xpk);
    return ret;
}

#define der_output_type         "DER"
#define pem_output_type         "PEM"

/* ---------------------------------------------------------------------- */

#ifndef OPENSSL_NO_DH
static int prepare_dh_params(const void *dh, int nid,
                             void **pstr, int *pstrtype)
{
    ASN1_STRING *params = ASN1_STRING_new();

    if (params == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (nid == EVP_PKEY_DHX)
        params->length = i2d_DHxparams(dh, &params->data);
    else
        params->length = i2d_DHparams(dh, &params->data);

    if (params->length <= 0) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        ASN1_STRING_free(params);
        return 0;
    }
    params->type = V_ASN1_SEQUENCE;

    *pstr = params;
    *pstrtype = V_ASN1_SEQUENCE;
    return 1;
}

static int dh_pub_to_der(const void *dh, unsigned char **pder)
{
    const BIGNUM *bn = NULL;
    ASN1_INTEGER *pub_key = NULL;
    int ret;

    if ((bn = DH_get0_pub_key(dh)) == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY);
        return 0;
    }
    if ((pub_key = BN_to_ASN1_INTEGER(bn, NULL)) == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BN_ERROR);
        return 0;
    }

    ret = i2d_ASN1_INTEGER(pub_key, pder);

    ASN1_STRING_clear_free(pub_key);
    return ret;
}

static int dh_priv_to_der(const void *dh, unsigned char **pder)
{
    const BIGNUM *bn = NULL;
    ASN1_INTEGER *priv_key = NULL;
    int ret;

    if ((bn = DH_get0_priv_key(dh)) == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        return 0;
    }
    if ((priv_key = BN_to_ASN1_INTEGER(bn, NULL)) == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BN_ERROR);
        return 0;
    }

    ret = i2d_ASN1_INTEGER(priv_key, pder);

    ASN1_STRING_clear_free(priv_key);
    return ret;
}

static int dh_params_to_der_bio(BIO *out, const void *key)
{
    int type =
        DH_test_flags(key, DH_FLAG_TYPE_DHX) ? EVP_PKEY_DHX : EVP_PKEY_DH;

    if (type == EVP_PKEY_DH)
        return i2d_DHparams_bio(out, key);
    return i2d_DHxparams_bio(out, key);
}

static int dh_params_to_pem_bio(BIO *out, const void *key)
{
    int type =
        DH_test_flags(key, DH_FLAG_TYPE_DHX) ? EVP_PKEY_DHX : EVP_PKEY_DH;

    if (type == EVP_PKEY_DH)
        return PEM_write_bio_DHparams(out, key);

    return PEM_write_bio_DHxparams(out, key);
}

static int dh_check_key_type(const void *key, int expected_type)
{
    int type =
        DH_test_flags(key, DH_FLAG_TYPE_DHX) ? EVP_PKEY_DHX : EVP_PKEY_DH;

    return type == expected_type;
}

# define dh_evp_type            EVP_PKEY_DH
# define dhx_evp_type           EVP_PKEY_DHX
# define dh_input_type          "DH"
# define dhx_input_type         "DHX"
#endif

/* ---------------------------------------------------------------------- */

#ifndef OPENSSL_NO_DSA
static int prepare_some_dsa_params(const void *dsa, int nid,
                                   void **pstr, int *pstrtype)
{
    ASN1_STRING *params = ASN1_STRING_new();

    if (params == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    params->length = i2d_DSAparams(dsa, &params->data);

    if (params->length <= 0) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        ASN1_STRING_free(params);
        return 0;
    }

    *pstrtype = V_ASN1_SEQUENCE;
    *pstr = params;
    return 1;
}

static int prepare_all_dsa_params(const void *dsa, int nid,
                                  void **pstr, int *pstrtype)
{
    const BIGNUM *p = DSA_get0_p(dsa);
    const BIGNUM *q = DSA_get0_q(dsa);
    const BIGNUM *g = DSA_get0_g(dsa);

    if (p != NULL && q != NULL && g != NULL)
        return prepare_some_dsa_params(dsa, nid, pstr, pstrtype);

    *pstr = NULL;
    *pstrtype = V_ASN1_UNDEF;
    return 1;
}

static int prepare_dsa_params(const void *dsa, int nid,
                              void **pstr, int *pstrtype)
{
    /*
     * TODO(v3.0) implement setting save_parameters, see dsa_pub_encode()
     * in crypto/dsa/dsa_ameth.c
     */
    int save_parameters = 1;

    return save_parameters
        ?  prepare_all_dsa_params(dsa, nid, pstr, pstrtype)
        :  prepare_some_dsa_params(dsa, nid, pstr, pstrtype);
}

static int dsa_pub_to_der(const void *dsa, unsigned char **pder)
{
    const BIGNUM *bn = NULL;
    ASN1_INTEGER *pub_key = NULL;
    int ret;

    if ((bn = DSA_get0_pub_key(dsa)) == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY);
        return 0;
    }
    if ((pub_key = BN_to_ASN1_INTEGER(bn, NULL)) == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BN_ERROR);
        return 0;
    }

    ret = i2d_ASN1_INTEGER(pub_key, pder);

    ASN1_STRING_clear_free(pub_key);
    return ret;
}

static int dsa_priv_to_der(const void *dsa, unsigned char **pder)
{
    const BIGNUM *bn = NULL;
    ASN1_INTEGER *priv_key = NULL;
    int ret;

    if ((bn = DSA_get0_priv_key(dsa)) == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        return 0;
    }
    if ((priv_key = BN_to_ASN1_INTEGER(bn, NULL)) == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BN_ERROR);
        return 0;
    }

    ret = i2d_ASN1_INTEGER(priv_key, pder);

    ASN1_STRING_clear_free(priv_key);
    return ret;
}

static int dsa_params_to_der_bio(BIO *out, const void *key)
{
    return i2d_DSAparams_bio(out, key);
}

static int dsa_params_to_pem_bio(BIO *out, const void *key)
{
    return PEM_write_bio_DSAparams(out, key);
}

# define dsa_check_key_type     NULL
# define dsa_evp_type           EVP_PKEY_DSA
# define dsa_input_type         "DSA"
#endif

/* ---------------------------------------------------------------------- */

#ifndef OPENSSL_NO_EC
static int prepare_ec_explicit_params(const void *eckey,
                                      void **pstr, int *pstrtype)
{
    ASN1_STRING *params = ASN1_STRING_new();

    if (params == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    params->length = i2d_ECParameters(eckey, &params->data);
    if (params->length <= 0) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        ASN1_STRING_free(params);
        return 0;
    }

    *pstrtype = V_ASN1_SEQUENCE;
    *pstr = params;
    return 1;
}

static int prepare_ec_params(const void *eckey, int nid,
                             void **pstr, int *pstrtype)
{
    int curve_nid;
    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    ASN1_OBJECT *params = NULL;

    if (group == NULL)
        return 0;
    curve_nid = EC_GROUP_get_curve_name(group);
    if (curve_nid != NID_undef) {
        params = OBJ_nid2obj(curve_nid);
        if (params == NULL)
            return 0;
    }

    if (curve_nid != NID_undef
        && (EC_GROUP_get_asn1_flag(group) & OPENSSL_EC_NAMED_CURVE)) {
        if (OBJ_length(params) == 0) {
            /* Some curves might not have an associated OID */
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_OID);
            ASN1_OBJECT_free(params);
            return 0;
        }
        *pstr = params;
        *pstrtype = V_ASN1_OBJECT;
        return 1;
    } else {
        return prepare_ec_explicit_params(eckey, pstr, pstrtype);
    }
}

static int ec_params_to_der_bio(BIO *out, const void *eckey)
{
    return i2d_ECPKParameters_bio(out, EC_KEY_get0_group(eckey));
}

static int ec_params_to_pem_bio(BIO *out, const void *eckey)
{
    return PEM_write_bio_ECPKParameters(out, EC_KEY_get0_group(eckey));
}

static int ec_pub_to_der(const void *eckey, unsigned char **pder)
{
    return i2o_ECPublicKey(eckey, pder);
}

static int ec_priv_to_der(const void *veckey, unsigned char **pder)
{
    EC_KEY *eckey = (EC_KEY *)veckey;
    unsigned int old_flags;
    int ret = 0;

    /*
     * For PKCS8 the curve name appears in the PKCS8_PRIV_KEY_INFO object
     * as the pkeyalg->parameter field. (For a named curve this is an OID)
     * The pkey field is an octet string that holds the encoded
     * ECPrivateKey SEQUENCE with the optional parameters field omitted.
     * We omit this by setting the EC_PKEY_NO_PARAMETERS flag.
     */
    old_flags = EC_KEY_get_enc_flags(eckey); /* save old flags */
    EC_KEY_set_enc_flags(eckey, old_flags | EC_PKEY_NO_PARAMETERS);
    ret = i2d_ECPrivateKey(eckey, pder);
    EC_KEY_set_enc_flags(eckey, old_flags); /* restore old flags */
    return ret; /* return the length of the der encoded data */
}

# define ec_check_key_type      NULL
# define ec_evp_type            EVP_PKEY_EC
# define ec_input_type          "EC"
#endif

/* ---------------------------------------------------------------------- */

#ifndef OPENSSL_NO_EC
# define prepare_ecx_params NULL

static int ecx_pub_to_der(const void *vecxkey, unsigned char **pder)
{
    const ECX_KEY *ecxkey = vecxkey;
    unsigned char *keyblob;

    if (ecxkey == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    keyblob = OPENSSL_memdup(ecxkey->pubkey, ecxkey->keylen);
    if (keyblob == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    *pder = keyblob;
    return ecxkey->keylen;
}

static int ecx_priv_to_der(const void *vecxkey, unsigned char **pder)
{
    const ECX_KEY *ecxkey = vecxkey;
    ASN1_OCTET_STRING oct;
    int keybloblen;

    if (ecxkey == NULL || ecxkey->privkey == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    oct.data = ecxkey->privkey;
    oct.length = ecxkey->keylen;
    oct.flags = 0;

    keybloblen = i2d_ASN1_OCTET_STRING(&oct, pder);
    if (keybloblen < 0) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    return keybloblen;
}

# define ecx_params_to_der_bio  NULL
# define ecx_params_to_pem_bio  NULL
# define ecx_check_key_type     NULL

# define ed25519_evp_type       EVP_PKEY_ED25519
# define ed448_evp_type         EVP_PKEY_ED448
# define x25519_evp_type        EVP_PKEY_X25519
# define x448_evp_type          EVP_PKEY_X448
# define ed25519_input_type     "ED25519"
# define ed448_input_type       "ED448"
# define x25519_input_type      "X25519"
# define x448_input_type        "X448"
#endif

/* ---------------------------------------------------------------------- */

/*
 * Helper functions to prepare RSA-PSS params for encoding.  We would
 * have simply written the whole AlgorithmIdentifier, but existing libcrypto
 * functionality doesn't allow that.
 */

static int prepare_rsa_params(const void *rsa, int nid,
                              void **pstr, int *pstrtype)
{
    const RSA_PSS_PARAMS_30 *pss = ossl_rsa_get0_pss_params_30((RSA *)rsa);

    *pstr = NULL;

    switch (RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK)) {
    case RSA_FLAG_TYPE_RSA:
        /* If plain RSA, the parameters shall be NULL */
        *pstrtype = V_ASN1_NULL;
        return 1;
    case RSA_FLAG_TYPE_RSASSAPSS:
        if (ossl_rsa_pss_params_30_is_unrestricted(pss)) {
            *pstrtype = V_ASN1_UNDEF;
            return 1;
        } else {
            ASN1_STRING *astr = NULL;
            WPACKET pkt;
            unsigned char *str = NULL;
            size_t str_sz = 0;
            int i;

            for (i = 0; i < 2; i++) {
                switch (i) {
                case 0:
                    if (!WPACKET_init_null_der(&pkt))
                        goto err;
                    break;
                case 1:
                    if ((str = OPENSSL_malloc(str_sz)) == NULL
                        || !WPACKET_init_der(&pkt, str, str_sz)) {
                        goto err;
                    }
                    break;
                }
                if (!ossl_DER_w_RSASSA_PSS_params(&pkt, -1, pss)
                    || !WPACKET_finish(&pkt)
                    || !WPACKET_get_total_written(&pkt, &str_sz))
                    goto err;
                WPACKET_cleanup(&pkt);

                /*
                 * If no PSS parameters are going to be written, there's no
                 * point going for another iteration.
                 * This saves us from getting |str| allocated just to have it
                 * immediately de-allocated.
                 */
                if (str_sz == 0)
                    break;
            }

            if ((astr = ASN1_STRING_new()) == NULL)
                goto err;
            *pstrtype = V_ASN1_SEQUENCE;
            ASN1_STRING_set0(astr, str, (int)str_sz);
            *pstr = astr;

            return 1;
         err:
            OPENSSL_free(str);
            return 0;
        }
    }

    /* Currently unsupported RSA key type */
    return 0;
}

#define rsa_params_to_der_bio   NULL
#define rsa_params_to_pem_bio   NULL
#define rsa_priv_to_der         (i2d_of_void *)i2d_RSAPrivateKey
#define rsa_pub_to_der          (i2d_of_void *)i2d_RSAPublicKey

static int rsa_check_key_type(const void *rsa, int expected_type)
{
    switch (RSA_test_flags(rsa, RSA_FLAG_TYPE_MASK)) {
    case RSA_FLAG_TYPE_RSA:
        return expected_type == EVP_PKEY_RSA;
    case RSA_FLAG_TYPE_RSASSAPSS:
        return expected_type == EVP_PKEY_RSA_PSS;
    }

    /* Currently unsupported RSA key type */
    return EVP_PKEY_NONE;
}

#define rsa_evp_type            EVP_PKEY_RSA
#define rsapss_evp_type         EVP_PKEY_RSA_PSS
#define rsa_input_type          "RSA"
#define rsapss_input_type       "RSA-PSS"

/* ---------------------------------------------------------------------- */

static OSSL_FUNC_decoder_newctx_fn key2any_newctx;
static OSSL_FUNC_decoder_freectx_fn key2any_freectx;
static OSSL_FUNC_decoder_gettable_params_fn key2any_gettable_params;

static void *key2any_newctx(void *provctx)
{
    struct key2any_ctx_st *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL)
        ctx->provctx = provctx;

    return ctx;
}

static void key2any_freectx(void *vctx)
{
    struct key2any_ctx_st *ctx = vctx;

    ossl_pw_clear_passphrase_data(&ctx->pwdata);
    EVP_CIPHER_free(ctx->cipher);
    OPENSSL_free(ctx);
}

static const OSSL_PARAM *key2any_gettable_params(void *provctx)
{
    static const OSSL_PARAM gettables[] = {
        { OSSL_ENCODER_PARAM_OUTPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        OSSL_PARAM_END,
    };

    return gettables;
}

static int key2any_get_params(OSSL_PARAM params[], const char *input_type,
                              const char *output_type)
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_ENCODER_PARAM_INPUT_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, input_type))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_ENCODER_PARAM_OUTPUT_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, output_type))
        return 0;

    return 1;
}

static const OSSL_PARAM *key2any_settable_ctx_params(ossl_unused void *provctx)
{
    static const OSSL_PARAM settables[] = {
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_ENCODER_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END,
    };

    return settables;
}

static int key2any_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct key2any_ctx_st *ctx = vctx;
    OPENSSL_CTX *libctx = ossl_prov_ctx_get0_library_context(ctx->provctx);
    const OSSL_PARAM *cipherp =
        OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_CIPHER);
    const OSSL_PARAM *propsp =
        OSSL_PARAM_locate_const(params, OSSL_ENCODER_PARAM_PROPERTIES);

    if (cipherp != NULL) {
        const char *ciphername = NULL;
        const char *props = NULL;

        if (!OSSL_PARAM_get_utf8_string_ptr(cipherp, &ciphername))
            return 0;
        if (propsp != NULL && !OSSL_PARAM_get_utf8_string_ptr(propsp, &props))
            return 0;

        EVP_CIPHER_free(ctx->cipher);
        ctx->cipher_intent = ciphername != NULL;
        if (ciphername != NULL
            && ((ctx->cipher =
                 EVP_CIPHER_fetch(libctx, ciphername, props)) == NULL))
            return 0;
    }
    return 1;
}

static int key2any_encode(struct key2any_ctx_st *ctx, OSSL_CORE_BIO *cout,
                          const void *key, int type,
                          check_key_type_fn *checker,
                          key_to_der_fn *writer,
                          OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg,
                          key_to_paramstring_fn *key2paramstring,
                          i2d_of_void *key2der)
{
    int ret = 0;

    if (key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
    } else if (checker == NULL || checker(key, type)) {
        BIO *out = bio_new_from_core_bio(ctx->provctx, cout);

        if (out != NULL
            && writer != NULL
            && ossl_pw_set_ossl_passphrase_cb(&ctx->pwdata, cb, cbarg))
            ret = writer(out, key, type, key2paramstring, key2der, ctx);

        BIO_free(out);
    } else {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
    }
    return ret;
}

static int key2any_encode_params(struct key2any_ctx_st *ctx,
                                 OSSL_CORE_BIO *cout,
                                 const void *key, int type,
                                 check_key_type_fn *checker,
                                 write_bio_of_void_fn *writer)
{
    int ret = 0;

    if (key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
    } else if (checker == NULL || checker(key, type)) {
        BIO *out = bio_new_from_core_bio(ctx->provctx, cout);

        if (out != NULL && writer != NULL)
            ret = writer(out, key);

        BIO_free(out);
    } else {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
    }

    return ret;
}

#define MAKE_ENCODER(impl, type, evp_type, output)                          \
    static OSSL_FUNC_encoder_get_params_fn                                  \
    impl##2##output##_get_params;                                           \
    static OSSL_FUNC_encoder_import_object_fn                               \
    impl##2##output##_import_object;                                        \
    static OSSL_FUNC_encoder_free_object_fn                                 \
    impl##2##output##_free_object;                                          \
    static OSSL_FUNC_encoder_encode_fn impl##2##output##_encode;            \
                                                                            \
    static int impl##2##output##_get_params(OSSL_PARAM params[])            \
    {                                                                       \
        return key2any_get_params(params, impl##_input_type,                \
                                  output##_output_type);                    \
    }                                                                       \
    static void *                                                           \
    impl##2##output##_import_object(void *vctx, int selection,              \
                                    const OSSL_PARAM params[])              \
    {                                                                       \
        struct key2any_ctx_st *ctx = vctx;                                  \
        return ossl_prov_import_key(ossl_##impl##_keymgmt_functions,        \
                                    ctx->provctx, selection, params);       \
    }                                                                       \
    static void impl##2##output##_free_object(void *key)                    \
    {                                                                       \
        ossl_prov_free_key(ossl_##impl##_keymgmt_functions, key);           \
    }                                                                       \
    static int                                                              \
    impl##2##output##_encode(void *ctx, OSSL_CORE_BIO *cout,                \
                             const void *key,                               \
                             const OSSL_PARAM key_abstract[],               \
                             int selection,                                 \
                             OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)     \
    {                                                                       \
        /* We don't deal with abstract objects */                           \
        if (key_abstract != NULL) {                                         \
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);         \
            return 0;                                                       \
        }                                                                   \
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)             \
            return key2any_encode(ctx, cout, key, impl##_evp_type,          \
                                  type##_check_key_type,                    \
                                  key_to_##output##_pkcs8_bio,              \
                                  cb, cbarg,                                \
                                  prepare_##type##_params,                  \
                                  type##_priv_to_der);                      \
        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)              \
            return key2any_encode(ctx, cout, key, impl##_evp_type,          \
                                  type##_check_key_type,                    \
                                  key_to_##output##_pubkey_bio,             \
                                  cb, cbarg,                                \
                                  prepare_##type##_params,                  \
                                  type##_pub_to_der);                       \
        if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0)          \
            return key2any_encode_params(ctx, cout, key,                    \
                                         impl##_evp_type,                   \
                                         type##_check_key_type,             \
                                         type##_params_to_##output##_bio);  \
                                                                            \
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);             \
        return 0;                                                           \
    }                                                                       \
    const OSSL_DISPATCH ossl_##impl##_to_##output##_encoder_functions[] = { \
        { OSSL_FUNC_ENCODER_NEWCTX,                                         \
          (void (*)(void))key2any_newctx },                                 \
        { OSSL_FUNC_ENCODER_FREECTX,                                        \
          (void (*)(void))key2any_freectx },                                \
        { OSSL_FUNC_ENCODER_GETTABLE_PARAMS,                                \
          (void (*)(void))key2any_gettable_params },                        \
        { OSSL_FUNC_ENCODER_GET_PARAMS,                                     \
          (void (*)(void))impl##2##output##_get_params },                   \
        { OSSL_FUNC_ENCODER_SETTABLE_CTX_PARAMS,                            \
          (void (*)(void))key2any_settable_ctx_params },                    \
        { OSSL_FUNC_ENCODER_SET_CTX_PARAMS,                                 \
          (void (*)(void))key2any_set_ctx_params },                         \
        { OSSL_FUNC_ENCODER_IMPORT_OBJECT,                                  \
          (void (*)(void))impl##2##output##_import_object },                \
        { OSSL_FUNC_ENCODER_FREE_OBJECT,                                    \
          (void (*)(void))impl##2##output##_free_object },                  \
        { OSSL_FUNC_ENCODER_ENCODE,                                         \
          (void (*)(void))impl##2##output##_encode },                       \
        { 0, NULL }                                                         \
    }

#ifndef OPENSSL_NO_DH
MAKE_ENCODER(dh, dh, EVP_PKEY_DH, der);
MAKE_ENCODER(dh, dh, EVP_PKEY_DH, pem);
MAKE_ENCODER(dhx, dh, EVP_PKEY_DHX, der);
MAKE_ENCODER(dhx, dh, EVP_PKEY_DHX, pem);
#endif
#ifndef OPENSSL_NO_DSA
MAKE_ENCODER(dsa, dsa, EVP_PKEY_DSA, der);
MAKE_ENCODER(dsa, dsa, EVP_PKEY_DSA, pem);
#endif
#ifndef OPENSSL_NO_EC
MAKE_ENCODER(ec, ec, EVP_PKEY_EC, der);
MAKE_ENCODER(ec, ec, EVP_PKEY_EC, pem);
MAKE_ENCODER(ed25519, ecx, EVP_PKEY_ED25519, der);
MAKE_ENCODER(ed25519, ecx, EVP_PKEY_ED25519, pem);
MAKE_ENCODER(ed448, ecx, EVP_PKEY_ED448, der);
MAKE_ENCODER(ed448, ecx, EVP_PKEY_ED448, pem);
MAKE_ENCODER(x25519, ecx, EVP_PKEY_X25519, der);
MAKE_ENCODER(x25519, ecx, EVP_PKEY_X25519, pem);
MAKE_ENCODER(x448, ecx, EVP_PKEY_ED448, der);
MAKE_ENCODER(x448, ecx, EVP_PKEY_ED448, pem);
#endif
MAKE_ENCODER(rsa, rsa, EVP_PKEY_RSA, der);
MAKE_ENCODER(rsa, rsa, EVP_PKEY_RSA, pem);
MAKE_ENCODER(rsapss, rsa, EVP_PKEY_RSA, der);
MAKE_ENCODER(rsapss, rsa, EVP_PKEY_RSA, pem);
