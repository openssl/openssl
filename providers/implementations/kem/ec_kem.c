/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * The following implementation is part of RFC 9180 related to DHKEM using
 * EC keys (i.e. 256, P-384 and P-521)
 * References to Sections in the comments below refer to RFC 9180.
 */

#include "internal/deprecated.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/kdf.h>
#include "prov/provider_ctx.h"
#include "prov/implementations.h"
#include "prov/securitycheck.h"
#include "prov/providercommon.h"

#include "crypto/hpke.h"
#include "crypto/ec.h"
#include "prov/ec.h"
#include "eckem.h"

static OSSL_FUNC_kem_newctx_fn eckem_newctx;
static OSSL_FUNC_kem_encapsulate_init_fn eckem_encapsulate_init;
static OSSL_FUNC_kem_encapsulate_fn eckem_encapsulate;
static OSSL_FUNC_kem_decapsulate_init_fn eckem_decapsulate_init;
static OSSL_FUNC_kem_decapsulate_fn eckem_decapsulate;
static OSSL_FUNC_kem_freectx_fn eckem_freectx;
static OSSL_FUNC_kem_dupctx_fn eckem_dupctx;
static OSSL_FUNC_kem_get_ctx_params_fn eckem_get_ctx_params;
static OSSL_FUNC_kem_gettable_ctx_params_fn eckem_gettable_ctx_params;
static OSSL_FUNC_kem_set_ctx_params_fn eckem_set_ctx_params;
static OSSL_FUNC_kem_settable_ctx_params_fn eckem_settable_ctx_params;
static OSSL_FUNC_kem_set_auth_fn eckem_set_auth;
static OSSL_FUNC_kem_derivekey_init_fn eckem_derivekey_init;
static OSSL_FUNC_kem_derivekey_fn eckem_derivekey;

typedef struct {
    const OSSL_HPKE_KEM_ALG *alg;
    EC_KEY *key;
    EC_KEY *authkey;
    OSSL_LIB_CTX *libctx;
    char *propq;
    unsigned char *ikm;
    size_t ikmlen;
    unsigned int mode;
    unsigned int op;

} PROV_EC_CTX;

static const char *supported_curves[] = {
    "P-256",
    "P-384",
    "P-521",
    NULL
};

/* If there is a private key, check that is non zero (mod order) */
static int eckey_privkeycheck(const EC_KEY *ec)
{
    int rv = 0;
    BN_CTX *bnctx = NULL;
    BIGNUM *rem = NULL;
    const BIGNUM *priv = EC_KEY_get0_private_key(ec);

    if (priv == NULL) {
        return 1;
    } else {
        const EC_GROUP *group = EC_KEY_get0_group(ec);
        const BIGNUM *order = EC_GROUP_get0_order(group);

        bnctx = BN_CTX_new_ex(ossl_ec_key_get_libctx(ec));
        rem = BN_new();

        if (order != NULL && rem != NULL && bnctx != NULL) {
             rv = BN_mod(rem, priv, order, bnctx)
                  && !BN_is_zero(rem);
        }
    }
    BN_free(rem);
    BN_CTX_free(bnctx);
    return rv;
}

/* Returns 1 if the group and private key are valid */
static int eckem_check_key(const EC_KEY *ec)
{
    int i, nid;
    const char *curve_name;
    const EC_GROUP *group = EC_KEY_get0_group(ec);

    if (group == NULL) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_CURVE, "No group");
        return 0;
    }
    nid = EC_GROUP_get_curve_name(group);
    if (nid == NID_undef) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_CURVE,
                       "Explicit curves are not allowed");
        return 0;
    }
    curve_name = EC_curve_nid2nist(nid);
    if (curve_name == NULL) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_CURVE,
                       "Curve %s is not approved in FIPS mode", curve_name);
        return 0;
    }
    if (!eckey_privkeycheck(ec))
        return 0;
    for (i = 0; supported_curves[i] != NULL; ++i) {
        if (OPENSSL_strcasecmp(curve_name, supported_curves[i]) == 0)
            return 1;
    }
    ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_CURVE,
                   "Curve %s is not supported", curve_name);

    return 0;
}

/* return kem info associated with a EC curve name or NULL if not supported */
static const OSSL_HPKE_KEM_ALG *find_kem_alg(EC_KEY *key)
{
    int nid;
    const char *curve = NULL;

    nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(key));
    curve = EC_curve_nid2nist(nid);
    if (curve == NULL)
        return NULL;

    return ossl_hpke_get_kemalg("EC", curve, NULL, NULL);
}

/*
 * Set the recipient key, and free any existing key.
 * ec can be NULL. The ec key may have only a private or public component.
 */
static int setkey(PROV_EC_CTX *ctx, EC_KEY *ec)
{
    EC_KEY_free(ec);
    ctx->key = ec;
    return ec == NULL;
}

/*
 * Set the senders auth key, and free any existing auth key.
 * ec can be NULL.
 */
static int setauthkey(PROV_EC_CTX *ctx, EC_KEY *ec)
{
    EC_KEY_free(ctx->authkey);
    ctx->authkey = ec;
    return ec == NULL;
}

/*
 * Serialize a new EC key from byte array's for the encoded public & private keys.
 * ctx is used to access the curvename from the recipient key.
 * privbuf or pubbuf may be NULL.
 * Returns: The created EC_KEY or NULL on error.
 */
static EC_KEY *eckey_fromdata(PROV_EC_CTX *ctx,
                              const unsigned char *privbuf, size_t privbuflen,
                              const unsigned char *pubbuf, size_t pubbuflen,
                              BIGNUM *priv, BN_CTX *bnctx)
{
    EC_KEY *ec = NULL;
    const EC_GROUP *group = EC_KEY_get0_group(ctx->key);

    ec = EC_KEY_new_by_curve_name_ex(ctx->libctx, ctx->propq,
                                     EC_GROUP_get_curve_name(group));
    if (privbuf != NULL && !EC_KEY_oct2priv(ec, privbuf, privbuflen))
        goto err;
    if (priv != NULL && !ossl_ec_set_public_key(ec, priv, bnctx))
        goto err;
    if (pubbuf != NULL &&!EC_KEY_oct2key(ec, pubbuf, pubbuflen, bnctx))
        goto err;
    return ec;
err:
   EC_KEY_free(ec);
   return NULL;
}

/*
 * Deserialises a EC private key into a encoded byte array.
 * Returns: 1 if successful or 0 otherwise.
 */
static int ecprivkey_todata(const EC_KEY *ec, unsigned char *out, size_t *outlen,
                            size_t maxoutlen)
{
    *outlen = EC_KEY_priv2oct(ec, out, maxoutlen);
    return *outlen != 0;
}

/*
 * Deserialises a EC public key into a encoded byte array.
 * Returns: 1 if successful or 0 otherwise.
 */
static int ecpubkey_todata(EC_KEY *ec, unsigned char *out, size_t *outlen,
                           size_t maxoutlen)
{
    *outlen = EC_POINT_point2oct(EC_KEY_get0_group(ec),
                                 EC_KEY_get0_public_key(ec),
                                 POINT_CONVERSION_UNCOMPRESSED,
                                 out, maxoutlen, NULL);
    return *outlen != 0;
}

static void *eckem_newctx(void *provctx)
{
    PROV_EC_CTX *ctx =  OPENSSL_zalloc(sizeof(PROV_EC_CTX));

    if (ctx == NULL)
        return NULL;
    ctx->libctx = PROV_LIBCTX_OF(provctx);

    return ctx;
}

static void eckem_freectx(void *vectx)
{
    PROV_EC_CTX *ctx = (PROV_EC_CTX *)vectx;

    OPENSSL_clear_free(ctx->ikm, ctx->ikmlen);
    setkey(ctx, NULL);
    setauthkey(ctx, NULL);
    OPENSSL_free(ctx);
}

static void *eckem_dupctx(void *vctx)
{
    return NULL;
}

static int eckem_init(void *vctx, void *vec,
                      ossl_unused const OSSL_PARAM params[], int operation)
{
    PROV_EC_CTX *ctx = (PROV_EC_CTX *)vctx;
    EC_KEY *ec = vec;

    if (!ossl_prov_is_running())
        return 0;

    if (ctx == NULL || ec == NULL)
        return 0;
    if (!eckem_check_key(ec))
        return 0;
    if (!EC_KEY_up_ref(ec))
        return 0;

    setkey(ctx, ec);
    setauthkey(ctx, NULL);

    ctx->op = operation;
    ctx->alg = find_kem_alg(ec);
    if (ctx->alg == NULL) {
        setkey(ctx, NULL);
        return 0;
    }
    return eckem_set_ctx_params(vctx, params);
}

static int eckem_encapsulate_init(void *vctx, void *vec,
                                   const OSSL_PARAM params[])
{
    return eckem_init(vctx, vec, params, EVP_PKEY_OP_ENCAPSULATE);
}

static int eckem_decapsulate_init(void *vctx, void *vec,
                                   const OSSL_PARAM params[])
{
    return eckem_init(vctx, vec, params, EVP_PKEY_OP_DECAPSULATE);
}

static int eckem_derivekey_init(void *vctx, void *vec,
                                const OSSL_PARAM params[])
{
    return eckem_init(vctx, vec, params, EVP_PKEY_OP_KEMDERIVE);
}

static int eckem_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    PROV_EC_CTX *ctx = (PROV_EC_CTX *)vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_KEM_PARAM_ID);
    if (p != NULL) {
        unsigned int kemid = ctx->alg->kemid;

        return OSSL_PARAM_set_uint(p, kemid);
    }
    return 0;
}

static const OSSL_PARAM known_gettable_eckem_ctx_params[] = {
    OSSL_PARAM_uint(OSSL_KEM_PARAM_ID, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *eckem_gettable_ctx_params(ossl_unused void *vctx,
                                                   ossl_unused void *provctx)
{
    return known_gettable_eckem_ctx_params;
}

static int eckem_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_EC_CTX *ctx = (PROV_EC_CTX *)vctx;
    const OSSL_PARAM *p;
    int mode;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_KEM_PARAM_IKME);
    if (p != NULL) {
        void *tmp = NULL;
        size_t tmplen = 0;

        if (p->data != NULL && p->data_size != 0) {
            if (!OSSL_PARAM_get_octet_string(p, &tmp, 0, &tmplen))
                return 0;
        }
        OPENSSL_clear_free(ctx->ikm, ctx->ikmlen);
        /* Set the ephemeral seed */
        ctx->ikm = tmp;
        ctx->ikmlen = tmplen;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KEM_PARAM_OPERATION);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        mode = ossl_ecdhkem_modename2id(p->data);
        if (mode < 0)
            return 0;
        ctx->mode = mode;
    }
    return 1;
}

static const OSSL_PARAM known_settable_eckem_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_KEM_PARAM_OPERATION, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KEM_PARAM_IKME, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *eckem_settable_ctx_params(ossl_unused void *vctx,
                                                    ossl_unused void *provctx)
{
    return known_settable_eckem_ctx_params;
}

/*
 * See Section 4.1 DH-Based KEM (DHKEM) ExtractAndExpand
 */
static int dhkem_extract_and_expand(EVP_KDF_CTX *kctx,
                                    unsigned char *okm, size_t okmlen,
                                    uint16_t kemid,
                                    const unsigned char *dhkm, size_t dhkmlen,
                                    const unsigned char *kemctx,
                                    size_t kemctxlen)
{
    /* suite_id = concat("KEM", I2OSP(kem_id, 2)) */
    uint8_t suiteid[5] = {'K', 'E', 'M', kemid >> 8, kemid & 0xff };
    uint8_t prk[EVP_MAX_MD_SIZE];
    size_t prklen = dhkmlen;
    int ret;

    if (prklen > sizeof(prk))
        return 0;

    ret = ossl_hpke_labeled_extract(kctx, prk, prklen,
                                    NULL, 0, suiteid, sizeof(suiteid),
                                    "eae_prk", dhkm, dhkmlen)
          && ossl_hpke_labeled_expand(kctx, okm, okmlen, prk, prklen,
                                      suiteid, sizeof(suiteid),
                                      "shared_secret", kemctx, kemctxlen);
    OPENSSL_cleanse(prk, prklen);
    return ret;
}

/*
 * See Section 7.1.3 DeriveKeyPair
 */
static EC_KEY *derivekey(PROV_EC_CTX *ctx,
                         const unsigned char *ikm, size_t ikmlen)
{
    uint16_t kemid = ctx->alg->kemid;
    EVP_KDF_CTX *kdfctx = NULL;
    uint8_t suiteid[5] = {'K', 'E', 'M', kemid >> 8, kemid & 0xff };
    unsigned char prk[EVP_MAX_KEY_LENGTH];
    unsigned char privbuf[EVP_MAX_KEY_LENGTH];
    size_t privbuflen = ctx->alg->secretlen; /* Nsk */
    BIGNUM *priv = NULL;
    EC_KEY *ec;
    const EC_GROUP *group = EC_KEY_get0_group(ctx->key);
    const BIGNUM *order = EC_GROUP_get0_order(group);
    unsigned char counter = 0;
    BN_CTX *bnctx = NULL;

    kdfctx = ossl_kdf_ctx_create(ctx->alg->kdfname, ctx->alg->kdfdigestname,
                                 ctx->libctx, ctx->propq);
    if (kdfctx == NULL)
        return 0;

    priv = BN_secure_new();
    if (priv == NULL)
        goto err;

    /* ikmlen should have a length of at least Nsk */
    if (ikmlen < privbuflen)
        goto err;

    if (!ossl_hpke_labeled_extract(kdfctx, prk, privbuflen,
                                   NULL, 0, suiteid, sizeof(suiteid),
                                   "dkp_prk", ikm, ikmlen))
        goto err;

    do {
        if (!ossl_hpke_labeled_expand(kdfctx, privbuf, privbuflen,
                                      prk, privbuflen,
                                      suiteid, sizeof(suiteid),
                                      "candidate", &counter, 1))
            goto err;
        privbuf[0] &= ctx->alg->bitmask;
        if (BN_bin2bn(privbuf, privbuflen, priv) == NULL)
            goto err;
        if (counter == 0xFF) {
//            "Raise DeriveKeyPairError"
            goto err;
        }
        counter++;
    } while (BN_is_zero(priv) || BN_cmp(priv, order) >= 0);

    bnctx = BN_CTX_secure_new_ex(ctx->libctx);
    if (bnctx == NULL)
        goto err;
    ec = eckey_fromdata(ctx, privbuf, privbuflen, NULL, 0, priv, bnctx);
err:
    BN_CTX_free(bnctx);
    OPENSSL_cleanse(prk, sizeof(prk));
    OPENSSL_cleanse(privbuf, sizeof(privbuf));
    EVP_KDF_CTX_free(kdfctx);
    BN_clear_free(priv);
    return ec;
}

/*
 * Generate a ec keypair from a seed value and return the keypair as encoded bytes
 * Returns 1 if successful or 0 otherwise.
 */
static int hpke_derivekey(PROV_EC_CTX *ctx,
                          unsigned char *pub, size_t *publen,
                          unsigned char *priv, size_t *privlen,
                          const unsigned char *ikm, size_t ikmlen)
{
    int ret = 0;
    EC_KEY *ec = NULL;

    ec = derivekey(ctx, ikm, ikmlen);
    if (ec == NULL)
        goto err;
    if (!ecpubkey_todata(ec, pub, publen, *publen)
            || !ecprivkey_todata(ec, priv, privlen, *privlen))
        goto err;
    EC_KEY_free(ec);
    ret = 1;
 err:
    return ret;
}

/*
 * Before doing a key exchange the public key of the peer needs to be checked
 * Note that the group check is not done here as we have already checked
 * that it only uses one of the approved curve names when the key was set.
 *
 * Returns 1 if the public key is valid, or 0 if it fails.
 */
static int check_publickey(EC_KEY *pub)
{
    int ret = 0;
    BN_CTX *bnctx = BN_CTX_new_ex(ossl_ec_key_get_libctx(pub));

    if (bnctx == NULL)
        return 0;
    ret = ossl_ec_key_public_check(pub, bnctx);
    BN_CTX_free(bnctx);

    return ret;
}

/*
 * Do an ecdh key exchange.
 * This is either dhkm = concat(DH(sender, peer), DH(auth, peer)) or
 *                dhkm = DH(sender, peer) if auth is NULL.
 * i.e. The generated secret is twice as long if there is an auth key.
 *
 * NOTE: Instead of using EVP_PKEY_derive() API's, we use EC_KEY operations
 *       to avoid messy conversions back to EVP_PKEY.
 *
 * Returns the size of the secret if successful, or 0 otherwise,
 */
static int generate_ecdhkm(EC_KEY *sender, EC_KEY *peer, EC_KEY *auth,
                           unsigned char *dhkm, size_t dhkmlen,
                           unsigned int secretsz)
{
    const EC_GROUP *group = EC_KEY_get0_group(sender);
    size_t secretlen = (EC_GROUP_get_degree(group) + 7) / 8;
    size_t retsecretlen = (auth != NULL ? 2 * secretlen : secretlen);

    if (secretlen != secretsz || dhkmlen < retsecretlen)
        return 0;

    if (!check_publickey(peer)) {
        //"KeyValidationError"
        return 0;
    }
    if (ECDH_compute_key(dhkm, secretlen, EC_KEY_get0_public_key(peer),
                         sender, NULL) == 0)
        return 0;
    if (auth != NULL) {
        if (ECDH_compute_key(dhkm + secretlen, dhkmlen - secretlen,
                             EC_KEY_get0_public_key(peer), auth, NULL) == 0)
            return 0;
    }
    return retsecretlen;
}

/*
 * See Section 4.1 Encap()
 */
static int hpke_encap(PROV_EC_CTX *ctx,
                      unsigned char *enc, size_t *enclen,
                      unsigned char *secret, size_t *secretlen)
{
    int ret = 0;
    EVP_KDF_CTX *kdfctx = NULL;
    unsigned char kemctx[OSSL_HPKE_MAX_PUBLIC * 2];
    unsigned char dhkm[OSSL_HPKE_MAX_SECRET * 2];
    EC_KEY *senderkey = NULL;
    size_t senderpublen, peerpublen, kemctxlen, dhkmlen;
    unsigned char senderpub[OSSL_HPKE_MAX_PUBLIC];
    unsigned char peerpub[OSSL_HPKE_MAX_PUBLIC];

    if (*secretlen < ctx->alg->secretlen)
        return 0;

    kdfctx = ossl_kdf_ctx_create(ctx->alg->kdfname, ctx->alg->kdfdigestname,
                                 ctx->libctx, ctx->propq);
    if (kdfctx == NULL)
        return 0;

    /* Create an ephemeral key */
    senderkey = derivekey(ctx, ctx->ikm, ctx->ikmlen);
    if (senderkey == NULL)
        goto err;
    if (!ecpubkey_todata(senderkey, senderpub, &senderpublen, sizeof(senderpub))
            || !ecpubkey_todata(ctx->key, peerpub, &peerpublen, sizeof(peerpub)))
        goto err;

    kemctxlen = senderpublen + peerpublen;
    if (senderpublen != ctx->alg->encodedpublen
            || peerpublen != senderpublen
            || kemctxlen > sizeof(kemctx))
        goto err;

    dhkmlen = generate_ecdhkm(senderkey, ctx->key, ctx->authkey,
                              dhkm, sizeof(dhkm), ctx->alg->secretlen);
    if (dhkmlen == 0)
        goto err;

    /* kemctx is the concat of both sides encoded public key */
    memcpy(kemctx, senderpub, senderpublen);
    memcpy(kemctx + senderpublen, peerpub, peerpublen);
    if (!dhkem_extract_and_expand(kdfctx, secret, ctx->alg->secretlen,
                                  ctx->alg->kemid, dhkm, dhkmlen,
                                  kemctx, kemctxlen))
        goto err;
    memcpy(enc, senderpub, senderpublen);
    *enclen = senderpublen;
    *secretlen = ctx->alg->secretlen;
    ret = 1;
err:
    EC_KEY_free(senderkey);
    EVP_KDF_CTX_free(kdfctx);
    return ret;
}

/*
 * See Section 4.1 Dencap()
 */
static int hpke_decap(PROV_EC_CTX *ctx,
                      unsigned char *secret, size_t *secretlen,
                      const unsigned char *enc, size_t enclen)
{
    int ret = 0;
    EVP_KDF_CTX *kdfctx = NULL;
    EC_KEY *peerkey = NULL;
    unsigned char kemctx[OSSL_HPKE_MAX_PUBLIC * 2];
    unsigned char dhkm[OSSL_HPKE_MAX_SECRET];
    unsigned char recipientpub[OSSL_HPKE_MAX_PUBLIC];
    size_t recipientpublen, kemctxlen, dhkmlen;

    if (*secretlen < ctx->alg->secretlen)
        return 0;

    kdfctx = ossl_kdf_ctx_create(ctx->alg->kdfname, ctx->alg->kdfdigestname,
                                 ctx->libctx, ctx->propq);
    if (kdfctx == NULL)
        return 0;

    peerkey = eckey_fromdata(ctx, NULL, 0, enc, enclen, NULL, NULL);
    if (peerkey == NULL)
        goto err;

    dhkmlen = generate_ecdhkm(ctx->key, peerkey, ctx->authkey,
                              dhkm, sizeof(dhkm), ctx->alg->secretlen);
    if (dhkmlen == 0)
        goto err;

    if (!ecpubkey_todata(ctx->key, recipientpub, &recipientpublen,
                         sizeof(recipientpub)))
        goto err;
    kemctxlen = recipientpublen + enclen;
    if (enclen != ctx->alg->encodedpublen
            || recipientpublen != enclen
            || kemctxlen > sizeof(kemctx))
        goto err;
    memcpy(kemctx, enc, enclen);
    memcpy(kemctx + enclen, recipientpub, recipientpublen);
    if (!dhkem_extract_and_expand(kdfctx, secret, ctx->alg->secretlen,
                                  ctx->alg->kemid, dhkm, dhkmlen,
                                  kemctx, kemctxlen))
        goto err;
    *secretlen = ctx->alg->secretlen;
    ret = 1;
err:
    EC_KEY_free(peerkey);
    EVP_KDF_CTX_free(kdfctx);
    return ret;
}

static int eckem_encapsulate(void *vctx, unsigned char *out, size_t *outlen,
                             unsigned char *secret, size_t *secretlen)
{
    PROV_EC_CTX *ctx = (PROV_EC_CTX *)vctx;

    if (ctx->op != EVP_PKEY_OP_ENCAPSULATE)
        return 0;
    switch (ctx->mode) {
        case KEM_MODE_HPKE:
            return hpke_encap(ctx, out, outlen, secret, secretlen);
        default:
            return -2;
    }
}

static int eckem_decapsulate(void *vctx, unsigned char *out, size_t *outlen,
                             const unsigned char *in, size_t inlen)
{
    PROV_EC_CTX *ctx = (PROV_EC_CTX *)vctx;

    if (ctx->op != EVP_PKEY_OP_DECAPSULATE)
        return 0;
    switch (ctx->mode) {
        case KEM_MODE_HPKE:
            return hpke_decap(ctx, out, outlen, in, inlen);
        default:
            return -2;
    }
}

static int eckem_derivekey(void *vctx,
                           unsigned char *pub, size_t *publen,
                           unsigned char *priv, size_t *privlen,
                           const unsigned char *ikm, size_t ikmlen)
{
    PROV_EC_CTX *ctx = (PROV_EC_CTX *)vctx;

    if (ctx->op != EVP_PKEY_OP_KEMDERIVE)
        return 0;
    switch (ctx->mode) {
        case KEM_MODE_HPKE:
            return hpke_derivekey(ctx, pub, publen, priv, privlen, ikm, ikmlen);
        default:
            return -2;
    }
}

static int eckem_set_auth(void *vctx, void *vec)
{
    PROV_EC_CTX *ctx = (PROV_EC_CTX *)vctx;

    if (!ossl_prov_is_running() || ctx == NULL)
        return 0;

    if (vec != NULL) {
        if (!ossl_ec_match_params(vec, ctx->key)
            || !!eckem_check_key(vec)
            || !EC_KEY_up_ref(vec))
            return 0;
    }
    setauthkey(ctx, vec);
    return 1;
}

const OSSL_DISPATCH ossl_ec_asym_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))eckem_newctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT,
      (void (*)(void))eckem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))eckem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT,
      (void (*)(void))eckem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))eckem_decapsulate },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))eckem_freectx },
    { OSSL_FUNC_KEM_DUPCTX, (void (*)(void))eckem_dupctx },
    { OSSL_FUNC_KEM_GET_CTX_PARAMS,
      (void (*)(void))eckem_get_ctx_params },
    { OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS,
      (void (*)(void))eckem_gettable_ctx_params },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS,
      (void (*)(void))eckem_set_ctx_params },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,
      (void (*)(void))eckem_settable_ctx_params },
    { OSSL_FUNC_KEM_SET_AUTH, (void (*)(void))eckem_set_auth },
    { OSSL_FUNC_KEM_DERIVEKEY_INIT,
      (void (*)(void))eckem_derivekey_init },
    { OSSL_FUNC_KEM_DERIVEKEY, (void (*)(void))eckem_derivekey },
    { 0, NULL }
};
