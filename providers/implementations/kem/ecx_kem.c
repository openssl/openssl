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
 * ECX keys (i.e. X25519 and X448)
 * References to Sections in the comments below refer to RFC 9180.
 */

#include "internal/deprecated.h"

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "prov/provider_ctx.h"
#include "prov/implementations.h"
#include "prov/securitycheck.h"
#include "prov/providercommon.h"

#include "crypto/hpke.h"
#include "crypto/ecx.h"
#include "prov/ec.h"
#include "eckem.h"

static OSSL_FUNC_kem_newctx_fn ecxkem_newctx;
static OSSL_FUNC_kem_encapsulate_init_fn ecxkem_encapsulate_init;
static OSSL_FUNC_kem_encapsulate_fn ecxkem_encapsulate;
static OSSL_FUNC_kem_decapsulate_init_fn ecxkem_decapsulate_init;
static OSSL_FUNC_kem_decapsulate_fn ecxkem_decapsulate;
static OSSL_FUNC_kem_freectx_fn ecxkem_freectx;
static OSSL_FUNC_kem_dupctx_fn ecxkem_dupctx;
static OSSL_FUNC_kem_get_ctx_params_fn ecxkem_get_ctx_params;
static OSSL_FUNC_kem_gettable_ctx_params_fn ecxkem_gettable_ctx_params;
static OSSL_FUNC_kem_set_ctx_params_fn ecxkem_set_ctx_params;
static OSSL_FUNC_kem_settable_ctx_params_fn ecxkem_settable_ctx_params;
static OSSL_FUNC_kem_set_auth_fn ecxkem_set_auth;
static OSSL_FUNC_kem_derivekey_init_fn ecxkem_derivekey_init;
static OSSL_FUNC_kem_derivekey_fn ecxkem_derivekey;

typedef struct {
    const OSSL_HPKE_KEM_ALG *alg;
    ECX_KEY *key;
    ECX_KEY *authkey;
    OSSL_LIB_CTX *libctx;
    char *propq;
    unsigned char *ikm;
    size_t ikmlen;
    unsigned int mode;
    unsigned int op;
} PROV_ECX_CTX;

/* return kem info associated with a ECX key type or NULL if not found */
static const OSSL_HPKE_KEM_ALG *find_kem_alg(ECX_KEY *ecx)
{
    const char *name;

    if (ecx->type == ECX_KEY_TYPE_X25519)
        name = "X25519";
    else if (ecx->type == ECX_KEY_TYPE_X448)
        name = "X448";
    else
        return NULL;
    return ossl_hpke_get_kemalg(name, NULL, NULL, NULL);
}

/*
 * Set the recipient key, and free any existing key.
 * ecx can be NULL. The ecx key may have only a private or public component.
 */
static int setkey(PROV_ECX_CTX *ctx, ECX_KEY *ecx)
{
    ossl_ecx_key_free(ctx->key);
    ctx->key = ecx;
    return ecx == NULL;
}

/*
 * Set the senders auth key, and free any existing auth key.
 * ecx can be NULL.
 */
static int setauthkey(PROV_ECX_CTX *ctx, ECX_KEY *ecx)
{
    ossl_ecx_key_free(ctx->authkey);
    ctx->authkey = ecx;
    return ecx == NULL;
}

/*
 * Serialize a new EC key from byte array's for the encoded public & private keys.
 * ctx is used to access the curvename from the recipient key.
 * privbuf or pubbuf may be NULL.
 * Returns: The created EC_KEY or NULL on error.
 */
static ECX_KEY *ecxkey_fromdata(PROV_ECX_CTX *ctx,
                                const unsigned char *privbuf, size_t privbuflen,
                                const unsigned char *pubbuf, size_t pubbuflen)
{
    ECX_KEY *ecx = NULL;
    OSSL_PARAM params[3], *p = params;

    if (privbuf != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                                 (char *)privbuf, privbuflen);
    if (pubbuf != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                 (char *)pubbuf, pubbuflen);
    *p = OSSL_PARAM_construct_end();

    ecx = ossl_ecx_key_new(ctx->libctx, ctx->key->type, 1, ctx->propq);
    if (ecx == NULL)
        return NULL;
    if (ossl_ecx_key_fromdata(ecx, params, privbuf != NULL) <= 0) {
        ossl_ecx_key_free(ecx);
        ecx = NULL;
    }
    return ecx;
}

/*
 * Deserialises a ECX private key into a encoded byte array.
 * Returns: 1 if successful or 0 otherwise.
 */
static int ecxprivkey_todata(ECX_KEY *ecx, unsigned char *out, size_t *outlen,
                             size_t maxoutlen)
{
    if (ecx->keylen > maxoutlen)
        return 0;
    memcpy(out, ecx->privkey,  ecx->keylen);
    *outlen = ecx->keylen;
    return 1;
}

/*
 * Deserialises a ECX public key into a encoded byte array.
 * Returns: 1 if successful or 0 otherwise.
 */
static int ecxpubkey_todata(ECX_KEY *ecx, unsigned char *out, size_t *outlen,
                            size_t maxoutlen)
{
    if (ecx->keylen > maxoutlen)
        return 0;
    memcpy(out, ecx->pubkey, ecx->keylen);
    *outlen = ecx->keylen;
    return 1;
}

static void *ecxkem_newctx(void *provctx)
{
    PROV_ECX_CTX *ctx =  OPENSSL_zalloc(sizeof(PROV_ECX_CTX));

    if (ctx == NULL)
        return NULL;
    ctx->libctx = PROV_LIBCTX_OF(provctx);

    return ctx;
}

static void ecxkem_freectx(void *vectx)
{
    PROV_ECX_CTX *ctx = (PROV_ECX_CTX *)vectx;

    OPENSSL_clear_free(ctx->ikm, ctx->ikmlen);
    setkey(ctx, NULL);
    setauthkey(ctx, NULL);
    OPENSSL_free(ctx);
}

static void *ecxkem_dupctx(void *vctx)
{
    /* Not supported */
    return NULL;
}

static int ecxkem_init(void *vecxctx, void *vecx,
                       ossl_unused const OSSL_PARAM params[], int operation)
{
    PROV_ECX_CTX *ctx = (PROV_ECX_CTX *)vecxctx;
    ECX_KEY *ecx = vecx;

    if (!ossl_prov_is_running())
        return 0;

    if (ctx == NULL || ecx == NULL)
        return 0;
    if (!ossl_ecx_key_up_ref(ecx))
        return 0;

    setkey(ctx, ecx);
    setauthkey(ctx, NULL);

    ctx->op = operation;
    ctx->alg = find_kem_alg(ecx);
    if (ctx->alg == NULL) {
        setkey(ctx, NULL);
        return 0;
    }
    return ecxkem_set_ctx_params(vecxctx, params);
}

static int ecxkem_encapsulate_init(void *vecxctx, void *vecx,
                                   const OSSL_PARAM params[])
{
    return ecxkem_init(vecxctx, vecx, params, EVP_PKEY_OP_ENCAPSULATE);
}

static int ecxkem_decapsulate_init(void *vecxctx, void *vecx,
                                   const OSSL_PARAM params[])
{
    return ecxkem_init(vecxctx, vecx, params, EVP_PKEY_OP_DECAPSULATE);
}

static int ecxkem_derivekey_init(void *vctx, void *vec,
                                 const OSSL_PARAM params[])
{
    return ecxkem_init(vctx, vec, params, EVP_PKEY_OP_KEMDERIVE);
}

static int ecxkem_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    PROV_ECX_CTX *ctx = (PROV_ECX_CTX *)vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_KEM_PARAM_ID);
    if (p != NULL) {
        unsigned int kemid = ctx->alg->kemid;

        return OSSL_PARAM_set_uint(p, kemid);
    }
    return 0;
}

static const OSSL_PARAM known_gettable_ecxkem_ctx_params[] = {
    OSSL_PARAM_uint(OSSL_KEM_PARAM_ID, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ecxkem_gettable_ctx_params(ossl_unused void *vctx,
                                                    ossl_unused void *provctx)
{
    return known_gettable_ecxkem_ctx_params;
}

static int ecxkem_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_ECX_CTX *ctx = (PROV_ECX_CTX *)vctx;
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

static const OSSL_PARAM known_settable_ecxkem_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_KEM_PARAM_OPERATION, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KEM_PARAM_IKME, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ecxkem_settable_ctx_params(ossl_unused void *vctx,
                                                   ossl_unused void *provctx)
{
    return known_settable_ecxkem_ctx_params;
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
    /* suiteid = concat("KEM", I2OSP(kem_id, 2)) */
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
static ECX_KEY *derivekey(PROV_ECX_CTX *ctx,
                          const unsigned char *ikm, size_t ikmlen)
{
    uint16_t kemid = ctx->alg->kemid;
    EVP_KDF_CTX *kdfctx = NULL;
    uint8_t suiteid[5] = {'K', 'E', 'M', kemid >> 8, kemid & 0xff };
    unsigned char prk[EVP_MAX_KEY_LENGTH];
    unsigned char privbuf[EVP_MAX_KEY_LENGTH];
    size_t privbuflen = ctx->alg->secretlen;
    ECX_KEY *ecx = NULL;

    kdfctx = ossl_kdf_ctx_create(ctx->alg->kdfname, ctx->alg->kdfdigestname,
                                 ctx->libctx, ctx->propq);
    if (kdfctx == NULL)
        return 0;

    if (!ossl_hpke_labeled_extract(kdfctx, prk, privbuflen,
                                   NULL, 0, suiteid, sizeof(suiteid),
                                   "dkp_prk", ikm, ikmlen))
        goto err;

    if (!ossl_hpke_labeled_expand(kdfctx, privbuf, privbuflen, prk, privbuflen,
                                  suiteid, sizeof(suiteid), "sk", NULL, 0))
        goto err;

    ecx = ecxkey_fromdata(ctx, privbuf, privbuflen, NULL, 0);
err:
    OPENSSL_cleanse(prk, sizeof(prk));
    OPENSSL_cleanse(privbuf, sizeof(privbuf));
    EVP_KDF_CTX_free(kdfctx);
    return ecx;
}

/*
 * Generate a ec keypair from a seed value and return the keypair as encoded bytes
 * Returns 1 if successful or 0 otherwise.
 */
static int hpke_derivekey(PROV_ECX_CTX *ctx,
                          unsigned char *pub, size_t *publen,
                          unsigned char *priv, size_t *privlen,
                          const unsigned char *ikm, size_t ikmlen)
{
    int ret = 0;
    ECX_KEY *ecx = NULL;

    ecx = derivekey(ctx, ikm, ikmlen);
    if (ecx == NULL)
        goto err;
    if (!ecxpubkey_todata(ecx, pub, publen, *publen)
            || !ecxprivkey_todata(ecx, priv, privlen, *privlen))
        goto err;
    ossl_ecx_key_free(ecx);
    ret = 1;
 err:
    return ret;
}

/*
 * Do an ecdh key exchange.
 * This is either dhkm = concat(DH(sender, peer), DH(auth, peer)) or
 *                dhkm = DH(sender, peer) if auth is NULL.
 * i.e. The generated secret is twice as long if there is an auth key.
 *
 * NOTE: Instead of using EVP_PKEY_derive() API's, we use ECX_KEY operations
 *       to avoid messy conversions back to EVP_PKEY.
 *
 * Returns the size of the secret if successful, or 0 otherwise,
 */
static int generate_ecdhkm(ECX_KEY *sender, ECX_KEY *peer, ECX_KEY *auth,
                           unsigned char *dhkm,  size_t dhkmlen,
                           unsigned int secretsz)
{
    size_t secretlen = sender->keylen;
    size_t retsecretlen = (auth != NULL ? 2 * secretlen : secretlen);

    if (secretlen != secretsz || dhkmlen < retsecretlen)
        return 0;

    if (!peer->haspubkey)
        return 0;
    /* NOTE: ossl_ecx_compute_key checks for shared secret being all zeros */
    if (!ossl_ecx_compute_key(peer, sender, secretlen, dhkm,
                              &secretlen, dhkmlen))
        return 0;

    if (auth != NULL) {
        if (!ossl_ecx_compute_key(peer, auth, secretlen,
                                  dhkm + secretlen, &secretlen,
                                  dhkmlen - secretlen))
        return 0;
    }
    return retsecretlen;
}


/*
 * See Section 4.1 Enncap()
 */
static int hpke_encap(PROV_ECX_CTX *ctx,
                      unsigned char *enc, size_t *enclen,
                      unsigned char *secret, size_t *secretlen)
{
    int ret = 0;
    EVP_KDF_CTX *kdfctx = NULL;
    unsigned char kemctx[133 * 2];
    unsigned char dhkm[64 * 2];
    ECX_KEY *senderkey = NULL;
    size_t senderpublen, peerpublen, kemctxlen, dhkmlen;
    unsigned char senderpub[133];
    unsigned char peerpub[133];

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
    if (!ecxpubkey_todata(senderkey, senderpub, &senderpublen, sizeof(senderpub))
            || !ecxpubkey_todata(ctx->key, peerpub, &peerpublen, sizeof(peerpub)))
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
    /* Return the public part of the ephemeral key */
    memcpy(enc, senderpub, senderpublen);
    *enclen = senderpublen;
    *secretlen = ctx->alg->secretlen;
    ret = 1;
err:
    ossl_ecx_key_free(senderkey);
    EVP_KDF_CTX_free(kdfctx);
    return ret;
}

/*
 * See Section 4.1 Decap()
 */
static int hpke_decap(PROV_ECX_CTX *ctx,
                      unsigned char *secret, size_t *secretlen,
                      const unsigned char *enc, size_t enclen)
{
    int ret = 0;
    EVP_KDF_CTX *kdfctx = NULL;
    ECX_KEY *recipientkey = ctx->key;
    ECX_KEY *peerkey = NULL;
    unsigned char kemctx[133 * 2];
    unsigned char dhkm[64];
    unsigned char recipientpub[133];
    size_t recipientpublen, kemctxlen, dhkmlen;

    if (*secretlen < ctx->alg->secretlen)
        return 0;

    kdfctx = ossl_kdf_ctx_create(ctx->alg->kdfname, ctx->alg->kdfdigestname,
                                 ctx->libctx, ctx->propq);
    if (kdfctx == NULL)
        return 0;

    /* Get the public part of the ephemeral key created by encap */
    peerkey = ecxkey_fromdata(ctx, NULL, 0, enc, enclen);
    if (peerkey == NULL)
        goto err;

    dhkmlen = generate_ecdhkm(recipientkey, peerkey, ctx->authkey,
                              dhkm, sizeof(dhkm), ctx->alg->secretlen);
    if (dhkmlen == 0)
        goto err;

    if (!ecxpubkey_todata(recipientkey, recipientpub, &recipientpublen,
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
    ossl_ecx_key_free(peerkey);
    EVP_KDF_CTX_free(kdfctx);
    return ret;
}

static int ecxkem_encapsulate(void *vctx, unsigned char *out, size_t *outlen,
                              unsigned char *secret, size_t *secretlen)
{
    PROV_ECX_CTX *ctx = (PROV_ECX_CTX *)vctx;

    if (ctx->op != EVP_PKEY_OP_ENCAPSULATE)
        return 0;

    switch (ctx->mode) {
        case KEM_MODE_HPKE:
            return hpke_encap(ctx, out, outlen, secret, secretlen);
        default:
            return -2;
    }
}

static int ecxkem_decapsulate(void *vctx, unsigned char *out, size_t *outlen,
                              const unsigned char *in, size_t inlen)
{
    PROV_ECX_CTX *ctx = (PROV_ECX_CTX *)vctx;

    if (ctx->op != EVP_PKEY_OP_DECAPSULATE)
        return 0;
    switch (ctx->mode) {
        case KEM_MODE_HPKE:
            return hpke_decap(vctx, out, outlen, in, inlen);
        default:
            return -2;
    }
}

static int ecxkem_derivekey(void *vctx,
                            unsigned char *pub, size_t *publen,
                            unsigned char *priv, size_t *privlen,
                            const unsigned char *ikm, size_t ikmlen)
{
    PROV_ECX_CTX *ctx = (PROV_ECX_CTX *)vctx;

    if (ctx->op != EVP_PKEY_OP_KEMDERIVE)
        return 0;
    switch (ctx->mode) {
        case KEM_MODE_HPKE:
            return hpke_derivekey(ctx, pub, publen, priv, privlen, ikm, ikmlen);
        default:
            return -2;
    }
}

static int ecxkem_set_auth(void *vctx, void *vec)
{
    PROV_ECX_CTX *ctx = (PROV_ECX_CTX *)vctx;

    if (!ossl_prov_is_running() || ctx == NULL)
        return 0;
    if (vec != NULL) {
        if (!ossl_ecx_match_params(vec, ctx->key)
                || !ossl_ecx_key_up_ref(vec))
            return 0;
    }
    setauthkey(ctx, vec);
    return 1;
}

const OSSL_DISPATCH ossl_ecx_asym_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))ecxkem_newctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT,
      (void (*)(void))ecxkem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))ecxkem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT,
      (void (*)(void))ecxkem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))ecxkem_decapsulate },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))ecxkem_freectx },
    { OSSL_FUNC_KEM_DUPCTX, (void (*)(void))ecxkem_dupctx },
    { OSSL_FUNC_KEM_GET_CTX_PARAMS,
      (void (*)(void))ecxkem_get_ctx_params },
    { OSSL_FUNC_KEM_GETTABLE_CTX_PARAMS,
      (void (*)(void))ecxkem_gettable_ctx_params },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS,
      (void (*)(void))ecxkem_set_ctx_params },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,
      (void (*)(void))ecxkem_settable_ctx_params },
      { OSSL_FUNC_KEM_SET_AUTH, (void (*)(void))ecxkem_set_auth },
      { OSSL_FUNC_KEM_DERIVEKEY_INIT,
        (void (*)(void))ecxkem_derivekey_init },
      { OSSL_FUNC_KEM_DERIVEKEY, (void (*)(void))ecxkem_derivekey },
    { 0, NULL }
};
