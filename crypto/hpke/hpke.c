/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h> /* memcpy */

#include <openssl/hpke.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "crypto/hpke.h"

#define HPKE_MODE_BASE     0x00
#define HPKE_MODE_PSK      0x01
#define HPKE_MODE_AUTH     0x02
#define HPKE_MODE_AUTH_PSK 0x03

#define HPKE_AEADID_EXPORT 0xFFFF

#define HPKE_SUITEID(kemid, kdfid, aeadid) {        \
    'H', 'P', 'K', 'E',                             \
    kemid >> 8, kemid & 0xff,                       \
    kdfid >> 8, kdfid & 0xff,                       \
    aeadid >> 8, aeadid & 0xff                      \
};

typedef struct {
    const char *name;
    const char *digestname;
    size_t digestlen;
    uint16_t id;
} HPKE_KDF_INFO;

typedef struct {
    const char *keytype;
    const HPKE_KDF_INFO *kdfinfo;
} HPKE_KEM_INFO;

typedef struct {
    const char *name;
    uint16_t id;
    size_t keylen;    /* Nk */
    size_t noncelen;  /* Nn */
    size_t taglen;    /* Nt */
} HPKE_AEAD_INFO;

typedef struct {
    EVP_CIPHER_CTX *ctx;
    const HPKE_AEAD_INFO *info;
    uint64_t ivseq;                      /* 64 bits */
    uint8_t key[EVP_MAX_KEY_LENGTH];
    uint8_t base_nonce[OSSL_HPKE_MAX_NONCE];
    size_t base_noncelen;
} HPKE_AEAD;

typedef struct {
    unsigned char pub[OSSL_HPKE_MAX_PUBLIC];
    unsigned char priv[OSSL_HPKE_MAX_PRIVATE];
    size_t publen;
    size_t privlen;
} HPKE_KEY;

/* The kem object */
struct ossl_hpke_kem_st
{
    EVP_PKEY_CTX *derivekeyctx;
    const OSSL_HPKE_KEM_ALG *alginfo;
    uint8_t isauth;
};

/* The sender or receiver context */
struct ossl_hpke_ctx_st
{
    OSSL_LIB_CTX *libctx;
    char *propq;
    EVP_KDF_CTX *kdfctx;                      /* kdf used for hpke operations */
    const HPKE_KDF_INFO *kdfinfo;
    HPKE_AEAD aead;
    uint8_t exporter_secret[EVP_MAX_MD_SIZE];
    size_t exporter_secretlen;
    uint16_t kemid;
    uint8_t mode;
    uint8_t issender;
};

static const HPKE_KDF_INFO kdf_list[] = {
    { "HKDF", "SHA256", 32, 0x0001 },
    { "HKDF", "SHA384", 48, 0x0002 },
    { "HKDF", "SHA512", 64, 0x0003 },
    { NULL, NULL, 0 }
};

static const HPKE_AEAD_INFO aead_list[] = {
    { "AES-128-GCM",       0x0001, 16, 12, 16 },
    { "AES-256-GCM",       0x0002, 32, 12, 16 },
    { "ChaCha20-Poly1305", 0x0003, 32, 12, 16 },
    { "Export",            0xFFFF, 0, 0, 0 },
};

static const HPKE_KDF_INFO *kdfname2info(const char *kdfalg,
                                         const char *kdfdigestalg)
{
    int i;

    if (kdfalg == NULL || kdfdigestalg == NULL)
        return NULL;

    /* Only HKDF is supported currently so just test this once */
    if (OPENSSL_strcasecmp(kdfalg, "HKDF") != 0)
        return NULL;

    for (i = 0; kdf_list[i].name != NULL; ++i) {
        if (OPENSSL_strcasecmp(kdf_list[i].digestname, kdfdigestalg) == 0)
            return &kdf_list[i];
    }
    return NULL;
}

static const HPKE_AEAD_INFO *aeadname2info(const char *aeadalg)
{
    int i;
    const char *alg = aeadalg != NULL ? aeadalg : "Export";

    for (i = 0; aead_list[i].name != NULL; ++i) {
        if (OPENSSL_strcasecmp(aead_list[i].name, alg) == 0)
            return &aead_list[i];
    }
    return NULL;
}

/*
 * Create an EVP_PKEY from encoded key data.
 * ctx is an existing EVP_PKEY_CTX that can be used with EVP_PKEY_fromdata().
 * key returns the created key.
 * curve is the EC curve name or NULL for ECX keys.
 * in contains optional public and private encoded Byte array data.
 * Returns 1 if the operation succeeds or 0 otherwise.
 */
static int evpkeyfromdata(EVP_PKEY_CTX *ctx, EVP_PKEY **key, const char *curve,
                          HPKE_KEY *in)
{
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *bn = NULL;
    int ret = 0, selection;

    if (in->privlen == 0) {
        if (in->publen == 0) {
            if (curve == NULL)
                return 0;
            selection = EVP_PKEY_KEY_PARAMETERS;
        } else {
            selection = EVP_PKEY_PUBLIC_KEY;
        }
    } else {
        selection = EVP_PKEY_KEYPAIR;
    }

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL)
        goto err;
    if (curve != NULL) {
        if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                             curve, 0))
            goto err;
    }
    if (in->privlen != 0) {
        if (curve != NULL) {
            bn = BN_bin2bn(in->priv, in->privlen, NULL);
            if (bn == NULL)
                goto err;
            if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, bn))
                goto err;
        } else {
            if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY,
                                                  in->priv, in->privlen))
                goto err;
        }
    }
    if (in->publen != 0) {
        if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                              in->pub, in->publen))
            goto err;
    }
    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL)
        goto err;

    if (EVP_PKEY_fromdata_init(ctx) <= 0)
        goto err;
    if (EVP_PKEY_fromdata(ctx, key, selection, params) <= 0)
        goto err;
    ret = 1;
err:
    BN_clear_free(bn);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return ret;
}

/*
 * In order to use the provider EVP_KEM interface it needs a EVP_PKEY.
 * Since the derivekey operation does not yet have a key, we create a dummy
 * one.
 * For EC it just need a group.
 * For ECX keys it just sets up a dummy public key
 * Returns 1 if the operation succeeds or 0 otherwise.
 */
static int createdummykey(OSSL_HPKE_KEM *kem, EVP_PKEY **out,
                          OSSL_LIB_CTX *libctx, const char *propq)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL;
    HPKE_KEY in;

    ctx = EVP_PKEY_CTX_new_from_name(libctx, kem->alginfo->keytype, propq);
    if (ctx == NULL)
        return 0;

    in.privlen = 0;
    if (kem->alginfo->name != NULL) {
        /* For EC just set up the group */
        in.publen = 0;
    } else {
        /* For ECX setup a dummy public key */
        in.publen = kem->alginfo->encodedpublen;
        OPENSSL_cleanse(in.pub, in.publen);
    }

    ret = evpkeyfromdata(ctx, out, kem->alginfo->name, &in);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

/*
 * Create an DHKEM object used for derive, encap and decap operations.
 *
 * keyname must be one of "EC", "X25519" or "X448"
 * curve is one of "P-256", "P-384", "P-521" or NULL,
 * kdfname is one of "HKDF" or NULL
 * kdfdigestname is one of "SHA256", SHA384", "SHA512", or NULL.
 * Returns the created KEM if the combination of input names is allowed, or NULL
 * otherwise.
 *
 * Notes: If any of the optional parameters are NULL, then it will chose
 * the smallest values for the curve and/or kdfdigestname.
 */
OSSL_HPKE_KEM *OSSL_HPKE_KEM_new(const char *keyname, const char *curvename,
                                 const char *kdfname, const char *kdfdigestname)
{
    OSSL_HPKE_KEM *kem = NULL;
    const OSSL_HPKE_KEM_ALG *alg;

    if (keyname == NULL)
        return NULL;

    alg = ossl_hpke_get_kemalg(keyname, curvename, kdfname, kdfdigestname);
    if (alg == NULL)
        return NULL;

    kem = OPENSSL_zalloc(sizeof(*kem));
    if (kem == NULL) {
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    kem->alginfo = alg;
    return kem;
}

void OSSL_HPKE_KEM_free(OSSL_HPKE_KEM *kem)
{
    if (kem == NULL)
        return;
    EVP_PKEY_CTX_free(kem->derivekeyctx);
    OPENSSL_free(kem);
}

/*
 * Must be called before OSSL_HPKE_KEM_derivekey()
 * kem kem algorithm info object
 * libctx & propq are used for fetching algorithms from providers.
 */
int OSSL_HPKE_KEM_derivekey_init(OSSL_HPKE_KEM *kem,
                                 OSSL_LIB_CTX *libctx, const char *propq)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    if (!createdummykey(kem, &key, libctx, propq))
        return 0;
    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, propq);
    EVP_PKEY_free(key);
    if (ctx == NULL)
        return 0;
    if (EVP_PKEY_KEM_derivekey_init(ctx, NULL) <= 0
            || EVP_PKEY_CTX_set_kem_op(ctx,
                                       OSSL_KEM_PARAM_OPERATION_HPKE) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    kem->derivekeyctx = ctx;
    return 1;
}

/*
 * Returns a Derived keypair using an input seed.
 * Can be called multiple times with different input seeds.
 *
 * kem kem algorithm info object
 * privkeyout The returned created private key.
 * pubkeyout The returned created pubkeyout. This can optionally be NULL.
 * ikm The input seed
 * ikmlen The length of the input seed.
 *
 * Returns 1 if the key was created, or 0 otherwise.
 */
int OSSL_HPKE_KEM_derivekey(OSSL_HPKE_KEM *kem,
                            EVP_PKEY **privkeyout, EVP_PKEY **pubkeyout,
                            const unsigned char *ikm, size_t ikmlen)
{
    int ret = 0;
    HPKE_KEY key;
    EVP_PKEY *pubkey = NULL, *privkey = NULL;

    if (privkeyout == NULL)
        return 0;

    if (ikmlen > OSSL_HPKE_MAX_KDF_INPUTLEN)
        return 0;

    key.privlen = kem->alginfo->encodedprivlen;
    key.publen = kem->alginfo->encodedpublen;;

    if (EVP_PKEY_KEM_derivekey(kem->derivekeyctx, key.pub, &key.publen,
                               key.priv, &key.privlen, ikm, ikmlen) <= 0)
        goto err;
    /* Generate public and private EVP_PKEY's */
    if (!evpkeyfromdata(kem->derivekeyctx, &privkey, kem->alginfo->name, &key))
        goto err;
    OPENSSL_cleanse(key.priv, key.privlen);
    key.privlen = 0;

    if (pubkeyout != NULL) {
        if (!evpkeyfromdata(kem->derivekeyctx, &pubkey, kem->alginfo->name, &key))
            goto err;
        *pubkeyout = pubkey;
    }
    *privkeyout = privkey;

    ret = 1;
err:
    OPENSSL_cleanse(key.priv, key.privlen);
    if (!ret)
        EVP_PKEY_free(privkey);
    return ret;
}

/*
 * ctx A EVP_PKEY_CTX containing the recipient public key.
 * kem kem algorithm info
 * ikme A seed used by the sender to derive an ephemeral key.
 * authprivkey A optional Auth key used by Auth and PSKAuth modes. If this
 *    is NULL then the mode will be either Base or PSK.
 */
int OSSL_HPKE_KEM_encapsulate_init(EVP_PKEY_CTX *rpubctx, OSSL_HPKE_KEM *kem,
                                   EVP_PKEY *authprivkey,
                                   const unsigned char *ikme, size_t ikmelen)
{
    int ret = 0;
    OSSL_PARAM params[3], *p = params;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KEM_PARAM_OPERATION,
                                            (char *)OSSL_KEM_PARAM_OPERATION_HPKE,
                                            0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KEM_PARAM_IKME,
                                             (char *)ikme, ikmelen);
    *p = OSSL_PARAM_construct_end();
    if (EVP_PKEY_encapsulate_init(rpubctx, params) < 0)
        goto err;

    kem->isauth = (authprivkey != NULL);
    if (EVP_PKEY_KEM_set_auth(rpubctx, authprivkey) <= 0)
        goto err;
    ret = 1;
err:
    return ret;
}

/*
 * ctx A EVP_PKEY_CTX containing the recipient public key.
 * enc returns the encoded public key. This value can be given to the
 *     recipient so that it can be used by OSSL_HPKE_KEM_decapsulate().
 * enclen passes in the max size of the enc buffer and returns the length
 *     of the returned encoded public key.
 *     recipient so that it can be used by OSSL_HPKE_KEM_decapsulate().
 * secret returns the generated shared secret.
 * secretlen passes in the max size of the secret buffer and returns the length
 *     of the returned secret.
 */
int OSSL_HPKE_KEM_encapsulate(EVP_PKEY_CTX *ctx,
                              unsigned char *enc, size_t *enclen,
                              unsigned char *secret, size_t *secretlen)
{
    return EVP_PKEY_encapsulate(ctx, enc, enclen, secret, secretlen);
}

/*
 * rprivctx A EVP_PKEY_CTX containing the recipient private key.
 * kem kem algorithm info
 * authprivkey A optional Auth key used by Auth and PSKAuth modes. If this
 *    is NULL then the mode will be either Base or PSK.
 */
int OSSL_HPKE_KEM_decapsulate_init(EVP_PKEY_CTX *rprivctx, OSSL_HPKE_KEM *kem,
                                   EVP_PKEY *authpubkey)
{
    int ret = 0;

    if (EVP_PKEY_decapsulate_init(rprivctx, NULL) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set_kem_op(rprivctx, OSSL_KEM_PARAM_OPERATION_HPKE) <= 0)
        goto err;
    kem->isauth = (authpubkey != NULL);
    if (EVP_PKEY_KEM_set_auth(rprivctx, authpubkey) <= 0)
        goto err;
    ret = 1;
err:
    return ret;
}

/*
 * rprivctx A EVP_PKEY_CTX containing the recipient private key.
 * secret returns the generated shared secret.
 * secretlen passes in the max size of the secret buffer and returns the length
 *     of the returned secret.
 * enc A encoded public key. This value was returned when the sender called
 *     OSSL_HPKE_KEM_enapsulate().
 * enclen The sizze of the enc buffer.
 *
 */
int OSSL_HPKE_KEM_decapsulate(EVP_PKEY_CTX *rprivctx,
                              unsigned char *secret, size_t *secretlen,
                              const unsigned char *enc, size_t enclen)
{
    return EVP_PKEY_decapsulate(rprivctx, secret, secretlen, enc, enclen);
}

/*
 * kem contains kem algorithm info
 * sender should be set to 1 for the sender, and 0 for the recipient.
 *     OSSL_HPKE_CTX_open() will fail if this value is 1.
 *     OSSL_HPKE_CTX_seal() will fail if this value is 0.
 * aeadalg should be one of "AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305",
 *     "Export" or NULL. If the value is "Export" or NULL then the seal and open
 *     related API's will return an error if used.
 * libctx & propq are used for fetching algorithms from providers.
 * Returns 1 if successful or 0 on error.
 */
OSSL_HPKE_CTX *OSSL_HPKE_CTX_new(OSSL_HPKE_KEM *kem, int sender,
                                 const char *kdfdigestalg,
                                 const char *aeadalg,
                                 OSSL_LIB_CTX *libctx, const char *propq)
{
    OSSL_HPKE_CTX *ctx;
    const char *kdfalg = "HKDF";

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->issender = sender;
    ctx->mode = kem->isauth ? HPKE_MODE_AUTH : HPKE_MODE_BASE;
    ctx->kemid = kem->alginfo->kemid;
    ctx->libctx = libctx;
    ctx->propq = OPENSSL_strdup(propq);

    ctx->kdfinfo = kdfname2info(kdfalg, kdfdigestalg);
    if (ctx->kdfinfo == 0)
        goto err;
    ctx->aead.info = aeadname2info(aeadalg);
    if (ctx->aead.info == NULL)
        goto err;

    ctx->kdfctx = ossl_kdf_ctx_create(kdfalg, kdfdigestalg, libctx, propq);
    if (ctx->kdfctx == NULL)
        goto err;
    return ctx;
err:
    OSSL_HPKE_CTX_free(ctx);
    return NULL;
}

void OSSL_HPKE_CTX_free(OSSL_HPKE_CTX *ctx)
{
    if (ctx == NULL)
        return;

    OPENSSL_free(ctx->propq);
    ossl_aead_free(ctx->aead.ctx);
    if (ctx->aead.info != NULL) {
        OPENSSL_cleanse(ctx->aead.base_nonce, ctx->aead.info->noncelen);
        OPENSSL_cleanse(ctx->aead.key, ctx->aead.info->keylen);
    }
    OPENSSL_cleanse(ctx->exporter_secret, ctx->exporter_secretlen);
    EVP_KDF_CTX_free(ctx->kdfctx);
    OPENSSL_free(ctx);
}

/*
 * See RFC 9180 Section 5.1 KeySchedule<ROLE>
 */
static int hpke_keyschedule(OSSL_HPKE_CTX *ctx,
                            const unsigned char *kemsharedsecret,
                            size_t kemsharedsecretlen,
                            const unsigned char *info, size_t infolen,
                            const unsigned char *psk, size_t psklen,
                            const unsigned char *pskid, size_t pskidlen)
{
    unsigned char suiteid[10] = HPKE_SUITEID(ctx->kemid,
                                             ctx->kdfinfo->id,
                                             ctx->aead.info->id);

    int ret = 0;
    EVP_KDF_CTX *kctx;
    uint8_t secret[EVP_MAX_MD_SIZE];
    uint8_t kscontext[sizeof(uint8_t) + 2 * EVP_MAX_MD_SIZE];
    size_t secretlen, kscontextlen;
    size_t Nh;

    if (ctx == NULL)
        return 0;

    kctx = ctx->kdfctx;
    Nh = ctx->kdfinfo->digestlen; /* HKDF digest len */

    /*
     * 5.1.4: The PSK must be Nh bytes or longer,
     * 7.2.1 KDF Input Length Restrictions of 64 bytes are recommended
     */
    if (psklen != 0
        && (psklen < Nh || psklen > OSSL_HPKE_MAX_KDF_INPUTLEN))
        return 0;
    if (pskidlen > OSSL_HPKE_MAX_KDF_INPUTLEN)
        return 0;
    if (infolen > OSSL_HPKE_MAX_KDF_INPUTLEN)
        return 0;

    kscontextlen = 1 + 2 * Nh;
    if (kscontextlen > sizeof(kscontext))
        return 0;
    kscontext[0] = ctx->mode;
    if (!ossl_hpke_labeled_extract(kctx, kscontext + 1, Nh,
                                   NULL, 0, suiteid, sizeof(suiteid),
                                   "psk_id_hash", pskid, pskidlen))
        goto err;
    if (!ossl_hpke_labeled_extract(kctx, kscontext + 1 + Nh, Nh,
                                   NULL, 0, suiteid, sizeof(suiteid),
                                   "info_hash", info, infolen))
        goto err;

    secretlen = Nh;
    if (secretlen > sizeof(secret))
        goto err;
    if (!ossl_hpke_labeled_extract(kctx, secret, secretlen,
                                   kemsharedsecret, kemsharedsecretlen,
                                   suiteid, sizeof(suiteid),
                                   "secret", psk, psklen))
        goto err;

    /* If only using the export then you don't need to calculate these */
    if (ctx->aead.info->id != HPKE_AEADID_EXPORT) {
        if (ctx->aead.info->keylen > sizeof(ctx->aead.key))
            goto err;
        if (!ossl_hpke_labeled_expand(kctx,
                                      ctx->aead.key, ctx->aead.info->keylen,
                                      secret, secretlen, suiteid, sizeof(suiteid),
                                      "key", kscontext, kscontextlen))
            goto err;

        if (ctx->aead.info->noncelen > sizeof(ctx->aead.base_nonce))
            goto err;

        if (!ossl_hpke_labeled_expand(kctx,
                                      ctx->aead.base_nonce,
                                      ctx->aead.info->noncelen,
                                      secret, secretlen, suiteid, sizeof(suiteid),
                                      "base_nonce", kscontext, kscontextlen))
            goto err;
        ctx->aead.base_noncelen = ctx->aead.info->noncelen;
    }

    ctx->exporter_secretlen = Nh;
    if (ctx->exporter_secretlen > sizeof(ctx->exporter_secret))
        goto err;
    if (!ossl_hpke_labeled_expand(kctx,
                                  ctx->exporter_secret, ctx->exporter_secretlen,
                                  secret, secretlen, suiteid, sizeof(suiteid),
                                  "exp", kscontext, kscontextlen))
        goto err;

    ret = 1;
err:
    return ret;
}

static int hpke_aead_init(OSSL_HPKE_CTX *ctx,
                          OSSL_LIB_CTX *libctx, const char *propq)
{
    EVP_CIPHER *cipher = NULL;

    /* Open/seal are not allowed in export only mode */
    if (ctx->aead.info == NULL || ctx->aead.info->id == HPKE_AEADID_EXPORT)
        return 0;

    cipher = EVP_CIPHER_fetch(libctx, ctx->aead.info->name, propq);
    if (cipher == NULL)
        return 0;
    ctx->aead.ctx = ossl_aead_init(cipher, ctx->aead.key, ctx->issender);
    EVP_CIPHER_free(cipher);
    return ctx->aead.ctx != NULL;
}

/* Use this API if Pre Shared keys are not used */
int OSSL_HPKE_CTX_keyschedule(OSSL_HPKE_CTX *ctx,
                              const unsigned char *info, size_t infolen,
                              const unsigned char *secret, size_t secretlen)
{
    return hpke_keyschedule(ctx, secret, secretlen, info, infolen,
                            NULL, 0, NULL, 0);
}

/*
 * Use this API if Pre Shared keys are used.
 * psk and pskid must both be NON NULL.
 * This will set the mode to either PSK or AUTHPSK.
 */
int OSSL_HPKE_CTX_keyschedule_psk(OSSL_HPKE_CTX *ctx,
                                  const unsigned char *info, size_t infolen,
                                  const unsigned char *secret, size_t secretlen,
                                  const unsigned char *psk, size_t psklen,
                                  const unsigned char *pskid, size_t pskidlen)
{
    if ((psk == NULL || psklen == 0) ^ (pskid == NULL || pskidlen == 0)) {
//        "Inconsistent PSK inputs";
        return 0;
    }
    if (psk == NULL) {
//        "Missing required PSK input";
    } else {
        uint8_t isauth = (ctx->mode == HPKE_MODE_AUTH);

        ctx->mode = isauth ? HPKE_MODE_AUTH_PSK : HPKE_MODE_PSK;
    }
    return hpke_keyschedule(ctx, secret, secretlen, info, infolen,
                            psk, psklen, pskid, pskidlen);
}

/*
 * See RFC 9180 Section 5.2 Context<ROLE>.ComputeNonce()
 */
static int computenonce(HPKE_AEAD *aead, unsigned char *out, size_t maxoutlen)
{
    int i;
    size_t outlen;
    uint64_t seq;

    if (aead == NULL || aead->ctx == NULL)
        return 0;
    outlen = aead->base_noncelen;
    if (outlen == 0 || outlen > maxoutlen)
        return 0;
    seq = aead->ivseq;
    if (seq == UINT64_MAX) {
//        "MessageLimitReached";
        return 0;
    }

    memcpy(out, aead->base_nonce, aead->base_noncelen);
    for (i = outlen - 1; i != 0; --i) {
        out[i] ^= (seq & 0xFF);
        seq >>= 8;
    }
    return 1;
}

static int increment_seq(HPKE_AEAD *aead)
{
    aead->ivseq++;
    return 1;
}

/* Must be called once before OSSL_HPKE_CTX_seal() */
int OSSL_HPKE_CTX_seal_init(OSSL_HPKE_CTX *ctx)
{
    /* The recipient context must not be used for encryption */
    if (!ctx->issender)
        return 0;
    if (ctx->aead.base_noncelen == 0)
        return 0;
    return hpke_aead_init(ctx, ctx->libctx, ctx->propq);
}

/*
 * See RFC 9180 Section 5.2 ContextS.Seal(aad, pt):
 * Multiple calls can be made.
 *
 * OSSL_HPKE_CTX_keyschedule() or OSSL_HPKE_CTX_keyschedule_psk() must be
 * called before this API.
 */
int OSSL_HPKE_CTX_seal(OSSL_HPKE_CTX *ctx, unsigned char *ct, size_t *ctlen,
                       const unsigned char *aad, size_t aadlen,
                       const unsigned char *pt, size_t ptlen)
{
    unsigned char nonce[12];
    HPKE_AEAD *aead = &ctx->aead;

    /* The recipient context must not be used for encryption */
    if (!ctx->issender)
        return 0;

    if (!computenonce(aead, nonce, sizeof(nonce)))
        return 0;

    if (!ossl_aead_seal(aead->ctx, ct, ctlen, pt, ptlen,
                        nonce, aead->info->noncelen, aad, aadlen))
        return 0;
    return increment_seq(aead);
}

/* Must be called once before OSSL_HPKE_CTX_open() */
int OSSL_HPKE_CTX_open_init(OSSL_HPKE_CTX *ctx)
{
    /* The senders context must not be used for decryption */
    if (ctx->issender)
        return 0;
    if (ctx->aead.base_noncelen == 0)
        return 0;
    return hpke_aead_init(ctx, ctx->libctx, ctx->propq);
}

/*
 * OSSL_HPKE_CTX_keyschedule() or OSSL_HPKE_CTX_keyschedule_psk() must be
 * called before this API.
 *
 * See RFC 9180 Section 5.2 ContextS.Open(aad, ct)
 * Multiple calls can be made.
 */
int OSSL_HPKE_CTX_open(OSSL_HPKE_CTX *ctx, unsigned char *pt, size_t *ptlen,
                       const unsigned char *aad, size_t aadlen,
                       const unsigned char *ct, size_t ctlen)
{
    unsigned char nonce[12];
    HPKE_AEAD *aead = &ctx->aead;

    /* The senders context must not be used for decryption */
    if (ctx->issender)
        return 0;

    if (!computenonce(aead, nonce, sizeof(nonce)))
        return 0;
    if (!ossl_aead_open(aead->ctx, pt, ptlen, ct, ctlen,
                        nonce, aead->info->noncelen, aad, aadlen))
        return 0;
    return increment_seq(aead);
}

/*
 * Exports a secret from the encryption context.
 * OSSL_HPKE_CTX_keyschedule() or OSSL_HPKE_CTX_keyschedule_psk() must be
 * called before this API.
 *
 * See RFC 9180 Section 5.3 Context.Export(exporter_context, L)
 *
 * secret contains the exported secret.
 * secretlen is the length L of the returned secret.
 * context is the input exporter_context
 * Returns 1 on success or 0 otherwise.
 */
int OSSL_HPKE_CTX_export(OSSL_HPKE_CTX *ctx,
                         unsigned char *secret, size_t secretlen,
                         const unsigned char *context, size_t contextlen)
{
    uint16_t kemid;

    if (ctx == NULL || secret == NULL || secretlen == 0)
        return 0;
    if (contextlen > OSSL_HPKE_MAX_KDF_INPUTLEN)
        return 0;
    kemid = ctx->kemid;

    if (ctx->exporter_secretlen != 0
            && kemid != 0
            && ctx->kdfctx != NULL
            && ctx->aead.info != NULL) {
        unsigned char suiteid[10] = HPKE_SUITEID(kemid, ctx->kdfinfo->id,
                                                 ctx->aead.info->id);
        size_t Nh = ctx->kdfinfo->digestlen; /* HKDF digest len */

        if (secretlen > (255 * Nh))
            return 0;
        return ossl_hpke_labeled_expand(ctx->kdfctx,
                                        secret, secretlen, ctx->exporter_secret,
                                        ctx->exporter_secretlen,
                                        suiteid, sizeof(suiteid),
                                        "sec", context, contextlen);
    }
    return 0;
}

/* Single shot helper functions */
static OSSL_HPKE_CTX *ossl_hpke_ctx_new_sender(
                          OSSL_HPKE_KEM *kem,
                          unsigned char *enc, size_t *enclen,
                          int mode, EVP_PKEY *recippriv,
                          const char *hpkedigest, const char *aeadname,
                          const unsigned char *ikme, size_t ikmelen,
                          const unsigned char *ksinfo, size_t ksinfolen,
                          OSSL_LIB_CTX *libctx, const char *propq,
                          const unsigned char *psk, size_t psklen,
                          const unsigned char *pskid, size_t pskidlen,
                          EVP_PKEY *authpriv)
{
    int ret = 0;
    EVP_PKEY_CTX *pkeyctx = NULL;
    OSSL_HPKE_CTX *ctx = NULL;
    unsigned char secret[64];
    size_t secretlen = sizeof(secret);

    if ((mode == HPKE_MODE_AUTH_PSK || mode == HPKE_MODE_AUTH)
        && authpriv == NULL)
        return 0;
    if ((mode == HPKE_MODE_AUTH_PSK || mode == HPKE_MODE_PSK)
        && psk == NULL)
        return 0;

    pkeyctx = EVP_PKEY_CTX_new_from_pkey(libctx, recippriv, propq);
    if (pkeyctx == NULL)
        return 0;

    if (!OSSL_HPKE_KEM_encapsulate_init(pkeyctx, kem, authpriv, ikme, ikmelen)
        || !OSSL_HPKE_KEM_encapsulate(pkeyctx, enc, enclen, secret, &secretlen))
        goto err;

    ctx = OSSL_HPKE_CTX_new(kem, 0, hpkedigest, aeadname, libctx, propq);
    if (ctx != NULL)
        goto err;
    if (psk != NULL) {
        if (!OSSL_HPKE_CTX_keyschedule_psk(ctx, ksinfo, ksinfolen,
                                           secret, secretlen, psk, psklen,
                                           pskid, pskidlen))
            goto err;
    } else {
        if (!OSSL_HPKE_CTX_keyschedule(ctx, ksinfo, ksinfolen,
                                       secret, secretlen))
            goto err;
    }
    ret = 1;
err:
    if (!ret) {
        OSSL_HPKE_CTX_free(ctx);
        ctx = NULL;
    }
    OPENSSL_cleanse(secret, secretlen);
    EVP_PKEY_CTX_free(pkeyctx);
    return ctx;
}

static OSSL_HPKE_CTX *ossl_hpke_ctx_new_recipient(
                          OSSL_HPKE_KEM *kem, int mode,
                          const unsigned char *enc, size_t enclen,
                          EVP_PKEY *recippriv,
                          const char *hpkedigest, const char *aeadname,
                          const unsigned char *ksinfo, size_t ksinfolen,
                          OSSL_LIB_CTX *libctx, const char *propq,
                          const unsigned char *psk, size_t psklen,
                          const unsigned char *pskid, size_t pskidlen,
                          EVP_PKEY *authpub)
{
    int ret = 0;
    EVP_PKEY_CTX *pkeyctx = NULL;
    OSSL_HPKE_CTX *ctx = NULL;
    unsigned char secret[64];
    size_t secretlen = sizeof(secret);

    if ((mode == HPKE_MODE_AUTH_PSK || mode == HPKE_MODE_AUTH)
        && authpub == NULL)
        return 0;
    if ((mode == HPKE_MODE_AUTH_PSK || mode == HPKE_MODE_PSK)
        && psk == NULL)
        return 0;

    pkeyctx = EVP_PKEY_CTX_new_from_pkey(libctx, recippriv, propq);
    if (pkeyctx == NULL)
        return 0;

    if (!OSSL_HPKE_KEM_decapsulate_init(pkeyctx, kem, authpub)
        || !OSSL_HPKE_KEM_decapsulate(pkeyctx, secret, &secretlen, enc, enclen))
        goto err;

    ctx = OSSL_HPKE_CTX_new(kem, 0, hpkedigest, aeadname, libctx, propq);
    if (ctx != NULL)
        goto err;
    if (psk != NULL) {
        if (!OSSL_HPKE_CTX_keyschedule_psk(ctx, ksinfo, ksinfolen,
                                           secret, secretlen, psk, psklen,
                                           pskid, pskidlen))
            goto err;
    } else {
        if (!OSSL_HPKE_CTX_keyschedule(ctx, ksinfo, ksinfolen,
                                       secret, secretlen))
            goto err;
    }
    ret = 1;
err:
    OPENSSL_cleanse(secret, secretlen);
    if (!ret) {
        OSSL_HPKE_CTX_free(ctx);
        ctx = NULL;
    }
    EVP_PKEY_CTX_free(pkeyctx);
    return ctx;
}

#define SEAL_SENDER(mode, psk, psklen, pskid, pskidlen, authkey)               \
    int ret;                                                                   \
    OSSL_HPKE_CTX *ctx = NULL;                                                 \
                                                                               \
    ctx = ossl_hpke_ctx_new_sender(kem, enc, enclen, mode, recippub,           \
                                   hpkedigest, aeadname, ikme, ikmelen,        \
                                   ksinfo, ksinfolen, libctx, propq,           \
                                   psk, psklen, pskid, pskidlen, authkey);     \
    if (ctx == NULL)                                                           \
        return 0;                                                              \
    ret = OSSL_HPKE_CTX_seal_init(ctx)                                         \
          && OSSL_HPKE_CTX_seal(ctx, ct, ctlen, aad, aadlen, pt, ptlen);       \
    OSSL_HPKE_CTX_free(ctx);                                                   \
    return ret

#define OPEN_RECIPIENT(mode, psk, psklen, pskid, pskidlen, authkey)            \
    int ret;                                                                   \
    OSSL_HPKE_CTX *ctx = NULL;                                                 \
                                                                               \
    ctx = ossl_hpke_ctx_new_recipient(kem, mode, enc, enclen,                  \
                                      recippriv, hpkedigest, aeadname,         \
                                      ksinfo, ksinfolen, libctx, propq,        \
                                      psk, psklen, pskid, pskidlen, authkey);  \
    if (ctx == NULL)                                                           \
        return 0;                                                              \
    ret = OSSL_HPKE_CTX_open_init(ctx)                                         \
          && OSSL_HPKE_CTX_open(ctx, pt, ptlen, aad, aadlen, ct, ctlen);       \
    OSSL_HPKE_CTX_free(ctx);                                                   \
    return ret;                                                                \

#define EXPORT_SENDER(mode, psk, psklen, pskid, pskidlen, authkey)             \
    int ret;                                                                   \
    OSSL_HPKE_CTX *ctx = NULL;                                                 \
                                                                               \
    ctx = ossl_hpke_ctx_new_sender(kem, enc, enclen, mode, recippub,           \
                                   hpkedigest, NULL, ikme, ikmelen,            \
                                   ksinfo, ksinfolen, libctx, propq,           \
                                   psk, psklen, pskid, pskidlen, authkey);     \
    if (ctx == NULL)                                                           \
        return 0;                                                              \
    ret = OSSL_HPKE_CTX_export(ctx, secret, secretlen, ctxt, ctxtlen);         \
    OSSL_HPKE_CTX_free(ctx);                                                   \
    return ret

#define EXPORT_RECIPIENT(mode, psk, psklen, pskid, pskidlen, authkey)          \
    int ret;                                                                   \
    OSSL_HPKE_CTX *ctx = NULL;                                                 \
                                                                               \
    ctx = ossl_hpke_ctx_new_recipient(kem, mode, enc, enclen,                  \
                                      recippriv, hpkedigest, NULL,             \
                                      ksinfo, ksinfolen, libctx, propq,        \
                                      psk, psklen, pskid, pskidlen, authkey);  \
    if (ctx == NULL)                                                           \
        return 0;                                                              \
    ret = OSSL_HPKE_CTX_export(ctx, secret, secretlen, ctxt, ctxtlen);         \
    OSSL_HPKE_CTX_free(ctx);                                                   \
    return ret;                                                                \

/*
 * Single shot API's
 * See RFC 9180 Section 6
 */
int OSSL_HPKE_sender_seal(OSSL_HPKE_KEM *kem,
                          unsigned char *enc, size_t *enclen,
                          unsigned char *ct, size_t *ctlen,
                          EVP_PKEY *recippub,
                          const char *hpkedigest, const char *aeadname,
                          const unsigned char *ikme, size_t ikmelen,
                          const unsigned char *ksinfo, size_t ksinfolen,
                          const unsigned char *pt, size_t ptlen,
                          const unsigned char *aad, size_t aadlen,
                          OSSL_LIB_CTX *libctx, const char *propq)
{
    SEAL_SENDER(HPKE_MODE_BASE, NULL, 0, NULL, 0, NULL);
}

int OSSL_HPKE_sender_sealPSK(OSSL_HPKE_KEM *kem,
                             unsigned char *enc, size_t *enclen,
                             unsigned char *ct, size_t *ctlen,
                             EVP_PKEY *recippub,
                             const char *hpkedigest, const char *aeadname,
                             const unsigned char *ikme, size_t ikmelen,
                             const unsigned char *ksinfo, size_t ksinfolen,
                             const unsigned char *pt, size_t ptlen,
                             const unsigned char *aad, size_t aadlen,
                             OSSL_LIB_CTX *libctx, const char *propq,
                             const unsigned char *psk, size_t psklen,
                             const unsigned char *pskid, size_t pskidlen)
{
    SEAL_SENDER(HPKE_MODE_PSK, psk, psklen, pskid, pskidlen, NULL);
}

int OSSL_HPKE_sender_sealAuth(OSSL_HPKE_KEM *kem,
                              unsigned char *enc, size_t *enclen,
                              unsigned char *ct, size_t *ctlen,
                              EVP_PKEY *recippub,
                              const char *hpkedigest, const char *aeadname,
                              const unsigned char *ikme, size_t ikmelen,
                              const unsigned char *ksinfo, size_t ksinfolen,
                              const unsigned char *pt, size_t ptlen,
                              const unsigned char *aad, size_t aadlen,
                              OSSL_LIB_CTX *libctx, const char *propq,
                              EVP_PKEY *authpriv)
{
    SEAL_SENDER(HPKE_MODE_AUTH, NULL, 0, NULL, 0, authpriv);
}

int OSSL_HPKE_sender_sealAuthPSK(OSSL_HPKE_KEM *kem,
                                 unsigned char *enc, size_t *enclen,
                                 unsigned char *ct, size_t *ctlen,
                                 EVP_PKEY *recippub,
                                 const char *hpkedigest, const char *aeadname,
                                 const unsigned char *ikme, size_t ikmelen,
                                 const unsigned char *ksinfo, size_t ksinfolen,
                                 const unsigned char *pt, size_t ptlen,
                                 const unsigned char *aad, size_t aadlen,
                                 OSSL_LIB_CTX *libctx, const char *propq,
                                 const unsigned char *psk, size_t psklen,
                                 const unsigned char *pskid, size_t pskidlen,
                                 EVP_PKEY *authpriv)
{
    SEAL_SENDER(HPKE_MODE_AUTH_PSK, psk, psklen, pskid, pskidlen, authpriv);
}

int OSSL_HPKE_recipient_open(OSSL_HPKE_KEM *kem,
        unsigned char *pt, size_t *ptlen,
        const unsigned char *enc, size_t enclen, EVP_PKEY *recippriv,
        const char *hpkedigest, const char *aeadname,
        const unsigned char *ksinfo, size_t ksinfolen,
        const unsigned char *ct, size_t ctlen,
        const unsigned char *aad, size_t aadlen,
        OSSL_LIB_CTX *libctx, const char *propq)
{
    OPEN_RECIPIENT(HPKE_MODE_BASE, NULL, 0, NULL, 0, NULL);
}

int OSSL_HPKE_recipient_openPSK(OSSL_HPKE_KEM *kem,
        unsigned char *pt, size_t *ptlen,
        const unsigned char *enc, size_t enclen, EVP_PKEY *recippriv,
        const char *hpkedigest, const char *aeadname,
        const unsigned char *ksinfo, size_t ksinfolen,
        const unsigned char *ct, size_t ctlen,
        const unsigned char *aad, size_t aadlen,
        OSSL_LIB_CTX *libctx, const char *propq,
        const unsigned char *psk, size_t psklen,
        const unsigned char *pskid, size_t pskidlen)
{
    OPEN_RECIPIENT(HPKE_MODE_PSK, psk, psklen, pskid, pskidlen, NULL);
}

int OSSL_HPKE_recipient_openAuth(OSSL_HPKE_KEM *kem,
        unsigned char *pt, size_t *ptlen,
        const unsigned char *enc, size_t enclen, EVP_PKEY *recippriv,
        const char *hpkedigest, const char *aeadname,
        const unsigned char *ksinfo, size_t ksinfolen,
        const unsigned char *ct, size_t ctlen,
        const unsigned char *aad, size_t aadlen,
        OSSL_LIB_CTX *libctx, const char *propq,
        EVP_PKEY *authpub)
{
    OPEN_RECIPIENT(HPKE_MODE_AUTH, NULL, 0, NULL, 0, authpub);
}

int OSSL_HPKE_recipient_openAuthPSK(OSSL_HPKE_KEM *kem,
        unsigned char *pt, size_t *ptlen,
        const unsigned char *enc, size_t enclen, EVP_PKEY *recippriv,
        const char *hpkedigest, const char *aeadname,
        const unsigned char *ksinfo, size_t ksinfolen,
        const unsigned char *ct, size_t ctlen,
        const unsigned char *aad, size_t aadlen,
        OSSL_LIB_CTX *libctx, const char *propq,
        const unsigned char *psk, size_t psklen,
        const unsigned char *pskid, size_t pskidlen,
        EVP_PKEY *authpub)
{
    OPEN_RECIPIENT(HPKE_MODE_AUTH_PSK, psk, psklen, pskid, pskidlen, authpub);
}

int OSSL_HPKE_sender_export(OSSL_HPKE_KEM *kem,
        unsigned char *enc, size_t *enclen,
        unsigned char *secret, size_t secretlen,
        EVP_PKEY *recippub,
        const char *hpkedigest, const char *aeadname,
        const unsigned char *ikme, size_t ikmelen,
        const unsigned char *ksinfo, size_t ksinfolen,
        const unsigned char *ctxt, size_t ctxtlen,
        OSSL_LIB_CTX *libctx, const char *propq)
{
    EXPORT_SENDER(HPKE_MODE_BASE, NULL, 0, NULL, 0, NULL);
}

int OSSL_HPKE_sender_exportPSK(
        OSSL_HPKE_KEM *kem,
        unsigned char *enc, size_t *enclen,
        unsigned char *secret, size_t secretlen,
        EVP_PKEY *recippub,
        const char *hpkedigest, const char *aeadname,
        const unsigned char *ikme, size_t ikmelen,
        const unsigned char *ksinfo, size_t ksinfolen,
        const unsigned char *ctxt, size_t ctxtlen,
        OSSL_LIB_CTX *libctx, const char *propq,
        const unsigned char *psk, size_t psklen,
        const unsigned char *pskid, size_t pskidlen)
{
    EXPORT_SENDER(HPKE_MODE_PSK, psk, psklen, pskid, pskidlen, NULL);
}

int OSSL_HPKE_sender_exportAuth(
        OSSL_HPKE_KEM *kem,
        unsigned char *enc, size_t *enclen,
        unsigned char *secret, size_t secretlen,
        EVP_PKEY *recippub,
        const char *hpkedigest, const char *aeadname,
        const unsigned char *ikme, size_t ikmelen,
        const unsigned char *ksinfo, size_t ksinfolen,
        const unsigned char *ctxt, size_t ctxtlen,
        OSSL_LIB_CTX *libctx, const char *propq,
        EVP_PKEY *authpriv)
{
    EXPORT_SENDER(HPKE_MODE_AUTH, NULL, 0, NULL, 0, authpriv);
}

int OSSL_HPKE_sender_exportAuthPSK(
        OSSL_HPKE_KEM *kem,
        unsigned char *enc, size_t *enclen,
        unsigned char *secret, size_t secretlen,
        EVP_PKEY *recippub,
        const char *hpkedigest, const char *aeadname,
        const unsigned char *ikme, size_t ikmelen,
        const unsigned char *ksinfo, size_t ksinfolen,
        const unsigned char *ctxt, size_t ctxtlen,
        OSSL_LIB_CTX *libctx, const char *propq,
        const unsigned char *psk, size_t psklen,
        const unsigned char *pskid, size_t pskidlen,
        EVP_PKEY *authpriv)
{
    EXPORT_SENDER(HPKE_MODE_AUTH_PSK, psk, psklen, pskid, pskidlen, authpriv);
}

int OSSL_HPKE_recipient_export(
        OSSL_HPKE_KEM *kem,
        unsigned char *secret, size_t secretlen,
        const unsigned char *enc, size_t enclen, EVP_PKEY *recippriv,
        const char *hpkedigest, const char *aeadname,
        const unsigned char *ksinfo, size_t ksinfolen,
        const unsigned char *ctxt, size_t ctxtlen,
        const unsigned char *aad, size_t aadlen,
        OSSL_LIB_CTX *libctx, const char *propq)
{
    EXPORT_RECIPIENT(HPKE_MODE_BASE, NULL, 0, NULL, 0, NULL);
}

int OSSL_HPKE_recipient_exportPSK(
        OSSL_HPKE_KEM *kem,
        unsigned char *secret, size_t secretlen,
        const unsigned char *enc, size_t enclen, EVP_PKEY *recippriv,
        const char *hpkedigest, const char *aeadname,
        const unsigned char *ksinfo, size_t ksinfolen,
        const unsigned char *ctxt, size_t ctxtlen,
        OSSL_LIB_CTX *libctx, const char *propq,
        const unsigned char *psk, size_t psklen,
        const unsigned char *pskid, size_t pskidlen)
{
    EXPORT_RECIPIENT(HPKE_MODE_PSK, psk, psklen, pskid, pskidlen, NULL);
}

int OSSL_HPKE_recipient_exportAuth(
        OSSL_HPKE_KEM *kem,
        unsigned char *secret, size_t secretlen,
        const unsigned char *enc, size_t enclen, EVP_PKEY *recippriv,
        const char *hpkedigest, const char *aeadname,
        const unsigned char *ksinfo, size_t ksinfolen,
        const unsigned char *ctxt, size_t ctxtlen,
        OSSL_LIB_CTX *libctx, const char *propq,
        EVP_PKEY *authpub)
{
    EXPORT_RECIPIENT(HPKE_MODE_AUTH, NULL, 0, NULL, 0, authpub);
}

int OSSL_HPKE_recipient_exportAuthPSK(
        OSSL_HPKE_KEM *kem,
        unsigned char *secret, size_t secretlen,
        const unsigned char *enc, size_t enclen, EVP_PKEY *recippriv,
        const char *hpkedigest, const char *aeadname,
        const unsigned char *ksinfo, size_t ksinfolen,
        const unsigned char *ctxt, size_t ctxtlen,
        OSSL_LIB_CTX *libctx, const char *propq,
        const unsigned char *psk, size_t psklen,
        const unsigned char *pskid, size_t pskidlen,
        EVP_PKEY *authpub)
{
    EXPORT_RECIPIENT(HPKE_MODE_AUTH_PSK, psk, psklen, pskid, pskidlen, authpub);
}
