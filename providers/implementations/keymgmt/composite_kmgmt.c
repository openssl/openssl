/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/param_build.h>
#include <openssl/proverr.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/x509.h>
#include "crypto/evp.h"
#include "crypto/ml_dsa.h"
#include "internal/param_build_set.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "prov/ml_dsa.h"
#include "prov/composite.h"
#include "providers/implementations/keymgmt/composite_kmgmt.inc"

/*
 * Per-algorithm generation context.
 * Allocated in composite_gen_init(), freed in composite_gen_cleanup().
 */
typedef struct {
    PROV_CTX *provctx; /* full provider context (not just libctx) */
    char *propq;
    /* Algorithm-specific constants are passed directly to composite_gen()
     * from the per-algorithm wrapper in MAKE_KEYMGMT_FUNCTIONS; they are
     * compile-time literals and do not need to live in the context. */
    uint8_t *priv_seed; /* optional: mldsaSeed||tradSK for deterministic gen */
    size_t priv_seed_len;
} COMPOSITE_GEN_CTX;

/* Forward declarations of all static keymgmt functions */
static OSSL_FUNC_keymgmt_free_fn composite_free_key;
static OSSL_FUNC_keymgmt_has_fn composite_has;
static OSSL_FUNC_keymgmt_match_fn composite_match;
static OSSL_FUNC_keymgmt_dup_fn composite_dup_key;
static OSSL_FUNC_keymgmt_validate_fn composite_validate;
static OSSL_FUNC_keymgmt_export_fn composite_export;
static OSSL_FUNC_keymgmt_import_types_fn composite_import_types;
static OSSL_FUNC_keymgmt_export_types_fn composite_export_types;
static OSSL_FUNC_keymgmt_gettable_params_fn composite_gettable_params;
static OSSL_FUNC_keymgmt_get_params_fn composite_get_params;
static OSSL_FUNC_keymgmt_load_fn composite_load;
static OSSL_FUNC_keymgmt_gen_init_fn composite_gen_init;
static OSSL_FUNC_keymgmt_gen_cleanup_fn composite_gen_cleanup;
static OSSL_FUNC_keymgmt_gen_set_params_fn composite_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn composite_gen_settable_params;

/* =========================================================================
 * Key management helpers
 * ========================================================================= */

static COMPOSITE_KEY *ossl_composite_key_new(OSSL_LIB_CTX *libctx,
    const char *propq,
    int ml_dsa_evp_type)
{
    COMPOSITE_KEY *key = OPENSSL_zalloc(sizeof(*key));

    if (key == NULL)
        return NULL;
    key->ml_dsa_key = ossl_ml_dsa_key_new(libctx, propq, ml_dsa_evp_type);
    if (key->ml_dsa_key == NULL) {
        OPENSSL_free(key);
        return NULL;
    }
    return key;
}

void ossl_composite_key_free(COMPOSITE_KEY *key)
{
    if (key == NULL)
        return;
    ossl_ml_dsa_key_free(key->ml_dsa_key);
    EVP_PKEY_free(key->classic_key);
    OPENSSL_free(key);
}

/* True only if the ML-DSA half satisfies selection AND the classic half is present. */
static int ossl_composite_key_has(const COMPOSITE_KEY *key, int selection)
{
    if (!ossl_ml_dsa_key_has(key->ml_dsa_key, selection))
        return 0;
    if (key->classic_key == NULL)
        return 0;
    return 1;
}

/*
 * Approximate combined public key length in bytes (ML-DSA pk_len plus
 * ceil(classic bits / 8)).  Not the exact DER/point-encoded size — only
 * valid for reporting OSSL_PKEY_PARAM_BITS, never for buffer sizing.
 */
static size_t ossl_composite_key_get_pub_len(const COMPOSITE_KEY *key)
{
    size_t ml_dsa_len = ossl_ml_dsa_key_get_pub_len(key->ml_dsa_key);

    if (key->classic_key == NULL)
        return ml_dsa_len; // if there is not classic key, composite is malformed
    return ml_dsa_len + (size_t)((EVP_PKEY_get_bits(key->classic_key) + 7) / 8);
}

/*
 * Security bits of the composite = minimum of ML-DSA collision strength and
 * the classic component's security bits.
 */
static int ossl_composite_key_get_security_bits(const COMPOSITE_KEY *key)
{
    size_t ml_dsa_sec = ossl_ml_dsa_key_get_collision_strength_bits(key->ml_dsa_key);
    int classic_sec = (key->classic_key != NULL)
        ? EVP_PKEY_get_security_bits(key->classic_key)
        : 0;

    if (classic_sec <= 0)
        return (int)ml_dsa_sec;
    return (int)ml_dsa_sec < classic_sec ? (int)ml_dsa_sec : classic_sec;
}

/*
 * Maximum composite signature size: ML-DSA fixed sig_len plus the classic
 * component's maximum signature size.
 */
static int ossl_composite_key_get_max_size(const COMPOSITE_KEY *key)
{
    size_t ml_dsa_sig = ossl_ml_dsa_key_get_sig_len(key->ml_dsa_key);
    int classic_sig = (key->classic_key != NULL)
        ? EVP_PKEY_get_size(key->classic_key)
        : 0;

    return (int)ml_dsa_sig + (classic_sig > 0 ? classic_sig : 0);
}

/* Compares EC group names, resolving NIST aliases (e.g. "P-256") to their canonical NID. */
static int composite_ec_curve_matches(const char *grp, const char *ec_curve)
{
    int actual_nid = OBJ_txt2nid(grp);
    int expected_nid = EC_curve_nist2nid(ec_curve);

    if (expected_nid == NID_undef)
        expected_nid = OBJ_txt2nid(ec_curve);
    return actual_nid != NID_undef && actual_nid == expected_nid;
}

/* Forward declarations for helpers defined later in this file */
static int composite_encode_classic_key(const EVP_PKEY *pkey, int include_priv,
    unsigned char **out, size_t *out_len);
static EVP_PKEY *composite_decode_classic_key(OSSL_LIB_CTX *libctx,
    const char *classic_alg, int classic_bits, const char *ec_curve,
    int include_priv, const unsigned char *buf, size_t buf_len);

COMPOSITE_KEY *ossl_prov_composite_new(PROV_CTX *ctx, const char *propq,
    int ml_dsa_evp_type)
{
    if (!ossl_prov_is_running())
        return NULL;

    return ossl_composite_key_new(PROV_LIBCTX_OF(ctx), propq, ml_dsa_evp_type);
}

static void composite_free_key(void *keydata)
{
    ossl_composite_key_free((COMPOSITE_KEY *)keydata);
}

static int composite_has(const void *keydata, int selection)
{
    const COMPOSITE_KEY *key = keydata;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 1; /* the selection is not missing */

    return ossl_composite_key_has(key, selection);
}

static void *composite_gen_init(void *provctx, int selection,
    const OSSL_PARAM params[])
{
    COMPOSITE_GEN_CTX *gctx = NULL;

    if (!ossl_prov_is_running())
        return NULL;

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->provctx = provctx;
        if (!composite_gen_set_params(gctx, params)) {
            OPENSSL_free(gctx);
            gctx = NULL;
        }
    }

    return gctx;
}

static void composite_gen_cleanup(void *genctx)
{
    COMPOSITE_GEN_CTX *gctx = genctx;

    if (gctx == NULL)
        return;

    OPENSSL_secure_clear_free(gctx->priv_seed, gctx->priv_seed_len);
    OPENSSL_free(gctx->propq);
    OPENSSL_free(gctx);
}

static const OSSL_PARAM *composite_gen_settable_params(void *genctx,
    void *provctx)
{
    return composite_gen_set_params_list;
}

static int composite_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    COMPOSITE_GEN_CTX *gctx = genctx;
    struct composite_gen_set_params_st p;

    if (gctx == NULL || !composite_gen_set_params_decoder(params, &p))
        return 0;

    if (p.privkey != NULL) {
        const void *seed_ptr;
        size_t seed_len;

        if (!OSSL_PARAM_get_octet_string_ptr(p.privkey, &seed_ptr, &seed_len))
            return 0;
        OPENSSL_secure_clear_free(gctx->priv_seed, gctx->priv_seed_len);
        gctx->priv_seed = OPENSSL_secure_malloc(seed_len);
        if (gctx->priv_seed == NULL)
            return 0;
        memcpy(gctx->priv_seed, seed_ptr, seed_len);
        gctx->priv_seed_len = seed_len;
    }

    if (p.propq != NULL) {
        OPENSSL_free(gctx->propq);
        gctx->propq = NULL;
        if (!OSSL_PARAM_get_utf8_string(p.propq, &gctx->propq, 0))
            return 0;
    }
    return 1;
}

static void *composite_gen(void *genctx, int evp_type,
    const char *classic_alg, int classic_bits,
    const char *ec_curve)
{
    COMPOSITE_GEN_CTX *gctx = genctx;
    COMPOSITE_KEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    if (!ossl_prov_is_running())
        return NULL;

    key = ossl_prov_composite_new(gctx->provctx, gctx->propq, evp_type);
    if (key == NULL)
        return NULL;

    if (gctx->priv_seed_len != 0) {
        /*
         * Deterministic keygen: caller supplied mldsaSeed(32) || tradSK.
         * Expand the ML-DSA seed and import the classic private key directly.
         */
        if (gctx->priv_seed_len <= ML_DSA_SEED_BYTES) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SEED_LENGTH);
            goto err;
        }
        if (!ossl_ml_dsa_set_prekey(key->ml_dsa_key, 0, 0,
                gctx->priv_seed, ML_DSA_SEED_BYTES, NULL, 0))
            goto err;
        if (!ossl_ml_dsa_generate_key(key->ml_dsa_key)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
            goto err;
        }
        key->classic_key = composite_decode_classic_key(
            PROV_LIBCTX_OF(gctx->provctx), classic_alg, classic_bits, ec_curve, 1,
            gctx->priv_seed + ML_DSA_SEED_BYTES,
            gctx->priv_seed_len - ML_DSA_SEED_BYTES);
        if (key->classic_key == NULL)
            goto err;
    } else if (!ossl_ml_dsa_generate_key(key->ml_dsa_key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
        goto err;
    } else if (strcmp(classic_alg, "RSA") == 0) {
        unsigned int rsa_bits = (unsigned int)classic_bits;
        OSSL_PARAM rsa_params[2];

        rsa_params[0] = OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_BITS,
            &rsa_bits);
        rsa_params[1] = OSSL_PARAM_construct_end();
        ctx = EVP_PKEY_CTX_new_from_name(PROV_LIBCTX_OF(gctx->provctx),
            "RSA", gctx->propq);
        if (ctx == NULL)
            goto err;
        if (EVP_PKEY_keygen_init(ctx) <= 0)
            goto err;
        if (EVP_PKEY_CTX_set_params(ctx, rsa_params) <= 0)
            goto err;
        if (EVP_PKEY_keygen(ctx, &key->classic_key) <= 0)
            goto err;
    } else if (strcmp(classic_alg, "EC") == 0) {
        ctx = EVP_PKEY_CTX_new_from_name(PROV_LIBCTX_OF(gctx->provctx),
            "EC", gctx->propq);
        if (ctx == NULL)
            goto err;
        if (EVP_PKEY_keygen_init(ctx) <= 0)
            goto err;
        if (EVP_PKEY_CTX_set_group_name(ctx, ec_curve) <= 0)
            goto err;
        if (EVP_PKEY_keygen(ctx, &key->classic_key) <= 0)
            goto err;
        /* composite draft requires ECPrivateKey without publicKey field */
        EVP_PKEY_set_int_param(key->classic_key,
            OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, 0);
    } else if (strcmp(classic_alg, "ED25519") == 0
        || strcmp(classic_alg, "ED448") == 0) {
        ctx = EVP_PKEY_CTX_new_from_name(PROV_LIBCTX_OF(gctx->provctx),
            classic_alg, gctx->propq);
        if (ctx == NULL)
            goto err;
        if (EVP_PKEY_keygen_init(ctx) <= 0)
            goto err;
        if (EVP_PKEY_keygen(ctx, &key->classic_key) <= 0)
            goto err;
    } else {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
            "unsupported classic algorithm: %s", classic_alg);
        goto err;
    }

    EVP_PKEY_CTX_free(ctx);
    return key;
err:
    EVP_PKEY_CTX_free(ctx);
    ossl_composite_key_free(key);
    return NULL;
}

static const OSSL_PARAM *composite_gettable_params(void *provctx)
{
    return composite_get_params_list;
}

static int composite_get_params(void *keydata, OSSL_PARAM params[])
{
    COMPOSITE_KEY *key = keydata;
    struct composite_get_params_st p;

    if (key == NULL || !composite_get_params_decoder(params, &p))
        return 0;

    if (p.bits != NULL && !OSSL_PARAM_set_int(p.bits, (int)(8 * ossl_composite_key_get_pub_len(key))))
        return 0;

    if (p.secbits != NULL && !OSSL_PARAM_set_int(p.secbits, ossl_composite_key_get_security_bits(key)))
        return 0;

    if (p.maxsize != NULL && !OSSL_PARAM_set_int(p.maxsize, ossl_composite_key_get_max_size(key)))
        return 0;

    if (p.privkey != NULL) {
        /* Build mldsaSeed(32) || tradSK from the composite key */
        const uint8_t *ml_dsa_seed = ossl_ml_dsa_key_get_seed(key->ml_dsa_key);
        unsigned char *classic_priv = NULL;
        size_t classic_priv_len = 0;
        unsigned char *priv_buf = NULL;
        size_t priv_len;
        int ok = 0;

        if (ml_dsa_seed == NULL || key->classic_key == NULL)
            return 0;
        if (!composite_encode_classic_key(key->classic_key, 1,
                &classic_priv, &classic_priv_len))
            return 0;
        priv_len = ML_DSA_SEED_BYTES + classic_priv_len;
        priv_buf = OPENSSL_secure_malloc(priv_len);
        if (priv_buf != NULL) {
            memcpy(priv_buf, ml_dsa_seed, ML_DSA_SEED_BYTES);
            memcpy(priv_buf + ML_DSA_SEED_BYTES, classic_priv, classic_priv_len);
            ok = OSSL_PARAM_set_octet_string(p.privkey, priv_buf, priv_len);
            OPENSSL_secure_clear_free(priv_buf, priv_len);
        }
        OPENSSL_clear_free(classic_priv, classic_priv_len);
        if (!ok)
            return 0;
    }

    if (p.pubkey != NULL) {
        /* Build mldsaPK || tradPK from the composite key */
        const ML_DSA_PARAMS *kp = ossl_ml_dsa_key_params(key->ml_dsa_key);
        const uint8_t *ml_dsa_pub = ossl_ml_dsa_key_get_pub(key->ml_dsa_key);
        unsigned char *classic_pub = NULL;
        size_t classic_pub_len = 0;
        unsigned char *pub_buf = NULL;
        size_t pub_len;
        int ok = 0;

        if (ml_dsa_pub == NULL || key->classic_key == NULL)
            return 0;
        if (!composite_encode_classic_key(key->classic_key, 0,
                &classic_pub, &classic_pub_len))
            return 0;
        pub_len = kp->pk_len + classic_pub_len;
        pub_buf = OPENSSL_malloc(pub_len);
        if (pub_buf != NULL) {
            memcpy(pub_buf, ml_dsa_pub, kp->pk_len);
            memcpy(pub_buf + kp->pk_len, classic_pub, classic_pub_len);
            ok = OSSL_PARAM_set_octet_string(p.pubkey, pub_buf, pub_len);
            OPENSSL_free(pub_buf);
        }
        OPENSSL_free(classic_pub);
        if (!ok)
            return 0;
    }

    return 1;
}

/*
 * Validates the key material itself (pairwise pub/priv consistency for
 * both sub-keys).
 */
static int composite_validate(const void *keydata, int selection,
    int check_type)
{
    const COMPOSITE_KEY *key = keydata;

    if (!composite_has(keydata, selection))
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == OSSL_KEYMGMT_SELECT_KEYPAIR) {
        if (!ossl_ml_dsa_key_pairwise_check(key->ml_dsa_key))
            return 0;

        if (key->classic_key == NULL || !evp_pkey_is_provided(key->classic_key))
            return 0;
        return evp_keymgmt_validate(key->classic_key->keymgmt,
            key->classic_key->keydata,
            selection, check_type);
    }
    return 1;
}

static const OSSL_PARAM *composite_import_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return NULL;
    return composite_import_params_list;
}

static const OSSL_PARAM *composite_export_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return NULL;
    return composite_export_params_list;
}

/*
 * Decode the traditional sub-key from its raw wire format as defined in
 * draft-ietf-lamps-pq-composite-sigs:
 *
 *   RSA:      RSAPublicKey DER (pub)  / RSAPrivateKey DER (priv)   — PKCS#1
 *   EC:       Uncompressed X9.62 point 0x04||x||y (pub)
 *             / ECPrivateKey DER with NamedCurve (priv)            — RFC5915
 */
/* Extract the privateKey OCTET STRING content from an RFC 5915 ECPrivateKey DER. */
static const unsigned char *rfc5915_extract_privkey(const unsigned char *buf,
    size_t buf_len, size_t *priv_len)
{
    const unsigned char *p = buf;
    const unsigned char *end = buf + buf_len;
    size_t seq_len, key_len;

    /* Outer SEQUENCE tag */
    if (p >= end || *p++ != 0x30)
        return NULL;
    /* DER length of SEQUENCE content */
    if (p >= end)
        return NULL;
    if (*p & 0x80) {
        int nb = (int)(*p++ & 0x7f);
        if (nb == 0 || nb > 4 || p + nb > end)
            return NULL;
        seq_len = 0;
        while (nb--)
            seq_len = (seq_len << 8) | (unsigned char)*p++;
    } else {
        seq_len = (unsigned char)*p++;
    }
    if ((size_t)(end - p) < seq_len)
        return NULL;
    end = p + seq_len;

    /* version: 02 01 01 */
    if (end - p < 3 || p[0] != 0x02 || p[1] != 0x01 || p[2] != 0x01)
        return NULL;
    p += 3;

    /* privateKey OCTET STRING: 04 <len> <bytes> */
    if (p >= end || *p++ != 0x04)
        return NULL;
    if (p >= end)
        return NULL;
    if (*p & 0x80) {
        int nb = (int)(*p++ & 0x7f);
        if (nb == 0 || nb > 2 || p + nb > end)
            return NULL;
        key_len = 0;
        while (nb--)
            key_len = (key_len << 8) | (unsigned char)*p++;
    } else {
        key_len = (unsigned char)*p++;
    }
    if ((size_t)(end - p) < key_len)
        return NULL;
    *priv_len = key_len;
    return p;
}

static EVP_PKEY *composite_decode_classic_key(OSSL_LIB_CTX *libctx,
    const char *classic_alg,
    int classic_bits,
    const char *ec_curve,
    int include_priv,
    const unsigned char *buf,
    size_t buf_len)
{
    EVP_PKEY *pkey = NULL;
    const unsigned char *ptr;
    size_t ptrlen;
    OSSL_DECODER_CTX *dctx;
    OSSL_PARAM params[4];
    EVP_PKEY_CTX *pctx;

    if (strcmp(classic_alg, "RSA") == 0) {
        /*
         * RSAPublicKey (pub) or RSAPrivateKey (priv) — PKCS#1 DER.
         * The "type-specific" OSSL_DECODER structure handles both via
         * d2i_RSAPublicKey / d2i_RSAPrivateKey.
         */
        ptr = buf;
        ptrlen = buf_len;
        dctx = OSSL_DECODER_CTX_new_for_pkey(
            &pkey, "DER", "type-specific", "RSA",
            include_priv ? OSSL_KEYMGMT_SELECT_PRIVATE_KEY
                         : OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            libctx, NULL);
        if (dctx == NULL)
            return NULL;
        if (!OSSL_DECODER_from_data(dctx, &ptr, &ptrlen))
            pkey = NULL;
        OSSL_DECODER_CTX_free(dctx);
    } else if (strcmp(classic_alg, "EC") == 0) {
        if (include_priv) {
            /* Try the standard decoder first; fall back to manual RFC 5915
             * parsing on targets where the decoder chain is unavailable. */
            ptr = buf;
            ptrlen = buf_len;
            dctx = OSSL_DECODER_CTX_new_for_pkey(
                &pkey, "DER", "type-specific", "EC",
                OSSL_KEYMGMT_SELECT_PRIVATE_KEY, libctx, NULL);
            if (dctx != NULL) {
                if (!OSSL_DECODER_from_data(dctx, &ptr, &ptrlen))
                    pkey = NULL;
                OSSL_DECODER_CTX_free(dctx);
            }
            if (pkey == NULL) {
                const unsigned char *priv_bytes;
                size_t priv_len;
                BIGNUM *priv_bn = NULL;
                OSSL_PARAM_BLD *bld = NULL;
                OSSL_PARAM *built = NULL;

                ERR_clear_error();
                priv_bytes = rfc5915_extract_privkey(buf, buf_len, &priv_len);
                if (priv_bytes == NULL)
                    return NULL;

                priv_bn = BN_bin2bn(priv_bytes, (int)priv_len, NULL);
                bld = priv_bn != NULL ? OSSL_PARAM_BLD_new() : NULL;
                if (bld == NULL
                    || !OSSL_PARAM_BLD_push_utf8_string(bld,
                        OSSL_PKEY_PARAM_GROUP_NAME, ec_curve, 0)
                    || !OSSL_PARAM_BLD_push_BN(bld,
                        OSSL_PKEY_PARAM_PRIV_KEY, priv_bn)
                    || (built = OSSL_PARAM_BLD_to_param(bld)) == NULL) {
                    OSSL_PARAM_BLD_free(bld);
                    BN_free(priv_bn);
                    return NULL;
                }
                OSSL_PARAM_BLD_free(bld);
                BN_free(priv_bn);

                pctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
                if (pctx == NULL) {
                    OSSL_PARAM_free(built);
                    return NULL;
                }
                if (EVP_PKEY_fromdata_init(pctx) <= 0
                    || EVP_PKEY_fromdata(pctx, &pkey,
                           OSSL_KEYMGMT_SELECT_PRIVATE_KEY
                               | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
                           built)
                        <= 0)
                    pkey = NULL;
                EVP_PKEY_CTX_free(pctx);
                OSSL_PARAM_free(built);
            }
            /* composite draft requires ECPrivateKey without publicKey field */
            if (pkey != NULL)
                EVP_PKEY_set_int_param(pkey,
                    OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, 0);
        } else {
            /*
             * Uncompressed X9.62 public key point: 0x04 || x || y.
             * No DER wrapper — import directly via EVP_PKEY_fromdata with
             * the curve name and raw point bytes.
             */
            params[0] = OSSL_PARAM_construct_utf8_string(
                OSSL_PKEY_PARAM_GROUP_NAME, (char *)ec_curve, 0);
            params[1] = OSSL_PARAM_construct_octet_string(
                OSSL_PKEY_PARAM_PUB_KEY, (void *)buf, buf_len);
            params[2] = OSSL_PARAM_construct_end();

            pctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
            if (pctx == NULL)
                return NULL;
            if (EVP_PKEY_fromdata_init(pctx) <= 0
                || EVP_PKEY_fromdata(pctx, &pkey,
                       OSSL_KEYMGMT_SELECT_PUBLIC_KEY
                           | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
                       params)
                    <= 0)
                pkey = NULL;
            EVP_PKEY_CTX_free(pctx);
        }
    }

    if (pkey == NULL)
        return NULL;

    /* Bind the decoded classic component's actual parameters to the composite variant */
    if (strcmp(classic_alg, "RSA") == 0
        && EVP_PKEY_get_bits(pkey) != classic_bits) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    if (strcmp(classic_alg, "EC") == 0) {
        char grp[80];
        size_t grplen = 0;

        if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                grp, sizeof(grp), &grplen)
            || !composite_ec_curve_matches(grp, ec_curve)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
            EVP_PKEY_free(pkey);
            return NULL;
        }
    }

    return pkey;
}

/*
 * Reconstruct a COMPOSITE_KEY from raw bytes in params[], using the wire
 * format defined in draft-ietf-lamps-pq-composite-sigs:
 *
 *   Public key:  mldsaPK(fixed size) || tradPK(raw)
 *   Private key: mldsaSeed(32 bytes) || tradSK(raw)
 *
 * classic_alg: "RSA" or "EC"
 * ec_curve:    curve name for EC (e.g. "P-256")
 */
static int composite_import_internal(void *keydata, int selection,
    const OSSL_PARAM params[],
    const char *classic_alg,
    int classic_bits,
    const char *ec_curve)
{
    COMPOSITE_KEY *key = keydata;
    const ML_DSA_PARAMS *kp;
    const uint8_t *buf;
    size_t buf_len, ml_dsa_len;
    OSSL_LIB_CTX *libctx;
    const char *pname;
    const OSSL_PARAM *p;
    int include_priv;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    include_priv = ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0);
    kp = ossl_ml_dsa_key_params(key->ml_dsa_key);
    libctx = ossl_ml_dsa_key_get0_libctx(key->ml_dsa_key);

    /* 1. Extract the combined octet string (ml_dsa_bytes || classic_bytes).
     *
     * EVP_PKEY_new_raw_public_key_ex() calls EVP_PKEY_fromdata() with
     * EVP_PKEY_KEYPAIR as the selection but only provides PUB_KEY in params.
     * Fall back to PUB_KEY when the caller asked for private but only supplied
     * a public-key blob.
     */
    pname = include_priv ? OSSL_PKEY_PARAM_PRIV_KEY : OSSL_PKEY_PARAM_PUB_KEY;
    p = OSSL_PARAM_locate_const(params, pname);
    if (p == NULL && include_priv) {
        /* No private key in params — try loading as public key only */
        include_priv = 0;
        pname = OSSL_PKEY_PARAM_PUB_KEY;
        p = OSSL_PARAM_locate_const(params, pname);
    }
    if (p == NULL
        || !OSSL_PARAM_get_octet_string_ptr(p, (const void **)&buf, &buf_len))
        return 0;

    /*
     * 2. Split at the ML-DSA boundary per the draft spec:
     *    - Private key: first ML_DSA_SEED_BYTES (32) bytes are the seed,
     *      NOT the expanded key (sk_len is 4032/3936/etc.).
     *    - Public key: first kp->pk_len bytes (1312/1952/2592).
     */
    ml_dsa_len = include_priv ? ML_DSA_SEED_BYTES : kp->pk_len;
    if (buf_len <= ml_dsa_len)
        return 0;

    if (include_priv) {
        /*
         * Load the 32-byte seed and expand it into the full key pair.
         * ossl_ml_dsa_set_prekey stores the seed; ossl_ml_dsa_generate_key
         * derives rho, K, A, s1, s2, t0, t1 from it.
         */
        if (!ossl_ml_dsa_set_prekey(key->ml_dsa_key, 0, 0,
                buf, ML_DSA_SEED_BYTES, NULL, 0))
            return 0;
        if (!ossl_ml_dsa_generate_key(key->ml_dsa_key)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
            return 0;
        }
    } else {
        if (!ossl_ml_dsa_pk_decode(key->ml_dsa_key, buf, ml_dsa_len))
            return 0;
    }

    /* 3. Decode the classic portion from its raw wire format */
    key->classic_key = composite_decode_classic_key(libctx,
        classic_alg, classic_bits, ec_curve,
        include_priv,
        buf + ml_dsa_len,
        buf_len - ml_dsa_len);
    return key->classic_key != NULL;
}

/*
 * Encode the traditional sub-key to its raw wire format per
 * draft-ietf-lamps-pq-composite-sigs:
 *
 *   RSA:      RSAPublicKey DER (pub)  / RSAPrivateKey DER (priv)   — PKCS#1
 *   EC:       Uncompressed X9.62 point 0x04||x||y (pub)
 *             / ECPrivateKey DER (priv)                            — RFC5915
 *
 * On success, *out points to a newly-allocated buffer and *out_len holds its
 * length.  The caller must OPENSSL_free(*out) (or OPENSSL_clear_free for priv).
 */
static int composite_encode_classic_key(const EVP_PKEY *pkey,
    int include_priv,
    unsigned char **out,
    size_t *out_len)
{
    int keytype = EVP_PKEY_get_base_id(pkey);
    OSSL_ENCODER_CTX *ectx;
    size_t len;

    *out = NULL;
    *out_len = 0;

    if (keytype == EVP_PKEY_RSA) {
        /*
         * RSAPublicKey (pub) or RSAPrivateKey (priv) — PKCS#1 DER.
         * OSSL_ENCODER "type-specific" uses i2d_RSAPublicKey / i2d_RSAPrivateKey.
         */
        ectx = OSSL_ENCODER_CTX_new_for_pkey(
            pkey,
            include_priv ? OSSL_KEYMGMT_SELECT_PRIVATE_KEY
                         : OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            "DER", "type-specific", NULL);
        if (ectx == NULL)
            return 0;
        if (!OSSL_ENCODER_to_data(ectx, out, out_len))
            *out = NULL;
        OSSL_ENCODER_CTX_free(ectx);
    } else if (keytype == EVP_PKEY_EC) {
        if (include_priv) {
            ectx = OSSL_ENCODER_CTX_new_for_pkey(
                pkey, OSSL_KEYMGMT_SELECT_ALL, "DER", "type-specific", NULL);
            if (ectx == NULL)
                return 0;
            if (!OSSL_ENCODER_to_data(ectx, out, out_len))
                *out = NULL;
            OSSL_ENCODER_CTX_free(ectx);
        } else {
            /*
             * Uncompressed X9.62 point: 0x04 || x || y.
             * OSSL_PKEY_PARAM_PUB_KEY returns the point in uncompressed form.
             * (There is no "type-specific" EC public encoder.)
             */
            if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                    NULL, 0, &len))
                return 0;
            *out = OPENSSL_malloc(len);
            if (*out == NULL)
                return 0;
            if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                    *out, len, out_len)) {
                OPENSSL_free(*out);
                *out = NULL;
            }
        }
    } else {
        return 0;
    }

    return *out != NULL;
}

/*
 * composite_export:
 * Serialize both sub-keys into the caller's OSSL_PARAM array.
 * Wire format per draft-ietf-lamps-pq-composite-sigs:
 *   Public key:  mldsaPK(pk_len bytes) || tradPK(raw)
 *   Private key: mldsaSeed(32 bytes)   || tradSK(raw)
 */
static int composite_export(void *keydata, int selection,
    OSSL_CALLBACK *param_cb, void *cbarg)
{
    COMPOSITE_KEY *key = keydata;
    const ML_DSA_PARAMS *kp;
    const uint8_t *ml_dsa_bytes;
    unsigned char *priv_buf = NULL, *pub_buf = NULL;
    unsigned char *classic_priv = NULL, *classic_pub = NULL;
    size_t classic_priv_len = 0, classic_pub_len = 0;
    size_t priv_len = 0, pub_len = 0;
    OSSL_PARAM params[3];
    int include_priv, pnum = 0, ret = 0;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;
    if (!composite_has(keydata, selection))
        return 0;

    kp = ossl_ml_dsa_key_params(key->ml_dsa_key);
    include_priv = ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0);

    /* ---- Private key: mldsaSeed(32) || tradSK(raw) ---- */
    if (include_priv) {
        ml_dsa_bytes = ossl_ml_dsa_key_get_seed(key->ml_dsa_key);
        if (ml_dsa_bytes == NULL)
            goto done; /* seed required; key was not loaded from seed */
        if (!composite_encode_classic_key(key->classic_key, 1,
                &classic_priv, &classic_priv_len))
            goto done;
        priv_len = ML_DSA_SEED_BYTES + classic_priv_len;
        priv_buf = OPENSSL_secure_malloc(priv_len);
        if (priv_buf == NULL)
            goto done;
        memcpy(priv_buf, ml_dsa_bytes, ML_DSA_SEED_BYTES);
        memcpy(priv_buf + ML_DSA_SEED_BYTES, classic_priv, classic_priv_len);
        params[pnum++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PRIV_KEY, priv_buf, priv_len);
    }

    /* ---- Public key: mldsaPK(pk_len) || tradPK(raw) ---- */
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        ml_dsa_bytes = ossl_ml_dsa_key_get_pub(key->ml_dsa_key);
        if (ml_dsa_bytes == NULL)
            goto done;
        if (!composite_encode_classic_key(key->classic_key, 0,
                &classic_pub, &classic_pub_len))
            goto done;
        pub_len = kp->pk_len + classic_pub_len;
        pub_buf = OPENSSL_malloc(pub_len);
        if (pub_buf == NULL)
            goto done;
        memcpy(pub_buf, ml_dsa_bytes, kp->pk_len);
        memcpy(pub_buf + kp->pk_len, classic_pub, classic_pub_len);
        params[pnum++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY, pub_buf, pub_len);
    }

    if (pnum == 0)
        goto done;
    params[pnum] = OSSL_PARAM_construct_end();
    ret = param_cb(params, cbarg);

done:
    if (priv_buf != NULL)
        OPENSSL_secure_clear_free(priv_buf, priv_len);
    if (classic_priv != NULL)
        OPENSSL_clear_free(classic_priv, classic_priv_len);
    OPENSSL_free(pub_buf);
    OPENSSL_free(classic_pub);
    return ret;
}

static void *composite_dup_key(const void *keydata_from, int selection)
{
    const COMPOSITE_KEY *src = keydata_from;
    COMPOSITE_KEY *key;

    if (!ossl_prov_is_running() || src == NULL)
        return NULL;

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        return NULL;

    key->ml_dsa_key = ossl_ml_dsa_key_dup(src->ml_dsa_key, selection);
    if (key->ml_dsa_key == NULL)
        goto err;

    key->classic_key = EVP_PKEY_dup(src->classic_key);
    if (key->classic_key == NULL)
        goto err;

    return key;
err:
    ossl_ml_dsa_key_free(key->ml_dsa_key);
    OPENSSL_free(key);
    return NULL;
}

static int composite_match(const void *keydata1, const void *keydata2,
    int selection)
{
    const COMPOSITE_KEY *key1 = keydata1;
    const COMPOSITE_KEY *key2 = keydata2;

    if (!ossl_prov_is_running())
        return 0;
    if (key1 == NULL || key2 == NULL)
        return 0;
    if (!ossl_ml_dsa_key_equal(key1->ml_dsa_key, key2->ml_dsa_key, selection))
        return 0;
    if (!EVP_PKEY_eq(key1->classic_key, key2->classic_key))
        return 0;
    return 1;
}

static void *composite_load(const void *reference, size_t reference_sz)
{
    COMPOSITE_KEY *key = NULL;
    const uint8_t *seed;

    if (!ossl_prov_is_running() || reference == NULL
        || reference_sz != sizeof(key))
        return NULL;

    /* The contents of the reference is the address to our object */
    key = *(COMPOSITE_KEY **)reference;
    /* We grabbed, so we detach it */
    *(COMPOSITE_KEY **)reference = NULL;

    if (key == NULL)
        return NULL;

    /*
     * Classic half must be a fully-loaded, provider-side key.
     * Unlike ML-DSA there is no "prekey" mechanism for EVP_PKEY —
     * the classic component must already be complete in the reference.
     */
    if (key->classic_key == NULL || !evp_pkey_is_provided(key->classic_key))
        goto err;

    /* All done if the ML-DSA public key is already present. */
    if (ossl_ml_dsa_key_get_pub(key->ml_dsa_key) != NULL)
        return key;

    /*
     * Handle ML-DSA prekey: composite wire format stores only the 32-byte
     * seed (never the expanded sk), so the only valid prekey state here is
     * seed-present.  Expand it to derive the full key pair.
     */
    seed = ossl_ml_dsa_key_get_seed(key->ml_dsa_key);
    if (seed != NULL) {
        if (ossl_ml_dsa_generate_key(key->ml_dsa_key))
            return key;
    } else {
        /* No pub and no seed: public-key-only reference, return as-is. */
        return key;
    }

err:
    ossl_ml_dsa_key_free(key->ml_dsa_key);
    EVP_PKEY_free(key->classic_key);
    OPENSSL_free(key);
    return NULL;
}

#define MAKE_KEYMGMT_FUNCTIONS(alg, ml_dsa_evp_type, classic_alg_, classic_bits_, ec_curve_)      \
    static OSSL_FUNC_keymgmt_new_fn composite_##alg##_new_key;                                    \
    static OSSL_FUNC_keymgmt_gen_fn composite_##alg##_gen;                                        \
    static OSSL_FUNC_keymgmt_import_fn composite_##alg##_import;                                  \
    static void *composite_##alg##_new_key(void *provctx)                                         \
    {                                                                                             \
        return ossl_prov_composite_new(provctx, NULL, ml_dsa_evp_type);                           \
    }                                                                                             \
    static void *composite_##alg##_gen(void *genctx,                                              \
        OSSL_CALLBACK *osslcb, void *cbarg)                                                       \
    {                                                                                             \
        return composite_gen(genctx, ml_dsa_evp_type,                                             \
            classic_alg_, classic_bits_, ec_curve_);                                              \
    }                                                                                             \
    static int composite_##alg##_import(void *keydata, int selection,                             \
        const OSSL_PARAM params[])                                                                \
    {                                                                                             \
        return composite_import_internal(keydata, selection, params,                              \
            classic_alg_, classic_bits_, ec_curve_);                                              \
    }                                                                                             \
    const OSSL_DISPATCH ossl_##alg##_keymgmt_functions[] = {                                      \
        { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))composite_##alg##_new_key },                     \
        { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))composite_free_key },                           \
        { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))composite_has },                                 \
        { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))composite_match },                             \
        { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))composite_##alg##_import },                   \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))composite_import_types },               \
        { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))composite_export },                           \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))composite_export_types },               \
        { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))composite_load },                               \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))composite_get_params },                   \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))composite_gettable_params },         \
        { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))composite_validate },                       \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))composite_gen_init },                       \
        { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))composite_##alg##_gen },                         \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))composite_gen_cleanup },                 \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))composite_gen_set_params },           \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))composite_gen_settable_params }, \
        { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))composite_dup_key },                             \
        OSSL_DISPATCH_END                                                                         \
    }

/* alg                                  ml_dsa_evp_type    classic_alg  bits  ec_curve          */
MAKE_KEYMGMT_FUNCTIONS(mldsa65_rsa3072_pkcs15_sha512, EVP_PKEY_ML_DSA_65, "RSA", 3072, NULL);
MAKE_KEYMGMT_FUNCTIONS(mldsa65_ecdsa_p256_sha512, EVP_PKEY_ML_DSA_65, "EC", 256, "P-256");
