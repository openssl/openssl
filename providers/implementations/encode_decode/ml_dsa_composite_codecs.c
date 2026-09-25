/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/core_names.h>
#include <openssl/objects.h>
#include <openssl/proverr.h>
#include "crypto/ml_dsa.h"
#include "prov/ml_dsa_composite_codecs.h"
#include "prov/ml_dsa_codecs.h"
#include "prov/provider_ctx.h"

#ifndef OPENSSL_NO_ML_DSA_COMPOSITE

/*
 * Encode the classic sub-key public component to its raw wire format
 * (draft-ietf-lamps-pq-composite-sigs):
 *
 *   RSA:      RSAPublicKey DER (PKCS#1)
 *   EC:       Uncompressed X9.62 point 0x04||x||y
 *
 * On success, *out is a newly-allocated buffer of *out_len bytes.
 * Caller must OPENSSL_free(*out).
 */
static int ml_dsa_composite_encode_classic_pub(const EVP_PKEY *pkey,
    unsigned char **out,
    size_t *out_len)
{
    int keytype = EVP_PKEY_get_base_id(pkey);
    OSSL_ENCODER_CTX *ectx;
    size_t len;

    *out = NULL;
    *out_len = 0;

    if (keytype == EVP_PKEY_RSA) {
        ectx = OSSL_ENCODER_CTX_new_for_pkey(
            pkey, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
            "DER", "type-specific", NULL);
        if (ectx == NULL)
            return 0;
        if (!OSSL_ENCODER_to_data(ectx, out, out_len))
            *out = NULL;
        OSSL_ENCODER_CTX_free(ectx);
    } else if (keytype == EVP_PKEY_EC) {
        /* Uncompressed point: 0x04 || x || y */
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
    } else {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
            "unsupported classic key type %d", keytype);
        return 0;
    }

    return *out != NULL;
}

/*
 * Encode the classic sub-key private component to its raw wire format:
 *
 *   RSA:      RSAPrivateKey DER (PKCS#1)
 *   EC:       ECPrivateKey DER with NamedCurve (RFC5915)
 *
 * On success, *out is a newly-allocated buffer of *out_len bytes.
 * Caller must OPENSSL_clear_free(*out, *out_len).
 */
static int ml_dsa_composite_encode_classic_priv(const EVP_PKEY *pkey,
    unsigned char **out,
    size_t *out_len)
{
    int keytype = EVP_PKEY_get_base_id(pkey);
    OSSL_ENCODER_CTX *ectx;

    *out = NULL;
    *out_len = 0;

    if (keytype == EVP_PKEY_RSA) {
        ectx = OSSL_ENCODER_CTX_new_for_pkey(
            pkey, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
            "DER", "type-specific", NULL);
        if (ectx == NULL)
            return 0;
        if (!OSSL_ENCODER_to_data(ectx, out, out_len))
            *out = NULL;
        OSSL_ENCODER_CTX_free(ectx);
    } else if (keytype == EVP_PKEY_EC) {
        /*
         * ECPrivateKey DER (RFC5915) with NamedCurve but WITHOUT publicKey,
         * per composite draft section 4:
         *   "The private key MUST be encoded as ECPrivateKey specified in
         *    [RFC5915] with the 'NamedCurve' parameter set to the OID of
         *    the curve, but without the 'publicKey' field."
         */
        int include_pub = 0;
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC,
                &include_pub),
            OSSL_PARAM_construct_end()
        };
        EVP_PKEY *ec_copy = EVP_PKEY_dup((EVP_PKEY *)pkey);

        if (ec_copy == NULL)
            return 0;
        if (!EVP_PKEY_set_params(ec_copy, params)) {
            EVP_PKEY_free(ec_copy);
            return 0;
        }
        ectx = OSSL_ENCODER_CTX_new_for_pkey(
            ec_copy, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
            "DER", "type-specific", NULL);
        if (ectx != NULL) {
            if (!OSSL_ENCODER_to_data(ectx, out, out_len))
                *out = NULL;
            OSSL_ENCODER_CTX_free(ectx);
        }
        EVP_PKEY_free(ec_copy);
    } else {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED,
            "unsupported classic key type %d", keytype);
        return 0;
    }

    return *out != NULL;
}

/*
 * Encode the composite public key: mldsaPK || tradPK
 * Returns total byte length (>0) on success, 0 on error.
 * If |out| is NULL, only the length is computed (no allocation).
 */
int ossl_ml_dsa_composite_i2d_pubkey(const ML_DSA_COMPOSITE_KEY *key, unsigned char **out)
{
    const ML_DSA_PARAMS *kp;
    const uint8_t *ml_dsa_pub;
    unsigned char *classic_pub = NULL;
    size_t classic_pub_len = 0;
    int total, ret = 0;

    if (key == NULL || key->classic_key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY);
        return 0;
    }

    kp = ossl_ml_dsa_key_params(key->ml_dsa_key);
    ml_dsa_pub = ossl_ml_dsa_key_get_pub(key->ml_dsa_key);
    if (ml_dsa_pub == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY);
        return 0;
    }

    if (!ml_dsa_composite_encode_classic_pub(key->classic_key,
            &classic_pub, &classic_pub_len))
        return 0;

    total = (int)(kp->pk_len + classic_pub_len);

    if (out != NULL) {
        *out = OPENSSL_malloc((size_t)total);
        if (*out == NULL)
            goto done;
        memcpy(*out, ml_dsa_pub, kp->pk_len);
        memcpy(*out + kp->pk_len, classic_pub, classic_pub_len);
    }

    ret = total;
done:
    OPENSSL_free(classic_pub);
    return ret;
}

/*
 * Encode the composite private key: mldsaSeed[32] || tradSK
 * Returns total byte length (>0) on success, 0 on error.
 * If |out| is NULL, only the length is computed (no allocation).
 */
int ossl_ml_dsa_composite_i2d_prvkey(const ML_DSA_COMPOSITE_KEY *key, unsigned char **out)
{
    const uint8_t *seed;
    unsigned char *classic_priv = NULL;
    size_t classic_priv_len = 0;
    int total, ret = 0;

    if (key == NULL || key->classic_key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        return 0;
    }

    seed = ossl_ml_dsa_key_get_seed(key->ml_dsa_key);
    if (seed == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        return 0;
    }

    if (!ml_dsa_composite_encode_classic_priv(key->classic_key,
            &classic_priv, &classic_priv_len))
        return 0;

    total = (int)(ML_DSA_SEED_BYTES + classic_priv_len);

    if (out != NULL) {
        *out = OPENSSL_malloc((size_t)total);
        if (*out == NULL)
            goto done;
        memcpy(*out, seed, ML_DSA_SEED_BYTES);
        memcpy(*out + ML_DSA_SEED_BYTES, classic_priv, classic_priv_len);
    }

    ret = total;
done:
    OPENSSL_clear_free(classic_priv, classic_priv_len);
    return ret;
}

/*
 * Print a human-readable description of a composite key to |out|.
 */
int ossl_ml_dsa_composite_key_to_text(BIO *out, const ML_DSA_COMPOSITE_KEY *key,
    int selection)
{
    const ML_DSA_PARAMS *kp;
    int is_priv = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
    int ret = 0;

    if (out == NULL || key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    kp = ossl_ml_dsa_key_params(key->ml_dsa_key);

    if (BIO_printf(out, "Composite %s Key (%s)\n",
            is_priv ? "Private" : "Public",
            kp != NULL ? kp->alg : "unknown")
        <= 0)
        return 0;

    /* ML-DSA component */
    if (BIO_printf(out, "ML-DSA component:\n") <= 0)
        return 0;
    if (!ossl_ml_dsa_key_to_text(out, key->ml_dsa_key, selection))
        return 0;

    /* Classic component */
    if (BIO_printf(out, "Classic component:\n") <= 0)
        return 0;
    if (key->classic_key == NULL) {
        if (BIO_printf(out, "    (none)\n") <= 0)
            return 0;
    } else {
        if (is_priv)
            ret = EVP_PKEY_print_private(out, key->classic_key, 4, NULL);
        else
            ret = EVP_PKEY_print_public(out, key->classic_key, 4, NULL);
        if (ret <= 0)
            return 0;
    }

    return 1;
}

/* Compares EC group names, resolving NIST aliases (e.g. "P-256") to their canonical NID. */
static int ml_dsa_composite_ec_curve_matches(const char *grp, const char *ec_curve)
{
    int actual_nid = OBJ_txt2nid(grp);
    int expected_nid = EC_curve_nist2nid(ec_curve);

    if (expected_nid == NID_undef)
        expected_nid = OBJ_txt2nid(ec_curve);
    return actual_nid != NID_undef && actual_nid == expected_nid;
}

/* Bind the decoded classic component's actual parameters to the composite variant */
static int ml_dsa_composite_codecs_check_classic_params(EVP_PKEY *pkey,
    const char *classic_alg, int classic_bits, const char *ec_curve)
{
    if (strcmp(classic_alg, "RSA") == 0) {
        if (EVP_PKEY_get_bits(pkey) != classic_bits) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
    } else if (strcmp(classic_alg, "EC") == 0) {
        char grp[80];
        size_t grplen = 0;

        if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                grp, sizeof(grp), &grplen)
            || !ml_dsa_composite_ec_curve_matches(grp, ec_curve)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
            return 0;
        }
    }
    return 1;
}

/*
 * Decode the classic sub-key from its raw wire format.
 * Used by ossl_ml_dsa_composite_d2i_pubkey() and ossl_ml_dsa_composite_d2i_prvkey().
 */
static EVP_PKEY *ml_dsa_composite_codecs_decode_classic_pub(OSSL_LIB_CTX *libctx,
    const char *classic_alg,
    int classic_bits,
    const char *ec_curve,
    const unsigned char *buf,
    size_t buf_len)
{
    EVP_PKEY *pkey = NULL;
    const unsigned char *ptr = buf;
    size_t ptrlen = buf_len;
    OSSL_DECODER_CTX *dctx;
    OSSL_PARAM params[3];
    EVP_PKEY_CTX *pctx;

    if (strcmp(classic_alg, "RSA") == 0) {
        dctx = OSSL_DECODER_CTX_new_for_pkey(
            &pkey, "DER", "type-specific", "RSA",
            OSSL_KEYMGMT_SELECT_PUBLIC_KEY, libctx, NULL);
        if (dctx == NULL)
            return NULL;
        if (!OSSL_DECODER_from_data(dctx, &ptr, &ptrlen))
            pkey = NULL;
        OSSL_DECODER_CTX_free(dctx);
    } else if (strcmp(classic_alg, "EC") == 0) {
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
                   EVP_PKEY_PUBLIC_KEY, params)
                <= 0)
            pkey = NULL;
        EVP_PKEY_CTX_free(pctx);
    }
    if (pkey != NULL
        && !ml_dsa_composite_codecs_check_classic_params(pkey, classic_alg,
            classic_bits, ec_curve)) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    return pkey;
}

static EVP_PKEY *ml_dsa_composite_codecs_decode_classic_priv(OSSL_LIB_CTX *libctx,
    const char *classic_alg,
    int classic_bits,
    const char *ec_curve,
    const unsigned char *buf,
    size_t buf_len)
{
    EVP_PKEY *pkey = NULL;
    const unsigned char *ptr = buf;
    size_t ptrlen = buf_len;
    OSSL_DECODER_CTX *dctx;

    if (strcmp(classic_alg, "RSA") == 0) {
        dctx = OSSL_DECODER_CTX_new_for_pkey(
            &pkey, "DER", "type-specific", "RSA",
            OSSL_KEYMGMT_SELECT_PRIVATE_KEY, libctx, NULL);
        if (dctx == NULL)
            return NULL;
        if (!OSSL_DECODER_from_data(dctx, &ptr, &ptrlen))
            pkey = NULL;
        OSSL_DECODER_CTX_free(dctx);
    } else if (strcmp(classic_alg, "EC") == 0) {
        dctx = OSSL_DECODER_CTX_new_for_pkey(
            &pkey, "DER", "type-specific", "EC",
            OSSL_KEYMGMT_SELECT_PRIVATE_KEY, libctx, NULL);
        if (dctx == NULL)
            return NULL;
        if (!OSSL_DECODER_from_data(dctx, &ptr, &ptrlen))
            pkey = NULL;
        OSSL_DECODER_CTX_free(dctx);
    }
    if (pkey != NULL
        && !ml_dsa_composite_codecs_check_classic_params(pkey, classic_alg,
            classic_bits, ec_curve)) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    return pkey;
}

ML_DSA_COMPOSITE_KEY *ossl_ml_dsa_composite_d2i_pubkey(const unsigned char *pk,
    int pk_len,
    int ml_dsa_evp_type,
    const char *classic_alg,
    int classic_bits,
    const char *ec_curve,
    PROV_CTX *provctx,
    const char *propq)
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    const ML_DSA_PARAMS *kp;
    ML_DSA_COMPOSITE_KEY *key;
    size_t ml_dsa_len;

    if (pk == NULL || pk_len <= 0 || classic_alg == NULL)
        return NULL;

    key = ossl_prov_ml_dsa_composite_new(provctx, propq, ml_dsa_evp_type);
    if (key == NULL)
        return NULL;

    kp = ossl_ml_dsa_key_params(key->ml_dsa_key);
    if (kp == NULL)
        goto err;

    ml_dsa_len = kp->pk_len;
    if ((size_t)pk_len <= ml_dsa_len)
        goto err;

    if (!ossl_ml_dsa_pk_decode(key->ml_dsa_key, pk, ml_dsa_len)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        goto err;
    }

    key->classic_key = ml_dsa_composite_codecs_decode_classic_pub(
        libctx, classic_alg, classic_bits, ec_curve,
        pk + ml_dsa_len, (size_t)pk_len - ml_dsa_len);
    if (key->classic_key == NULL)
        goto err;

    return key;

err:
    ossl_ml_dsa_composite_key_free(key);
    return NULL;
}

ML_DSA_COMPOSITE_KEY *ossl_ml_dsa_composite_d2i_prvkey(const unsigned char *priv,
    int priv_len,
    int ml_dsa_evp_type,
    const char *classic_alg,
    int classic_bits,
    const char *ec_curve,
    PROV_CTX *provctx,
    const char *propq)
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    ML_DSA_COMPOSITE_KEY *key;

    if (priv == NULL || priv_len <= ML_DSA_SEED_BYTES || classic_alg == NULL)
        return NULL;

    key = ossl_prov_ml_dsa_composite_new(provctx, propq, ml_dsa_evp_type);
    if (key == NULL)
        return NULL;

    /* Load the 32-byte seed and derive the full ML-DSA key pair */
    if (!ossl_ml_dsa_set_prekey(key->ml_dsa_key, 0, 0,
            priv, ML_DSA_SEED_BYTES, NULL, 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BAD_ENCODING);
        goto err;
    }
    if (!ossl_ml_dsa_generate_key(key->ml_dsa_key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
        goto err;
    }

    key->classic_key = ml_dsa_composite_codecs_decode_classic_priv(
        libctx, classic_alg, classic_bits, ec_curve,
        priv + ML_DSA_SEED_BYTES,
        (size_t)priv_len - ML_DSA_SEED_BYTES);
    if (key->classic_key == NULL)
        goto err;

    return key;

err:
    ossl_ml_dsa_composite_key_free(key);
    return NULL;
}

#endif /* OPENSSL_NO_ML_DSA_COMPOSITE */
