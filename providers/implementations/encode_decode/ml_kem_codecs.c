/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/byteorder.h>
#include <openssl/proverr.h>
#include <openssl/x509.h>
#include <openssl/core_names.h>
#include "internal/encoder.h"
#include "ml_kem_codecs.h"

/*-
 * Tables describing supported ASN.1 input/output formats.
 * For each parameter set we support a few PKCS#8 input formats, three
 * corresponding to the "either or both" variants of:
 *
 *  ML-KEM-PrivateKey ::= SEQUENCE {
 *    seed OCTET STRING SIZE (64) OPTIONAL,
 *    expandedKey [1] IMPLICIT OCTET STRING SIZE (1632 | 2400 | 3172) OPTIONAL }
 *   (WITH COMPONENTS {..., seed  PRESENT } |
 *    WITH COMPONENTS {..., expandedKey  PRESENT })
 *
 * and two more for historical OQS encodings.
 *
 * - OQS private key: OCTET STRING
 * - OQS private + public key: OCTET STRING
 *   (The public key is ignored, just as with PKCS#8 v2.)
 *
 * and two more that are "inspired" by the IETF non-ASN.1 seed encoding.
 *
 * - Bare seed (just the 64 bytes)
 * - Bare priv (just the key bytes)
 *
 * An offset of zero means that particular field is absent.
 *
 * On output the PKCS8 info table order is important:
 * - When we have a seed we'll use the first entry with a non-zero seed offset.
 * - Otherwise, the first entry with a zero seed offset.
 *
 * As written, when possible, we prefer to output both the seed and private
 * key, otherwise, just the private key ([1] IMPLICIT OCTET STRING form).
 *
 * The various lengths in the PKCS#8 tag/len fields could have been left
 * zeroed, and filled in on the fly from the algorithm parameters, but that
 * makes the code more complex, so a choice was made to embed them directly
 * into the tables.  Had they been zeroed, one table could cover all three
 * ML-KEM parameter sets.
 */
#define NUM_PKCS8_FORMATS   7

/*-
 * ML-KEM-512:
 * Public key bytes:   800 (0x0320)
 * Private key bytes: 1632 (0x0660)
 */
static const ML_KEM_SPKI_INFO ml_kem_512_spki_info = {
    { 0x30, 0x82, 0x03, 0x32, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48,
      0x01, 0x65, 0x03, 0x04, 0x04, 0x01, 0x03, 0x82, 0x03, 0x21, 0x00, }
};
static const ML_KEM_PKCS8_INFO ml_kem_512_pkcs8_info[] = {
    { "seed-priv", 0x06aa, 0x308206a6, 0x0440, 6, 0x40, 0x81820660, 0x4a, 0x0660, 0x0000, 0x0000 },
    { "priv-only", 0x0668, 0x30820664, 0,      0, 0x00, 0x81820660, 0x08, 0x0660, 0x0000, 0x0000 },
    { "seed-only", 0x0044, 0x30420440, 0,      4, 0x40, 0,          0x00, 0x0000, 0x0000, 0x0000 },
    { "priv-oqs",  0x0664, 0x04820660, 0,      0, 0x00, 0x04820660, 0x04, 0x0660, 0x0000, 0x0000 },
    { "pair-oqs",  0x0984, 0x04820980, 0,      0, 0x00, 0x04820980, 0x04, 0x0660, 0x0664, 0x0320 },
    { "bare-seed", 0x0040, 0,          0,      0, 0x40, 0,          0x00, 0x0000, 0x0000, 0x0000 },
    { "bare-priv", 0x0660, 0,          0,      0, 0x00, 0,          0x00, 0x0660, 0x0000, 0x0000 },
};

/*-
 * ML-KEM-768:
 * Public key bytes:  1184 (0x04a0)
 * Private key bytes: 2400 (0x0960)
 */
static const ML_KEM_SPKI_INFO ml_kem_768_spki_info = {
    { 0x30, 0x82, 0x04, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48,
      0x01, 0x65, 0x03, 0x04, 0x04, 0x02, 0x03, 0x82, 0x04, 0xa1, 0x00, }
};
static const ML_KEM_PKCS8_INFO ml_kem_768_pkcs8_info[] = {
    { "seed-priv", 0x09aa, 0x308209a6, 0x0440, 6, 0x40, 0x81820960, 0x4a, 0x0960, 0x0000, 0x0000 },
    { "priv-only", 0x0968, 0x30820964, 0,      0, 0x00, 0x81820960, 0x08, 0x0960, 0x0000, 0x0000 },
    { "seed-only", 0x0044, 0x30420440, 0,      4, 0x40, 0,          0x00, 0x0000, 0x0000, 0x0000 },
    { "priv-oqs",  0x0964, 0x04820960, 0,      0, 0x00, 0x04820960, 0x04, 0x0960, 0x0000, 0x0000 },
    { "pair-oqs",  0x0e04, 0x04820e00, 0,      0, 0x00, 0x04820e00, 0x04, 0x0960, 0x0964, 0x04a0 },
    { "bare-seed", 0x0040, 0,          0,      0, 0x40, 0,          0x00, 0x0000, 0x0000, 0x0000 },
    { "bare-priv", 0x0960, 0,          0,      0, 0x00, 0,          0x00, 0x0960, 0x0000, 0x0000 },
};

/*-
 * ML-KEM-1024:
 * Private key bytes: 3168 (0x0c60)
 * Public key bytes:  1568 (0x0620)
 */
static const ML_KEM_SPKI_INFO ml_kem_1024_spki_info = {
    { 0x30, 0x82, 0x06, 0x32, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48,
      0x01, 0x65, 0x03, 0x04, 0x04, 0x03, 0x03, 0x82, 0x06, 0x21, 0x00, }
};
static const ML_KEM_PKCS8_INFO ml_kem_1024_pkcs8_info[] = {
    { "seed-priv", 0x0caa, 0x30820ca6, 0x0440, 6, 0x40, 0x81820c60, 0x4a, 0x0c60, 0x0000, 0x0000 },
    { "priv-only", 0x0c68, 0x30820c64, 0,      0, 0x00, 0x81820c60, 0x08, 0x0c60, 0x0000, 0x0000 },
    { "seed-only", 0x0044, 0x30420440, 0,      4, 0x40, 0,          0x00, 0x0000, 0x0000, 0x0000 },
    { "priv-oqs",  0x0c64, 0x04820c60, 0,      0, 0x00, 0x04820c60, 0x04, 0x0c60, 0x0000, 0x0000 },
    { "pair-oqs",  0x1284, 0x04821280, 0,      0, 0x00, 0x04821280, 0x04, 0x0c60, 0x0c64, 0x0620 },
    { "bare-seed", 0x0040, 0,          0,      0, 0x40, 0,          0x00, 0x0000, 0x0000, 0x0000 },
    { "bare-priv", 0x0c60, 0,          0,      0, 0x00, 0,          0x00, 0x0c60, 0x0000, 0x0000 },
};

/* Indices of slots in the `codecs` table below */
#define ML_KEM_512_CODEC    0
#define ML_KEM_768_CODEC    1
#define ML_KEM_1024_CODEC   2

/*
 * Per-variant fixed parameters
 */
static const ML_KEM_CODEC codecs[3] = {
    { &ml_kem_512_spki_info,  ml_kem_512_pkcs8_info },
    { &ml_kem_768_spki_info,  ml_kem_768_pkcs8_info },
    { &ml_kem_1024_spki_info, ml_kem_1024_pkcs8_info }
};

/* Retrieve the parameters of one of the ML-KEM variants */
static const ML_KEM_CODEC *ml_kem_get_codec(int evp_type)
{
    switch (evp_type) {
    case EVP_PKEY_ML_KEM_512:
        return &codecs[ML_KEM_512_CODEC];
    case EVP_PKEY_ML_KEM_768:
        return &codecs[ML_KEM_768_CODEC];
    case EVP_PKEY_ML_KEM_1024:
        return &codecs[ML_KEM_1024_CODEC];
    }
    return NULL;
}

static int vp8_pref_cmp(const void *va, const void *vb)
{
    const ML_KEM_PKCS8_PREF *a = va;
    const ML_KEM_PKCS8_PREF *b = vb;

    /*
     * Zeros sort last, otherwise the sort is in increasing order.
     *
     * The preferences are small enough to ensure the comparison is transitive
     * as required by qsort(3).  When overflow or underflow is possible, the
     * correct transitive comparison would be: (b < a) - (a < b).
     */
    if (a->vp8_pref > 0 && b->vp8_pref > 0)
        return a->vp8_pref - b->vp8_pref;
    /* A preference of 0 is "larger" than (sorts after) any nonzero value. */
    return b->vp8_pref - a->vp8_pref;
}

static ML_KEM_PKCS8_PREF *vp8_order(const char *algorithm_name,
                                    const ML_KEM_PKCS8_INFO *pkcs8_info,
                                    const char *direction, const char *formats)
{
    ML_KEM_PKCS8_PREF *ret;
    int i, count = 0;
    const char *fmt = formats, *end;
    const char *sep = "\t ,";

    /* Reserve an extra terminal slot with vp8_entry == NULL */
    if ((ret = OPENSSL_zalloc((NUM_PKCS8_FORMATS + 1) * sizeof(*ret))) == NULL)
        return NULL;

    /* Entries that match a format will get a non-zero preference. */
    for (i = 0; i < NUM_PKCS8_FORMATS; ++i) {
        ret[i].vp8_entry = &pkcs8_info[i];
        ret[i].vp8_pref = 0;
    }

    /* Default to compile-time table order when none specified. */
    if (formats == NULL)
        return ret;

    /*
     * Formats are case-insensitive, separated by spaces, tabs or commas.
     * Duplicate formats are allowed, the first occurence determines the order.
     */
    do {
        if (*(fmt += strspn(fmt, sep)) == '\0')
            break;
        end = fmt + strcspn(fmt, sep);
        for (i = 0; i < NUM_PKCS8_FORMATS; ++i) {
            /* Skip slots already selected or with a different name. */
            if (ret[i].vp8_pref > 0
                || OPENSSL_strncasecmp(ret[i].vp8_entry->p8_name,
                                       fmt, (end - fmt)) != 0)
                continue;
            /* First time match */
            ret[i].vp8_pref = ++count;
            break;
        }
        fmt = end;
    } while (count < NUM_PKCS8_FORMATS);

    /* No formats matched, raise an error */
    if (count == 0) {
        OPENSSL_free(ret);
        ERR_raise_data(ERR_LIB_PROV, PROV_R_ML_KEM_NO_FORMAT,
                       "no %s private key %s formats are enabled",
                       algorithm_name, direction);
        return NULL;
    }
    /* Sort by preference, with 0's last */
    qsort(ret, NUM_PKCS8_FORMATS, sizeof(*ret), vp8_pref_cmp);
    /* Terminate the list at first unselected entry, perhaps reserved slot. */
    ret[count].vp8_entry = NULL;
    return ret;
}

ML_KEM_KEY *
ossl_ml_kem_d2i_PUBKEY(const uint8_t *pubenc, int publen, int evp_type,
                       PROV_CTX *provctx, const char *propq)
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    const ML_KEM_VINFO *v;
    const ML_KEM_CODEC *codec;
    const ML_KEM_SPKI_INFO *vspki;
    ML_KEM_KEY *ret;

    if ((v = ossl_ml_kem_get_vinfo(evp_type)) == NULL
        || (codec = ml_kem_get_codec(evp_type)) == NULL)
        return NULL;
    vspki = codec->spki_info;
    if (publen != ML_KEM_SPKI_OVERHEAD + (ossl_ssize_t) v->pubkey_bytes
        || memcmp(pubenc, vspki->asn1_prefix, ML_KEM_SPKI_OVERHEAD) != 0)
        return NULL;
    publen -= ML_KEM_SPKI_OVERHEAD;
    pubenc += ML_KEM_SPKI_OVERHEAD;

    if ((ret = ossl_ml_kem_key_new(libctx, propq, evp_type)) == NULL)
        return NULL;

    if (!ossl_ml_kem_parse_public_key(pubenc, (size_t) publen, ret)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_ENCODING,
                       "errror parsing %s public key from input SPKI",
                       v->algorithm_name);
        ossl_ml_kem_key_free(ret);
        return NULL;
    }

    return ret;
}

ML_KEM_KEY *
ossl_ml_kem_d2i_PKCS8(const uint8_t *prvenc, int prvlen,
                      int evp_type, PROV_CTX *provctx,
                      const char *propq)
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    const ML_KEM_VINFO *v;
    const ML_KEM_CODEC *codec;
    ML_KEM_PKCS8_PREF *vp8_alloc = NULL, *vp8_slot;
    const ML_KEM_PKCS8_INFO *vp8;
    ML_KEM_KEY *key = NULL, *ret = NULL;
    PKCS8_PRIV_KEY_INFO *p8inf = NULL;
    const uint8_t *buf, *pos;
    const X509_ALGOR *alg = NULL;
    const char *formats;
    int len, ptype;
    uint32_t magic, p8_magic;
    uint16_t seed_magic;

    /* Which ML-KEM variant? */
    if ((v = ossl_ml_kem_get_vinfo(evp_type)) == NULL
        || (codec = ml_kem_get_codec(evp_type)) == NULL)
        return 0;

    /* Extract the key OID and any parameters. */
    if ((p8inf = d2i_PKCS8_PRIV_KEY_INFO(NULL, &prvenc, prvlen)) == NULL)
        return 0;
    /* Shortest prefix is 4 bytes: seq tag/len  + octet string tag/len */
    if (!PKCS8_pkey_get0(NULL, &buf, &len, &alg, p8inf))
        goto end;
    /* Bail out early if this is some other key type. */
    if (OBJ_obj2nid(alg->algorithm) != evp_type)
        goto end;

    /* Get the list of enabled decoders. Their order is not important here. */
    formats = ossl_prov_ctx_get_param(
        provctx, OSSL_PKEY_PARAM_ML_KEM_INPUT_FORMATS, NULL);
    vp8_slot = vp8_alloc = vp8_order(v->algorithm_name, codec->pkcs8_info,
                                     "input", formats);
    if (vp8_alloc == NULL)
        goto end;

    /* Parameters must be absent. */
    X509_ALGOR_get0(NULL, &ptype, NULL, alg);
    if (ptype != V_ASN1_UNDEF) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_UNEXPECTED_KEY_PARAMETERS,
                       "unexpected parameters with a PKCS#8 %s private key",
                       v->algorithm_name);
        goto end;
    }
    if ((ossl_ssize_t)len < (ossl_ssize_t)sizeof(magic))
        goto end;

    /* Find the matching p8 info slot, that also has the expected length. */
    pos = OPENSSL_load_u32_be(&magic, buf);
    for (vp8_slot = vp8_alloc; vp8_slot->vp8_entry != NULL; ++vp8_slot) {
        if (len != (ossl_ssize_t)vp8_slot->vp8_entry->p8_bytes)
            continue;
        /* p8_magic == 0, signals a non-ASN.1 length-based encoding */
        if ((p8_magic = vp8_slot->vp8_entry->p8_magic) == 0) {
            pos = buf;
            break;
        }
        if (magic == p8_magic)
            break;
    }
    if ((vp8 = vp8_slot->vp8_entry) == NULL
        || (vp8->seed_length > 0 && vp8->seed_length != ML_KEM_SEED_BYTES)
        || (vp8->priv_length > 0 && vp8->priv_length != v->prvkey_bytes)
        || (vp8->pub_length > 0 && vp8->pub_length != v->pubkey_bytes)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_ML_KEM_NO_FORMAT,
                       "no matching enabled %s private key input formats",
                       v->algorithm_name);
        goto end;
    }

    if (vp8->seed_length > 0) {
        /* Check |seed| tag/len, if not subsumed by |magic|. */
        if (pos + sizeof(uint16_t) == buf + vp8->seed_offset) {
            pos = OPENSSL_load_u16_be(&seed_magic, pos);
            if (seed_magic != vp8->seed_magic)
                goto end;
        } else if (pos != buf + vp8->seed_offset) {
            goto end;
        }
        pos += ML_KEM_SEED_BYTES;
    }
    if (vp8->priv_length > 0) {
        /* Check |priv| tag/len */
        if (pos + sizeof(uint32_t) == buf + vp8->priv_offset) {
            pos = OPENSSL_load_u32_be(&magic, pos);
            if (magic != vp8->priv_magic)
                goto end;
        } else if (pos != buf + vp8->priv_offset) {
            goto end;
        }
        pos += v->prvkey_bytes;
    }
    if (vp8->pub_length > 0) {
        if (pos != buf + vp8->pub_offset)
            goto end;
        pos += v->pubkey_bytes;
    }
    if (pos != buf + len)
        goto end;

    /*
     * Collect the seed and/or key into a "decoded" private key object,
     * to be turned into a real key on provider "load" or "import".
     */
    if ((key = ossl_ml_kem_key_new(libctx, propq, evp_type)) == NULL)
        goto end;
    key->retain_seed = ossl_prov_ctx_get_bool_param(
        provctx, OSSL_PKEY_PARAM_ML_KEM_RETAIN_SEED, 1);
    key->prefer_seed = ossl_prov_ctx_get_bool_param(
        provctx, OSSL_PKEY_PARAM_ML_KEM_PREFER_SEED, 1);
    if (vp8->seed_length > 0) {
        if (!ossl_ml_kem_set_seed(buf + vp8->seed_offset,
                                  ML_KEM_SEED_BYTES, key)) {
            ERR_raise_data(ERR_LIB_OSSL_DECODER, ERR_R_INTERNAL_ERROR,
                           "error storing %s private key seed",
                           v->algorithm_name);
            goto end;
        }
    }
    if (vp8->priv_length > 0) {
        if ((key->encoded_dk = OPENSSL_malloc(vp8->priv_length)) == NULL) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_KEY,
                           "error parsing %s private key",
                           v->algorithm_name);
            goto end;
        }
        memcpy(key->encoded_dk, buf + vp8->priv_offset, vp8->priv_length);
    }
    /* Any OQS public key content is ignored */
    ret = key;

  end:
    OPENSSL_free(vp8_alloc);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    if (ret == NULL)
        ossl_ml_kem_key_free(key);
    return ret;
}

/* Same as ossl_ml_kem_encode_pubkey, but allocates the output buffer. */
int ossl_ml_kem_i2d_pubkey(const ML_KEM_KEY *key, unsigned char **out)
{
    size_t publen;

    if (!ossl_ml_kem_have_pubkey(key)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY,
                       "no %s public key data available",
                       key->vinfo->algorithm_name);
        return 0;
    }
    publen = key->vinfo->pubkey_bytes;

    if (out != NULL
        && (*out = OPENSSL_malloc(publen)) == NULL)
        return 0;
    if (!ossl_ml_kem_encode_public_key(*out, publen, key)) {
        ERR_raise_data(ERR_LIB_OSSL_ENCODER, ERR_R_INTERNAL_ERROR,
                       "error encoding %s public key",
                       key->vinfo->algorithm_name);
        OPENSSL_free(*out);
        return 0;
    }

    return (int)publen;
}

/* Allocate and encode PKCS#8 private key payload. */
int ossl_ml_kem_i2d_prvkey(const ML_KEM_KEY *key, uint8_t **out,
                           PROV_CTX *provctx)
{
    const ML_KEM_VINFO *v = key->vinfo;
    const ML_KEM_CODEC *codec;
    ML_KEM_PKCS8_PREF *vp8_alloc, *vp8_slot;
    const ML_KEM_PKCS8_INFO *vp8;
    uint8_t *buf = NULL, *pos;
    const char *formats;
    int len = ML_KEM_SEED_BYTES;
    int ret = 0;

    /* Not ours to handle */
    if ((codec = ml_kem_get_codec(v->evp_type)) == NULL)
        return 0;

    if (!ossl_ml_kem_have_prvkey(key)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY,
                       "no %s private key data available",
                       key->vinfo->algorithm_name);
        return 0;
    }

    formats = ossl_prov_ctx_get_param(
        provctx, OSSL_PKEY_PARAM_ML_KEM_OUTPUT_FORMATS, NULL);
    vp8_slot = vp8_alloc = vp8_order(v->algorithm_name, codec->pkcs8_info,
                                     "output", formats);
    if (vp8_alloc == NULL)
        return 0;

    /* If we don't have a seed, skip seedful entries */
    if (!ossl_ml_kem_have_seed(key))
        while (vp8_slot->vp8_entry != NULL
               && vp8_slot->vp8_entry->seed_length != 0)
            ++vp8_slot;
    /* No matching table entries, give up */
    if ((vp8 = vp8_slot->vp8_entry) == NULL
        || (vp8->seed_length > 0 && vp8->seed_length != ML_KEM_SEED_BYTES)
        || (vp8->priv_length > 0 && vp8->priv_length != v->prvkey_bytes)
        || (vp8->pub_length > 0 && vp8->pub_length != v->pubkey_bytes)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_ML_KEM_NO_FORMAT,
                       "no matching enabled %s private key output formats",
                       v->algorithm_name);
        goto end;
    }
    len = vp8->p8_bytes;

    if (out == NULL) {
        ret = len;
        goto end;
    }

    if ((pos = buf = OPENSSL_malloc((size_t) len)) == NULL)
        goto end;

    if (vp8->p8_magic != 0)
        pos = OPENSSL_store_u32_be(pos, vp8->p8_magic);
    if (vp8->seed_length != 0) {
        /*
         * Either the tag/len were already included in |magic| or they require
         * us to write two bytes now.
         */
        if (pos + sizeof(uint16_t) == buf + vp8->seed_offset)
            pos = OPENSSL_store_u16_be(pos, vp8->seed_magic);
        if (pos != buf + vp8->seed_offset
            || !ossl_ml_kem_encode_seed(pos, ML_KEM_SEED_BYTES, key)) {
            ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
                           "error encoding %s private key",
                           v->algorithm_name);
            goto end;
        }
        pos += ML_KEM_SEED_BYTES;
    }
    if (vp8->priv_length != 0) {
        if (pos + sizeof(uint32_t) == buf + vp8->priv_offset)
            pos = OPENSSL_store_u32_be(pos, vp8->priv_magic);
        if (pos != buf + vp8->priv_offset
            || !ossl_ml_kem_encode_private_key(pos, v->prvkey_bytes, key)) {
            ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
                           "error encoding %s private key",
                           v->algorithm_name);
            goto end;
        }
        pos += v->prvkey_bytes;
    }
    /* OQS form output with tacked-on public key */
    if (vp8->pub_length != 0) {
        /* The OQS pubkey is never separately DER-wrapped */
        if (pos != buf + vp8->pub_offset
            || !ossl_ml_kem_encode_public_key(pos, v->pubkey_bytes, key)) {
            ERR_raise_data(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR,
                           "error encoding %s private key",
                           v->algorithm_name);
            goto end;
        }
        pos += v->pubkey_bytes;
    }

    if (pos == buf + len) {
        *out = buf;
        ret = len;
    }

  end:
    OPENSSL_free(vp8_alloc);
    if (ret == 0)
        OPENSSL_free(buf);
    return ret;
}

int ossl_ml_kem_key_to_text(BIO *out, const ML_KEM_KEY *key, int selection)
{
    uint8_t seed[ML_KEM_SEED_BYTES], *prvenc = NULL, *pubenc = NULL;
    size_t publen, prvlen;
    const char *type_label = NULL;
    int ret = 0;

    if (out == NULL || key == NULL) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    type_label = key->vinfo->algorithm_name;
    publen = key->vinfo->pubkey_bytes;
    prvlen = key->vinfo->prvkey_bytes;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
        && (ossl_ml_kem_have_prvkey(key)
            || ossl_ml_kem_have_seed(key))) {
        if (BIO_printf(out, "%s Private-Key:\n", type_label) <= 0)
            return 0;

        if (ossl_ml_kem_have_seed(key)) {
            if (!ossl_ml_kem_encode_seed(seed, sizeof(seed), key))
                goto end;
            if (!ossl_bio_print_labeled_buf(out, "seed:", seed, sizeof(seed)))
                goto end;
        }
        if (ossl_ml_kem_have_prvkey(key)) {
            if ((prvenc = OPENSSL_malloc(prvlen)) == NULL)
                return 0;
            if (!ossl_ml_kem_encode_private_key(prvenc, prvlen, key))
                goto end;
            if (!ossl_bio_print_labeled_buf(out, "dk:", prvenc, prvlen))
                goto end;
        }
        ret = 1;
    }

    /* The public key is output regardless of the selection */
    if (ossl_ml_kem_have_pubkey(key)) {
        /* If we did not output private key bits, this is a public key */
        if (ret == 0 && BIO_printf(out, "%s Public-Key:\n", type_label) <= 0)
            goto end;

        if ((pubenc = OPENSSL_malloc(key->vinfo->pubkey_bytes)) == NULL
            || !ossl_ml_kem_encode_public_key(pubenc, publen, key)
            || !ossl_bio_print_labeled_buf(out, "ek:", pubenc, publen))
            goto end;
        ret = 1;
    }

    /* If we got here, and ret == 0, there was no key material */
    if (ret == 0)
        ERR_raise_data(ERR_LIB_PROV, PROV_R_MISSING_KEY,
                       "no %s key material available",
                       type_label);

  end:
    OPENSSL_free(pubenc);
    OPENSSL_free(prvenc);
    return ret;
}
