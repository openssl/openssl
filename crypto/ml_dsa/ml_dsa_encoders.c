/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "ml_dsa_local.h"
#include "ml_dsa_key.h"
#include "ml_dsa_params.h"
#include "internal/packet.h"

typedef int (PRIV_ENCODE_FN)(WPACKET *pkt, const POLY *s);
typedef int (PRIV_DECODE_FN)(PACKET *pkt, POLY *s);

static PRIV_ENCODE_FN poly_encode_signed_2;
static PRIV_ENCODE_FN poly_encode_signed_4;
static PRIV_DECODE_FN poly_decode_signed_2;
static PRIV_DECODE_FN poly_decode_signed_4;

static ossl_inline int constant_time_declassify_int(int v)
{
    return value_barrier_32(v);
}

/* Bit packing */

// FIPS 204, Algorithm 16 (`SimpleBitPack`). Specialized to bitlen(b) = 4.

#if 0
/*
 * @param s A scalar with coefficients all in the range (0..15)
 */
static int poly_encode_4(WPACKET *pkt, const POLY *s)
{
    uint8_t *out;
    uint32_t *in, end = s->c + 256;

    if (!WPACKET_reserve_bytes(pkt, 256 / 2, &out))
        return 0;

    for (in = s->c; in < end; ) {
        uint32_t c0 = *in++;
        uint32_t c1 = *in++;
        uint32_t c2 = *in++;
        uint32_t c3 = *in++;

        *out++ = c0 | c1 << 4;
        *out++ = c2 | c3 << 4;
    }
    return 1;
}
#endif

// FIPS 204, Algorithm 16 (`SimpleBitPack`). Specialized to bitlen(b) = 10
/* We use 10 bits from each coefficient and pack them into bytes
 * So every 4 coefficients fit into 5 bytes.
 *  |c0||c1||c2||c3|
 *   |\  |\  |\  |\
 *  |8|2 6|4 4|6 2|8|
 *
 * @param s A scalar with coefficients all in the range (0..1023)
 */
static int poly_encode_10_bits(WPACKET *pkt, const POLY *p)
{
    uint8_t *out;
    const uint32_t *in = p->coeff, *end = in + 256;

    if (!WPACKET_allocate_bytes(pkt, 5 * (256 / 4), &out))
        return 0;

    while (in < end) {
        uint32_t c0 = *in++;
        uint32_t c1 = *in++;
        uint32_t c2 = *in++;
        uint32_t c3 = *in++;

        *out++ = (uint8_t)c0;
        *out++ = (uint8_t)((c0 >> 8) | (c1 << 2));
        *out++ = (uint8_t)((c1 >> 6) | (c2 << 4));
        *out++ = (uint8_t)((c2 >> 4) | (c3 << 6));
        *out++ = (uint8_t)(c3 >> 2);
    }
    return 1;
}

// FIPS 204, Algorithm 18 (`SimpleBitUnpack`). Specialized for bitlen(b) == 10.
static int poly_decode_10_bits(PACKET *pkt, POLY *p)
{
    int i, ret = 0;
    const uint8_t *in = NULL;
    uint32_t v, *out = p->coeff;

    for (i = 0; i < (ML_DSA_NUM_POLY_COEFFICIENTS / 4); i++) {
        if (!PACKET_get_bytes(pkt, &in, 5))
            goto err;
        memcpy(&v, in, sizeof(v));
        *out++ = v & 0x3ff;
        *out++ = (v >> 10) & 0x3ff;
        *out++ = (v >> 20) & 0x3ff;
        *out++ = (v >> 30) | (((uint32_t)in[4]) << 2);
    }
    ret = 1;
err:
    return ret;
}

// FIPS 204, Algorithm 17 (`BitPack`). Specialized to bitlen(b) = 4 and b = 4.

/*
 * For coefficients in the range -4..4
 * We use 4 bits from each coefficient and pack them into bytes
 * So every 2 coefficients fit into 1 byte.
 *
 * @param pkt A packet to write the encoded scalar to.
 * @param s An array of 256 coefficients all in the range -4..4
 */
static int poly_encode_signed_4(WPACKET *pkt, const POLY *s)
{
    uint8_t *out;
    const uint32_t *in = s->coeff, *end = in + 256;

    if (!WPACKET_allocate_bytes(pkt, 32 * 4, &out))
        return 0;

    while (in < end) {
        uint32_t z0 = mod_sub(4, *in++); /* 0..8 */
        uint32_t z1 = mod_sub(4, *in++); /* 0..8 */

        *out++ = z0 | (z1 << 4);
    }
    return 1;
}

static int poly_decode_signed_4(PACKET *pkt, POLY *s)
{
    int i, ret = 0;
    uint32_t v, *out = s->coeff;
    const uint8_t *in;

    for (i = 0; i < (ML_DSA_NUM_POLY_COEFFICIENTS / 8); i++) {
        if (!PACKET_get_bytes(pkt, &in, 4))
            goto err;
        memcpy(&v, &in, 4);
        // None of the nibbles may be >= 9. So if the MSB of any nibble is set, none
        // of the other bits may be set. First, select all the MSBs.
        const uint32_t msbs = v & 0x88888888u;
        // For each nibble where the MSB is set, form a mask of all the other bits.
        const uint32_t mask = (msbs >> 1) | (msbs >> 2) | (msbs >> 3);
        // A nibble is only out of range in the case of invalid input, in which case
        // it is okay to leak the value.
        if (constant_time_declassify_int((mask & v) != 0))
            goto err;

        *out++ = mod_sub(4, v & 15);
        *out++ = mod_sub(4, (v >> 4) & 15);
        *out++ = mod_sub(4, (v >> 8) & 15);
        *out++ = mod_sub(4, (v >> 12) & 15);
        *out++ = mod_sub(4, (v >> 16) & 15);
        *out++ = mod_sub(4, (v >> 20) & 15);
        *out++ = mod_sub(4, (v >> 24) & 15);
        *out++ = mod_sub(4, v >> 28);
    }
    ret = 1;
 err:
    return ret;
}

/*
 * For coefficients in the range -2..2
 * We use 3 bits from each coefficient and pack them into bytes
 * So every 8 coefficients fit into 3 bytes.
 *  |c0 c1 c2 c3 c4 c5 c6 c7|
 *   | /  / | |  / / | |  /
 *  |3 3 2| 1 3 3 1| 2 3 3|
 *
 * @param pkt A packet to write the encoded scalar to.
 * @param s An array of 256 coefficients all in the range -2..2
 */
static int poly_encode_signed_2(WPACKET *pkt, const POLY *s)
{
    uint8_t *out;
    const uint32_t *in = s->coeff, *end = in + 256;

    if (!WPACKET_allocate_bytes(pkt, 32 * 3, &out))
        return 0;

    while (in < end) {
        uint32_t z0 = mod_sub(2, *in++); /* 0..7 */
        uint32_t z1 = mod_sub(2, *in++); /* 0..7 */
        uint32_t z2 = mod_sub(2, *in++); /* 0..7 */
        uint32_t z3 = mod_sub(2, *in++); /* 0..7 */
        uint32_t z4 = mod_sub(2, *in++); /* 0..7 */
        uint32_t z5 = mod_sub(2, *in++); /* 0..7 */
        uint32_t z6 = mod_sub(2, *in++); /* 0..7 */
        uint32_t z7 = mod_sub(2, *in++); /* 0..7 */

        *out++ = (uint8_t)z0 | (uint8_t)(z1 << 3) | (uint8_t)(z2 << 6);
        *out++ = (uint8_t)(z2 >> 2) | (uint8_t)(z3 << 1) | (uint8_t)(z4 << 4) | (uint8_t)(z5 << 7);
        *out++ = (uint8_t)(z5 >> 1) | (uint8_t)(z6 << 2) | (uint8_t)(z7 << 5);
    }
    return 1;
}

static int poly_decode_signed_2(PACKET *pkt, POLY *s)
{
    int i, ret = 0;
    uint32_t v = 0, *out = s->coeff;
    const uint8_t *in;

    for (i = 0; i < (ML_DSA_NUM_POLY_COEFFICIENTS / 8); i++) {
        if (!PACKET_get_bytes(pkt, &in, 3))
            goto err;
        memcpy(&v, &in, 3);
        // Each octal value (3 bits) must be <= 4, So if the MSB is set then the
        // bottom 2 bits must not be set.
        // First, select all the MSBs (we use octal representation for the mask)
        const uint32_t msbs = v & 044444444;
        // For each octal value where the MSB is set, form a mask of the 2 other bits.
        const uint32_t mask = (msbs >> 1) | (msbs >> 2);
        // A nibble is only out of range in the case of invalid input, in which case
        // it is okay to leak the value.
        if (constant_time_declassify_int((mask & v) != 0))
            goto err;

        *out++ = mod_sub(2, v & 7);
        *out++ = mod_sub(2, (v >> 3) & 7);
        *out++ = mod_sub(2, (v >> 6) & 7);
        *out++ = mod_sub(2, (v >> 9) & 7);
        *out++ = mod_sub(2, (v >> 12) & 7);
        *out++ = mod_sub(2, (v >> 15) & 7);
        *out++ = mod_sub(2, (v >> 18) & 7);
        *out++ = mod_sub(2, (v >> 21) & 7);
    }
    ret = 1;
 err:
    return ret;
}

/*
 * FIPS 204, Algorithm 17 (`BitPack`).
 * For coefficients ranging from -2^(13-1)+1 ... 2^(13-1)
 * We use 13 bits from each coefficient and pack them into bytes
 *
 * The code below packs them into 2 64 bits blocks by doing..
 * z0 z1 z2 z3  z4  z5 z6  z7
 * |   |  | |   / \  |  |  |
 *|13 13 13 13 12 |1 13 13 13 |
 */
static int poly_encode_signed_two_to_power_12(WPACKET *pkt, const POLY *s)
{
    static const uint32_t range = 1u << 12;
    const uint32_t *in = s->coeff, *end = in + 256;

    while (in < end) {
        uint64_t z0 = mod_sub(range, *in++); /* < 2^13 */
        uint64_t z1 = mod_sub(range, *in++);
        uint64_t z2 = mod_sub(range, *in++);
        uint64_t z3 = mod_sub(range, *in++);
        uint64_t z4 = mod_sub(range, *in++);
        uint64_t z5 = mod_sub(range, *in++);
        uint64_t z6 = mod_sub(range, *in++);
        uint64_t z7 = mod_sub(range, *in++);
        uint64_t a1 = (z0) | (z1 << 13) | (z2 << 26) | (z3 << 39) | (z4 << 52);
        uint64_t a2 = (z4 >> 12) | (z5 << 1) | (z6 << 14) | (z7 << 27);

        if (!WPACKET_memcpy(pkt, &a1, 8)
                || !WPACKET_memcpy(pkt, &a2, 5))
            return 0;
    }
    return 1;
}

// FIPS 204, Algorithm 18 (`SimpleBitUnpack`).
static int poly_decode_signed_two_to_power_12(PACKET *pkt, POLY *s)
{
    int i, ret = 0;
    uint64_t a1 = 0, a2 = 0;
    uint32_t *out = s->coeff;
    const uint8_t *in;
    static const uint32_t range = 1u << 12;
    static const uint32_t mask_13_bits = (1u << 13) - 1;

    for (i = 0; i < (ML_DSA_NUM_POLY_COEFFICIENTS / 8); i++) {
        if (!PACKET_get_bytes(pkt, &in, 13))
            goto err;
        memcpy(&a1, &in, 8);
        memcpy(&a2, in + 8, 5);

        // It's not possible for a 13-bit number to be out of range when the
        // max is 2^12.
        *out++ = mod_sub(range, a1 & mask_13_bits);
        *out++ = mod_sub(range, (a1 >> 13) & mask_13_bits);
        *out++ = mod_sub(range, (a1 >> 26) & mask_13_bits);
        *out++ = mod_sub(range, (a1 >> 39) & mask_13_bits);
        *out++ = mod_sub(range, (a1 >> 52) | ((a2 << 12) & mask_13_bits));
        *out++ = mod_sub(range, (a2 >> 1) & mask_13_bits);
        *out++ = mod_sub(range, (a2 >> 14) & mask_13_bits);
        *out++ = mod_sub(range, (a2 >> 27) & mask_13_bits);
    }
    ret = 1;
 err:
    return ret;
}

// FIPS 204, Algorithm 22 (`pkEncode`).
int ossl_ml_dsa_pk_encode(ML_DSA_KEY *key)
{
    int ret = 0;
    size_t i;
    const POLY *t1 = key->t1.poly;
    size_t t1_len = key->t1.num_poly;
    size_t enc_len = key->params->pk_len;
    uint8_t *enc = OPENSSL_zalloc(enc_len);
    WPACKET pkt;

    if (enc == NULL)
        return 0;

    if (!WPACKET_init_static_len(&pkt, enc, enc_len, 0)
            || !WPACKET_memcpy(&pkt, key->rho, sizeof(key->rho)))
        goto err;
    for (i = 0; i < t1_len; i++)
        if (!poly_encode_10_bits(&pkt, t1 + i))
            goto err;
    OPENSSL_free(key->pub_encoding);
    key->pub_encoding = enc;
    ret = 1;
err:
    WPACKET_finish(&pkt);
    if (ret == 0)
        OPENSSL_free(enc);
    return ret;
}

// FIPS 204, Algorithm 23 (`pkDecode`).
int ossl_ml_dsa_pk_decode(const uint8_t *in, size_t in_len, ML_DSA_KEY *key)
{
    int ret = 0;
    size_t i;
    PACKET pkt;

    if (in_len != key->params->pk_len)
        return 0;

    if (!PACKET_buf_init(&pkt, in, in_len)
            || PACKET_copy_bytes(&pkt, key->rho, sizeof(key->rho)))
        goto err;
    for (i = 0; i < key->t1.num_poly; i++)
        if (!poly_decode_10_bits(&pkt, &key->t1.poly[i]))
            goto err;
    memcpy(key->pub_encoding, in, in_len);
    ret = 1;
err:
    return ret;
}

// FIPS 204, Algorithm 24 (`skEncode`)

int ossl_ml_dsa_sk_encode(ML_DSA_KEY *key)
{
    int ret = 0;
    const ML_DSA_PARAMS *params = key->params;
    size_t i, k = params->k, l = params->l;
    PRIV_ENCODE_FN *encode_fn;
    size_t enc_len = params->sk_len;
    const POLY *t0 = key->t0.poly;
    uint8_t *enc = OPENSSL_zalloc(enc_len);
    WPACKET pkt;

    if (enc == NULL)
        return 0;

    /* Eta is the range of private key coefficents (-eta...eta) */
    if (params->eta == 4)
        encode_fn = poly_encode_signed_4;
    else
        encode_fn = poly_encode_signed_2;

    if (!WPACKET_init_static_len(&pkt, enc, enc_len, 0)
            || !WPACKET_memcpy(&pkt, key->rho, sizeof(key->rho))
            || !WPACKET_memcpy(&pkt, key->K, sizeof(key->K))
            || !WPACKET_memcpy(&pkt, key->tr, sizeof(key->tr)))
        goto err;
    for (i = 0; i < l; ++i)
        if (!encode_fn(&pkt, &key->s1.poly[i]))
            goto err;
    for (i = 0; i < k; ++i)
        if (!encode_fn(&pkt, &key->s2.poly[i]))
            goto err;
    for (i = 0; i < k; ++i, t0++)
        if (!poly_encode_signed_two_to_power_12(&pkt, t0))
            goto err;
    OPENSSL_clear_free(key->priv_encoding, enc_len);
    key->priv_encoding = enc;
    ret = 1;
err:
    WPACKET_finish(&pkt);
    if (ret == 0)
        OPENSSL_clear_free(enc, enc_len);
    return ret;
}

// FIPS 204, Algorithm 25 (`skDecode`).
int ossl_ml_dsa_sk_decode(const uint8_t *in, size_t in_len, ML_DSA_KEY *key)
{
    int ret = 0;
    PRIV_DECODE_FN *decode_fn;
    const ML_DSA_PARAMS *params = key->params;
    size_t i, k = params->k, l = params->l;
    PACKET pkt;

    if (in_len != key->params->sk_len)
        return 0;

    /* Eta is the range of private key coefficents (-eta...eta) */
    if (params->eta == 4)
        decode_fn = poly_decode_signed_4;
    else
        decode_fn = poly_decode_signed_2;

    if (!PACKET_buf_init(&pkt, in, in_len)
            || !PACKET_copy_bytes(&pkt, key->rho, sizeof(key->rho))
            || !PACKET_copy_bytes(&pkt, key->K, sizeof(key->K))
            || !PACKET_copy_bytes(&pkt, key->tr, sizeof(key->tr)))
        goto err;

    for (i = 0; i < l; ++i)
        if (!decode_fn(&pkt, key->s1.poly + i))
            goto err;
    for (i = 0; i < k; ++i)
        if (!decode_fn(&pkt, key->s2.poly + i))
            goto err;
    for (i = 0; i < k; ++i)
        if (!poly_decode_signed_two_to_power_12(&pkt, key->t0.poly + i))
            goto err;
    if (PACKET_remaining(&pkt) != 0)
        goto err;
    OPENSSL_clear_free(key->priv_encoding, in_len);
    key->priv_encoding = OPENSSL_memdup(in, in_len);
    ret = 1;
err:
    return ret;
}

#if 0
int ossl_ml_dsa_sig_encode(WPACKET *pkt,...);
int ossl_ml_dsa_sig_decode(PACKET *pkt,...);
int ossl_ml_dsa_w1_encode();
#endif
