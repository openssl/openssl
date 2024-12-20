/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include "ml_dsa_local.h"
#include "ml_dsa_key.h"
#include "ml_dsa_params.h"
#include "ml_dsa_sign.h"
#include "internal/packet.h"

typedef int (ENCODE_FN)(const POLY *s, WPACKET *pkt);
typedef int (DECODE_FN)(POLY *s, PACKET *pkt);

static ENCODE_FN poly_encode_signed_2;
static ENCODE_FN poly_encode_signed_4;
static ENCODE_FN poly_encode_signed_two_to_power_17;
static ENCODE_FN poly_encode_signed_two_to_power_19;
static DECODE_FN poly_decode_signed_2;
static DECODE_FN poly_decode_signed_4;
static DECODE_FN poly_decode_signed_two_to_power_17;
static DECODE_FN poly_decode_signed_two_to_power_19;

/* Bit packing Algorithms */

/*
 * Encodes a polynomial into a byte string, assuming that all coefficients are
 * in the range 0..15 (4 bits).
 *
 * See FIPS 204, Algorithm 16, SimpleBitPack(w, b) where b = 4 bits
 *
 * i.e. Use 4 bits from each coefficient and pack them into bytes
 * So every 2 coefficients fit into 1 byte.
 *
 * This is used to encode w1 when signing with ML-DSA-65 and ML-DSA-87
 *
 * @param p A polynomial with coefficients all in the range (0..15)
 * @param pkt A packet object to write 128 bytes to.
 *
 * @returns 1 on success, or 0 on error.
 */
static int poly_encode_4_bits(const POLY *p, WPACKET *pkt)
{
    uint8_t *out;
    const uint32_t *in = p->coeff, *end = in + ML_DSA_NUM_POLY_COEFFICIENTS;

    if (!WPACKET_allocate_bytes(pkt, 32 * 4, &out))
        return 0;

    while (in < end) {
        uint32_t z0 = *in++;
        uint32_t z1 = *in++;

        *out++ = z0 | (z1 << 4);
    }
    return 1;
}

/*
 * Encodes a polynomial into a byte string, assuming that all coefficients are
 * in the range 0..43 (6 bits).
 *
 * See FIPS 204, Algorithm 16, SimpleBitPack(w, b) where b = 43
 *
 * i.e. Use 6 bits from each coefficient and pack them into bytes
 * So every 4 coefficients fit into 3 bytes.
 *
 *  |c0||c1||c2||c3|
 *   |  /|  /\  /
 *  |6 2|4 4|2 6|
 *
 * This is used to encode w1 when signing with ML-DSA-44
 *
 * @param p A polynomial with coefficients all in the range (0..43)
 * @param pkt A packet object to write 96 bytes to.
 *
 * @returns 1 on success, or 0 on error.
 */
static int poly_encode_6_bits(const POLY *p, WPACKET *pkt)
{
    uint8_t *out;
    const uint32_t *in = p->coeff, *end = in + ML_DSA_NUM_POLY_COEFFICIENTS;

    if (!WPACKET_allocate_bytes(pkt, 32 * 3, &out))
        return 0;

    while (in < end) {
        uint32_t c0 = *in++;
        uint32_t c1 = *in++;
        uint32_t c2 = *in++;
        uint32_t c3 = *in++;

        *out++ = c0 | (c1 << 6);
        *out++ = c1 >> 4 | (c2 << 4);
        *out++ = c3;
    }
    return 1;
}

/*
 * Encodes a polynomial into a byte string, assuming that all coefficients are
 * unsigned 10 bit values.
 *
 * See FIPS 204, Algorithm 16, SimpleBitPack(w, b) where b = 10 bits
 *
 * i.e. Use 10 bits from each coefficient and pack them into bytes
 * So every 4 coefficients (c0..c3) fit into 5 bytes.
 *  |c0||c1||c2||c3|
 *   |\  |\  |\  |\
 *  |8|2 6|4 4|6 2|8|
 *
 * This is used to save t1 (the high part of public key polynomial t)
 *
 * @param p A polynomial with coefficients all in the range (0..1023)
 * @param pkt A packet object to write 320 bytes to.
 *
 * @returns 1 on success, or 0 on error.
 */
static int poly_encode_10_bits(const POLY *p, WPACKET *pkt)
{
    uint8_t *out;
    const uint32_t *in = p->coeff, *end = in + ML_DSA_NUM_POLY_COEFFICIENTS;

    if (!WPACKET_allocate_bytes(pkt, 32 * 10, &out))
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

/*
 * @brief Reverses the procedure of poly_encode_10_bits().
 * See FIPS 204, Algorithm 18, SimpleBitUnpack(v, b) where b = 10.
 *
 * @param p A polynomial to write coefficients to.
 * @param pkt A packet object to read 320 bytes from.
 *
 * @returns 1 on success, or 0 on error.
 */
static int poly_decode_10_bits(POLY *p, PACKET *pkt)
{
    int ret = 0;
    const uint8_t *in = NULL;
    uint32_t v, mask = 0x3ff; /* 10 bits */
    uint32_t *out = p->coeff, *end = out + ML_DSA_NUM_POLY_COEFFICIENTS;

    do {
        if (!PACKET_get_bytes(pkt, &in, 5))
            goto err;
        /* put first 4 bytes into v, 5th byte is accessed directly as in[4] */
        memcpy(&v, in, 4);
        *out++ = v & mask;
        *out++ = (v >> 10) & mask;
        *out++ = (v >> 20) & mask;
        *out++ = (v >> 30) | (((uint32_t)in[4]) << 2);
    } while (out < end);
    ret = 1;
err:
    return ret;
}

/*
 * @brief Encodes a polynomial into a byte string, assuming that all
 * coefficients are in the range -4..4.
 * See FIPS 204, Algorithm 17, BitPack(w, a, b). (a = 4, b = 4)
 *
 * It uses a nibble from each coefficient and packs them into bytes
 * So every 2 coefficients fit into 1 byte.
 *
 * This is used to encode the private key polynomial elements of s1 and s2
 * for ML-DSA-65 (i.e. eta = 4)
 *
 * @param p An array of 256 coefficients all in the range -4..4
 * @param pkt A packet to write 128 bytes of encoded polynomial coefficients to.
 *
 * @returns 1 on success, or 0 on error.
 */
static int poly_encode_signed_4(const POLY *p, WPACKET *pkt)
{
    uint8_t *out;
    const uint32_t *in = p->coeff, *end = in + ML_DSA_NUM_POLY_COEFFICIENTS;

    if (!WPACKET_allocate_bytes(pkt, 32 * 4, &out))
        return 0;

    while (in < end) {
        uint32_t z0 = mod_sub(4, *in++); /* 0..8 */
        uint32_t z1 = mod_sub(4, *in++); /* 0..8 */

        *out++ = z0 | (z1 << 4);
    }
    return 1;
}

/*
 * @brief Reverses the procedure of poly_encode_signed_4().
 * See FIPS 204, Algorithm 19, BitUnpack(v, a, b) where a = b = 4.
 *
 * @param p A polynomial to write coefficients to.
 * @param pkt A packet object to read 128 bytes from.
 *
 * @returns 1 on success, or 0 on error. An error will occur if any of the
 *          coefficients are not in the correct range.
 */
static int poly_decode_signed_4(POLY *p, PACKET *pkt)
{
    int i, ret = 0;
    uint32_t v, *out = p->coeff;
    const uint8_t *in;
    uint32_t msbs, mask;

    for (i = 0; i < (ML_DSA_NUM_POLY_COEFFICIENTS / 8); i++) {
        if (!PACKET_get_bytes(pkt, &in, 4))
            goto err;
        memcpy(&v, in, 4);

        /*
         * None of the nibbles may be >= 9. So if the MSB of any nibble is set,
         * none of the other bits may be set. First, select all the MSBs.
         */
        msbs = v & 0x88888888u;
        /* For each nibble where the MSB is set, form a mask of all the other bits. */
        mask = (msbs >> 1) | (msbs >> 2) | (msbs >> 3);
        /*
         * A nibble is only out of range in the case of invalid input, in which case
         * it is okay to leak the value.
         */
        if (value_barrier_32((mask & v) != 0))
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
 * @brief Encodes a polynomial into a byte string, assuming that all
 * coefficients are in the range -2..2.
 * See FIPS 204, Algorithm 17, BitPack(w, a, b). where a = b = 2.
 *
 * This is used to encode the private key polynomial elements of s1 and s2
 * for ML-DSA-44 and ML-DSA-87 (i.e. eta = 2)
 *
 * @param pkt A packet to write 128 bytes of encoded polynomial coefficients to.
 * @param p An array of 256 coefficients all in the range -2..2
 *
 * Use 3 bits from each coefficient and pack them into bytes
 * So every 8 coefficients fit into 3 bytes.
 *  |c0 c1 c2 c3 c4 c5 c6 c7|
 *   | /  / | |  / / | |  /
 *  |3 3 2| 1 3 3 1| 2 3 3|
 *
 * @param p An array of 256 coefficients all in the range -2..2
 * @param pkt A packet to write 64 bytes of encoded polynomial coefficients to.
 *
 * @returns 1 on success, or 0 on error.
 */
static int poly_encode_signed_2(const POLY *p, WPACKET *pkt)
{
    uint8_t *out;
    const uint32_t *in = p->coeff, *end = in + ML_DSA_NUM_POLY_COEFFICIENTS;

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

/*
 * @brief Reverses the procedure of poly_encode_signed_2().
 * See FIPS 204, Algorithm 19, BitUnpack(v, a, b) where a = b = 2.
 *
 * @param p A polynomial to write coefficients to.
 * @param pkt A packet object to read 64 encoded bytes from.
 *
 * @returns 1 on success, or 0 on error. An error will occur if any of the
 *          coefficients are not in the correct range.
 */
static int poly_decode_signed_2(POLY *p, PACKET *pkt)
{
    int i, ret = 0;
    uint32_t v = 0, *out = p->coeff;
    uint32_t msbs, mask;
    const uint8_t *in;

    for (i = 0; i < (ML_DSA_NUM_POLY_COEFFICIENTS / 8); i++) {
        if (!PACKET_get_bytes(pkt, &in, 3))
            goto err;
        memcpy(&v, in, 3);
        /*
         * Each octal value (3 bits) must be <= 4, So if the MSB is set then the
         * bottom 2 bits must not be set.
         * First, select all the MSBs (Use octal representation for the mask)
         */
        msbs = v & 044444444;
        /* For each octal value where the MSB is set, form a mask of the 2 other bits. */
        mask = (msbs >> 1) | (msbs >> 2);
        /*
         * A nibble is only out of range in the case of invalid input, in which
         * case it is okay to leak the value.
         */
        if (value_barrier_32((mask & v) != 0))
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
 * @brief Encodes a polynomial into a byte string, assuming that all
 * coefficients are in the range (-2^12 + 1)..2^12.
 * See FIPS 204, Algorithm 17, BitPack(w, a, b). where a = 2^12 - 1, b = 2^12.
 *
 * This is used to encode the LSB of the public key polynomial elements of t0
 * (which are encoded as part of the encoded private key).
 *
 * Use 13 bits from each coefficient and pack them into bytes
 *
 * The code below packs them into 2 64 bits blocks by doing..
 *  z0 z1 z2 z3  z4  z5 z6  z7 0
 *  |   |  | |   / \  |  |  |  |
 * |13 13 13 13 12 |1 13 13 13 24
 *
 * @param p An array of 256 coefficients all in the range -2^12+1..2^12
 * @param pkt A packet to write 416 (13 * 256 / 8) bytes of encoded polynomial
 *            coefficients to.
 *
 * @returns 1 on success, or 0 on error.
 */
static int poly_encode_signed_two_to_power_12(const POLY *p, WPACKET *pkt)
{
    static const uint32_t range = 1u << 12;
    const uint32_t *in = p->coeff, *end = in + ML_DSA_NUM_POLY_COEFFICIENTS;

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

/*
 * @brief Reverses the procedure of poly_encode_signed_two_to_power_12().
 * See FIPS 204, Algorithm 19, BitUnpack(v, a, b) where a = 2^12 - 1, b = 2^12.
 *
 * @param p A polynomial to write coefficients to.
 * @param pkt A packet object to read 416 encoded bytes from.
 *
 * @returns 1 on success, or 0 on error.
 */
static int poly_decode_signed_two_to_power_12(POLY *p, PACKET *pkt)
{
    int i, ret = 0;
    uint64_t a1 = 0, a2 = 0;
    uint32_t *out = p->coeff;
    const uint8_t *in;
    static const uint32_t range = 1u << 12;
    static const uint32_t mask_13_bits = (1u << 13) - 1;

    for (i = 0; i < (ML_DSA_NUM_POLY_COEFFICIENTS / 8); i++) {
        if (!PACKET_get_bytes(pkt, &in, 13))
            goto err;
        memcpy(&a1, in, 8);
        memcpy(&a2, in + 8, 5);

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

/*
 * @brief Encodes a polynomial into a byte string, assuming that all
 * coefficients are in the range (-2^19 + 1)..2^19.
 * See FIPS 204, Algorithm 17, BitPack(w, a, b). where a = 2^19 - 1, b = 2^19.
 *
 * This is used to encode signatures for ML-DSA-65 & ML-DSA-87 (gamma1 = 2^19)
 *
 * Use 20 bits from each coefficient and pack them into bytes
 *
 * The code below packs every 4 (20 bit) coefficients into 10 bytes
 *  z0  z1  z2 z3
 *  |   |\  |  | \
 * |20 12|8 20 4|16
 *
 * @param p An array of 256 coefficients all in the range -2^19+1..2^19
 * @param pkt A packet to write 640 (20 * 256 / 8) bytes of encoded polynomial
 *            coefficients to.
 *
 * @returns 1 on success, or 0 on error.
 */
static int poly_encode_signed_two_to_power_19(const POLY *p, WPACKET *pkt)
{
    static const uint32_t range = 1u << 19;
    const uint32_t *in = p->coeff, *end = in + ML_DSA_NUM_POLY_COEFFICIENTS;

    while (in < end) {
        uint32_t z0 = mod_sub(range, *in++); /* < 2^20 */
        uint32_t z1 = mod_sub(range, *in++);
        uint32_t z2 = mod_sub(range, *in++);
        uint32_t z3 = mod_sub(range, *in++);

        z0 |= (z1 << 20);
        z1 >>= 12;
        z1 |= (z2 << 8) | (z3 << 28);
        z3 >>= 4;

        if (!WPACKET_memcpy(pkt, &z0, sizeof(z0))
                || !WPACKET_memcpy(pkt, &z1, sizeof(z1))
                || !WPACKET_memcpy(pkt, &z3, 2))
            return 0;
    }
    return 1;
}

/*
 * @brief Reverses the procedure of poly_encode_signed_two_to_power_19().
 * See FIPS 204, Algorithm 19, BitUnpack(v, a, b) where a = 2^19 - 1, b = 2^19.
 *
 * @param p A polynomial to write coefficients to.
 * @param pkt A packet object to read 640 encoded bytes from.
 *
 * @returns 1 on success, or 0 on error.
 */
static int poly_decode_signed_two_to_power_19(POLY *p, PACKET *pkt)
{
    int i, ret = 0;
    uint32_t a1, a2, a3 = 0;
    uint32_t *out = p->coeff;
    const uint8_t *in;
    static const uint32_t range = 1u << 19;
    static const uint32_t mask_20_bits = (1u << 20) - 1;

    for (i = 0; i < (ML_DSA_NUM_POLY_COEFFICIENTS / 4); i++) {
        if (!PACKET_get_bytes(pkt, &in, 10))
            goto err;
        memcpy(&a1, in, 4);
        memcpy(&a2, in + 4, 4);
        memcpy(&a3, in + 8, 2);

        *out++ = mod_sub(range, a1 & mask_20_bits);
        *out++ = mod_sub(range, (a1 >> 20) | ((a2 & 0xFF) << 12));
        *out++ = mod_sub(range, (a2 >> 8) & mask_20_bits);
        *out++ = mod_sub(range, (a2 >> 28) | (a3 << 4));
    }
    ret = 1;
 err:
    return ret;
}

/*
 * @brief Encodes a polynomial into a byte string, assuming that all
 * coefficients are in the range (-2^17 + 1)..2^17.
 * See FIPS 204, Algorithm 17, BitPack(w, a, b). where a = 2^17 - 1, b = 2^17.
 *
 * This is used to encode signatures for ML-DSA-44 (where gamma1 = 2^17)
 *
 * Use 18 bits from each coefficient and pack them into bytes
 *
 * The code below packs every 4 (18 bit) coefficients into 9 bytes
 *  z0  z1  z2 z3
 *  |   |\  |  | \
 * |18 14|4 18 10| 8
 *
 * @param p An array of 256 coefficients all in the range -2^17+1..2^17
 * @param pkt A packet to write 576 (18 * 256 / 8) bytes of encoded polynomial
 *            coefficients to.
 *
 * @returns 1 on success, or 0 on error.
 */
static int poly_encode_signed_two_to_power_17(const POLY *p, WPACKET *pkt)
{
    static const uint32_t range = 1u << 17;
    const uint32_t *in = p->coeff, *end = in + ML_DSA_NUM_POLY_COEFFICIENTS;

    while (in < end) {
        uint32_t z0 = mod_sub(range, *in++); /* < 2^18 */
        uint32_t z1 = mod_sub(range, *in++);
        uint32_t z2 = mod_sub(range, *in++);
        uint32_t z3 = mod_sub(range, *in++);

        z0 |= (z1 << 18);
        z1 >>= 14;
        z1 |= (z2 << 4) | (z3 << 22);
        z3 >>= 10;

        if (!WPACKET_memcpy(pkt, &z0, sizeof(z0))
                || !WPACKET_memcpy(pkt, &z1, sizeof(z1))
                || !WPACKET_memcpy(pkt, &z3, 1))
            return 0;
    }
    return 1;
}

/*
 * @brief Reverses the procedure of poly_encode_signed_two_to_power_17().
 * See FIPS 204, Algorithm 19, BitUnpack(v, a, b) where a = 2^17 - 1, b = 2^17.
 *
 * @param p A polynomial to write coefficients to.
 * @param pkt A packet object to read 576 encoded bytes from.
 *
 * @returns 1 on success, or 0 on error.
 */
static int poly_decode_signed_two_to_power_17(POLY *p, PACKET *pkt)
{
    int ret = 0;
    uint32_t a1, a2, a3 = 0;
    uint32_t *out = p->coeff;
    const uint32_t *end = out + ML_DSA_NUM_POLY_COEFFICIENTS;
    const uint8_t *in;
    static const uint32_t range = 1u << 17;
    static const uint32_t mask_18_bits = (1u << 18) - 1;

    while (out < end) {
        if (!PACKET_get_bytes(pkt, &in, 10))
            goto err;
        memcpy(&a1, in, 4);
        memcpy(&a2, in + 4, 4);
        memcpy(&a3, in + 8, 1);

        *out++ = mod_sub(range, a1 & mask_18_bits);
        *out++ = mod_sub(range, (a1 >> 18) | ((a2 & 0xF) << 14));
        *out++ = mod_sub(range, (a2 >> 4) & mask_18_bits);
        *out++ = mod_sub(range, (a2 >> 22) | (a3 << 10));
    }
    ret = 1;
 err:
    return ret;
}

/*
 * @brief Encode the public key as an array of bytes.
 * See FIPS 204, Algorithm 22, pkEncode().
 *
 * @param key A key object containing public key values. The encoded public
 *            key data is stored in this key.
 * @returns 1 if the public key was encoded successfully or 0 otherwise.
 */
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
        if (!poly_encode_10_bits(t1 + i, &pkt))
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

/*
 * @brief The reverse of ossl_ml_dsa_pk_encode().
 * See FIPS 204, Algorithm 23, pkDecode().
 *
 * @param in An encoded public key.
 * @param in_len The size of |in|
 * @param key A key object to store the decoded public key into.
 *
 * @returns 1 if the public key was decoded successfully or 0 otherwise.
 */
int ossl_ml_dsa_pk_decode(ML_DSA_KEY *key, const uint8_t *in, size_t in_len)
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
        if (!poly_decode_10_bits(key->t1.poly + i, &pkt))
            goto err;
    memcpy(key->pub_encoding, in, in_len);
    ret = 1;
err:
    return ret;
}

/*
 * @brief Encode the private key as an array of bytes.
 * See FIPS 204, Algorithm 24, skEncode().
 *
 * @param key A key object containing private key values. The encoded private
 *            key data is stored in this key.
 * @returns 1 if the private key was encoded successfully or 0 otherwise.
 */
int ossl_ml_dsa_sk_encode(ML_DSA_KEY *key)
{
    int ret = 0;
    const ML_DSA_PARAMS *params = key->params;
    size_t i, k = params->k, l = params->l;
    ENCODE_FN *encode_fn;
    size_t enc_len = params->sk_len;
    const POLY *t0 = key->t0.poly;
    WPACKET pkt;
    uint8_t *enc = OPENSSL_zalloc(enc_len);

    if (enc == NULL)
        return 0;

    /* eta is the range of private key coefficients (-eta...eta) */
    if (params->eta == ML_DSA_ETA_4)
        encode_fn = poly_encode_signed_4;
    else
        encode_fn = poly_encode_signed_2;

    if (!WPACKET_init_static_len(&pkt, enc, enc_len, 0)
            || !WPACKET_memcpy(&pkt, key->rho, sizeof(key->rho))
            || !WPACKET_memcpy(&pkt, key->K, sizeof(key->K))
            || !WPACKET_memcpy(&pkt, key->tr, sizeof(key->tr)))
        goto err;
    for (i = 0; i < l; ++i)
        if (!encode_fn(key->s1.poly + i, &pkt))
            goto err;
    for (i = 0; i < k; ++i)
        if (!encode_fn(key->s2.poly + i, &pkt))
            goto err;
    for (i = 0; i < k; ++i)
        if (!poly_encode_signed_two_to_power_12(t0++, &pkt))
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

/*
 * @brief The reverse of ossl_ml_dsa_sk_encode().
 * See FIPS 204, Algorithm 24, skDecode().
 *
 * @param in An encoded private key.
 * @param in_len The size of |in|
 * @param key A key object to store the decoded private key into.
 *
 * @returns 1 if the private key was decoded successfully or 0 otherwise.
 */
int ossl_ml_dsa_sk_decode(ML_DSA_KEY *key, const uint8_t *in, size_t in_len)
{
    int ret = 0;
    uint8_t *enc = NULL;
    DECODE_FN *decode_fn;
    const ML_DSA_PARAMS *params = key->params;
    size_t i, k = params->k, l = params->l;
    PACKET pkt;

    if (in_len != key->params->sk_len)
        return 0;
    enc = OPENSSL_memdup(in, in_len);
    if (enc == NULL)
        return 0;

    /* eta is the range of private key coefficients (-eta...eta) */
    if (params->eta == ML_DSA_ETA_4)
        decode_fn = poly_decode_signed_4;
    else
        decode_fn = poly_decode_signed_2;

    if (!PACKET_buf_init(&pkt, in, in_len)
            || !PACKET_copy_bytes(&pkt, key->rho, sizeof(key->rho))
            || !PACKET_copy_bytes(&pkt, key->K, sizeof(key->K))
            || !PACKET_copy_bytes(&pkt, key->tr, sizeof(key->tr)))
        goto err;

    for (i = 0; i < l; ++i)
        if (!decode_fn(key->s1.poly + i, &pkt))
            goto err;
    for (i = 0; i < k; ++i)
        if (!decode_fn(key->s2.poly + i, &pkt))
            goto err;
    for (i = 0; i < k; ++i)
        if (!poly_decode_signed_two_to_power_12(key->t0.poly + i, &pkt))
            goto err;
    if (PACKET_remaining(&pkt) != 0)
        goto err;
    OPENSSL_clear_free(key->priv_encoding, in_len);
    key->priv_encoding = enc;
    ret = 1;
err:
    return ret;
}

/*
 * See FIPS 204, Algorithm 20, HintBitPack().
 * Hint is composed of k polynomials with binary coefficients where only 'omega'
 * of all the coefficients are set to 1.
 * This can be encoded as a byte array of 'omega' polynomial coefficient index
 * positions for the coefficients that are set, followed by
 * k values of the last coefficient index used in each polynomial.
 */
static int hint_bits_encode(const VECTOR *hint, WPACKET *pkt, uint32_t omega)
{
    int i, j, k = hint->num_poly;
    size_t coeff_index = 0;
    POLY *p = hint->poly;
    uint8_t *data;

    if (!WPACKET_allocate_bytes(pkt, omega + k, &data))
        return 0;

    for (i = 0; i < k; i++, p++) {
        for (j = 0; j < ML_DSA_NUM_POLY_COEFFICIENTS; j++)
            if (p->coeff[j] != 0) {
                assert(coeff_index < omega);
                data[coeff_index++] = j;
            }
        data[omega + i] = (uint8_t)coeff_index;
    }
    return 1;
}

/*
 * @brief Reverse the process of hint_bits_encode()
 * See FIPS 204, Algorithm 21, HintBitUnpack()
 *
 * @returns 1 if the hints were successfully unpacked, or 0
 * if 'pkt' is too small or malformed.
 */
static int hint_bits_decode(VECTOR *hint, PACKET *pkt, uint32_t omega)
{
    size_t coeff_index = 0, k = hint->num_poly;
    const uint8_t *in, *limits;
    POLY *p = hint->poly, *end = p + k;

    if (!PACKET_get_bytes(pkt, &in, omega)
            || !PACKET_get_bytes(pkt, &limits, k))
        return 0;

    vector_zero(hint); /* Set all coefficients to zero */

    do {
        const uint32_t limit = *limits++;
        int last = -1;

        if (limit < coeff_index || limit > omega)
            return 0;

        while (coeff_index < limit) {
            int byte = in[coeff_index++];

            if (last >= 0 && byte <= last)
                return 0;
            last = byte;
            p->coeff[byte] = 1;
        }
    } while (++p < end);

    for (; coeff_index < omega; coeff_index++)
        if (in[coeff_index] != 0)
            return 0;
    return 1;
}

/*
 * @brief Encode a ML_DSA signature as an array of bytes.
 * See FIPS 204, Algorithm 26, sigEncode().
 *
 * @param
 * @param
 * @returns 1 if the signature was encoded successfully or 0 otherwise.
 */
int ossl_ml_dsa_sig_encode(const ML_DSA_SIG *sig, const ML_DSA_PARAMS *params,
                           uint8_t *out)
{
    int ret = 0;
    size_t i;
    ENCODE_FN *encode_fn;
    WPACKET pkt;

    if (out == NULL)
        return 0;

    if (params->gamma1 == ML_DSA_GAMMA1_TWO_POWER_19)
        encode_fn = poly_encode_signed_two_to_power_19;
    else
        encode_fn = poly_encode_signed_two_to_power_17;

    if (!WPACKET_init_static_len(&pkt, out, params->sig_len, 0)
            || !WPACKET_memcpy(&pkt, sig->c_tilde, sig->c_tilde_len))
        goto err;

    for (i = 0; i < sig->z.num_poly; ++i)
        if (!encode_fn(sig->z.poly + i, &pkt))
            goto err;
    if (!hint_bits_encode(&sig->hint, &pkt, params->omega))
        goto err;
    ret = 1;
err:
    WPACKET_finish(&pkt);
    return ret;
}

/*
 * @param sig is a initialized signature object to decode into.
 * @param in An encoded signature
 * @param in_len The size of |in|
 * @param params contains constants for an ML-DSA algorithm (such as gamma1)
 * @returns 1 if the signature was successfully decoded or 0 otherwise.
 */
int ossl_ml_dsa_sig_decode(ML_DSA_SIG *sig, const uint8_t *in, size_t in_len,
                           const ML_DSA_PARAMS *params)
{
    int ret = 0;
    size_t i;
    DECODE_FN *decode_fn;
    PACKET pkt;

    if (params->gamma1 == ML_DSA_GAMMA1_TWO_POWER_19)
        decode_fn = poly_decode_signed_two_to_power_19;
    else
        decode_fn = poly_decode_signed_two_to_power_17;

    if (!PACKET_buf_init(&pkt, in, in_len)
            || !PACKET_copy_bytes(&pkt, sig->c_tilde, sig->c_tilde_len))
        goto err;
    for (i = 0; i < sig->z.num_poly; ++i)
        if (!decode_fn(sig->z.poly + i, &pkt))
            goto err;

    if (!hint_bits_decode(&sig->hint, &pkt, params->omega)
            || PACKET_remaining(&pkt) != 0)
        goto err;
    ret = 1;
err:
    return ret;
}

int ossl_ml_dsa_poly_decode_expand_mask(POLY *out,
                                        const uint8_t *in, size_t in_len,
                                        uint32_t gamma1)
{
    PACKET pkt;

    if (!PACKET_buf_init(&pkt, in, in_len))
        return 0;
    if (gamma1 == ML_DSA_GAMMA1_TWO_POWER_19)
        return poly_decode_signed_two_to_power_19(out, &pkt);
    else
        return poly_decode_signed_two_to_power_17(out, &pkt);
}

/*
 * @brief Encode a polynomial vector as an array of bytes.
 * Where the polynomial coefficients have a range of [0..15] or [0..43]
 * depending on the value of gamma2.
 *
 * See FIPS 204, Algorithm 28, w1Encode().
 *
 * @param w1 The vector to convert to bytes
 * @param gamma2 either ML_DSA_GAMMA2_Q_MINUS1_DIV32 or ML_DSA_GAMMA2_Q_MINUS1_DIV88
 * @returns 1 if the signature was encoded successfully or 0 otherwise.
 */
int ossl_ml_dsa_w1_encode(const VECTOR *w1, uint32_t gamma2,
                          uint8_t *out, size_t out_len)
{
    WPACKET pkt;
    ENCODE_FN *encode_fn;
    int ret = 0;
    size_t i;

    if (!WPACKET_init_static_len(&pkt, out, out_len, 0))
        return 0;
    if (gamma2 == ML_DSA_GAMMA2_Q_MINUS1_DIV32)
        encode_fn = poly_encode_4_bits;
    else
        encode_fn = poly_encode_6_bits;
    for (i = 0; i < w1->num_poly; ++i)
        if (!encode_fn(w1->poly + i, &pkt))
            goto err;
    ret = 1;
err:
    WPACKET_finish(&pkt);
    return ret;
}
