/*
 * Copyright 2020-2025 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2020-2021, Intel Corporation. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 *
 * Originally written by Sergey Kirillov and Andrey Matyukov.
 * Special thanks to Ilya Albrekht for his valuable hints.
 * Intel Corporation
 *
 */

#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include "rsaz_exp.h"

#ifndef RSAZ_ENABLED
NON_EMPTY_TRANSLATION_UNIT
#else
#include <assert.h>
#include <string.h>

#define ALIGN_OF(ptr, boundary) \
    ((unsigned char *)(ptr) + (boundary - (((size_t)(ptr)) & (boundary - 1))))

/*
 * Square-and-multiply while BN_num_bits(exp) <= 80. Wider exponents use a
 * 5-bit window. Generic BN_mod_exp_mont already uses window 4 for exponents
 * longer than 79 bits (BN_window_bits_for_exponent_size).
 */
#define RSAZ_MOD_EXP_X1_SQM_MAX_BITS 80

/* Internal radix */
#define DIGIT_SIZE (52)
/* 52-bit mask */
#define DIGIT_MASK ((uint64_t)0xFFFFFFFFFFFFF)

#define BITS2WORD8_SIZE(x) (((x) + 7) >> 3)
#define BITS2WORD64_SIZE(x) (((x) + 63) >> 6)

/* Number of registers required to hold |digits_num| amount of qword digits */
#define NUMBER_OF_REGISTERS(digits_num, register_size) \
    (((digits_num) * 64 + (register_size) - 1) / (register_size))

static ossl_inline uint64_t get_digit(const uint8_t *in, int in_len);
static ossl_inline void put_digit(uint8_t *out, int out_len, uint64_t digit);
static void to_words52(BN_ULONG *out, int out_len, const BN_ULONG *in,
    int in_bitsize);
static void from_words52(BN_ULONG *bn_out, int out_bitsize, const BN_ULONG *in);
static ossl_inline void set_bit(BN_ULONG *a, int idx);

/* Number of |digit_size|-bit digits in |bitsize|-bit value */
static ossl_inline int number_of_digits(int bitsize, int digit_size)
{
    return (bitsize + digit_size - 1) / digit_size;
}

/*
 * For details of the methods declared below please refer to
 *    crypto/bn/asm/rsaz-avx512.pl
 *
 * Naming conventions:
 *  amm = Almost Montgomery Multiplication
 *  ams = Almost Montgomery Squaring
 *  52xZZ - data represented as array of ZZ digits in 52-bit radix
 *  _x1_/_x2_ - 1 or 2 independent inputs/outputs
 *  _ifma256 - uses 256-bit wide IFMA ISA (AVX512_IFMA256)
 *  _avxifma256 - uses 256-bit wide AVXIFMA ISA (AVX_IFMA256)
 */

void ossl_rsaz_amm52x20_x1_ifma256(BN_ULONG *res, const BN_ULONG *a,
    const BN_ULONG *b, const BN_ULONG *m,
    BN_ULONG k0);
void ossl_rsaz_amm52x20_x2_ifma256(BN_ULONG *out, const BN_ULONG *a,
    const BN_ULONG *b, const BN_ULONG *m,
    const BN_ULONG k0[2]);
void ossl_extract_multiplier_2x20_win5(BN_ULONG *red_Y,
    const BN_ULONG *red_table,
    int red_table_idx1, int red_table_idx2);

void ossl_rsaz_amm52x30_x1_ifma256(BN_ULONG *res, const BN_ULONG *a,
    const BN_ULONG *b, const BN_ULONG *m,
    BN_ULONG k0);
void ossl_rsaz_amm52x30_x2_ifma256(BN_ULONG *out, const BN_ULONG *a,
    const BN_ULONG *b, const BN_ULONG *m,
    const BN_ULONG k0[2]);
void ossl_extract_multiplier_2x30_win5(BN_ULONG *red_Y,
    const BN_ULONG *red_table,
    int red_table_idx1, int red_table_idx2);

void ossl_rsaz_amm52x40_x1_ifma256(BN_ULONG *res, const BN_ULONG *a,
    const BN_ULONG *b, const BN_ULONG *m,
    BN_ULONG k0);
void ossl_rsaz_amm52x40_x2_ifma256(BN_ULONG *out, const BN_ULONG *a,
    const BN_ULONG *b, const BN_ULONG *m,
    const BN_ULONG k0[2]);
void ossl_extract_multiplier_2x40_win5(BN_ULONG *red_Y,
    const BN_ULONG *red_table,
    int red_table_idx1, int red_table_idx2);

void ossl_rsaz_amm52x20_x1_avxifma256(BN_ULONG *res, const BN_ULONG *a,
    const BN_ULONG *b, const BN_ULONG *m,
    BN_ULONG k0);
void ossl_rsaz_amm52x20_x2_avxifma256(BN_ULONG *out, const BN_ULONG *a,
    const BN_ULONG *b, const BN_ULONG *m,
    const BN_ULONG k0[2]);
void ossl_extract_multiplier_2x20_win5_avx(BN_ULONG *red_Y,
    const BN_ULONG *red_table,
    int red_table_idx1,
    int red_table_idx2);

void ossl_rsaz_amm52x30_x1_avxifma256(BN_ULONG *res, const BN_ULONG *a,
    const BN_ULONG *b, const BN_ULONG *m,
    BN_ULONG k0);
void ossl_rsaz_amm52x30_x2_avxifma256(BN_ULONG *out, const BN_ULONG *a,
    const BN_ULONG *b, const BN_ULONG *m,
    const BN_ULONG k0[2]);
void ossl_extract_multiplier_2x30_win5_avx(BN_ULONG *red_Y,
    const BN_ULONG *red_table,
    int red_table_idx1,
    int red_table_idx2);

void ossl_rsaz_amm52x40_x1_avxifma256(BN_ULONG *res, const BN_ULONG *a,
    const BN_ULONG *b, const BN_ULONG *m,
    BN_ULONG k0);
void ossl_rsaz_amm52x40_x2_avxifma256(BN_ULONG *out, const BN_ULONG *a,
    const BN_ULONG *b, const BN_ULONG *m,
    const BN_ULONG k0[2]);
void ossl_extract_multiplier_2x40_win5_avx(BN_ULONG *red_Y,
    const BN_ULONG *red_table,
    int red_table_idx1,
    int red_table_idx2);

typedef void (*AMM)(BN_ULONG *res, const BN_ULONG *a, const BN_ULONG *b,
    const BN_ULONG *m, BN_ULONG k0);

static AMM ossl_rsaz_amm52_x1[] = {
    ossl_rsaz_amm52x20_x1_avxifma256,
    ossl_rsaz_amm52x20_x1_ifma256,
    ossl_rsaz_amm52x30_x1_avxifma256,
    ossl_rsaz_amm52x30_x1_ifma256,
    ossl_rsaz_amm52x40_x1_avxifma256,
    ossl_rsaz_amm52x40_x1_ifma256,
};

typedef void (*DAMM)(BN_ULONG *res, const BN_ULONG *a, const BN_ULONG *b,
    const BN_ULONG *m, const BN_ULONG k0[2]);

static DAMM ossl_rsaz_amm52_x2[] = {
    ossl_rsaz_amm52x20_x2_avxifma256,
    ossl_rsaz_amm52x20_x2_ifma256,
    ossl_rsaz_amm52x30_x2_avxifma256,
    ossl_rsaz_amm52x30_x2_ifma256,
    ossl_rsaz_amm52x40_x2_avxifma256,
    ossl_rsaz_amm52x40_x2_ifma256,
};

typedef void (*DEXTRACT)(BN_ULONG *res, const BN_ULONG *red_table,
    int red_table_idx, int tbl_idx);

static const DEXTRACT ossl_extract_multiplier_win5[] = {
    ossl_extract_multiplier_2x20_win5_avx,
    ossl_extract_multiplier_2x20_win5,
    ossl_extract_multiplier_2x30_win5_avx,
    ossl_extract_multiplier_2x30_win5,
    ossl_extract_multiplier_2x40_win5_avx,
    ossl_extract_multiplier_2x40_win5,
};

static int RSAZ_mod_exp_x2_ifma256(BN_ULONG *res, const BN_ULONG *base,
    const BN_ULONG *exp[2], const BN_ULONG *m,
    const BN_ULONG *rr, const BN_ULONG k0[2],
    int modulus_bitsize);
static int RSAZ_mod_exp_x1_ifma256(BN_ULONG *out, const BN_ULONG *base,
    const BN_ULONG *exp, const BN_ULONG *m, const BN_ULONG *rr,
    BN_ULONG k0, int modulus_bitsize, int exp_bits);

/*
 * Dual Montgomery modular exponentiation using prime moduli of the
 * same bit size, optimized with AVX512 ISA or AVXIFMA ISA.
 *
 * Input and output parameters for each exponentiation are independent and
 * denoted here by index |i|, i = 1..2.
 *
 * Input and output are all in regular 2^64 radix.
 *
 * Each moduli shall be |factor_size| bit size.
 *
 * Supported cases:
 *   - 2x1024
 *   - 2x1536
 *   - 2x2048
 *
 *  [out] res|i|      - result of modular exponentiation: array of qword values
 *                      in regular (2^64) radix. Size of array shall be enough
 *                      to hold |factor_size| bits.
 *  [in]  base|i|     - base
 *  [in]  exp|i|      - exponent
 *  [in]  m|i|        - moduli
 *  [in]  rr|i|       - Montgomery parameter RR = R^2 mod m|i|
 *  [in]  k0_|i|      - Montgomery parameter k0 = -1/m|i| mod 2^64
 *  [in]  factor_size - moduli bit size
 *
 * \return 0 in case of failure,
 *         1 in case of success.
 */
int ossl_rsaz_mod_exp_avx512_x2(BN_ULONG *res1,
    const BN_ULONG *base1,
    const BN_ULONG *exp1,
    const BN_ULONG *m1,
    const BN_ULONG *rr1,
    BN_ULONG k0_1,
    BN_ULONG *res2,
    const BN_ULONG *base2,
    const BN_ULONG *exp2,
    const BN_ULONG *m2,
    const BN_ULONG *rr2,
    BN_ULONG k0_2,
    int factor_size)
{
    int ret = 0;

    /*
     * Number of word-size (BN_ULONG) digits to store exponent in redundant
     * representation.
     */
    int exp_digits = number_of_digits(factor_size + 2, DIGIT_SIZE);
    int coeff_pow = 4 * (DIGIT_SIZE * exp_digits - factor_size);

    /*  Number of YMM registers required to store exponent's digits */
    int ymm_regs_num = NUMBER_OF_REGISTERS(exp_digits, 256 /* ymm bit size */);
    /* Capacity of the register set (in qwords) to store exponent */
    int regs_capacity = ymm_regs_num * 4;

    BN_ULONG *base1_red, *m1_red, *rr1_red;
    BN_ULONG *base2_red, *m2_red, *rr2_red;
    BN_ULONG *coeff_red;
    BN_ULONG *storage = NULL;
    BN_ULONG *storage_aligned = NULL;
    int storage_len_bytes = 7 * regs_capacity * sizeof(BN_ULONG)
        + 64 /* alignment */;

    const BN_ULONG *exp[2] = { 0 };
    BN_ULONG k0[2] = { 0 };
    /* AMM = Almost Montgomery Multiplication */
    AMM amm = NULL;
    int avx512ifma = !!ossl_rsaz_avx512ifma_eligible();

    if (factor_size != 1024 && factor_size != 1536 && factor_size != 2048)
        goto err;

    amm = ossl_rsaz_amm52_x1[(factor_size / 512 - 2) * 2 + avx512ifma];

    storage = (BN_ULONG *)OPENSSL_malloc(storage_len_bytes);
    if (storage == NULL)
        goto err;
    storage_aligned = (BN_ULONG *)ALIGN_OF(storage, 64);

    /* Memory layout for red(undant) representations */
    base1_red = storage_aligned;
    base2_red = storage_aligned + 1 * regs_capacity;
    m1_red = storage_aligned + 2 * regs_capacity;
    m2_red = storage_aligned + 3 * regs_capacity;
    rr1_red = storage_aligned + 4 * regs_capacity;
    rr2_red = storage_aligned + 5 * regs_capacity;
    coeff_red = storage_aligned + 6 * regs_capacity;

    /* Convert base_i, m_i, rr_i, from regular to 52-bit radix */
    to_words52(base1_red, regs_capacity, base1, factor_size);
    to_words52(base2_red, regs_capacity, base2, factor_size);
    to_words52(m1_red, regs_capacity, m1, factor_size);
    to_words52(m2_red, regs_capacity, m2, factor_size);
    to_words52(rr1_red, regs_capacity, rr1, factor_size);
    to_words52(rr2_red, regs_capacity, rr2, factor_size);

    /*
     * Compute target domain Montgomery converters RR' for each modulus
     * based on precomputed original domain's RR.
     *
     * RR -> RR' transformation steps:
     *  (1) coeff = 2^k
     *  (2) t = AMM(RR,RR) = RR^2 / R' mod m
     *  (3) RR' = AMM(t, coeff) = RR^2 * 2^k / R'^2 mod m
     * where
     *  k = 4 * (52 * digits52 - modlen)
     *  R  = 2^(64 * ceil(modlen/64)) mod m
     *  RR = R^2 mod m
     *  R' = 2^(52 * ceil(modlen/52)) mod m
     *
     *  EX/ modlen = 1024: k = 64, RR = 2^2048 mod m, RR' = 2^2080 mod m
     */
    memset(coeff_red, 0, exp_digits * sizeof(BN_ULONG));
    /* (1) in reduced domain representation */
    set_bit(coeff_red, 64 * (int)(coeff_pow / 52) + coeff_pow % 52);

    amm(rr1_red, rr1_red, rr1_red, m1_red, k0_1); /* (2) for m1 */
    amm(rr1_red, rr1_red, coeff_red, m1_red, k0_1); /* (3) for m1 */

    amm(rr2_red, rr2_red, rr2_red, m2_red, k0_2); /* (2) for m2 */
    amm(rr2_red, rr2_red, coeff_red, m2_red, k0_2); /* (3) for m2 */

    exp[0] = exp1;
    exp[1] = exp2;

    k0[0] = k0_1;
    k0[1] = k0_2;

    /* Dual (2-exps in parallel) exponentiation */
    ret = RSAZ_mod_exp_x2_ifma256(rr1_red, base1_red, exp, m1_red, rr1_red,
        k0, factor_size);
    if (!ret)
        goto err;

    /* Convert rr_i back to regular radix */
    from_words52(res1, factor_size, rr1_red);
    from_words52(res2, factor_size, rr2_red);

    /* bn_reduce_once_in_place expects number of BN_ULONG, not bit size */
    factor_size /= sizeof(BN_ULONG) * 8;

    bn_reduce_once_in_place(res1, /*carry=*/0, m1, storage, factor_size);
    bn_reduce_once_in_place(res2, /*carry=*/0, m2, storage, factor_size);

err:
    if (storage != NULL) {
        OPENSSL_cleanse(storage, storage_len_bytes);
        OPENSSL_free(storage);
    }
    return ret;
}

static void rsaz_extract_multiplier_x1(BN_ULONG *dst, const BN_ULONG *red_table,
    int red_digits, int idx)
{
    OPENSSL_assert(idx >= 0 && idx < (1 << 5));
    /*
     * Public / non-const-time callers only (see BN_mod_exp_mont hook). Window
     * index is not secret; use a direct copy instead of scanning all rows.
     */
    memcpy(dst, red_table + (size_t)idx * (size_t)red_digits,
        (size_t)red_digits * sizeof(BN_ULONG));
}

/*
 * Single {2048}-bit w-ary modular exponentiation using Almost Montgomery
 * Multiplication, optimized with AVX512_IFMA256 ISA.
 *
 * The parameter w (window size) = 5 when |exp_bits| is greater than
 * RSAZ_MOD_EXP_X1_SQM_MAX_BITS; otherwise binary square-and-multiply is used.
 *
 *  [out] out      - result of modular exponentiation: {40} qword
 *                   values in 2^52 radix.
 *  [in]  base     - base ({40} qword values in 2^52 radix)
 *  [in]  exp      - {32} qword values in 2^64 radix.
 *                   Exponent is not converted to redundant representation.
 *  [in]  m        - modulus ({40} qword values in 2^52 radix)
 *  [in]  rr       - Montgomery parameter:
 *                     RR(2048) = 2^4160 mod m.
 *                   ({40} qword values in 2^52 radix)
 *  [in]  k0       - Montgomery parameter: k0 = -1/m mod 2^64
 *  [in]  modulus_bitsize - modulus bit size (must be 2048)
 *  [in]  exp_bits  - BN_num_bits(exp); controls exponentiation loop length
 *
 * \return 0 in case of failure,
 *         1 in case of success.
 */
static int RSAZ_mod_exp_x1_ifma256(BN_ULONG *out,
    const BN_ULONG *base,
    const BN_ULONG *exp,
    const BN_ULONG *m,
    const BN_ULONG *rr,
    BN_ULONG k0,
    int modulus_bitsize,
    int exp_bits)
{
    int ret = 0;
    /* Exponent window size */
    int exp_win_size = 5;
    int exp_win_mask = (1U << exp_win_size) - 1;

    /* Number of digits (64-bit words) in redundant representation to handle
     * modulus bits
     */
    int red_digits = 0;
    int exp_digits = 0;

    BN_ULONG *storage = NULL;
    BN_ULONG *storage_aligned = NULL;
    int storage_len_bytes = 0;

    /* Redundant representation of modulus and exponent */
    BN_ULONG *red_Y = NULL;
    BN_ULONG *red_X = NULL;
    /* Precomputed table of multipliers for the exponent */
    BN_ULONG *red_table = NULL;
    /* Exponent in redundant representation */
    BN_ULONG *expz = NULL;

    /* Single-lane AMM */
    AMM amm = NULL;
    int avx512ifma = !!ossl_rsaz_avx512ifma_eligible();

#define AMS1(r, a, m, k) amm((r), (a), (a), (m), (k))

    if (modulus_bitsize != 2048)
        goto err;

    if (exp_bits < 1)
        exp_bits = 1;
    else if (exp_bits > modulus_bitsize)
        exp_bits = modulus_bitsize;

    red_digits = 40;
    exp_digits = 32;
    amm = ossl_rsaz_amm52_x1[(modulus_bitsize / 512 - 2) * 2 + avx512ifma];

    if (exp_bits <= RSAZ_MOD_EXP_X1_SQM_MAX_BITS) {
        /* red_Y, red_X, red_table[0..1], expz */
        storage_len_bytes = (red_digits + red_digits + 2 * red_digits
                                + (exp_digits + 1))
                * sizeof(BN_ULONG)
            + 64;
    } else {
        storage_len_bytes = (red_digits + red_digits
                                + red_digits * (1U << exp_win_size)
                                + (exp_digits + 1))
                * sizeof(BN_ULONG)
            + 64;
    }

    storage = (BN_ULONG *)OPENSSL_zalloc(storage_len_bytes);
    if (storage == NULL)
        goto err;
    storage_aligned = (BN_ULONG *)ALIGN_OF(storage, 64);

    red_Y = storage_aligned;
    red_X = red_Y + red_digits;
    red_table = red_X + red_digits;
    if (exp_bits <= RSAZ_MOD_EXP_X1_SQM_MAX_BITS)
        expz = red_table + 2 * red_digits;
    else
        expz = red_table + red_digits * (1U << exp_win_size);

    memset(red_X, 0, (size_t)red_digits * sizeof(BN_ULONG));
    red_X[0] = 1;
    amm(&red_table[0 * red_digits], (const BN_ULONG *)red_X, rr, m, k0);
    amm(&red_table[1 * red_digits], base, rr, m, k0);

    memcpy(expz, exp, (size_t)exp_digits * sizeof(BN_ULONG));
    expz[exp_digits] = 0;

    if (exp_bits <= RSAZ_MOD_EXP_X1_SQM_MAX_BITS) {
        int i;

        memcpy(red_Y, &red_table[0 * red_digits],
            (size_t)red_digits * sizeof(BN_ULONG));
        for (i = exp_bits - 1; i >= 0; i--) {
            const BN_ULONG limb = expz[(unsigned)i / BN_BITS2];
            const unsigned shift = (unsigned)i % BN_BITS2;

            AMS1(red_Y, red_Y, m, k0);
            if (((limb >> shift) & (BN_ULONG)1) != 0)
                amm(red_Y, (const BN_ULONG *)red_Y,
                    &red_table[1 * red_digits], m, k0);
        }
    } else {
        int idx;

        for (idx = 1; idx < (int)((1U << exp_win_size) / 2); idx++) {
            AMS1(&red_table[(2 * idx + 0) * red_digits],
                &red_table[(1 * idx) * red_digits], m, k0);
            amm(&red_table[(2 * idx + 1) * red_digits],
                &red_table[(2 * idx) * red_digits],
                &red_table[1 * red_digits], m, k0);
        }

        {
            /*
             * Round exponent bit-length up to a multiple of the window size so
             * the first 5-bit window aligns with BN_num_bits(exp); high bits
             * are zero when exp_bits < modulus_bitsize (e.g. public RSA e).
             * Same starting index as the full-width case when exp_bits ==
             * modulus_bitsize.
             */
            const int exp_eb = ((exp_bits + exp_win_size - 1) / exp_win_size)
                * exp_win_size;
            const BN_ULONG table_idx_mask = exp_win_mask;
            int exp_bit_no = exp_eb - exp_win_size;
            int exp_chunk_no = exp_bit_no / 64;
            int exp_chunk_shift = exp_bit_no % 64;

            BN_ULONG red_table_idx;

            /* Process 1-st exp window - just init result */
            {
                BN_ULONG T;

                red_table_idx = expz[exp_chunk_no];
                T = expz[exp_chunk_no + 1];
                red_table_idx >>= exp_chunk_shift;
                /*
                 * Get additional bits from the next quadword
                 * when 64-bit boundaries are crossed.
                 */
                if (exp_chunk_shift > 64 - exp_win_size) {
                    T <<= (64 - exp_chunk_shift);
                    red_table_idx ^= T;
                }
                red_table_idx &= table_idx_mask;
            }
            rsaz_extract_multiplier_x1(red_Y, red_table, red_digits,
                (int)red_table_idx);

            /* Process other exp windows */
            for (exp_bit_no -= exp_win_size; exp_bit_no >= 0;
                exp_bit_no -= exp_win_size) {
                /* Extract pre-computed multiplier from the table */
                {
                    BN_ULONG T;

                    exp_chunk_no = exp_bit_no / 64;
                    exp_chunk_shift = exp_bit_no % 64;
                    {
                        red_table_idx = expz[exp_chunk_no];
                        T = expz[exp_chunk_no + 1];

                        red_table_idx >>= exp_chunk_shift;
                        /*
                         * Get additional bits from the next quadword
                         * when 64-bit boundaries are crossed.
                         */
                        if (exp_chunk_shift > 64 - exp_win_size) {
                            T <<= (64 - exp_chunk_shift);
                            red_table_idx ^= T;
                        }
                        red_table_idx &= table_idx_mask;
                    }

                    rsaz_extract_multiplier_x1(red_X, red_table, red_digits,
                        (int)red_table_idx);
                }

                /* Series of squaring */
                AMS1(red_Y, red_Y, m, k0);
                AMS1(red_Y, red_Y, m, k0);
                AMS1(red_Y, red_Y, m, k0);
                AMS1(red_Y, red_Y, m, k0);
                AMS1(red_Y, red_Y, m, k0);
                amm(red_Y, (const BN_ULONG *)red_Y, (const BN_ULONG *)red_X, m, k0);
            }
        }
    }

    memset(red_X, 0, (size_t)red_digits * sizeof(BN_ULONG));
    red_X[0] = 1;
    amm(out, (const BN_ULONG *)red_Y, (const BN_ULONG *)red_X, m, k0);

    ret = 1;

err:
    if (storage != NULL) {
        OPENSSL_cleanse(storage, storage_len_bytes);
        OPENSSL_free(storage);
    }

#undef AMS1
    return ret;
}

/*
 * Dual {1024,1536,2048}-bit w-ary modular exponentiation using prime moduli of
 * the same bit size using Almost Montgomery Multiplication, optimized with
 * AVX512_IFMA256 ISA.
 *
 * The parameter w (window size) = 5.
 *
 *  [out] res      - result of modular exponentiation: 2x{20,30,40} qword
 *                   values in 2^52 radix.
 *  [in]  base     - base (2x{20,30,40} qword values in 2^52 radix)
 *  [in]  exp      - array of 2 pointers to {16,24,32} qword values in 2^64 radix.
 *                   Exponent is not converted to redundant representation.
 *  [in]  m        - moduli (2x{20,30,40} qword values in 2^52 radix)
 *  [in]  rr       - Montgomery parameter for 2 moduli:
 *                     RR(1024) = 2^2080 mod m.
 *                     RR(1536) = 2^3120 mod m.
 *                     RR(2048) = 2^4160 mod m.
 *                   (2x{20,30,40} qword values in 2^52 radix)
 *  [in]  k0       - Montgomery parameter for 2 moduli: k0 = -1/m mod 2^64
 *
 * \return (void).
 */
int RSAZ_mod_exp_x2_ifma256(BN_ULONG *out,
    const BN_ULONG *base,
    const BN_ULONG *exp[2],
    const BN_ULONG *m,
    const BN_ULONG *rr,
    const BN_ULONG k0[2],
    int modulus_bitsize)
{
    int ret = 0;
    int idx;

    /* Exponent window size */
    int exp_win_size = 5;
    int exp_win_mask = (1U << exp_win_size) - 1;

    /*
     * Number of digits (64-bit words) in redundant representation to handle
     * modulus bits
     */
    int red_digits = 0;
    int exp_digits = 0;

    BN_ULONG *storage = NULL;
    BN_ULONG *storage_aligned = NULL;
    int storage_len_bytes = 0;

    /* Red(undant) result Y and multiplier X */
    BN_ULONG *red_Y = NULL; /* [2][red_digits] */
    BN_ULONG *red_X = NULL; /* [2][red_digits] */
    /* Pre-computed table of base powers */
    BN_ULONG *red_table = NULL; /* [1U << exp_win_size][2][red_digits] */
    /* Expanded exponent */
    BN_ULONG *expz = NULL; /* [2][exp_digits + 1] */

    /* Dual AMM */
    DAMM damm = NULL;
    /* Extractor from red_table */
    DEXTRACT extract = NULL;
    int avx512ifma = !!ossl_rsaz_avx512ifma_eligible();

/*
 * Squaring is done using multiplication now. That can be a subject of
 * optimization in future.
 */
#define DAMS(r, a, m, k0) damm((r), (a), (a), (m), (k0))

    if (modulus_bitsize != 1024 && modulus_bitsize != 1536 && modulus_bitsize != 2048)
        goto err;

    damm = ossl_rsaz_amm52_x2[(modulus_bitsize / 512 - 2) * 2 + avx512ifma];
    extract = ossl_extract_multiplier_win5[(modulus_bitsize / 512 - 2) * 2 + avx512ifma];

    switch (modulus_bitsize) {
    case 1024:
        red_digits = 20;
        exp_digits = 16;
        break;
    case 1536:
        /* Extended with 2 digits padding to avoid mask ops in high YMM register */
        red_digits = 30 + 2;
        exp_digits = 24;
        break;
    case 2048:
        red_digits = 40;
        exp_digits = 32;
        break;
    default:
        goto err;
    }

    storage_len_bytes = (2 * red_digits /* red_Y     */
                            + 2 * red_digits /* red_X     */
                            + 2 * red_digits * (1U << exp_win_size) /* red_table */
                            + 2 * (exp_digits + 1)) /* expz      */
            * sizeof(BN_ULONG)
        + 64; /* alignment */

    storage = (BN_ULONG *)OPENSSL_zalloc(storage_len_bytes);
    if (storage == NULL)
        goto err;
    storage_aligned = (BN_ULONG *)ALIGN_OF(storage, 64);

    red_Y = storage_aligned;
    red_X = red_Y + 2 * red_digits;
    red_table = red_X + 2 * red_digits;
    expz = red_table + 2 * red_digits * (1U << exp_win_size);

    /*
     * Compute table of powers base^i, i = 0, ..., (2^EXP_WIN_SIZE) - 1
     *   table[0] = mont(x^0) = mont(1)
     *   table[1] = mont(x^1) = mont(x)
     */
    red_X[0 * red_digits] = 1;
    red_X[1 * red_digits] = 1;
    damm(&red_table[0 * 2 * red_digits], (const BN_ULONG *)red_X, rr, m, k0);
    damm(&red_table[1 * 2 * red_digits], base, rr, m, k0);

    for (idx = 1; idx < (int)((1U << exp_win_size) / 2); idx++) {
        DAMS(&red_table[(2 * idx + 0) * 2 * red_digits],
            &red_table[(1 * idx) * 2 * red_digits], m, k0);
        damm(&red_table[(2 * idx + 1) * 2 * red_digits],
            &red_table[(2 * idx) * 2 * red_digits],
            &red_table[1 * 2 * red_digits], m, k0);
    }

    /* Copy and expand exponents */
    memcpy(&expz[0 * (exp_digits + 1)], exp[0], exp_digits * sizeof(BN_ULONG));
    expz[1 * (exp_digits + 1) - 1] = 0;
    memcpy(&expz[1 * (exp_digits + 1)], exp[1], exp_digits * sizeof(BN_ULONG));
    expz[2 * (exp_digits + 1) - 1] = 0;

    /* Exponentiation */
    {
        const int rem = modulus_bitsize % exp_win_size;
        const BN_ULONG table_idx_mask = exp_win_mask;

        int exp_bit_no = modulus_bitsize - rem;
        int exp_chunk_no = exp_bit_no / 64;
        int exp_chunk_shift = exp_bit_no % 64;

        BN_ULONG red_table_idx_0, red_table_idx_1;

        /*
         * If rem == 0, then
         *      exp_bit_no = modulus_bitsize - exp_win_size
         * However, this isn't possible because rem is { 1024, 1536, 2048 } % 5
         * which is { 4, 1, 3 } respectively.
         *
         * If this assertion ever fails the fix above is easy.
         */
        OPENSSL_assert(rem != 0);

        /* Process 1-st exp window - just init result */
        red_table_idx_0 = expz[exp_chunk_no + 0 * (exp_digits + 1)];
        red_table_idx_1 = expz[exp_chunk_no + 1 * (exp_digits + 1)];

        /*
         * The function operates with fixed moduli sizes divisible by 64,
         * thus table index here is always in supported range [0, EXP_WIN_SIZE).
         */
        red_table_idx_0 >>= exp_chunk_shift;
        red_table_idx_1 >>= exp_chunk_shift;

        extract(&red_Y[0 * red_digits], (const BN_ULONG *)red_table, (int)red_table_idx_0, (int)red_table_idx_1);

        /* Process other exp windows */
        for (exp_bit_no -= exp_win_size; exp_bit_no >= 0; exp_bit_no -= exp_win_size) {
            /* Extract pre-computed multiplier from the table */
            {
                BN_ULONG T;

                exp_chunk_no = exp_bit_no / 64;
                exp_chunk_shift = exp_bit_no % 64;
                {
                    red_table_idx_0 = expz[exp_chunk_no + 0 * (exp_digits + 1)];
                    T = expz[exp_chunk_no + 1 + 0 * (exp_digits + 1)];

                    red_table_idx_0 >>= exp_chunk_shift;
                    /*
                     * Get additional bits from then next quadword
                     * when 64-bit boundaries are crossed.
                     */
                    if (exp_chunk_shift > 64 - exp_win_size) {
                        T <<= (64 - exp_chunk_shift);
                        red_table_idx_0 ^= T;
                    }
                    red_table_idx_0 &= table_idx_mask;
                }
                {
                    red_table_idx_1 = expz[exp_chunk_no + 1 * (exp_digits + 1)];
                    T = expz[exp_chunk_no + 1 + 1 * (exp_digits + 1)];

                    red_table_idx_1 >>= exp_chunk_shift;
                    /*
                     * Get additional bits from then next quadword
                     * when 64-bit boundaries are crossed.
                     */
                    if (exp_chunk_shift > 64 - exp_win_size) {
                        T <<= (64 - exp_chunk_shift);
                        red_table_idx_1 ^= T;
                    }
                    red_table_idx_1 &= table_idx_mask;
                }

                extract(&red_X[0 * red_digits], (const BN_ULONG *)red_table, (int)red_table_idx_0, (int)red_table_idx_1);
            }

            /* Series of squaring */
            DAMS((BN_ULONG *)red_Y, (const BN_ULONG *)red_Y, m, k0);
            DAMS((BN_ULONG *)red_Y, (const BN_ULONG *)red_Y, m, k0);
            DAMS((BN_ULONG *)red_Y, (const BN_ULONG *)red_Y, m, k0);
            DAMS((BN_ULONG *)red_Y, (const BN_ULONG *)red_Y, m, k0);
            DAMS((BN_ULONG *)red_Y, (const BN_ULONG *)red_Y, m, k0);

            damm((BN_ULONG *)red_Y, (const BN_ULONG *)red_Y, (const BN_ULONG *)red_X, m, k0);
        }
    }

    /*
     *
     * NB: After the last AMM of exponentiation in Montgomery domain, the result
     * may be (modulus_bitsize + 1), but the conversion out of Montgomery domain
     * performs an AMM(x,1) which guarantees that the final result is less than
     * |m|, so no conditional subtraction is needed here. See [1] for details.
     *
     * [1] Gueron, S. Efficient software implementations of modular exponentiation.
     *     DOI: 10.1007/s13389-012-0031-5
     */

    /* Convert result back in regular 2^52 domain */
    memset(red_X, 0, 2 * red_digits * sizeof(BN_ULONG));
    red_X[0 * red_digits] = 1;
    red_X[1 * red_digits] = 1;
    damm(out, (const BN_ULONG *)red_Y, (const BN_ULONG *)red_X, m, k0);

    ret = 1;

err:
    if (storage != NULL) {
        /* Clear whole storage */
        OPENSSL_cleanse(storage, storage_len_bytes);
        OPENSSL_free(storage);
    }

#undef DAMS
    return ret;
}

/*
 * Single Montgomery modular exponentiation, optimized with AVX512 ISA or
 * AVXIFMA ISA.
 *
 * Input and output are all in regular 2^64 radix.
 *
 * Modulus shall be |factor_size| bit size.
 *
 * Supported case:
 *   - 2048
 *
 *  [out] res       - result of modular exponentiation: array of qword values
 *                    in regular (2^64) radix. Size of array shall be enough
 *                    to hold |factor_size| bits.
 *  [in]  base      - base
 *  [in]  exp       - exponent
 *  [in]  m         - modulus
 *  [in]  rr        - Montgomery parameter RR = R^2 mod m
 *  [in]  k0        - Montgomery parameter k0 = -1/m mod 2^64
 *  [in]  factor_size - modulus bit size
 *  [in]  exp_bits  - BN_num_bits(exp); controls exponentiation loop length
 *
 * \return 0 in case of failure,
 *         1 in case of success.
 */
int ossl_rsaz_mod_exp_avx512_x1(BN_ULONG *res,
    const BN_ULONG *base,
    const BN_ULONG *exp,
    const BN_ULONG *m,
    const BN_ULONG *rr,
    BN_ULONG k0,
    int factor_size,
    int exp_bits)
{
    int ret = 0;

    /*
     * Exponent limb count, Montgomery bump exponent, and YMM scratch capacity
     * for radix-52 temporaries (filled per supported |factor_size|).
     */
    int exp_digits = number_of_digits(factor_size + 2, DIGIT_SIZE);
    int coeff_pow = 4 * (DIGIT_SIZE * exp_digits - factor_size);

    /* Number of YMM registers required to store exponent's digits */
    int ymm_regs_num = NUMBER_OF_REGISTERS(exp_digits, 256);
    /* Capacity of the register set (in qwords) to store exponent */
    int regs_capacity = ymm_regs_num * 4;

    /* Scratch layout: base_red, m_red, rr_red, coeff_red (reused as RR'). */
    BN_ULONG *base_red, *m_red, *rr_red;
    BN_ULONG *coeff_red;
    BN_ULONG *storage = NULL;
    BN_ULONG *storage_aligned = NULL;
    int storage_len_bytes = 4 * regs_capacity * (int)sizeof(BN_ULONG)
        + 64; /* alignment */

    /* Single-lane AMM */
    AMM amm = NULL;
    int avx512ifma = !!ossl_rsaz_avx512ifma_eligible();

    if (factor_size != 2048)
        goto err;

    amm = ossl_rsaz_amm52_x1[(factor_size / 512 - 2) * 2 + avx512ifma];

    storage = (BN_ULONG *)OPENSSL_zalloc((size_t)storage_len_bytes);
    if (storage == NULL)
        goto err;
    storage_aligned = (BN_ULONG *)ALIGN_OF(storage, 64);

    base_red = storage_aligned;
    m_red = base_red + regs_capacity;
    rr_red = m_red + regs_capacity;
    coeff_red = rr_red + regs_capacity;

    to_words52(base_red, regs_capacity, base, factor_size);
    to_words52(m_red, regs_capacity, m, factor_size);
    to_words52(rr_red, regs_capacity, rr, factor_size);

    memset(coeff_red, 0, (size_t)exp_digits * sizeof(BN_ULONG));
    set_bit(coeff_red, 64 * (int)(coeff_pow / 52) + coeff_pow % 52);

    amm(rr_red, rr_red, rr_red, m_red, k0);
    amm(rr_red, rr_red, coeff_red, m_red, k0);
    memcpy(coeff_red, rr_red, (size_t)regs_capacity * sizeof(BN_ULONG));

    /* Exponentiation */
    ret = RSAZ_mod_exp_x1_ifma256(rr_red, base_red, exp, m_red,
        coeff_red, k0, factor_size, exp_bits);
    if (!ret)
        goto err;

    /* Convert result back in regular 2^64 domain */
    from_words52(res, factor_size, rr_red);

    factor_size /= (int)(sizeof(BN_ULONG) * 8);
    bn_reduce_once_in_place(res, /*carry=*/0, m, storage, factor_size);

    ret = 1;

err:
    if (storage != NULL) {
        /* Clear whole storage */
        OPENSSL_cleanse(storage, storage_len_bytes);
        OPENSSL_free(storage);
    }
    return ret;
}

static ossl_inline uint64_t get_digit(const uint8_t *in, int in_len)
{
    uint64_t digit = 0;

    assert(in != NULL);
    assert(in_len <= 8);

    for (; in_len > 0; in_len--) {
        digit <<= 8;
        digit += (uint64_t)(in[in_len - 1]);
    }
    return digit;
}

/*
 * Convert array of words in regular (base=2^64) representation to array of
 * words in redundant (base=2^52) one.
 */
static void to_words52(BN_ULONG *out, int out_len,
    const BN_ULONG *in, int in_bitsize)
{
    uint8_t *in_str = NULL;

    assert(out != NULL);
    assert(in != NULL);
    /* Check destination buffer capacity */
    assert(out_len >= number_of_digits(in_bitsize, DIGIT_SIZE));

    in_str = (uint8_t *)in;

    for (; in_bitsize >= (2 * DIGIT_SIZE); in_bitsize -= (2 * DIGIT_SIZE), out += 2) {
        uint64_t digit;

        memcpy(&digit, in_str, sizeof(digit));
        out[0] = digit & DIGIT_MASK;
        in_str += 6;
        memcpy(&digit, in_str, sizeof(digit));
        out[1] = (digit >> 4) & DIGIT_MASK;
        in_str += 7;
        out_len -= 2;
    }

    if (in_bitsize > DIGIT_SIZE) {
        uint64_t digit = get_digit(in_str, 7);

        out[0] = digit & DIGIT_MASK;
        in_str += 6;
        in_bitsize -= DIGIT_SIZE;
        digit = get_digit(in_str, BITS2WORD8_SIZE(in_bitsize));
        out[1] = digit >> 4;
        out += 2;
        out_len -= 2;
    } else if (in_bitsize > 0) {
        out[0] = get_digit(in_str, BITS2WORD8_SIZE(in_bitsize));
        out++;
        out_len--;
    }

    memset(out, 0, out_len * sizeof(BN_ULONG));
}

static ossl_inline void put_digit(uint8_t *out, int out_len, uint64_t digit)
{
    assert(out != NULL);
    assert(out_len <= 8);

    for (; out_len > 0; out_len--) {
        *out++ = (uint8_t)(digit & 0xFF);
        digit >>= 8;
    }
}

/*
 * Convert array of words in redundant (base=2^52) representation to array of
 * words in regular (base=2^64) one.
 */
static void from_words52(BN_ULONG *out, int out_bitsize, const BN_ULONG *in)
{
    int i;
    int out_len = BITS2WORD64_SIZE(out_bitsize);

    assert(out != NULL);
    assert(in != NULL);

    for (i = 0; i < out_len; i++)
        out[i] = 0;

    {
        uint8_t *out_str = (uint8_t *)out;

        for (; out_bitsize >= (2 * DIGIT_SIZE);
            out_bitsize -= (2 * DIGIT_SIZE), in += 2) {
            uint64_t digit;

            digit = in[0];
            memcpy(out_str, &digit, sizeof(digit));
            out_str += 6;
            digit = digit >> 48 | in[1] << 4;
            memcpy(out_str, &digit, sizeof(digit));
            out_str += 7;
        }

        if (out_bitsize > DIGIT_SIZE) {
            put_digit(out_str, 7, in[0]);
            out_str += 6;
            out_bitsize -= DIGIT_SIZE;
            put_digit(out_str, BITS2WORD8_SIZE(out_bitsize),
                (in[1] << 4 | in[0] >> 48));
        } else if (out_bitsize) {
            put_digit(out_str, BITS2WORD8_SIZE(out_bitsize), in[0]);
        }
    }
}

/*
 * Set bit at index |idx| in the words array |a|.
 * It does not do any boundaries checks, make sure the index is valid before
 * calling the function.
 */
static ossl_inline void set_bit(BN_ULONG *a, int idx)
{
    assert(a != NULL);

    {
        int i, j;

        i = idx / BN_BITS2;
        j = idx % BN_BITS2;
        a[i] |= (((BN_ULONG)1) << j);
    }
}

#endif
