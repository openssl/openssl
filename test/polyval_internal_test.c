/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Internal tests for the AES-GCM-SIV provider's POLYVAL (RFC 8452 section 3).
 *
 * POLYVAL and GHASH are the same field with opposite bit and byte conventions
 * (RFC 8452 Appendix A), and the provider reaches the GHASH kernel by byte
 * reversing every block. A wrong byte order anywhere in that path still yields
 * a self-consistent AEAD, so it can only be caught against an independent
 * definition. Two checks, run on every kernel the CPU has (the recipe re-runs
 * this program with the capability vector masked down tier by tier):
 *
 *  1. the worked examples of RFC 8452 Appendix A (with Errata ID 5854 applied),
 *     known answers with no GHASH in them;
 *  2. a bit-serial reference POLYVAL written straight from the definition
 *     (dot(a, b) = a * b * x^-128 mod x^128 + x^127 + x^126 + x^121 + 1, least
 *     significant bit of byte 0 = coefficient of x^0), checked first against
 *     the same example and then against ossl_polyval_ghash_hash() at every
 *     length across the kernel boundaries (16-byte generic blocks, 4-block and
 *     16-block native groups, 4 KiB reversal runs, and split calls).
 */

#include <string.h>
#include "crypto/modes.h"
#include "testutil.h"

/* the provider's entry points (providers/implementations/ciphers/cipher_aes_gcm_siv.h) */
void ossl_polyval_ghash_init(u128 Htable[16], const uint64_t H[2]);
void ossl_polyval_ghash_hash(const u128 Htable[16], uint8_t *tag, const uint8_t *inp,
    size_t len, uint8_t *scratch, size_t scratch_len, const uint8_t *H);

/* ---- a bit-serial reference, from the definition ---- */

static void load_le128(uint64_t w[2], const uint8_t b[16])
{
    int i;

    w[0] = w[1] = 0;
    for (i = 0; i < 8; i++) {
        w[0] |= (uint64_t)b[i] << (8 * i);
        w[1] |= (uint64_t)b[8 + i] << (8 * i);
    }
}

static void store_le128(uint8_t b[16], const uint64_t w[2])
{
    int i;

    for (i = 0; i < 8; i++) {
        b[i] = (uint8_t)(w[0] >> (8 * i));
        b[8 + i] = (uint8_t)(w[1] >> (8 * i));
    }
}

/* r = a * b * x^-128 mod P, as four 64-bit words during the product */
static void ref_dot(uint8_t r[16], const uint8_t a[16], const uint8_t b[16])
{
    uint64_t aw[2], bw[2], z[4] = { 0, 0, 0, 0 };
    /* P = x^128 + x^127 + x^126 + x^121 + 1 as a 256-bit polynomial */
    const uint64_t p[4] = { 1, (1ULL << 57) | (1ULL << 62) | (1ULL << 63), 1, 0 };
    int i, k;

    load_le128(aw, a);
    load_le128(bw, b);
    /* carry-less product: z = a * b, bit i of a adds b << i */
    for (i = 0; i < 128; i++) {
        if ((aw[i >> 6] >> (i & 63)) & 1) {
            uint64_t s[4] = { 0, 0, 0, 0 };
            int wi = i >> 6, bi = i & 63;

            for (k = 0; k < 2; k++) {
                s[k + wi] ^= bw[k] << bi;
                if (bi != 0)
                    s[k + wi + 1] ^= bw[k] >> (64 - bi);
            }
            for (k = 0; k < 4; k++)
                z[k] ^= s[k];
        }
    }
    /* multiply by x^-128 mod P: 128 exact divisions by x (Montgomery REDC) */
    for (i = 0; i < 128; i++) {
        if (z[0] & 1)
            for (k = 0; k < 4; k++)
                z[k] ^= p[k];
        z[0] = (z[0] >> 1) | (z[1] << 63);
        z[1] = (z[1] >> 1) | (z[2] << 63);
        z[2] = (z[2] >> 1) | (z[3] << 63);
        z[3] >>= 1;
    }
    store_le128(r, z);
}

/* S = POLYVAL(H, X_1 .. X_n) over len bytes (a multiple of 16), continuing from S */
static void ref_polyval(uint8_t s[16], const uint8_t h[16], const uint8_t *x, size_t len)
{
    uint8_t t[16];
    size_t i, j;

    for (i = 0; i < len; i += 16) {
        for (j = 0; j < 16; j++)
            t[j] = s[j] ^ x[i + j];
        ref_dot(s, t, h);
    }
}

/*
 * mulX_POLYVAL (RFC 8452 Appendix A): multiply by x in POLYVAL's convention.
 * x^128 = x^127 + x^126 + x^121 + 1, so the carry folds into bits 127, 126, 121
 * and 0.
 */
static void ref_mulx_polyval(uint8_t r[16], const uint8_t a[16])
{
    uint64_t w[2], carry;

    load_le128(w, a);
    carry = w[1] >> 63;
    w[1] = (w[1] << 1) | (w[0] >> 63);
    w[0] <<= 1;
    if (carry) {
        w[0] ^= 1;
        w[1] ^= (1ULL << 57) | (1ULL << 62) | (1ULL << 63);
    }
    store_le128(r, w);
}

/* ---- the provider under test, driven the way the provider drives it ---- */

static int provider_polyval(uint8_t s[16], const uint8_t h[16], const uint8_t *x, size_t len,
    int with_scratch, int with_native)
{
    u128 Htable[16];
    uint8_t scratch[4096];

    ossl_polyval_ghash_init(Htable, (const uint64_t *)h);
    ossl_polyval_ghash_hash(Htable, s, x, len, with_scratch ? scratch : NULL,
        with_scratch ? sizeof(scratch) : 0, with_native ? h : NULL);
    return 1;
}

static const uint8_t rfc_h[16] = {
    0x25, 0x62, 0x93, 0x47, 0x58, 0x92, 0x42, 0x76, 0x1d, 0x31, 0xf8, 0x26, 0xba, 0x4b, 0x75, 0x7b
};
static const uint8_t rfc_x[32] = {
    0x4f, 0x4f, 0x95, 0x66, 0x8c, 0x83, 0xdf, 0xb6, 0x40, 0x17, 0x62, 0xbb, 0x2d, 0x01, 0xa2, 0x62,
    0xd1, 0xa2, 0x4d, 0xdd, 0x27, 0x21, 0xd0, 0x06, 0xbb, 0xe4, 0x5f, 0x20, 0xd3, 0xc9, 0xf3, 0x62
};
static const uint8_t rfc_polyval[16] = {
    0xf7, 0xa3, 0xb4, 0x7b, 0x84, 0x61, 0x19, 0xfa, 0xe5, 0xb7, 0x86, 0x6c, 0xf5, 0xe5, 0xb7, 0x7e
};

static int test_rfc8452_appendix_a(void)
{
    uint8_t s[16], r[16];
    static const uint8_t one[16] = { 0x01 };
    static const uint8_t mulx_one[16] = { 0x02 };
    static const uint8_t v[16] = {
        0x9c, 0x98, 0xc0, 0x4d, 0xf9, 0x38, 0x7d, 0xed, 0x82, 0x81, 0x75, 0xa9, 0x2b, 0xa6, 0x52, 0xd8
    };
    /*
     * RFC 8452 prints this as ...a5f2; Errata ID 5854 (verified) corrects the
     * last byte to 0x72, which is what the polynomial gives.
     */
    static const uint8_t mulx_v[16] = {
        0x39, 0x31, 0x81, 0x9b, 0xf2, 0x71, 0xfa, 0xda, 0x05, 0x03, 0xeb, 0x52, 0x57, 0x4c, 0xa5, 0x72
    };
    int m;

    /* the reference agrees with the RFC (as corrected) before it is used as a reference */
    ref_mulx_polyval(r, one);
    if (!TEST_mem_eq(r, 16, mulx_one, 16))
        return 0;
    ref_mulx_polyval(r, v);
    if (!TEST_mem_eq(r, 16, mulx_v, 16))
        return 0;
    memset(s, 0, 16);
    ref_polyval(s, rfc_h, rfc_x, 32);
    if (!TEST_mem_eq(s, 16, rfc_polyval, 16))
        return 0;
    /* the provider, with and without a scratch buffer / native kernels */
    for (m = 0; m < 4; m++) {
        memset(s, 0, 16);
        provider_polyval(s, rfc_h, rfc_x, 32, m & 1, (m & 2) != 0);
        if (!TEST_mem_eq(s, 16, rfc_polyval, 16)) {
            TEST_info("mode scratch=%d native=%d", m & 1, (m & 2) != 0);
            return 0;
        }
    }
    return 1;
}

static int test_polyval_vs_reference(void)
{
    static const size_t lens[] = {
        16, 32, 48, 64, 80, 128, 240, 256, 272, 512, 1024, 4096, 4096 + 16, 8192 + 48
    };
    uint8_t h[16], *x, s_ref[16], s_prov[16], s_split[16];
    uint32_t seed = 0x9e3779b9u;
    size_t i, n, cut;
    int ok = 0, m;

    if (!TEST_ptr(x = OPENSSL_malloc(8192 + 48)))
        return 0;
    for (i = 0; i < 16; i++)
        h[i] = (uint8_t)(seed = seed * 1103515245u + 12345u);
    for (i = 0; i < 8192 + 48; i++)
        x[i] = (uint8_t)((seed = seed * 1103515245u + 12345u) >> 16);

    for (n = 0; n < OSSL_NELEM(lens); n++) {
        memset(s_ref, 0, 16);
        ref_polyval(s_ref, h, x, lens[n]);
        for (m = 0; m < 4; m++) {
            memset(s_prov, 0, 16);
            provider_polyval(s_prov, h, x, lens[n], m & 1, (m & 2) != 0);
            if (!TEST_mem_eq(s_prov, 16, s_ref, 16)) {
                TEST_info("len %zu scratch=%d native=%d", lens[n], m & 1, (m & 2) != 0);
                goto err;
            }
        }
        /* two calls continuing the same accumulator == one call */
        for (cut = 16; cut < lens[n]; cut += (lens[n] > 512 ? 240 : 16)) {
            memset(s_split, 0, 16);
            provider_polyval(s_split, h, x, cut, 1, 1);
            provider_polyval(s_split, h, x + cut, lens[n] - cut, 1, 1);
            if (!TEST_mem_eq(s_split, 16, s_ref, 16)) {
                TEST_info("len %zu split at %zu", lens[n], cut);
                goto err;
            }
        }
    }
    ok = 1;
err:
    OPENSSL_free(x);
    return ok;
}

int setup_tests(void)
{
    ADD_TEST(test_rfc8452_appendix_a);
    ADD_TEST(test_polyval_vs_reference);
    return 1;
}
