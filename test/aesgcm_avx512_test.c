/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Correctness test for AES-GCM across the internal block-loop dispatch
 * boundaries.
 *
 * The AVX-512/VAES implementation (crypto/modes/asm/aes-gcm-avx512.pl) selects
 * different 4/8/16/32-block code paths by message length. A decrypt/verify
 * roundtrip cannot detect a bug in those paths because encrypt and decrypt
 * share the same GHASH, so a wrong tag is computed identically on both sides
 * and still "verifies".
 *
 * To get an independent oracle this test takes the ciphertext produced by EVP
 * (AES-CTR keystream is unaffected by GHASH bugs) and recomputes the expected
 * GCM tag here with a small, portable GF(2^128) GHASH implemented straight
 * from SP 800-38D. The recomputed tag is compared with the tag EVP returned.
 *
 * The chosen lengths straddle the 4->8 (128 B), 8->16 (704 B) and 16->32
 * (1792 B) crossovers and include the 512-byte residues that can accidentally
 * pass, so the test exercises every dispatch path and its drain.
 */

#include <openssl/evp.h>
#include <string.h>
#include "testutil.h"

#define GCM_BLOCK 16

static const int keybits[] = { 128, 192, 256 };

/*
 * Message lengths: 0 and 1, the 4->8 (128 B), 8->16 (704 B) and 16->32
 * (1792 B) crossovers with +-1 neighbours, the 512-byte residues that can
 * accidentally pass, and several larger sizes that force multiple 32-block
 * big-loop iterations plus assorted drain tails.
 */
static const size_t lengths[] = {
    0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 191, 192, 240, 256,
    703, 704, 705, 1791, 1792, 1793, 1800, 1808, 2047, 2048, 2064, 2288,
    2304, 2400, 2560, 2576, 3000, 3584, 4096, 4111, 5000, 6000, 8192, 12000
};

/*
 * IV lengths: 12 is the 96-bit fast path (J0 = IV || 1); the others force the
 * GHASH-based J0 derivation, which runs CALC_AAD_HASH over the IV.
 */
static const size_t ivlens[] = { 1, 12, 13, 16, 60 };

/*
 * AAD lengths: 0, sub-block, block-aligned, and around the 16-block (256 B)
 * boundary of CALC_AAD_HASH's small/large paths.
 */
static const size_t aadlens[] = { 0, 13, 16, 20, 240, 255, 256, 257 };

#define MAX_IVLEN 60
#define MAX_AADLEN 257

#define NUM_KEYS (int)(sizeof(keybits) / sizeof(keybits[0]))
#define NUM_LENS (int)(sizeof(lengths) / sizeof(lengths[0]))
#define NUM_IVS (int)(sizeof(ivlens) / sizeof(ivlens[0]))
#define NUM_AADS (int)(sizeof(aadlens) / sizeof(aadlens[0]))

static const EVP_CIPHER *gcm_cipher(int bits)
{
    switch (bits) {
    case 128:
        return EVP_aes_128_gcm();
    case 192:
        return EVP_aes_192_gcm();
    case 256:
        return EVP_aes_256_gcm();
    }
    return NULL;
}

static const EVP_CIPHER *ecb_cipher(int bits)
{
    switch (bits) {
    case 128:
        return EVP_aes_128_ecb();
    case 192:
        return EVP_aes_192_ecb();
    case 256:
        return EVP_aes_256_ecb();
    }
    return NULL;
}

/* One AES block encryption (ECB, no padding) used to derive H and E(J0). */
static int aes_ecb_block(int bits, const unsigned char *key,
    const unsigned char *in, unsigned char *out)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int outl = 0, ok = 0;

    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new()))
        return 0;
    ok = TEST_true(EVP_EncryptInit_ex(ctx, ecb_cipher(bits), NULL, key, NULL))
        && TEST_true(EVP_CIPHER_CTX_set_padding(ctx, 0))
        && TEST_true(EVP_EncryptUpdate(ctx, out, &outl, in, GCM_BLOCK))
        && TEST_int_eq(outl, GCM_BLOCK);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* Z = X * Y in GF(2^128), GCM bit ordering (SP 800-38D). */
static void gf_mul(const unsigned char *X, const unsigned char *Y,
    unsigned char *Z)
{
    unsigned char V[GCM_BLOCK];
    unsigned char R[GCM_BLOCK];
    int i, j;

    memset(R, 0, sizeof(R));
    memcpy(V, Y, GCM_BLOCK);
    memset(Z, 0, GCM_BLOCK);

    for (i = 0; i < 128; i++) {
        /* bit i of X, most-significant bit first */
        if ((X[i >> 3] >> (7 - (i & 7))) & 1)
            for (j = 0; j < GCM_BLOCK; j++)
                Z[j] ^= V[j];

        /* V >>= 1 over the big-endian 128-bit value */
        {
            unsigned char lsb = (unsigned char)(V[GCM_BLOCK - 1] & 1);
            for (j = GCM_BLOCK - 1; j > 0; j--)
                V[j] = (unsigned char)((V[j] >> 1) | ((V[j - 1] & 1) << 7));
            V[0] >>= 1;
            if (lsb)
                V[0] ^= 0xe1; /* R = 0xe1 || 0^120 */
        }
    }
    (void)R;
}

static void ghash_blocks(unsigned char *state, const unsigned char *H,
    const unsigned char *data, size_t len)
{
    unsigned char blk[GCM_BLOCK], tmp[GCM_BLOCK];
    size_t off = 0;
    int j;

    while (off < len) {
        size_t n = len - off < GCM_BLOCK ? len - off : GCM_BLOCK;

        memset(blk, 0, GCM_BLOCK);
        memcpy(blk, data + off, n);
        for (j = 0; j < GCM_BLOCK; j++)
            state[j] ^= blk[j];
        gf_mul(state, H, tmp);
        memcpy(state, tmp, GCM_BLOCK);
        off += n;
    }
}

/* Independent GCM tag over (aad, ct) for an arbitrary-length IV. */
static int gcm_reference_tag(int bits, const unsigned char *key,
    const unsigned char *iv, size_t iv_len,
    const unsigned char *aad, size_t aad_len,
    const unsigned char *ct, size_t ct_len,
    unsigned char *tag_out)
{
    unsigned char H[GCM_BLOCK] = { 0 };
    unsigned char J0[GCM_BLOCK] = { 0 };
    unsigned char EJ0[GCM_BLOCK];
    unsigned char state[GCM_BLOCK] = { 0 };
    unsigned char lenblk[GCM_BLOCK] = { 0 };
    unsigned char zero[GCM_BLOCK] = { 0 };
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits = (uint64_t)ct_len * 8;
    int j;

    if (!aes_ecb_block(bits, key, zero, H))
        return 0;

    if (iv_len == 12) {
        /* 96-bit IV fast path: J0 = IV || 0x00000001 */
        memcpy(J0, iv, 12);
        J0[15] = 1;
    } else {
        /* J0 = GHASH_H(IV padded to a block multiple || 0^64 || len(IV)_64) */
        uint64_t iv_bits = (uint64_t)iv_len * 8;

        ghash_blocks(J0, H, iv, iv_len);
        memset(lenblk, 0, GCM_BLOCK);
        for (j = 0; j < 8; j++)
            lenblk[15 - j] = (unsigned char)(iv_bits >> (8 * j));
        for (j = 0; j < GCM_BLOCK; j++)
            J0[j] ^= lenblk[j];
        {
            unsigned char tmp[GCM_BLOCK];
            gf_mul(J0, H, tmp);
            memcpy(J0, tmp, GCM_BLOCK);
        }
        memset(lenblk, 0, GCM_BLOCK);
    }
    if (!aes_ecb_block(bits, key, J0, EJ0))
        return 0;

    ghash_blocks(state, H, aad, aad_len);
    ghash_blocks(state, H, ct, ct_len);

    for (j = 0; j < 8; j++) {
        lenblk[7 - j] = (unsigned char)(aad_bits >> (8 * j));
        lenblk[15 - j] = (unsigned char)(ct_bits >> (8 * j));
    }
    for (j = 0; j < GCM_BLOCK; j++)
        state[j] ^= lenblk[j];
    {
        unsigned char tmp[GCM_BLOCK];
        gf_mul(state, H, tmp);
        memcpy(state, tmp, GCM_BLOCK);
    }

    for (j = 0; j < GCM_BLOCK; j++)
        tag_out[j] = (unsigned char)(state[j] ^ EJ0[j]);
    return 1;
}

/* idx encodes (key, length, ivlen, aadlen) as a flat 4-D index. */
static int test_gcm_tag(int idx)
{
    int a = idx % NUM_AADS;
    idx /= NUM_AADS;
    int v = idx % NUM_IVS;
    idx /= NUM_IVS;
    int l = idx % NUM_LENS;
    idx /= NUM_LENS;
    int bits = keybits[idx];
    size_t len = lengths[l];
    size_t iv_len = ivlens[v];
    size_t aad_len = aadlens[a];
    unsigned char key[32], iv[MAX_IVLEN], aad[MAX_AADLEN];
    unsigned char *pt = NULL, *ct = NULL;
    unsigned char evp_tag[GCM_BLOCK], ref_tag[GCM_BLOCK];
    EVP_CIPHER_CTX *ctx = NULL;
    int outl = 0, tmpl = 0, ok = 0;
    size_t i;

    for (i = 0; i < sizeof(key); i++)
        key[i] = (unsigned char)(0x10 + i);
    for (i = 0; i < iv_len; i++)
        iv[i] = (unsigned char)(0xA0 + i);
    for (i = 0; i < aad_len; i++)
        aad[i] = (unsigned char)(0x50 + i);

    if (!TEST_ptr(pt = OPENSSL_malloc(len ? len : 1))
        || !TEST_ptr(ct = OPENSSL_malloc(len ? len : 1)))
        goto err;
    for (i = 0; i < len; i++)
        pt[i] = (unsigned char)((i * 131u + 7u) & 0xff);

    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex(ctx, gcm_cipher(bits), NULL,
            NULL, NULL))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
            (int)iv_len, NULL))
        || !TEST_true(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        || !TEST_true(EVP_EncryptUpdate(ctx, NULL, &outl, aad, (int)aad_len))
        || !TEST_true(EVP_EncryptUpdate(ctx, ct, &outl, pt, (int)len))
        || !TEST_true(EVP_EncryptFinal_ex(ctx, ct + outl, &tmpl))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
            GCM_BLOCK, evp_tag)))
        goto err;

    if (!gcm_reference_tag(bits, key, iv, iv_len, aad, aad_len, ct, len,
            ref_tag))
        goto err;

    if (!TEST_mem_eq(ref_tag, GCM_BLOCK, evp_tag, GCM_BLOCK)) {
        TEST_info("AES-%d GCM tag mismatch: msglen=%zu ivlen=%zu aadlen=%zu",
            bits, len, iv_len, aad_len);
        goto err;
    }
    ok = 1;

err:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_free(pt);
    OPENSSL_free(ct);
    return ok;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_gcm_tag, NUM_KEYS * NUM_LENS * NUM_IVS * NUM_AADS);
    return 1;
}
