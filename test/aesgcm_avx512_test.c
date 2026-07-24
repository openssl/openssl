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
 * roundtrip alone cannot detect a bug in those paths because encrypt and
 * decrypt share the same GHASH, so a wrong tag is computed identically on both
 * sides and still "verifies"; likewise a tag recomputed over the produced
 * ciphertext cannot catch a counter/keystream bug, because the ciphertext
 * itself would be wrong.
 *
 * To get independent oracles this test, for every case:
 *   1. Encrypts (chunked AAD + in-place, split-across-calls payload updates so
 *      partial-block carry is exercised).
 *   2. Recomputes the ciphertext independently from an AES-CTR keystream built
 *      with plain AES-ECB over the J0 counter sequence (SP 800-38D) and compares
 *      it byte-for-byte with EVP's ciphertext. This validates the AES-CTR
 *      counter sequence/keystream regardless of GHASH.
 *   3. Recomputes the GCM tag with a small portable GF(2^128) GHASH and compares
 *      with EVP's tag.
 *   4. Decrypts (also chunked) and requires both tag verification to succeed and
 *      the recovered plaintext to match the original.
 *
 * The chosen lengths straddle the 4->8 (64 B), 8->16 (704 B) and 16->32
 * (1792 B) crossovers with +-1 neighbours, plus the 512-byte residues that can
 * accidentally pass, so the test exercises every dispatch path and its drain.
 *
 * The test also verifies the VAES/AVX-512 path is actually the one dispatched:
 * on hosts without the required ISA it skips instead of silently passing while
 * exercising a different implementation.
 *
 * A second, complementary check (the "dump" mode, driven by the recipe)
 * compares the VAES/AVX-512 path byte-for-byte against OpenSSL's non-VAES
 * (AES-NI/CLMUL) GCM over a deterministic grid. See the overview above
 * setup_tests() for how the two tests differ and why both are kept.
 */

#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "testutil.h"
#include "internal/cryptlib.h" /* OPENSSL_cpuid_setup() */

#define GCM_BLOCK 16

/*
 * Gate on the effective dispatch state, so a non-skipped run provably executed
 * the VAES/AVX-512 implementation (and the recipe's masked run provably executed
 * a different, AES-NI backend).
 *
 * The provider selects the implementation under review in ossl_prov_aes_hw_gcm()
 * via ossl_vaes_vpclmulqdq_capable(), which tests these exact bits of the
 * *effective* OPENSSL_ia32cap_P (the runtime capability vector, after any
 * OPENSSL_ia32cap mask is applied). We check the same vector and bits here. We
 * read OPENSSL_ia32cap_P directly (always defined on x86 in libcrypto, even in
 * no-asm builds) so this links on every build; the test is linked against the
 * static libcrypto (see test/build.info) so the internal symbol is reachable.
 * Requires x86_64.
 */
#if defined(__x86_64__) || defined(__x86_64) || defined(_M_AMD64) \
    || defined(_M_X64)
#define AESGCM_AVX512_GATE 1
#else
#define AESGCM_AVX512_GATE 0
#endif

static int vaes_avx512_available(void)
{
#if AESGCM_AVX512_GATE
    /* Same bits ossl_vaes_vpclmulqdq_capable() checks in OPENSSL_ia32cap_P+8. */
    const unsigned int need2 = (1u << 16) | (1u << 17) | (1u << 30)
        | (1u << 31); /* word 2: AVX512 F, DQ, BW, VL */
    const unsigned int need3 = (1u << 9) | (1u << 10); /* word 3: VAES,VPCLMULQDQ */

    /*
     * Ensure OPENSSL_ia32cap_P is populated (and any OPENSSL_ia32cap mask
     * applied) before reading it. Idempotent.
     */
    OPENSSL_cpuid_setup();
    return (OPENSSL_ia32cap_P[2] & need2) == need2
        && (OPENSSL_ia32cap_P[3] & need3) == need3;
#else
    return 0;
#endif
}

static const int keybits[] = { 128, 192, 256 };

/*
 * Message lengths: 0 and 1, the 4->8 (64 B), 8->16 (704 B) and 16->32
 * (1792 B) crossovers with +-1 neighbours, the 512-byte residues that can
 * accidentally pass, and several larger sizes that force multiple 32-block
 * big-loop iterations plus assorted drain tails.
 */
static const size_t lengths[] = {
    0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 191, 192, 193, 240, 255, 256,
    257, 703, 704, 705, 1791, 1792, 1793, 1800, 1808, 2047, 2048, 2064, 2288,
    2304, 2400, 2560, 2576, 3000, 3584, 4096, 4111, 5000, 6000, 8192, 12000
};

/*
 * IV lengths: 12 is the 96-bit fast path (J0 = IV || 1); the others force the
 * GHASH-based J0 derivation, which runs CALC_AAD_HASH over the IV. 128 is the
 * largest IV the EVP GCM provider accepts (GCM_IV_MAX_SIZE = 1024/8); longer
 * IVs are rejected before reaching this code, so the wider CALC_AAD_HASH tiers
 * (>= 256 B) are unreachable through the IV and are covered via AAD below.
 */
static const size_t ivlens[] = { 1, 12, 13, 16, 60, 128 };

/*
 * AAD lengths. Unlike the IV, AAD is not length-capped, so it is the only way
 * to drive CALC_AAD_HASH's wide tiers through EVP. The small values cover the
 * sub-16-block cases (and partial-block carry via the split feeder). Because
 * AAD is fed split across two update calls, a total length reaches the 512-byte
 * 32-block loop only once a single sub-chunk carries >= 512 block-aligned bytes
 * into one CALC_AAD_HASH call: 511/512/513/768 exercise the 16-block section
 * (256 B, H^1..H^16) and its boundary; 1024/1025 reach the 32-block loop
 * (H^1..H^32); and 2048 makes the first sub-chunk alone >= 512 -- so it
 * unconditionally enters the 32-block loop and drives it for more than one
 * iteration (exercising cross-iteration hash accumulation and pointer advance).
 */
static const size_t aadlens[] = {
    0, 13, 16, 20, 240, 255, 256, 257, 511, 512, 513, 768, 1024, 1025, 2048
};

#define MAX_IVLEN 128
#define MAX_AADLEN 2048

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

/* One AES block encryption (ECB, no padding) used to derive H, E(J0) and the
 * independent AES-CTR keystream. */
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
    int i, j;

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

/* inc32: increment the low 32 bits (big-endian) of a 128-bit counter block. */
static void gcm_inc32(unsigned char *ctr)
{
    uint32_t c = ((uint32_t)ctr[12] << 24) | ((uint32_t)ctr[13] << 16)
        | ((uint32_t)ctr[14] << 8) | (uint32_t)ctr[15];

    c++;
    ctr[12] = (unsigned char)(c >> 24);
    ctr[13] = (unsigned char)(c >> 16);
    ctr[14] = (unsigned char)(c >> 8);
    ctr[15] = (unsigned char)c;
}

/* Derive the hash subkey H = E(0) and the pre-counter block J0 (SP 800-38D). */
static int gcm_derive_H_J0(int bits, const unsigned char *key,
    const unsigned char *iv, size_t iv_len,
    unsigned char *H, unsigned char *J0)
{
    unsigned char zero[GCM_BLOCK] = { 0 };
    unsigned char lenblk[GCM_BLOCK] = { 0 };
    int j;

    memset(H, 0, GCM_BLOCK);
    memset(J0, 0, GCM_BLOCK);
    if (!aes_ecb_block(bits, key, zero, H))
        return 0;

    if (iv_len == 12) {
        /* 96-bit IV fast path: J0 = IV || 0x00000001 */
        memcpy(J0, iv, 12);
        J0[15] = 1;
    } else {
        /* J0 = GHASH_H(IV padded to a block multiple || 0^64 || len(IV)_64) */
        uint64_t iv_bits = (uint64_t)iv_len * 8;
        unsigned char tmp[GCM_BLOCK];

        ghash_blocks(J0, H, iv, iv_len);
        for (j = 0; j < 8; j++)
            lenblk[15 - j] = (unsigned char)(iv_bits >> (8 * j));
        for (j = 0; j < GCM_BLOCK; j++)
            J0[j] ^= lenblk[j];
        gf_mul(J0, H, tmp);
        memcpy(J0, tmp, GCM_BLOCK);
    }
    return 1;
}

/*
 * Independent ciphertext oracle: build the AES-CTR keystream from the counter
 * sequence inc32(J0), inc32^2(J0), ... using plain AES-ECB, and XOR it with the
 * plaintext. This depends only on the counter arithmetic and AES, not on GHASH,
 * so it catches counter/keystream bugs that a tag comparison cannot.
 */
static int gcm_reference_ct(int bits, const unsigned char *key,
    const unsigned char *J0, const unsigned char *pt, size_t len,
    unsigned char *ct)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char ctr[GCM_BLOCK], ks[GCM_BLOCK];
    size_t off, i;
    int outl = 0, ok = 0;

    /* One ECB context, key set once, reused for every counter block. */
    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex(ctx, ecb_cipher(bits), NULL, key,
            NULL))
        || !TEST_true(EVP_CIPHER_CTX_set_padding(ctx, 0)))
        goto err;

    memcpy(ctr, J0, GCM_BLOCK);
    for (off = 0; off < len; off += GCM_BLOCK) {
        size_t n = len - off < GCM_BLOCK ? len - off : GCM_BLOCK;

        gcm_inc32(ctr);
        if (!TEST_true(EVP_EncryptUpdate(ctx, ks, &outl, ctr, GCM_BLOCK))
            || !TEST_int_eq(outl, GCM_BLOCK))
            goto err;
        for (i = 0; i < n; i++)
            ct[off + i] = (unsigned char)(pt[off + i] ^ ks[i]);
    }
    ok = 1;

err:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* Independent GCM tag over (aad, ct) for an arbitrary-length IV. */
static int gcm_reference_tag(int bits, const unsigned char *key,
    const unsigned char *iv, size_t iv_len,
    const unsigned char *aad, size_t aad_len,
    const unsigned char *ct, size_t ct_len,
    unsigned char *tag_out)
{
    unsigned char H[GCM_BLOCK], J0[GCM_BLOCK], EJ0[GCM_BLOCK];
    unsigned char state[GCM_BLOCK] = { 0 };
    unsigned char lenblk[GCM_BLOCK] = { 0 };
    unsigned char tmp[GCM_BLOCK];
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits = (uint64_t)ct_len * 8;
    int j;

    if (!gcm_derive_H_J0(bits, key, iv, iv_len, H, J0))
        return 0;
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
    gf_mul(state, H, tmp);
    memcpy(state, tmp, GCM_BLOCK);

    for (j = 0; j < GCM_BLOCK; j++)
        tag_out[j] = (unsigned char)(state[j] ^ EJ0[j]);
    return 1;
}

/* Single AAD/cipher update in the requested direction (out == NULL for AAD). */
static int gcm_update(EVP_CIPHER_CTX *ctx, int enc, unsigned char *out,
    const unsigned char *in, int inlen)
{
    int outl = 0;

    if (enc)
        return EVP_EncryptUpdate(ctx, out, &outl, in, inlen);
    return EVP_DecryptUpdate(ctx, out, &outl, in, inlen);
}

/*
 * Feed [in, in+len) through the AAD/cipher in two calls split at a non-block
 * boundary, exercising split updates and partial-block carry across calls.
 * out == NULL feeds AAD; out may alias in for in-place operation.
 */
static int gcm_feed_split(EVP_CIPHER_CTX *ctx, int enc, unsigned char *out,
    const unsigned char *in, size_t len)
{
    size_t s1;

    if (len < 2)
        return gcm_update(ctx, enc, out, in, (int)len);

    s1 = len / 2;
    if (s1 % GCM_BLOCK == 0) /* force a partial-block carry across the split */
        s1--;
    if (s1 == 0)
        s1 = 1;

    return gcm_update(ctx, enc, out, in, (int)s1)
        && gcm_update(ctx, enc, out != NULL ? out + s1 : NULL, in + s1,
            (int)(len - s1));
}

/* idx encodes (key, length, ivlen, aadlen) as a flat 4-D index. */
static int test_gcm_tag(int idx)
{
    int inplace_dec = idx & 1; /* alternate in-place / out-of-place decrypt */
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
    unsigned char *pt = NULL, *ct = NULL, *dec = NULL, *ref_ct = NULL;
    unsigned char evp_tag[GCM_BLOCK], ref_tag[GCM_BLOCK];
    unsigned char H[GCM_BLOCK], J0[GCM_BLOCK], fin[GCM_BLOCK];
    EVP_CIPHER_CTX *ctx = NULL;
    int tmpl = 0, ok = 0;
    size_t i;

    for (i = 0; i < sizeof(key); i++)
        key[i] = (unsigned char)(0x10 + i);
    for (i = 0; i < iv_len; i++)
        iv[i] = (unsigned char)(0xA0 + i);
    for (i = 0; i < aad_len; i++)
        aad[i] = (unsigned char)(0x50 + i);

    if (!TEST_ptr(pt = OPENSSL_malloc(len ? len : 1))
        || !TEST_ptr(ct = OPENSSL_malloc(len ? len : 1))
        || !TEST_ptr(dec = OPENSSL_malloc(len ? len : 1))
        || !TEST_ptr(ref_ct = OPENSSL_malloc(len ? len : 1)))
        goto err;
    for (i = 0; i < len; i++)
        pt[i] = (unsigned char)((i * 131u + 7u) & 0xff);

    /*
     * Encrypt: split AAD, in-place (out == in == ct) split payload updates.
     * Copy plaintext into the output buffer first so pt is preserved for the
     * independent oracles and the decrypt comparison.
     */
    memcpy(ct, pt, len);
    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex(ctx, gcm_cipher(bits), NULL, NULL,
            NULL))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
            (int)iv_len, NULL))
        || !TEST_true(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        || !TEST_true(gcm_feed_split(ctx, 1, NULL, aad, aad_len))
        || !TEST_true(gcm_feed_split(ctx, 1, ct, ct, len))
        || !TEST_true(EVP_EncryptFinal_ex(ctx, fin, &tmpl))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
            GCM_BLOCK, evp_tag)))
        goto err;

    /* Independent AES-CTR keystream check (catches counter/keystream bugs). */
    if (!TEST_true(gcm_derive_H_J0(bits, key, iv, iv_len, H, J0))
        || !TEST_true(gcm_reference_ct(bits, key, J0, pt, len, ref_ct)))
        goto err;
    if (len != 0 && !TEST_mem_eq(ref_ct, len, ct, len)) {
        TEST_info("AES-%d GCM ciphertext mismatch: msglen=%zu ivlen=%zu "
                  "aadlen=%zu",
            bits, len, iv_len, aad_len);
        goto err;
    }

    /* Independent GHASH tag check. */
    if (!TEST_true(gcm_reference_tag(bits, key, iv, iv_len, aad, aad_len, ct,
            len, ref_tag)))
        goto err;
    if (!TEST_mem_eq(ref_tag, GCM_BLOCK, evp_tag, GCM_BLOCK)) {
        TEST_info("AES-%d GCM tag mismatch: msglen=%zu ivlen=%zu aadlen=%zu",
            bits, len, iv_len, aad_len);
        goto err;
    }

    /*
     * Decrypt: split AAD + payload, recover plaintext and verify the tag.
     * Alternate out-of-place (into dec) and in-place (out == in == ct, which
     * still holds the ciphertext and is no longer needed) by case index.
     */
    {
        unsigned char *dbuf = inplace_dec ? ct : dec;

        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
        if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
            || !TEST_true(EVP_DecryptInit_ex(ctx, gcm_cipher(bits), NULL, NULL,
                NULL))
            || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                (int)iv_len, NULL))
            || !TEST_true(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
            || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                GCM_BLOCK, evp_tag))
            || !TEST_true(gcm_feed_split(ctx, 0, NULL, aad, aad_len))
            || !TEST_true(gcm_feed_split(ctx, 0, dbuf, ct, len)))
            goto err;
        if (!TEST_int_gt(EVP_DecryptFinal_ex(ctx, fin, &tmpl), 0)) {
            TEST_info("AES-%d GCM decrypt tag verification failed: msglen=%zu "
                      "ivlen=%zu aadlen=%zu",
                bits, len, iv_len, aad_len);
            goto err;
        }
        if (len != 0 && !TEST_mem_eq(dbuf, len, pt, len)) {
            TEST_info("AES-%d GCM plaintext recovery mismatch: msglen=%zu "
                      "ivlen=%zu aadlen=%zu",
                bits, len, iv_len, aad_len);
            goto err;
        }
    }
    ok = 1;

err:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_free(pt);
    OPENSSL_free(ct);
    OPENSSL_free(dec);
    OPENSSL_free(ref_ct);
    return ok;
}

/*
 * Decrypt + verify one message; returns 1 iff the tag verified
 * (EVP_DecryptFinal_ex succeeded), 0 if it was rejected, -1 on setup error.
 */
static int gcm_verify(int bits, const unsigned char *key,
    const unsigned char *iv, size_t iv_len,
    const unsigned char *aad, size_t aad_len,
    const unsigned char *ct, size_t len,
    const unsigned char *tag, unsigned char *out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char tagbuf[GCM_BLOCK];
    int tmpl = 0, ret = -1;

    if (ctx == NULL)
        return -1;
    memcpy(tagbuf, tag, GCM_BLOCK);
    if (EVP_DecryptInit_ex(ctx, gcm_cipher(bits), NULL, NULL, NULL) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL)
            == 1
        && EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_BLOCK, tagbuf) == 1
        && gcm_feed_split(ctx, 0, NULL, aad, aad_len)
        && gcm_feed_split(ctx, 0, out, ct, len))
        ret = EVP_DecryptFinal_ex(ctx, out, &tmpl) > 0 ? 1 : 0;
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/*
 * Authentication-failure test at the dispatch boundaries: after a valid
 * encryption, a flipped tag byte, a flipped ciphertext byte and a flipped AAD
 * byte must each be rejected by decrypt/verify. OpenSSL already covers bad-tag
 * rejection at arbitrary lengths (evp_test GCM vectors); this pins the
 * rejection to the exact lengths this rewrite dispatches on -- the regime where
 * the drain bug produced forgeable tags. idx = key x length.
 */
static int test_gcm_auth_fail(int idx)
{
    int l = idx % NUM_LENS;
    int bits = keybits[idx / NUM_LENS];
    size_t len = lengths[l];
    size_t iv_len = 12;
    size_t aad_len = 16;
    unsigned char key[32], iv[MAX_IVLEN], aad[MAX_AADLEN];
    unsigned char *pt = NULL, *ct = NULL, *dec = NULL;
    unsigned char tag[GCM_BLOCK], bad[GCM_BLOCK];
    EVP_CIPHER_CTX *ctx = NULL;
    int tmpl = 0, ok = 0;
    size_t i;

    for (i = 0; i < sizeof(key); i++)
        key[i] = (unsigned char)(0x21 + i);
    for (i = 0; i < iv_len; i++)
        iv[i] = (unsigned char)(0xB0 + i);
    for (i = 0; i < aad_len; i++)
        aad[i] = (unsigned char)(0x40 + i);

    if (!TEST_ptr(pt = OPENSSL_malloc(len ? len : 1))
        || !TEST_ptr(ct = OPENSSL_malloc(len ? len : 1))
        || !TEST_ptr(dec = OPENSSL_malloc(len ? len : 1)))
        goto err;
    for (i = 0; i < len; i++)
        pt[i] = (unsigned char)((i * 197u + 3u) & 0xff);

    /* Produce a valid (ct, tag). */
    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex(ctx, gcm_cipher(bits), NULL, NULL,
            NULL))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
            (int)iv_len, NULL))
        || !TEST_true(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        || !TEST_true(gcm_feed_split(ctx, 1, NULL, aad, aad_len))
        || !TEST_true(gcm_feed_split(ctx, 1, ct, pt, len))
        || !TEST_true(EVP_EncryptFinal_ex(ctx, dec, &tmpl))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_BLOCK,
            tag)))
        goto err;

    /* Sanity: the untampered ciphertext must verify (guards vacuous passes). */
    if (!TEST_int_eq(gcm_verify(bits, key, iv, iv_len, aad, aad_len, ct, len,
                         tag, dec),
            1)) {
        TEST_info("AES-%d GCM valid decrypt failed: msglen=%zu", bits, len);
        goto err;
    }

    /* A flipped tag byte must be rejected. */
    memcpy(bad, tag, GCM_BLOCK);
    bad[0] ^= 0x01;
    if (!TEST_int_eq(gcm_verify(bits, key, iv, iv_len, aad, aad_len, ct, len,
                         bad, dec),
            0)) {
        TEST_info("AES-%d GCM accepted a forged tag: msglen=%zu", bits, len);
        goto err;
    }

    /* A flipped ciphertext byte must be rejected (len > 0). */
    if (len != 0) {
        unsigned char save = ct[len / 2];

        ct[len / 2] ^= 0x01;
        if (!TEST_int_eq(gcm_verify(bits, key, iv, iv_len, aad, aad_len, ct,
                             len, tag, dec),
                0)) {
            TEST_info("AES-%d GCM accepted tampered ciphertext: msglen=%zu",
                bits, len);
            goto err;
        }
        ct[len / 2] = save;
    }

    /* A flipped AAD byte must be rejected. */
    {
        unsigned char save = aad[aad_len / 2];

        aad[aad_len / 2] ^= 0x01;
        if (!TEST_int_eq(gcm_verify(bits, key, iv, iv_len, aad, aad_len, ct,
                             len, tag, dec),
                0)) {
            TEST_info("AES-%d GCM accepted tampered AAD: msglen=%zu", bits, len);
            goto err;
        }
        aad[aad_len / 2] = save;
    }

    ok = 1;

err:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_free(pt);
    OPENSSL_free(ct);
    OPENSSL_free(dec);
    return ok;
}

/*
 * Counter low-byte overflow across a split update.
 *
 * Each scenario drives one counter-overflow branch. A first block-aligned
 * update advances the counter so its low byte equals `t` at the start of the
 * second update; the second update (`blocks2` blocks) is then dispatched into
 * the path whose group crosses the wrap threshold. `t` is chosen so the target
 * group's *entry* low byte lands in the branch's trigger window:
 *
 *   - the 8-block preamble is the first group, so its entry byte == t;
 *   - the 8-block stitched group runs after the 8-block preamble (+8), so its
 *     entry byte == t + 8;
 *   - the 16-block hot-loop group runs after INITIAL_BLOCKS_16 (+16), so its
 *     entry byte == t + 16.
 *
 * Note: there is no 4-block scenario -- the dedicated 4-block path was removed
 * (< 128 B is handled by the masked small-block handler), so its preamble/loop
 * overflow branches no longer exist.
 */
static const struct {
    const char *name;
    int blocks2; /* size of the branch-triggering 2nd update, in blocks */
    int t_lo, t_hi; /* window of the 2nd update's entry counter low byte */
} ctr_ovf_scn[] = {
    { "8blk_preamble", 8, 248, 255 }, /* .L_8blk_preamble_overflow (>=248) */
    { "8blk_ghash", 16, 240, 247 }, /* .L_8blk_overflow (t+8 in [248,255]) */
    { "init16", 44, 240, 255 }, /* .L_next_16_overflow (INITIAL_BLOCKS_16) */
    { "loop16", 44, 224, 239 }, /* .L_16_blocks_overflow (t+16 in [240,255]) */
    /*
     * .L_16_blocks_overflow in GHASH_16_ENCRYPT_N_GHASH_N (the 32-block big-loop
     * drain). A 127-block (2032 B) update runs INITIAL_BLOCKS_16 + three 32-block
     * iterations + a 15-block drain whose group enters at t+112; t in [129,143]
     * lands it in [241,255]. (Layout-dependent: the drain tail size follows the
     * big-loop chunking; if that is re-tuned this window shifts.)
     */
    { "drain16", 127, 129, 143 }, /* .L_16_blocks_overflow (drain) */
};

#define CTR_OVF_NSCN ((int)(sizeof(ctr_ovf_scn) / sizeof(ctr_ovf_scn[0])))

static int ctr_ovf_cases_per_key(void)
{
    int s, n = 0;

    for (s = 0; s < CTR_OVF_NSCN; s++)
        n += ctr_ovf_scn[s].t_hi - ctr_ovf_scn[s].t_lo + 1;
    return n;
}

static int test_gcm_ctr_overflow_split(int idx)
{
    int per_key = ctr_ovf_cases_per_key();
    int bits = keybits[idx / per_key];
    int w = idx % per_key;
    int s = 0, t;
    const char *name;
    size_t iv_len = 12, aad_len = 16;
    unsigned char key[32], iv[12], aad[16];
    unsigned char H[GCM_BLOCK], J0[GCM_BLOCK];
    unsigned char tag[GCM_BLOCK], ref_tag[GCM_BLOCK];
    unsigned char *pt = NULL, *ct = NULL, *dec = NULL, *ref_ct = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    size_t m, len1, len2, total, i;
    unsigned int c0;
    int tmpl = 0, ok = 0;

    while (w > ctr_ovf_scn[s].t_hi - ctr_ovf_scn[s].t_lo) {
        w -= ctr_ovf_scn[s].t_hi - ctr_ovf_scn[s].t_lo + 1;
        s++;
    }
    t = ctr_ovf_scn[s].t_lo + w;
    name = ctr_ovf_scn[s].name;
    len2 = (size_t)ctr_ovf_scn[s].blocks2 * GCM_BLOCK;

    for (i = 0; i < sizeof(key); i++)
        key[i] = (unsigned char)(0x31 + i);
    for (i = 0; i < iv_len; i++)
        iv[i] = (unsigned char)(0x90 + i);
    for (i = 0; i < aad_len; i++)
        aad[i] = (unsigned char)(0x50 + i);

    /* c0 = J0 counter low byte; each processed block advances it by one. */
    if (!TEST_true(gcm_derive_H_J0(bits, key, iv, iv_len, H, J0)))
        goto err;
    c0 = J0[15];
    m = (size_t)(((unsigned)t - c0) & 0xffu); /* blocks to feed in update 1 */
    len1 = m * GCM_BLOCK;
    total = len1 + len2;

    if (!TEST_ptr(pt = OPENSSL_malloc(total))
        || !TEST_ptr(ct = OPENSSL_malloc(total))
        || !TEST_ptr(dec = OPENSSL_malloc(total))
        || !TEST_ptr(ref_ct = OPENSSL_malloc(total)))
        goto err;
    for (i = 0; i < total; i++)
        pt[i] = (unsigned char)((i * 131u + 7u) & 0xff);

    /*
     * Encrypt: AAD, then two block-aligned updates. update 1 advances the
     * counter into the wrap window; update 2 (a fresh 4-/8-block dispatch)
     * enters the overflow preamble.
     */
    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex(ctx, gcm_cipher(bits), NULL, NULL,
            NULL))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
            (int)iv_len, NULL))
        || !TEST_true(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        || !TEST_true(gcm_update(ctx, 1, NULL, aad, (int)aad_len))
        || !TEST_true(gcm_update(ctx, 1, ct, pt, (int)len1))
        || !TEST_true(gcm_update(ctx, 1, ct + len1, pt + len1, (int)len2))
        || !TEST_true(EVP_EncryptFinal_ex(ctx, dec, &tmpl))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_BLOCK,
            tag)))
        goto err;

    /* Independent oracle over the whole (update1 + update2) message. */
    if (!TEST_true(gcm_reference_ct(bits, key, J0, pt, total, ref_ct)))
        goto err;
    if (!TEST_mem_eq(ref_ct, total, ct, total)) {
        TEST_info("AES-%d ctr-overflow ct mismatch: scn=%s t=%d m=%zu", bits,
            name, t, m);
        goto err;
    }
    if (!TEST_true(gcm_reference_tag(bits, key, iv, iv_len, aad, aad_len, ct,
            total, ref_tag)))
        goto err;
    if (!TEST_mem_eq(ref_tag, GCM_BLOCK, tag, GCM_BLOCK)) {
        TEST_info("AES-%d ctr-overflow tag mismatch: scn=%s t=%d m=%zu", bits,
            name, t, m);
        goto err;
    }

    /* Decrypt/verify with the same split (the decrypt hits the same branch). */
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_DecryptInit_ex(ctx, gcm_cipher(bits), NULL, NULL,
            NULL))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
            (int)iv_len, NULL))
        || !TEST_true(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_BLOCK,
            tag))
        || !TEST_true(gcm_update(ctx, 0, NULL, aad, (int)aad_len))
        || !TEST_true(gcm_update(ctx, 0, dec, ct, (int)len1))
        || !TEST_true(gcm_update(ctx, 0, dec + len1, ct + len1, (int)len2))
        || !TEST_int_gt(EVP_DecryptFinal_ex(ctx, dec, &tmpl), 0)
        || !TEST_mem_eq(dec, total, pt, total)) {
        TEST_info("AES-%d ctr-overflow decrypt mismatch: scn=%s t=%d m=%zu",
            bits, name, t, m);
        goto err;
    }
    ok = 1;

err:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_free(pt);
    OPENSSL_free(ct);
    OPENSSL_free(dec);
    OPENSSL_free(ref_ct);
    return ok;
}

/*
 * Differential "dump" mode (driven by test/recipes/30-test_aesgcm_avx512.t).
 *
 * A deterministic grid -- every message length in lengths[] (which covers all
 * dispatch boundaries) x each key size x each IV/AAD length -- is run through
 * encrypt (chunked, optionally in-place) and decrypt/verify, and a single
 * SHA-256 digest is printed over all ciphertext/tag/decrypt results. The recipe
 * runs this twice: once natively (AVX-512/VAES where the CPU supports it) and
 * once with OPENSSL_ia32cap masked (AVX512F cleared) so libcrypto falls back to
 * its non-VAES GCM -- the AES-NI + CLMUL-GHASH path -- then compares the
 * digests. Equal digests prove the VAES/AVX-512 path is byte-identical to that
 * independent, mature implementation.
 *
 * The lengths, key sizes and IV/AAD lengths are fixed; only the key/IV/AAD/
 * plaintext content is drawn from a fixed-seed splitmix64 PRNG (not
 * RAND_bytes), so both runs process identical inputs and the sweep is fully
 * reproducible.
 */
static uint64_t diff_rng_state;

static uint64_t diff_rng_next(void)
{
    uint64_t z = (diff_rng_state += 0x9E3779B97F4A7C15ULL);

    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static void diff_rng_bytes(unsigned char *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        p[i] = (unsigned char)(diff_rng_next() & 0xff);
}

/* Number of independent seeded data vectors exercised per grid cell. */
#define DIFF_REPS 8

static int test_gcm_differential_dump(void)
{
    static const char hexd[] = "0123456789abcdef";
    EVP_MD_CTX *md = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *pt = NULL, *ct = NULL, *dec = NULL;
    unsigned char key[32], iv[MAX_IVLEN], aad[MAX_AADLEN];
    unsigned char tag[GCM_BLOCK], digest[EVP_MAX_MD_SIZE];
    char hex[2 * EVP_MAX_MD_SIZE + 1];
    unsigned int dlen = 0, i;
    unsigned long counter = 0;
    size_t maxlen = 1;
    int ki, li, vi, ai, ok = 0;

    for (li = 0; li < NUM_LENS; li++)
        if (lengths[li] > maxlen)
            maxlen = lengths[li];

    diff_rng_state = 0xA5A5F00DCAFEBABEULL; /* fixed seed => identical content */

    if (!TEST_ptr(pt = OPENSSL_malloc(maxlen))
        || !TEST_ptr(ct = OPENSSL_malloc(maxlen))
        || !TEST_ptr(dec = OPENSSL_malloc(maxlen))
        || !TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_ptr(md = EVP_MD_CTX_new())
        || !TEST_true(EVP_DigestInit_ex(md, EVP_sha256(), NULL)))
        goto err;

    /*
     * Deterministic grid: every message length in lengths[] (which covers all
     * dispatch boundaries) is exercised for each key size and each IV/AAD
     * length, with DIFF_REPS independent seeded data vectors per cell (broader
     * than Test 1's single index-derived pattern). Only the key/IV/AAD/
     * plaintext content comes from the fixed-seed PRNG, so the sequence is
     * identical on every run and for both the native and the ia32cap-masked
     * process.
     */
    for (ki = 0; ki < NUM_KEYS; ki++) {
        int bits = keybits[ki];

        for (li = 0; li < NUM_LENS; li++) {
            size_t len = lengths[li];

            for (vi = 0; vi < NUM_IVS; vi++) {
                size_t iv_len = ivlens[vi];

                for (ai = 0; ai < NUM_AADS; ai++) {
                    size_t aad_len = aadlens[ai];
                    int rep;

                    for (rep = 0; rep < DIFF_REPS; rep++) {
                        int inplace = (int)(counter++ & 1);
                        unsigned char hdr[16], decok;
                        int tmpl = 0;

                        diff_rng_bytes(key, sizeof(key));
                        diff_rng_bytes(iv, iv_len);
                        diff_rng_bytes(aad, aad_len);
                        diff_rng_bytes(pt, len);

                        /* Encrypt: chunked AAD + payload, optionally in-place. */
                        if (inplace)
                            memcpy(ct, pt, len);
                        if (!TEST_true(EVP_EncryptInit_ex(ctx, gcm_cipher(bits),
                                NULL, NULL, NULL))
                            || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx,
                                EVP_CTRL_GCM_SET_IVLEN, (int)iv_len, NULL))
                            || !TEST_true(EVP_EncryptInit_ex(ctx, NULL, NULL, key,
                                iv))
                            || !TEST_true(gcm_feed_split(ctx, 1, NULL, aad,
                                aad_len))
                            || !TEST_true(gcm_feed_split(ctx, 1, ct,
                                inplace ? ct : pt, len))
                            || !TEST_true(EVP_EncryptFinal_ex(ctx, tag, &tmpl))
                            || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx,
                                EVP_CTRL_GCM_GET_TAG, GCM_BLOCK, tag)))
                            goto err;

                        /*
                         * Decrypt back and record whether it verified and
                         * recovered the plaintext; a divergence here changes the
                         * digest and is caught by the recipe.
                         */
                        decok = (unsigned char)(EVP_DecryptInit_ex(ctx, gcm_cipher(bits), NULL, NULL,
                                                    NULL)
                                == 1
                            && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                   (int)iv_len, NULL)
                                == 1
                            && EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) == 1
                            && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                   GCM_BLOCK, tag)
                                == 1
                            && gcm_feed_split(ctx, 0, NULL, aad, aad_len)
                            && gcm_feed_split(ctx, 0, dec, ct, len)
                            && EVP_DecryptFinal_ex(ctx, dec, &tmpl) > 0
                            && (len == 0 || memcmp(dec, pt, len) == 0));

                        /* Fold everything that must agree across the two paths. */
                        hdr[0] = (unsigned char)bits;
                        hdr[1] = (unsigned char)iv_len;
                        hdr[2] = (unsigned char)(aad_len & 0xff);
                        hdr[3] = (unsigned char)(aad_len >> 8);
                        for (i = 0; i < 8; i++)
                            hdr[4 + i] = (unsigned char)((uint64_t)len >> (8 * i));
                        hdr[12] = decok;
                        hdr[13] = hdr[14] = hdr[15] = 0;
                        if (!TEST_true(EVP_DigestUpdate(md, hdr, sizeof(hdr)))
                            || !TEST_true(EVP_DigestUpdate(md, ct, len))
                            || !TEST_true(EVP_DigestUpdate(md, tag, GCM_BLOCK)))
                            goto err;
                    }
                }
            }
        }
    }

    if (!TEST_true(EVP_DigestFinal_ex(md, digest, &dlen)))
        goto err;
    for (i = 0; i < dlen; i++) {
        hex[2 * i] = hexd[digest[i] >> 4];
        hex[2 * i + 1] = hexd[digest[i] & 0x0f];
    }
    hex[2 * dlen] = '\0';

    /* Parsed by test/recipes/30-test_aesgcm_avx512.t */
    printf("DIFFDIGEST: VAES=%d %s\n", vaes_avx512_available() ? 1 : 0, hex);
    fflush(stdout);
    ok = 1;

err:
    EVP_MD_CTX_free(md);
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_free(pt);
    OPENSSL_free(ct);
    OPENSSL_free(dec);
    return ok;
}

/*
 * Two complementary tests guard the VAES/AVX-512 AES-GCM implementation; both
 * are intentionally kept because they use different oracles:
 *
 *   Test 1 ("aesgcm" mode, test_gcm_tag): absolute correctness against an
 *     INDEPENDENT, from-scratch SP 800-38D reference -- the hand-rolled AES-CTR
 *     keystream (gcm_reference_ct) and GF(2^128) GHASH (gcm_reference_tag/
 *     gf_mul) above, not OpenSSL code. An independent oracle can catch a bug
 *     common to both OpenSSL implementations, which a differential test cannot.
 *     It deterministically sweeps the exact dispatch boundaries (63/64/65 ...
 *     1791/1792/1793 ...) x key sizes x IV/AAD lengths on every run, so those
 *     edges are guaranteed to be exercised; the bitwise reference GHASH is slow,
 *     hence the curated size list.
 *
 *   Test 2 ("dump" mode, test_gcm_differential_dump): differential agreement
 *     with OpenSSL's non-VAES GCM (the AES-NI + CLMUL-GHASH path) over a
 *     deterministic grid -- every dispatch-boundary length x all key sizes
 *     (128/192/256) x IV/AAD lengths, with seeded-random content -- driven by
 *     test/recipes/30-test_aesgcm_avx512.t (a native run vs an
 *     OPENSSL_ia32cap-masked run with AVX512F cleared). It is cheap (EVP vs EVP)
 *     and catches AVX-512-specific divergence from that path, but it only proves
 *     the two OpenSSL implementations agree -- not that they are correct -- so
 *     Test 1 remains necessary.
 */
int setup_tests(void)
{
    const char *mode = test_get_argument(0);

    /*
     * Recipe-driven differential dump mode: run under whatever implementation
     * libcrypto selects (no VAES gate here, so the ia32cap-masked non-VAES run
     * also produces a digest) and emit it for comparison.
     */
    if (mode != NULL && strcmp(mode, "dump") == 0) {
        ADD_TEST(test_gcm_differential_dump);
        return 1;
    }

    if (!vaes_avx512_available()) {
        TEST_info("AES-GCM AVX-512/VAES not available on this host; skipping "
                  "(a pass here would not have exercised the VAES/AVX-512 path)");
        return 1;
    }
    ADD_ALL_TESTS(test_gcm_tag, NUM_KEYS * NUM_LENS * NUM_IVS * NUM_AADS);
    ADD_ALL_TESTS(test_gcm_auth_fail, NUM_KEYS * NUM_LENS);
    ADD_ALL_TESTS(test_gcm_ctr_overflow_split,
        NUM_KEYS * ctr_ovf_cases_per_key());
    return 1;
}
