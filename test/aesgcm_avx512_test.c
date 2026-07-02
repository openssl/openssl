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
 */

#include <openssl/evp.h>
#include <stdint.h>
#include <string.h>
#include "testutil.h"

#define GCM_BLOCK 16

/*
 * Detect the VAES/AVX-512 GCM ISA the same way the implementation dispatches
 * (ossl_vaes_vpclmulqdq_capable requires AVX512F/DQ/BW/VL + VAES +
 * VPCLMULQDQ). We probe CPUID directly rather than OPENSSL_ia32cap_P, which is
 * an internal, non-exported libcrypto symbol. OSXSAVE + XCR0 are checked first
 * so the AVX-512 feature bits are only trusted when the OS enables the state.
 */
#if defined(__x86_64__) || defined(__x86_64) || defined(_M_AMD64) \
    || defined(_M_X64)
#define AESGCM_AVX512_GATE 1

#if defined(_MSC_VER)
#include <intrin.h>

static void aesgcm_cpuidex(unsigned int leaf, unsigned int subleaf,
    unsigned int r[4])
{
    int regs[4];

    __cpuidex(regs, (int)leaf, (int)subleaf);
    r[0] = (unsigned int)regs[0];
    r[1] = (unsigned int)regs[1];
    r[2] = (unsigned int)regs[2];
    r[3] = (unsigned int)regs[3];
}

static uint64_t read_xcr0(void)
{
    return (uint64_t)_xgetbv(0);
}
#else
#include <cpuid.h>

static void aesgcm_cpuidex(unsigned int leaf, unsigned int subleaf,
    unsigned int r[4])
{
    __cpuid_count(leaf, subleaf, r[0], r[1], r[2], r[3]);
}

static uint64_t read_xcr0(void)
{
    uint32_t eax, edx;

    /* xgetbv with ECX=0 (encoded as .byte for maximum toolchain portability) */
    __asm__ volatile(".byte 0x0f, 0x01, 0xd0" : "=a"(eax), "=d"(edx) : "c"(0));
    return ((uint64_t)edx << 32) | eax;
}
#endif
#else
#define AESGCM_AVX512_GATE 0
#endif

static int vaes_avx512_available(void)
{
#if AESGCM_AVX512_GATE
    unsigned int r[4];
    const unsigned int ebx_need = (1u << 16) | (1u << 17) | (1u << 30)
        | (1u << 31); /* AVX512 F, DQ, BW, VL */
    const unsigned int ecx_need = (1u << 9) | (1u << 10); /* VAES, VPCLMULQDQ */

    /* leaf 1: require OSXSAVE before trusting XGETBV / the AVX-512 state bits */
    aesgcm_cpuidex(1, 0, r);
    if (!(r[2] & (1u << 27))) /* OSXSAVE */
        return 0;
    if ((read_xcr0() & 0xe6) != 0xe6) /* SSE, AVX, opmask, ZMM state */
        return 0;
    /* Reaching here means the OS has AVX-512 state enabled, so CPUID leaf 7
     * (and its AVX-512/VAES feature bits) is present and meaningful. */
    aesgcm_cpuidex(7, 0, r);
    return (r[1] & ebx_need) == ebx_need && (r[2] & ecx_need) == ecx_need;
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
    unsigned char ctr[GCM_BLOCK], ks[GCM_BLOCK];
    size_t off, i;

    memcpy(ctr, J0, GCM_BLOCK);
    for (off = 0; off < len; off += GCM_BLOCK) {
        size_t n = len - off < GCM_BLOCK ? len - off : GCM_BLOCK;

        gcm_inc32(ctr);
        if (!aes_ecb_block(bits, key, ctr, ks))
            return 0;
        for (i = 0; i < n; i++)
            ct[off + i] = (unsigned char)(pt[off + i] ^ ks[i]);
    }
    return 1;
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

    /* Decrypt: split AAD + payload, recover plaintext and verify the tag. */
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
        || !TEST_true(gcm_feed_split(ctx, 0, dec, ct, len)))
        goto err;
    if (!TEST_int_gt(EVP_DecryptFinal_ex(ctx, fin, &tmpl), 0)) {
        TEST_info("AES-%d GCM decrypt tag verification failed: msglen=%zu "
                  "ivlen=%zu aadlen=%zu",
            bits, len, iv_len, aad_len);
        goto err;
    }
    if (len != 0 && !TEST_mem_eq(dec, len, pt, len)) {
        TEST_info("AES-%d GCM plaintext recovery mismatch: msglen=%zu "
                  "ivlen=%zu aadlen=%zu",
            bits, len, iv_len, aad_len);
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

int setup_tests(void)
{
    if (!vaes_avx512_available()) {
        TEST_info("AES-GCM AVX-512/VAES not available on this host; skipping "
                  "(a pass here would not have exercised the VAES/AVX-512 path)");
        return 1;
    }
    ADD_ALL_TESTS(test_gcm_tag, NUM_KEYS * NUM_LENS * NUM_IVS * NUM_AADS);
    return 1;
}
