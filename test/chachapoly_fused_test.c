/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/crypto.h>
#include "crypto/chacha.h"
#include "crypto/poly1305.h"
#include "crypto/chacha_poly1305.h"
#include "testutil.h"

#ifndef CHACHA20_POLY1305_AVX512_CAPABLE

int setup_tests(void)
{
    const char *mode = test_get_argument(0);

    if (mode != NULL && strcmp(mode, "probe") == 0) {
        printf("IFMACAP: 0\n");
        fflush(stdout);
        return 1;
    }
    TEST_info("fused ChaCha20-Poly1305 not built on this platform");
    return 1;
}

#else

#define MAXLEN 16384
#define TAGLEN 16
#define IVLEN 12

static unsigned char key[32];
static unsigned char iv[IVLEN];
static unsigned char aadbuf[256];
static unsigned char plain[MAXLEN];

static const size_t aadlens[] = { 0, 1, 12, 16, 17, 63, 64, 255 };
static const size_t lens[] = {
    0, 1, 15, 16, 17, 31, 63, 64, 65, 127, 128, 191, 192, 193, 255, 256, 257,
    383, 384, 511, 512, 513, 767, 768, 1023, 1024, 1025, 1279, 1400, 1536,
    2048, 3072, 4096, 4097, 8191, 8192
};

/*
 * N-1/N/N+1 at the cutoffs.  192/193 and 960/961 select the park.  255/256
 * builds the r^n table.  AAD 128/129 is the hold limit.
 */
static const struct {
    size_t len;
    size_t aad_len;
} edges[] = {
    { 191, 0 }, { 192, 0 }, { 193, 0 },
    { 255, 0 }, { 256, 0 }, { 257, 0 },
    { 959, 0 }, { 960, 0 }, { 961, 0 },
    { 191, 12 }, { 192, 12 }, { 193, 12 },
    { 255, 12 }, { 256, 12 }, { 257, 12 },
    { 959, 12 }, { 960, 12 }, { 961, 12 },
    { 64, 127 }, { 64, 128 }, { 64, 129 },
    { 3072, 127 }, { 3072, 128 }, { 3072, 129 }
};

static size_t min_sz(size_t a, size_t b)
{
    return a < b ? a : b;
}

static void fill(unsigned char *p, size_t n, unsigned char seed)
{
    size_t i;

    for (i = 0; i < n; i++)
        p[i] = (unsigned char)(seed + i * 7 + (i >> 5));
}

static void load_key_counter(unsigned int k[8], unsigned int ctr[4])
{
    int i;

    for (i = 0; i < 8; i++)
        k[i] = CHACHA_U8TOU32(key + 4 * i);
    ctr[0] = 0;
    for (i = 0; i < 3; i++)
        ctr[i + 1] = CHACHA_U8TOU32(iv + 4 * i);
}

/*
 * RFC 8439 two-pass oracle: ChaCha20_ctr32 then Poly1305_*.  This does not
 * go through the provider, so the fuse decision cannot select the kernel.
 */
static void store_le64(unsigned char *p, uint64_t v)
{
    int i;

    for (i = 0; i < 8; i++)
        p[i] = (unsigned char)(v >> (8 * i));
}

static int ref_seal_kc(unsigned char *out, unsigned char *tag,
    const unsigned char *in, size_t len,
    const unsigned char *aad, size_t aad_len,
    const unsigned int k[8], const unsigned int ctr_in[4])
{
    static const unsigned char zero[CHACHA_BLK_SIZE] = { 0 };
    unsigned char block[CHACHA_BLK_SIZE], pad[POLY1305_BLOCK_SIZE], lenblk[16];
    unsigned int ctr[4];
    POLY1305 poly;
    size_t rem;

    memcpy(ctr, ctr_in, sizeof(ctr));
    ctr[0] = 0;
    ChaCha20_ctr32(block, zero, CHACHA_BLK_SIZE, k, ctr);
    Poly1305_Init(&poly, block);
    OPENSSL_cleanse(block, sizeof(block));

    ctr[0] = 1;
    if (len != 0)
        ChaCha20_ctr32(out, in, len, k, ctr);

    if (aad_len != 0)
        Poly1305_Update(&poly, aad, aad_len);
    rem = aad_len % POLY1305_BLOCK_SIZE;
    if (rem != 0) {
        memset(pad, 0, sizeof(pad));
        Poly1305_Update(&poly, pad, POLY1305_BLOCK_SIZE - rem);
    }
    if (len != 0)
        Poly1305_Update(&poly, out, len);
    rem = len % POLY1305_BLOCK_SIZE;
    if (rem != 0) {
        memset(pad, 0, sizeof(pad));
        Poly1305_Update(&poly, pad, POLY1305_BLOCK_SIZE - rem);
    }
    store_le64(lenblk, (uint64_t)aad_len);
    store_le64(lenblk + 8, (uint64_t)len);
    Poly1305_Update(&poly, lenblk, sizeof(lenblk));
    Poly1305_Final(&poly, tag);
    OPENSSL_cleanse(&poly, sizeof(poly));
    return 1;
}

static int ref_seal(unsigned char *out, unsigned char *tag,
    const unsigned char *in, size_t len,
    const unsigned char *aad, size_t aad_len)
{
    unsigned int k[8], ctr[4];

    load_key_counter(k, ctr);
    return ref_seal_kc(out, tag, in, len, aad, aad_len, k, ctr);
}

/*
 * One EVP update.  That length is the init hint.  Every non-TLS length
 * uses the kernel when it is available, and two-pass otherwise.
 */
static int evp_one_shot_vs_ref(size_t len, size_t aad_len, int seed)
{
    EVP_CIPHER_CTX *cctx = NULL;
    unsigned char *refct = NULL, *ct = NULL;
    unsigned char reftag[TAGLEN], tag[TAGLEN];
    int outl = 0, tmpl = 0, ok = 0;

    fill(key, sizeof(key), (unsigned char)(seed + 11));
    fill(iv, sizeof(iv), (unsigned char)(seed + 41));
    fill(aadbuf, aad_len, (unsigned char)(seed + 91));
    fill(plain, len, (unsigned char)(seed + 151));

    if (!TEST_ptr(refct = OPENSSL_malloc(len + TAGLEN))
        || !TEST_ptr(ct = OPENSSL_malloc(len + TAGLEN))
        || !TEST_true(ref_seal(refct, reftag, plain, len, aadbuf, aad_len))
        || !TEST_ptr(cctx = EVP_CIPHER_CTX_new()))
        goto err;

    if (!TEST_true(EVP_EncryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL,
            key, iv))
        || (aad_len != 0
            && !TEST_true(EVP_EncryptUpdate(cctx, NULL, &outl, aadbuf,
                (int)aad_len)))
        || (len != 0
            && !TEST_true(EVP_EncryptUpdate(cctx, ct, &outl, plain, (int)len)))
        || !TEST_true(EVP_EncryptFinal_ex(cctx, ct + len, &tmpl))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_GET_TAG, TAGLEN,
            tag)))
        goto err;
    if (!TEST_mem_eq(ct, len, refct, len)
        || !TEST_mem_eq(tag, TAGLEN, reftag, TAGLEN))
        goto err;

    /* Decrypt the same way, in place, and let EVP verify the tag. */
    memcpy(ct, refct, len);
    if (!TEST_true(EVP_DecryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL,
            key, iv))
        || (aad_len != 0
            && !TEST_true(EVP_DecryptUpdate(cctx, NULL, &outl, aadbuf,
                (int)aad_len)))
        || (len != 0
            && !TEST_true(EVP_DecryptUpdate(cctx, ct, &outl, ct, (int)len)))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_SET_TAG, TAGLEN,
            reftag))
        || !TEST_true(EVP_DecryptFinal_ex(cctx, ct + len, &tmpl)))
        goto err;
    if (!TEST_mem_eq(ct, len, plain, len))
        goto err;

    /* A corrupt tag must still be rejected on the fused path. */
    memcpy(ct, refct, len);
    reftag[0] ^= 0x80;
    if (!TEST_true(EVP_DecryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL,
            key, iv))
        || (aad_len != 0
            && !TEST_true(EVP_DecryptUpdate(cctx, NULL, &outl, aadbuf,
                (int)aad_len)))
        || (len != 0
            && !TEST_true(EVP_DecryptUpdate(cctx, ct, &outl, ct, (int)len)))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_SET_TAG, TAGLEN,
            reftag)))
        goto err;
    ERR_clear_error();
    if (!TEST_false(EVP_DecryptFinal_ex(cctx, ct + len, &tmpl))
        || !TEST_int_eq(ERR_GET_REASON(ERR_peek_last_error()),
            PROV_R_BAD_DECRYPT))
        goto err;

    ok = 1;
err:
    if (!ok)
        TEST_info("failed at len=%zu aad_len=%zu", len, aad_len);
    EVP_CIPHER_CTX_free(cctx);
    OPENSSL_free(refct);
    OPENSSL_free(ct);
    return ok;
}

static int test_provider(int idx)
{
    const size_t aad_len = aadlens[idx % OSSL_NELEM(aadlens)];
    const size_t len = lens[idx / OSSL_NELEM(aadlens)];

    return evp_one_shot_vs_ref(len, aad_len, idx);
}

static int test_provider_boundary(int idx)
{
    return evp_one_shot_vs_ref(edges[idx].len, edges[idx].aad_len, idx + 200);
}

static int evp_feed_aad(EVP_CIPHER_CTX *cctx, int enc,
    const unsigned char *aad, size_t aad_len, size_t first)
{
    int outl = 0;
    size_t n1;

    if (aad_len == 0)
        return 1;
    n1 = (first == 0 || first >= aad_len) ? aad_len : first;
    if (enc) {
        if (!TEST_true(EVP_EncryptUpdate(cctx, NULL, &outl, aad, (int)n1)))
            return 0;
        if (n1 < aad_len
            && !TEST_true(EVP_EncryptUpdate(cctx, NULL, &outl, aad + n1,
                (int)(aad_len - n1))))
            return 0;
    } else {
        if (!TEST_true(EVP_DecryptUpdate(cctx, NULL, &outl, aad, (int)n1)))
            return 0;
        if (n1 < aad_len
            && !TEST_true(EVP_DecryptUpdate(cctx, NULL, &outl, aad + n1,
                (int)(aad_len - n1))))
            return 0;
    }
    return 1;
}

static int evp_feed_pt(EVP_CIPHER_CTX *cctx, int enc, unsigned char *out,
    const unsigned char *in, size_t len, size_t first)
{
    int outl = 0;
    size_t n1;

    if (len == 0)
        return 1;
    n1 = (first == 0 || first >= len) ? len : first;
    if (enc) {
        if (!TEST_true(EVP_EncryptUpdate(cctx, out, &outl, in, (int)n1)))
            return 0;
        if (n1 < len
            && !TEST_true(EVP_EncryptUpdate(cctx, out + n1, &outl, in + n1,
                (int)(len - n1))))
            return 0;
    } else {
        if (!TEST_true(EVP_DecryptUpdate(cctx, out, &outl, in, (int)n1)))
            return 0;
        if (n1 < len
            && !TEST_true(EVP_DecryptUpdate(cctx, out + n1, &outl, in + n1,
                (int)(len - n1))))
            return 0;
    }
    return 1;
}

/*
 * One decision per message: on when the kernel is available, off for TLS.
 * AAD 129 starts the kernel with hint 0.  Each row is checked against
 * the two-pass oracle.  A zero first_aad or first_pt is one Update.
 */
static const struct {
    size_t len;
    size_t aad_len;
    size_t first_aad;
    size_t first_pt;
} decide_cases[] = {
    /* First payload chunk is the init hint.  192/193 selects the park,
     * 255/256/257 builds the r^n table, and 960/961 claims or drops it. */
    { 3072, 12, 0, 16 },
    { 3072, 12, 0, 191 },
    { 3072, 12, 0, 192 },
    { 3072, 12, 0, 193 },
    { 3072, 12, 0, 255 },
    { 3072, 12, 0, 256 },
    { 3072, 12, 0, 257 },
    { 3072, 12, 0, 960 },
    { 3072, 12, 0, 961 },
    { 3072, 12, 0, 1024 },
    { 3072, 12, 0, 3072 },
    { 2048, 0, 0, 2048 },
    { 1024, 0, 0, 1024 },
    /* Split AAD: 64+64 stays held; 64+65 starts the kernel with hint 0. */
    { 64, 128, 64, 64 },
    { 64, 128, 0, 64 },
    { 64, 129, 64, 64 },
    { 64, 129, 0, 64 },
    { 3072, 129, 0, 3072 },
    { 3072, 128, 80, 16 }
};

static int test_provider_decide(int idx)
{
    const size_t len = decide_cases[idx].len;
    const size_t aad_len = decide_cases[idx].aad_len;
    const size_t first_aad = decide_cases[idx].first_aad;
    const size_t first_pt = decide_cases[idx].first_pt;
    EVP_CIPHER_CTX *cctx = NULL;
    unsigned char *refct = NULL, *ct = NULL;
    unsigned char reftag[TAGLEN], tag[TAGLEN];
    int tmpl = 0, ok = 0;

    fill(key, sizeof(key), (unsigned char)(idx + 19));
    fill(iv, sizeof(iv), (unsigned char)(idx + 47));
    fill(aadbuf, aad_len, (unsigned char)(idx + 89));
    fill(plain, len, (unsigned char)(idx + 131));

    if (!TEST_ptr(refct = OPENSSL_malloc(len + TAGLEN))
        || !TEST_ptr(ct = OPENSSL_malloc(len + TAGLEN))
        || !TEST_true(ref_seal(refct, reftag, plain, len, aadbuf, aad_len))
        || !TEST_ptr(cctx = EVP_CIPHER_CTX_new()))
        goto err;

    if (!TEST_true(EVP_EncryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL,
            key, iv))
        || !TEST_true(evp_feed_aad(cctx, 1, aadbuf, aad_len, first_aad))
        || !TEST_true(evp_feed_pt(cctx, 1, ct, plain, len, first_pt))
        || !TEST_true(EVP_EncryptFinal_ex(cctx, ct + len, &tmpl))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_GET_TAG, TAGLEN,
            tag)))
        goto err;
    if (!TEST_mem_eq(ct, len, refct, len)
        || !TEST_mem_eq(tag, TAGLEN, reftag, TAGLEN))
        goto err;

    memcpy(ct, refct, len);
    if (!TEST_true(EVP_DecryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL,
            key, iv))
        || !TEST_true(evp_feed_aad(cctx, 0, aadbuf, aad_len, first_aad))
        || !TEST_true(evp_feed_pt(cctx, 0, ct, ct, len, first_pt))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_SET_TAG, TAGLEN,
            reftag))
        || !TEST_true(EVP_DecryptFinal_ex(cctx, ct + len, &tmpl)))
        goto err;
    if (!TEST_mem_eq(ct, len, plain, len))
        goto err;

    ok = 1;
err:
    if (!ok)
        TEST_info("decide failed len=%zu aad=%zu first_aad=%zu first_pt=%zu",
            len, aad_len, first_aad, first_pt);
    EVP_CIPHER_CTX_free(cctx);
    OPENSSL_free(refct);
    OPENSSL_free(ct);
    return ok;
}

/*
 * TLS leaves the streaming decision off and calls the one-shot when IFMA
 * is available.  Lengths include an empty record, the park cutoffs, and
 * the maximum record.  The oracle is two-pass.
 *
 * The provider calls ossl_chacha20_poly1305_tls_fused_record when this
 * binary defines it.  The count stays here.
 */
static unsigned int tls_fused_records;

/* Prototype required by -Wmissing-prototypes. */
void ossl_chacha20_poly1305_tls_fused_record(void);
void ossl_chacha20_poly1305_tls_fused_record(void)
{
    tls_fused_records++;
}

static const size_t tls_plens[] = {
    0, 16, 64, 192, 193, 960, 1024, 3072, 16383, 16384
};

static int test_provider_tls(int idx)
{
    const size_t len = tls_plens[idx];
    EVP_CIPHER_CTX *cctx = NULL;
    unsigned char tls_aad[EVP_AEAD_TLS1_AAD_LEN], tls_aad_dec[EVP_AEAD_TLS1_AAD_LEN];
    unsigned char *inbuf = NULL, *outbuf = NULL, *refct = NULL;
    unsigned char reftag[TAGLEN];
    unsigned int k[8], ctr[4];
    int pad, n, ok = 0;
    unsigned int records = tls_fused_records;

    fill(key, sizeof(key), (unsigned char)(idx + 23));
    fill(iv, sizeof(iv), (unsigned char)(idx + 53));
    fill(plain, len, (unsigned char)(idx + 97));

    memset(tls_aad, 0, sizeof(tls_aad));
    /* Non-zero RFC 7905 sequence number, XOR-ed into the ChaCha nonce. */
    tls_aad[0] = 0x01;
    tls_aad[1] = 0x23;
    tls_aad[2] = 0x45;
    tls_aad[3] = 0x67;
    tls_aad[4] = 0x89;
    tls_aad[5] = 0xab;
    tls_aad[6] = 0xcd;
    tls_aad[7] = 0xef;
    tls_aad[8] = 23; /* SSL3_RT_APPLICATION_DATA */
    tls_aad[9] = 3;
    tls_aad[10] = 3; /* TLS 1.2 */
    tls_aad[11] = (unsigned char)(len >> 8);
    tls_aad[12] = (unsigned char)len;
    memcpy(tls_aad_dec, tls_aad, sizeof(tls_aad));
    tls_aad_dec[11] = (unsigned char)((len + TAGLEN) >> 8);
    tls_aad_dec[12] = (unsigned char)(len + TAGLEN);

    /* RFC 7905: sequence number is XOR'd into the ChaCha20 nonce. */
    load_key_counter(k, ctr);
    ctr[2] ^= CHACHA_U8TOU32(tls_aad);
    ctr[3] ^= CHACHA_U8TOU32(tls_aad + 4);

    if (!TEST_ptr(refct = OPENSSL_malloc(len + TAGLEN))
        || !TEST_ptr(inbuf = OPENSSL_malloc(len + TAGLEN))
        || !TEST_ptr(outbuf = OPENSSL_malloc(len + TAGLEN))
        || !TEST_true(ref_seal_kc(refct, reftag, plain, len, tls_aad,
            EVP_AEAD_TLS1_AAD_LEN, k, ctr))
        || !TEST_ptr(cctx = EVP_CIPHER_CTX_new()))
        goto err;

    memcpy(inbuf, plain, len);
    memset(inbuf + len, 0, TAGLEN);
    if (!TEST_true(EVP_EncryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL,
            key, iv)))
        goto err;
    pad = EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_TLS1_AAD,
        EVP_AEAD_TLS1_AAD_LEN, tls_aad);
    if (!TEST_int_eq(pad, TAGLEN))
        goto err;
    n = EVP_Cipher(cctx, outbuf, inbuf, (unsigned int)(len + pad));
    if (!TEST_int_gt(n, 0)
        || !TEST_mem_eq(outbuf, len, refct, len)
        || !TEST_mem_eq(outbuf + len, TAGLEN, reftag, TAGLEN))
        goto err;

    memcpy(inbuf, outbuf, len + TAGLEN);
    if (!TEST_true(EVP_DecryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL,
            key, iv)))
        goto err;
    pad = EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_TLS1_AAD,
        EVP_AEAD_TLS1_AAD_LEN, tls_aad_dec);
    if (!TEST_int_eq(pad, TAGLEN))
        goto err;
    n = EVP_Cipher(cctx, outbuf, inbuf, (unsigned int)(len + pad));
    /*
     * EVP_Cipher returns the plaintext byte count.  An empty record
     * succeeds with 0; a tag failure returns -1.
     */
    if (!TEST_int_eq(n, (int)len) || !TEST_mem_eq(outbuf, len, plain, len))
        goto err;

    /* In-place record.  TLS encryption uses one buffer for input and output. */
    memcpy(outbuf, plain, len);
    memset(outbuf + len, 0, TAGLEN);
    if (!TEST_true(EVP_EncryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL,
            key, iv)))
        goto err;
    pad = EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_TLS1_AAD,
        EVP_AEAD_TLS1_AAD_LEN, tls_aad);
    if (!TEST_int_eq(pad, TAGLEN))
        goto err;
    n = EVP_Cipher(cctx, outbuf, outbuf, (unsigned int)(len + pad));
    if (!TEST_int_gt(n, 0)
        || !TEST_mem_eq(outbuf, len, refct, len)
        || !TEST_mem_eq(outbuf + len, TAGLEN, reftag, TAGLEN))
        goto err;

    if (!TEST_true(EVP_DecryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL,
            key, iv)))
        goto err;
    pad = EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_TLS1_AAD,
        EVP_AEAD_TLS1_AAD_LEN, tls_aad_dec);
    if (!TEST_int_eq(pad, TAGLEN))
        goto err;
    n = EVP_Cipher(cctx, outbuf, outbuf, (unsigned int)(len + pad));
    if (!TEST_int_eq(n, (int)len) || !TEST_mem_eq(outbuf, len, plain, len))
        goto err;

    /*
     * A bad tag fails quietly.  The record layer maps that to
     * bad_record_mac, so the provider must not raise PROV_R_BAD_DECRYPT.
     * Plaintext already written is wiped.
     */
    memcpy(outbuf, refct, len);
    memcpy(outbuf + len, reftag, TAGLEN);
    outbuf[len] ^= 0x80;
    if (!TEST_true(EVP_DecryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL,
            key, iv)))
        goto err;
    pad = EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_TLS1_AAD,
        EVP_AEAD_TLS1_AAD_LEN, tls_aad_dec);
    if (!TEST_int_eq(pad, TAGLEN))
        goto err;
    ERR_clear_error();
    n = EVP_Cipher(cctx, outbuf, outbuf, (unsigned int)(len + pad));
    if (!TEST_int_lt(n, 0) || !TEST_int_eq(ERR_peek_error(), 0))
        goto err;
    if (len != 0) {
        size_t zi;
        int wiped = 1;

        for (zi = 0; zi < len; zi++) {
            if (outbuf[zi] != 0)
                wiped = 0;
        }
        if (!TEST_true(wiped))
            goto err;
    }

    /*
     * Five records above.  With IFMA each one enters the one-shot kernel.
     * Without it the count stays put and two-pass runs.
     */
    if (ossl_chacha20_poly1305_avx512_available()) {
        if (!TEST_uint_eq(tls_fused_records, records + 5))
            goto err;
    } else if (!TEST_uint_eq(tls_fused_records, records)) {
        goto err;
    }

    ok = 1;
err:
    if (!ok)
        TEST_info("TLS record failed at plen=%zu", len);
    EVP_CIPHER_CTX_free(cctx);
    OPENSSL_free(refct);
    OPENSSL_free(inbuf);
    OPENSSL_free(outbuf);
    return ok;
}

/*
 * Recipe-driven dump: hash one-shot EVP ciphertext and tag over the cutoffs so
 * a native IFMA run can be compared to OPENSSL_ia32cap with IFMA cleared.
 */
static int test_dump(void)
{
    static const char hexd[] = "0123456789abcdef";
    EVP_MD_CTX *md = NULL;
    EVP_CIPHER_CTX *cctx = NULL;
    unsigned char *ct = NULL;
    unsigned char tag[TAGLEN], digest[EVP_MAX_MD_SIZE];
    char hex[2 * EVP_MAX_MD_SIZE + 1];
    unsigned int dlen = 0, i;
    size_t ei;
    int outl = 0, tmpl = 0, ok = 0;

    if (!TEST_ptr(ct = OPENSSL_malloc(MAXLEN + TAGLEN))
        || !TEST_ptr(cctx = EVP_CIPHER_CTX_new())
        || !TEST_ptr(md = EVP_MD_CTX_new())
        || !TEST_true(EVP_DigestInit_ex(md, EVP_sha256(), NULL)))
        goto err;

    for (ei = 0; ei < OSSL_NELEM(edges); ei++) {
        const size_t len = edges[ei].len;
        const size_t aad_len = edges[ei].aad_len;
        unsigned char hdr[16];

        fill(key, sizeof(key), (unsigned char)(ei + 3));
        fill(iv, sizeof(iv), (unsigned char)(ei + 7));
        fill(aadbuf, aad_len, (unsigned char)(ei + 11));
        fill(plain, len, (unsigned char)(ei + 13));

        if (!TEST_true(EVP_EncryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL,
                key, iv))
            || (aad_len != 0
                && !TEST_true(EVP_EncryptUpdate(cctx, NULL, &outl, aadbuf,
                    (int)aad_len)))
            || (len != 0
                && !TEST_true(EVP_EncryptUpdate(cctx, ct, &outl, plain,
                    (int)len)))
            || !TEST_true(EVP_EncryptFinal_ex(cctx, ct + len, &tmpl))
            || !TEST_true(EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_GET_TAG,
                TAGLEN, tag)))
            goto err;

        memset(hdr, 0, sizeof(hdr));
        hdr[0] = (unsigned char)len;
        hdr[1] = (unsigned char)(len >> 8);
        hdr[2] = (unsigned char)aad_len;
        if (!TEST_true(EVP_DigestUpdate(md, hdr, sizeof(hdr)))
            || !TEST_true(EVP_DigestUpdate(md, ct, len))
            || !TEST_true(EVP_DigestUpdate(md, tag, TAGLEN)))
            goto err;
    }

    if (!TEST_true(EVP_DigestFinal_ex(md, digest, &dlen)))
        goto err;
    for (i = 0; i < dlen; i++) {
        hex[2 * i] = hexd[digest[i] >> 4];
        hex[2 * i + 1] = hexd[digest[i] & 0x0f];
    }
    hex[2 * dlen] = '\0';
    printf("DIFFDIGEST: IFMA=%d %s\n",
        ossl_chacha20_poly1305_avx512_available() ? 1 : 0, hex);
    fflush(stdout);
    ok = 1;
err:
    EVP_MD_CTX_free(md);
    EVP_CIPHER_CTX_free(cctx);
    OPENSSL_free(ct);
    return ok;
}

static int test_against_evp(int idx)
{
    const size_t aad_len = aadlens[idx % OSSL_NELEM(aadlens)];
    const size_t len = lens[idx / OSSL_NELEM(aadlens)];
    unsigned char *refct = NULL, *ct = NULL, *pt = NULL;
    unsigned char reftag[TAGLEN], tag[TAGLEN];
    unsigned int k[8], ctr[4];
    int ok = 0;

    fill(key, sizeof(key), (unsigned char)(idx + 1));
    fill(iv, sizeof(iv), (unsigned char)(idx + 33));
    fill(aadbuf, aad_len, (unsigned char)(idx + 77));
    fill(plain, len, (unsigned char)(idx + 129));
    load_key_counter(k, ctr);

    if (!TEST_ptr(refct = OPENSSL_malloc(len + TAGLEN))
        || !TEST_ptr(ct = OPENSSL_malloc(len + TAGLEN))
        || !TEST_ptr(pt = OPENSSL_malloc(len + TAGLEN)))
        goto err;

    if (!TEST_true(ref_seal(refct, reftag, plain, len, aadbuf, aad_len)))
        goto err;

    /* Encrypt: ciphertext and tag must match the reference exactly. */
    if (!TEST_true(ossl_chacha20_poly1305_avx512(ct, plain, len, aadbuf,
            aad_len, k, ctr, tag, 1)))
        goto err;
    if (!TEST_mem_eq(ct, len, refct, len)
        || !TEST_mem_eq(tag, TAGLEN, reftag, TAGLEN))
        goto err;

    /* Decrypt: recover the plaintext and reproduce the same tag. */
    memset(tag, 0, sizeof(tag));
    if (!TEST_true(ossl_chacha20_poly1305_avx512(pt, refct, len, aadbuf,
            aad_len, k, ctr, tag, 0)))
        goto err;
    if (!TEST_mem_eq(pt, len, plain, len)
        || !TEST_mem_eq(tag, TAGLEN, reftag, TAGLEN))
        goto err;

    /* In-place encrypt. */
    memcpy(ct, plain, len);
    memset(tag, 0, sizeof(tag));
    if (!TEST_true(ossl_chacha20_poly1305_avx512(ct, ct, len, aadbuf, aad_len,
            k, ctr, tag, 1)))
        goto err;
    if (!TEST_mem_eq(ct, len, refct, len)
        || !TEST_mem_eq(tag, TAGLEN, reftag, TAGLEN))
        goto err;

    /* In-place decrypt. */
    memcpy(pt, refct, len);
    memset(tag, 0, sizeof(tag));
    if (!TEST_true(ossl_chacha20_poly1305_avx512(pt, pt, len, aadbuf, aad_len,
            k, ctr, tag, 0)))
        goto err;
    if (!TEST_mem_eq(pt, len, plain, len)
        || !TEST_mem_eq(tag, TAGLEN, reftag, TAGLEN))
        goto err;

    ok = 1;
err:
    if (!ok)
        TEST_info("failed at len=%zu aad_len=%zu", len, aad_len);
    OPENSSL_free(refct);
    OPENSSL_free(ct);
    OPENSSL_free(pt);
    return ok;
}

/*
 * Same vectors, but the AAD and the payload are handed to the streaming
 * interface in uneven pieces.  The chunk sizes include lengths that are not
 * multiples of the 64-byte ChaCha20 block or the 16-byte Poly1305 block, so
 * the carried keystream and the partial MAC block get exercised together.
 */
static int test_streaming(int idx)
{
    static const size_t chunks[] = { 1, 7, 16, 33, 64, 100, 127, 256, 999,
        1024, 1200, 4096 };
    const size_t aad_len = aadlens[idx % OSSL_NELEM(aadlens)];
    const size_t len = lens[idx / OSSL_NELEM(aadlens)];
    unsigned char *refct = NULL, *ct = NULL;
    unsigned char reftag[TAGLEN], tag[TAGLEN];
    unsigned int k[8], ctr[4];
    size_t ci, off;
    int ok = 0;

    fill(key, sizeof(key), (unsigned char)(idx + 5));
    fill(iv, sizeof(iv), (unsigned char)(idx + 37));
    fill(aadbuf, aad_len, (unsigned char)(idx + 81));
    fill(plain, len, (unsigned char)(idx + 133));
    load_key_counter(k, ctr);

    if (!TEST_ptr(refct = OPENSSL_malloc(len + TAGLEN))
        || !TEST_ptr(ct = OPENSSL_malloc(len + TAGLEN)))
        goto err;

    if (!TEST_true(ref_seal(refct, reftag, plain, len, aadbuf, aad_len)))
        goto err;

    for (ci = 0; ci < OSSL_NELEM(chunks); ci++) {
        const size_t step = chunks[ci];
        OSSL_CP_AVX512_CTX c;

        /* Encrypt out of place, feeding both the AAD and the payload in
         * step-sized pieces. */
        ossl_chacha20_poly1305_avx512_init(&c, k, ctr, len);
        for (off = 0; off < aad_len; off += step)
            ossl_chacha20_poly1305_avx512_aad(&c, aadbuf + off,
                min_sz(step, aad_len - off));
        ossl_chacha20_poly1305_avx512_aad_done(&c);
        for (off = 0; off < len; off += step)
            ossl_chacha20_poly1305_avx512_cipher(&c, ct + off, plain + off,
                min_sz(step, len - off), 1);
        memset(tag, 0, sizeof(tag));
        ossl_chacha20_poly1305_avx512_final(&c, tag, aad_len, len);

        if (!TEST_mem_eq(ct, len, refct, len)
            || !TEST_mem_eq(tag, TAGLEN, reftag, TAGLEN)) {
            TEST_info("encrypt chunk=%zu", step);
            goto err;
        }

        /* Decrypt in place, which is the case where the MAC has to read the
         * ciphertext before the XOR overwrites it. */
        memcpy(ct, refct, len);
        ossl_chacha20_poly1305_avx512_init(&c, k, ctr, len);
        for (off = 0; off < aad_len; off += step)
            ossl_chacha20_poly1305_avx512_aad(&c, aadbuf + off,
                min_sz(step, aad_len - off));
        ossl_chacha20_poly1305_avx512_aad_done(&c);
        for (off = 0; off < len; off += step)
            ossl_chacha20_poly1305_avx512_cipher(&c, ct + off, ct + off,
                min_sz(step, len - off), 0);
        memset(tag, 0, sizeof(tag));
        ossl_chacha20_poly1305_avx512_final(&c, tag, aad_len, len);

        if (!TEST_mem_eq(ct, len, plain, len)
            || !TEST_mem_eq(tag, TAGLEN, reftag, TAGLEN)) {
            TEST_info("decrypt chunk=%zu", step);
            goto err;
        }
    }

    ok = 1;
err:
    if (!ok)
        TEST_info("failed at len=%zu aad_len=%zu", len, aad_len);
    OPENSSL_free(refct);
    OPENSSL_free(ct);
    return ok;
}

/* RFC 8439 section 2.8.2. */
static int test_rfc8439_vector(void)
{
    static const unsigned char rfc_key[32] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    static const unsigned char rfc_iv[IVLEN] = {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
    };
    static const unsigned char rfc_aad[12] = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7
    };
    static const char rfc_pt[] = "Ladies and Gentlemen of the class of '99: If I could offer you only "
                                 "one tip for the future, sunscreen would be it.";
    static const unsigned char rfc_tag[TAGLEN] = {
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
    };
    static const unsigned char rfc_ct[] = {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc,
        0x53, 0xef, 0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e,
        0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
        0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
        0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65,
        0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16
    };
    const size_t len = sizeof(rfc_pt) - 1;
    unsigned char ct[sizeof(rfc_ct)], tag[TAGLEN];
    unsigned int k[8], ctr[4];

    memcpy(key, rfc_key, sizeof(key));
    memcpy(iv, rfc_iv, sizeof(iv));
    load_key_counter(k, ctr);

    if (!TEST_size_t_eq(len, sizeof(rfc_ct)))
        return 0;
    if (!TEST_true(ossl_chacha20_poly1305_avx512(ct, (const unsigned char *)rfc_pt,
            len, rfc_aad, sizeof(rfc_aad),
            k, ctr, tag, 1)))
        return 0;
    return TEST_mem_eq(ct, len, rfc_ct, sizeof(rfc_ct))
        && TEST_mem_eq(tag, TAGLEN, rfc_tag, TAGLEN);
}

/*
 * Repeated equal updates, with the init hint equal to one update.  A
 * 1024-byte encrypt stores the next chunk from the second call on, and only
 * when the previous call left no partial park.  A short update after that
 * spends the prefetched chunk as an ordinary park.
 */
static int test_repeated_updates(int idx)
{
    static const struct {
        size_t step;
        int reps;
        size_t tail;
        size_t aad_len;
        size_t hint;
    } cases[] = {
        { 768, 1, 0, 0, 768 },
        { 768, 2, 0, 0, 768 },
        { 768, 4, 0, 13, 768 },
        { 768, 8, 0, 16, 768 },
        { 896, 1, 0, 0, 896 },
        { 896, 3, 0, 13, 896 },
        { 896, 4, 0, 7, 896 },
        { 1024, 1, 0, 0, 1024 },
        { 1024, 2, 0, 0, 1024 },
        { 1024, 4, 0, 13, 1024 },
        { 1024, 3, 50, 0, 1024 },
        { 1024, 3, 1, 13, 1024 },
        { 768, 3, 0, 0, 0 },
        { 1024, 3, 17, 0, 0 }
    };
    const size_t step = cases[idx].step;
    const int reps = cases[idx].reps;
    const size_t tail = cases[idx].tail;
    const size_t aad_len = cases[idx].aad_len;
    const size_t hint = cases[idx].hint;
    const size_t len = step * (size_t)reps + tail;
    unsigned char *refct = NULL, *ct = NULL, *pt = NULL;
    unsigned char reftag[TAGLEN], tag[TAGLEN];
    unsigned int k[8], ctr[4];
    OSSL_CP_AVX512_CTX c;
    size_t off;
    int r, ok = 0;

    fill(key, sizeof(key), (unsigned char)(idx + 9));
    fill(iv, sizeof(iv), (unsigned char)(idx + 19));
    fill(aadbuf, aad_len, (unsigned char)(idx + 29));
    fill(plain, len, (unsigned char)(idx + 39));
    load_key_counter(k, ctr);

    if (!TEST_ptr(refct = OPENSSL_malloc(len + TAGLEN))
        || !TEST_ptr(ct = OPENSSL_malloc(len + TAGLEN))
        || !TEST_ptr(pt = OPENSSL_malloc(len + TAGLEN))
        || !TEST_true(ref_seal(refct, reftag, plain, len, aadbuf, aad_len)))
        goto err;

    ossl_chacha20_poly1305_avx512_init(&c, k, ctr, hint);
    if (aad_len != 0)
        ossl_chacha20_poly1305_avx512_aad(&c, aadbuf, aad_len);
    ossl_chacha20_poly1305_avx512_aad_done(&c);
    for (r = 0; r < reps; r++) {
        off = step * (size_t)r;
        ossl_chacha20_poly1305_avx512_cipher(&c, ct + off, plain + off, step, 1);
    }
    if (tail != 0)
        ossl_chacha20_poly1305_avx512_cipher(&c, ct + step * (size_t)reps,
            plain + step * (size_t)reps, tail, 1);
    memset(tag, 0, sizeof(tag));
    ossl_chacha20_poly1305_avx512_final(&c, tag, aad_len, len);
    if (!TEST_mem_eq(ct, len, refct, len)
        || !TEST_mem_eq(tag, TAGLEN, reftag, TAGLEN)) {
        TEST_info("encrypt step=%zu reps=%d tail=%zu hint=%zu",
            step, reps, tail, hint);
        goto err;
    }

    /* In-place decrypt of the same split. */
    memcpy(pt, refct, len);
    ossl_chacha20_poly1305_avx512_init(&c, k, ctr, hint);
    if (aad_len != 0)
        ossl_chacha20_poly1305_avx512_aad(&c, aadbuf, aad_len);
    ossl_chacha20_poly1305_avx512_aad_done(&c);
    for (r = 0; r < reps; r++) {
        off = step * (size_t)r;
        ossl_chacha20_poly1305_avx512_cipher(&c, pt + off, pt + off, step, 0);
    }
    if (tail != 0) {
        off = step * (size_t)reps;
        ossl_chacha20_poly1305_avx512_cipher(&c, pt + off, pt + off, tail, 0);
    }
    memset(tag, 0, sizeof(tag));
    ossl_chacha20_poly1305_avx512_final(&c, tag, aad_len, len);
    if (!TEST_mem_eq(pt, len, plain, len)
        || !TEST_mem_eq(tag, TAGLEN, reftag, TAGLEN)) {
        TEST_info("decrypt step=%zu reps=%d tail=%zu hint=%zu",
            step, reps, tail, hint);
        goto err;
    }

    ok = 1;
err:
    OPENSSL_free(refct);
    OPENSSL_free(ct);
    OPENSSL_free(pt);
    return ok;
}

/*
 * Block 0 is the one-time Poly1305 key, so the payload stops at counter 2^32-1.
 * A rejected update must not move the MAC: the following short update still
 * matches a message of only the bytes that were accepted.
 */
static int test_counter_limit(void)
{
    OSSL_CP_AVX512_CTX c;
    unsigned char in[32], out[32], refct[32];
    unsigned char tag[TAGLEN], reftag[TAGLEN];
    unsigned int k[8], ctr[4];
    const uint64_t max = OSSL_CP_AVX512_MAX_TEXT;

    memset(key, 0x11, sizeof(key));
    memset(iv, 0x22, sizeof(iv));
    memset(in, 0x33, sizeof(in));
    load_key_counter(k, ctr);

    if (!TEST_false(ossl_chacha20_poly1305_avx512(out, in, (size_t)(max + 1),
            NULL, 0, k, ctr, tag, 1)))
        return 0;

    ossl_chacha20_poly1305_avx512_init(&c, k, ctr, 0);
    ossl_chacha20_poly1305_avx512_aad_done(&c);
    if (!TEST_false(ossl_chacha20_poly1305_avx512_cipher(&c, NULL, NULL,
            (size_t)(max + 1), 1))
        || !TEST_false(ossl_chacha20_poly1305_avx512_cipher(&c, NULL, NULL,
            (size_t)(max + 1), 0))
        || !TEST_true(ossl_chacha20_poly1305_avx512_cipher(&c, out, in, 16, 1))
        || !TEST_false(ossl_chacha20_poly1305_avx512_cipher(&c, NULL, NULL,
            (size_t)(max - 15), 1))
        || !TEST_true(ossl_chacha20_poly1305_avx512_cipher(&c, out + 16,
            in + 16, 16, 1)))
        return 0;
    ossl_chacha20_poly1305_avx512_final(&c, tag, 0, 32);

    if (!TEST_true(ref_seal(refct, reftag, in, 32, NULL, 0))
        || !TEST_mem_eq(out, 32, refct, 32)
        || !TEST_mem_eq(tag, TAGLEN, reftag, TAGLEN))
        return 0;
    return 1;
}

/*
 * A TLS additional-data length shorter than the tag is rejected.  So is a
 * record whose buffer length does not match that additional data.
 */
static int test_tls_rejects(void)
{
    EVP_CIPHER_CTX *cctx = NULL;
    unsigned char aad[EVP_AEAD_TLS1_AAD_LEN];
    unsigned char buf[80];
    int pad, n, ok = 0;

    memset(key, 0x41, sizeof(key));
    memset(iv, 0x52, sizeof(iv));
    memset(buf, 0x63, sizeof(buf));
    memset(aad, 0, sizeof(aad));
    aad[8] = 23;
    aad[9] = 3;
    aad[10] = 3;

    if (!TEST_ptr(cctx = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_DecryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL,
            key, iv)))
        goto err;

    aad[11] = 0;
    aad[12] = 15; /* shorter than the 16-byte tag */
    ERR_clear_error();
    pad = EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_TLS1_AAD,
        EVP_AEAD_TLS1_AAD_LEN, aad);
    if (!TEST_int_le(pad, 0)
        || !TEST_int_eq(ERR_GET_REASON(ERR_peek_last_error()),
            PROV_R_INVALID_DATA))
        goto err;

    /* AAD says 64 bytes of plaintext, so the cipher buffer must be 80. */
    aad[12] = 64;
    if (!TEST_true(EVP_EncryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL,
            key, iv)))
        goto err;
    pad = EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_TLS1_AAD,
        EVP_AEAD_TLS1_AAD_LEN, aad);
    if (!TEST_int_eq(pad, TAGLEN))
        goto err;
    n = EVP_Cipher(cctx, buf, buf, 64);
    if (!TEST_int_lt(n, 0))
        goto err;
    n = EVP_Cipher(cctx, buf, buf, 81);
    if (!TEST_int_lt(n, 0))
        goto err;

    if (!TEST_true(EVP_EncryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL,
            key, iv)))
        goto err;
    pad = EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_TLS1_AAD,
        EVP_AEAD_TLS1_AAD_LEN, aad);
    if (!TEST_int_eq(pad, TAGLEN))
        goto err;
    n = EVP_Cipher(cctx, buf, buf, 80);
    if (!TEST_int_eq(n, 80))
        goto err;

    ok = 1;
err:
    EVP_CIPHER_CTX_free(cctx);
    return ok;
}

/*
 * Callers may ask for a tag shorter than 16 bytes.  The accepted prefix
 * matches the full tag, and a flipped bit inside that prefix is rejected.
 */
static int test_truncated_tag(int idx)
{
    static const int taglens[] = { 1, 8, 15 };
    const int taglen = taglens[idx];
    const size_t len = 300;
    const size_t aad_len = 12;
    EVP_CIPHER_CTX *cctx = NULL;
    unsigned char *ct = NULL, *pt = NULL;
    unsigned char full[TAGLEN], shorttag[TAGLEN];
    int outl = 0, tmpl = 0, ok = 0;

    fill(key, sizeof(key), (unsigned char)(idx + 17));
    fill(iv, sizeof(iv), (unsigned char)(idx + 29));
    fill(aadbuf, aad_len, (unsigned char)(idx + 43));
    fill(plain, len, (unsigned char)(idx + 61));

    if (!TEST_ptr(ct = OPENSSL_malloc(len))
        || !TEST_ptr(pt = OPENSSL_malloc(len))
        || !TEST_ptr(cctx = EVP_CIPHER_CTX_new()))
        goto err;

    if (!TEST_true(EVP_EncryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL,
            key, iv))
        || !TEST_true(EVP_EncryptUpdate(cctx, NULL, &outl, aadbuf,
            (int)aad_len))
        || !TEST_true(EVP_EncryptUpdate(cctx, ct, &outl, plain, (int)len))
        || !TEST_true(EVP_EncryptFinal_ex(cctx, ct + len, &tmpl))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_GET_TAG, TAGLEN,
            full))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_GET_TAG, taglen,
            shorttag)))
        goto err;
    if (!TEST_mem_eq(shorttag, taglen, full, taglen))
        goto err;

    memcpy(pt, ct, len);
    if (!TEST_true(EVP_DecryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL,
            key, iv))
        || !TEST_true(EVP_DecryptUpdate(cctx, NULL, &outl, aadbuf,
            (int)aad_len))
        || !TEST_true(EVP_DecryptUpdate(cctx, pt, &outl, pt, (int)len))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_SET_TAG, taglen,
            shorttag))
        || !TEST_true(EVP_DecryptFinal_ex(cctx, pt + len, &tmpl)))
        goto err;
    if (!TEST_mem_eq(pt, len, plain, len))
        goto err;

    shorttag[taglen - 1] ^= 0x01;
    memcpy(pt, ct, len);
    if (!TEST_true(EVP_DecryptInit_ex(cctx, EVP_chacha20_poly1305(), NULL,
            key, iv))
        || !TEST_true(EVP_DecryptUpdate(cctx, NULL, &outl, aadbuf,
            (int)aad_len))
        || !TEST_true(EVP_DecryptUpdate(cctx, pt, &outl, pt, (int)len))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_AEAD_SET_TAG, taglen,
            shorttag)))
        goto err;
    ERR_clear_error();
    if (!TEST_false(EVP_DecryptFinal_ex(cctx, pt + len, &tmpl))
        || !TEST_int_eq(ERR_GET_REASON(ERR_peek_last_error()),
            PROV_R_BAD_DECRYPT))
        goto err;

    ok = 1;
err:
    if (!ok)
        TEST_info("truncated tag failed at %d bytes", taglen);
    EVP_CIPHER_CTX_free(cctx);
    OPENSSL_free(ct);
    OPENSSL_free(pt);
    return ok;
}

int setup_tests(void)
{
    const char *mode = test_get_argument(0);
    int cap = ossl_chacha20_poly1305_avx512_available();

    if (mode != NULL && strcmp(mode, "probe") == 0) {
        printf("IFMACAP: %d\n", cap ? 1 : 0);
        fflush(stdout);
        return 1;
    }
    if (mode != NULL && strcmp(mode, "dump") == 0) {
        ADD_TEST(test_dump);
        return 1;
    }

    /*
     * Kernel tests need IFMA.  EVP against the two-pass oracle still runs
     * without it, so the ia32cap-masked host is covered.
     */
    if (cap) {
        ADD_TEST(test_rfc8439_vector);
        ADD_ALL_TESTS(test_against_evp, OSSL_NELEM(lens) * OSSL_NELEM(aadlens));
        ADD_ALL_TESTS(test_streaming, OSSL_NELEM(lens) * OSSL_NELEM(aadlens));
        ADD_ALL_TESTS(test_repeated_updates, 14);
        ADD_TEST(test_counter_limit);
    } else {
        TEST_info("CPU lacks AVX512F/VL/IFMA/BMI2/ADX; kernel tests skipped");
    }
    ADD_ALL_TESTS(test_provider, OSSL_NELEM(lens) * OSSL_NELEM(aadlens));
    ADD_ALL_TESTS(test_provider_boundary, OSSL_NELEM(edges));
    ADD_ALL_TESTS(test_provider_decide, OSSL_NELEM(decide_cases));
    ADD_ALL_TESTS(test_provider_tls, OSSL_NELEM(tls_plens));
    ADD_TEST(test_tls_rejects);
    ADD_ALL_TESTS(test_truncated_tag, 3);
    return 1;
}

#endif /* CHACHA20_POLY1305_AVX512_CAPABLE */
