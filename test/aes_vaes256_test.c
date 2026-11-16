/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (C) 2026, Advanced Micro Devices, all rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * VAES-256 CTR, CFB128 and CBC decryption against AES-NI.
 *
 * CPUs with AVX-512 VAES take the 512-bit kernels, so make test on those
 * machines never enters this code. The test clears AVX512F, AVX512DQ,
 * AVX512BW and AVX512VL in OPENSSL_ia32cap_P[2] before each operation.
 * That is the mask OPENSSL_ia32cap=:~0xC0030000. AVX2 (P[2] bit 5) and
 * VAES (P[3] bit 9) stay set, which is what the 256-bit dispatch requires.
 * The reference run clears VAES as well and stays on AES-NI.
 *
 * CTR enters the wide kernel at 64 bytes. CBC decryption enters at 256
 * bytes. Shorter inputs stay on AES-NI inside the wrapper, and those
 * lengths are still compared. CFB128 has no length threshold.
 */

#include <string.h>

/*
 * aes_platform.h uses AES_KEY. That type is hidden from public headers when
 * the library is configured no-deprecated, which is what the no-deprecated
 * and minimal CI jobs do. This has to come before any other OpenSSL header.
 */
#include "internal/deprecated.h"

#include <openssl/evp.h>
#include "internal/cryptlib.h"
#include "internal/nelem.h"
#include "crypto/aes_platform.h"
#include "testutil.h"

#if !VAES256_ELIGIBLE

static int test_vaes256(void)
{
    return TEST_skip("VAES-256 kernels are not built");
}

#else

#define MAX_LEN 4096

/*
 * Low 32 bits of the second OPENSSL_ia32cap word: AVX512F, AVX512DQ,
 * AVX512BW and AVX512VL. Clearing these leaves AVX2 and VAES in place.
 */
#define VAES256_CLEAR_AVX512 ((1u << 16) | (1u << 17) | (1u << 30) | (1u << 31))
#define VAES_CAP_BIT (1u << 9) /* OPENSSL_ia32cap_P[3], CPUID leaf 7 ECX */

struct cap_save {
    unsigned int p2;
    unsigned int p3;
};

static void cap_save(struct cap_save *saved)
{
    saved->p2 = OPENSSL_ia32cap_P[2];
    saved->p3 = OPENSSL_ia32cap_P[3];
}

static void cap_restore(const struct cap_save *saved)
{
    OPENSSL_ia32cap_P[2] = saved->p2;
    OPENSSL_ia32cap_P[3] = saved->p3;
}

/* Force the 256-bit path on a machine that also has AVX-512 VAES. */
static void hide_avx512(void)
{
    OPENSSL_ia32cap_P[2] &= ~VAES256_CLEAR_AVX512;
}

static void hide_vaes(void)
{
    OPENSSL_ia32cap_P[3] &= ~VAES_CAP_BIT;
}

static int cpu_has_vaes256(void)
{
    return (OPENSSL_ia32cap_P[1] & (1u << (57 - 32))) /* AES-NI */
        && (OPENSSL_ia32cap_P[2] & (1u << 5)) /* AVX2 */
        && (OPENSSL_ia32cap_P[3] & VAES_CAP_BIT); /* VAES */
}

static int vaes256_selected(void)
{
    int ok = 1;

#if VAES256_CTR_ELIGIBLE
    ok = ok && TEST_true(ossl_aes_ctr_vaes256_eligible());
#endif
#if VAES256_CBC_ELIGIBLE
    ok = ok && TEST_true(ossl_aes_cbc_vaes256_eligible());
#endif
#if VAES256_CFB_ELIGIBLE
    ok = ok && TEST_true(ossl_aes_cfb128_vaes256_eligible());
#endif
    return ok;
}

static int cipher_update(const EVP_CIPHER *cipher, int enc,
    const unsigned char *key, const unsigned char *iv,
    const unsigned char *in, int len, unsigned char *out, int split)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int outl = 0, outl2 = 0, fin = 0, ok = 0;
    int first = split;

    if (first <= 0 || first >= len)
        first = len;

    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_CipherInit_ex2(ctx, cipher, key, iv, enc, NULL))
        || !TEST_true(EVP_CIPHER_CTX_set_padding(ctx, 0))
        || !TEST_true(EVP_CipherUpdate(ctx, out, &outl, in, first)))
        goto end;

    if (first < len) {
        if (!TEST_true(EVP_CipherUpdate(ctx, out + outl, &outl2,
                in + first, len - first)))
            goto end;
        outl += outl2;
    }

    if (!TEST_true(EVP_CipherFinal_ex(ctx, out + outl, &fin))
        || !TEST_int_eq(outl + fin, len))
        goto end;
    ok = 1;

end:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/*
 * vaes_path selects the 256-bit kernels. The other path clears VAES and
 * uses AES-NI. Both hide AVX-512, so the reference is not the 512-bit code.
 */
static int crypt_path(const EVP_CIPHER *cipher, int enc, int vaes_path,
    const unsigned char *key, const unsigned char *iv,
    const unsigned char *in, int len, unsigned char *out, int split)
{
    struct cap_save saved;
    int ok;

    cap_save(&saved);
    hide_avx512();
    if (!vaes_path)
        hide_vaes();
    ok = cipher_update(cipher, enc, key, iv, in, len, out, split);
    cap_restore(&saved);
    return ok;
}

static int match(const char *name, const EVP_CIPHER *cipher, int enc,
    const unsigned char *key, const unsigned char *iv,
    const unsigned char *in, int len, int inplace, int split)
{
    unsigned char vaes_buf[MAX_LEN];
    unsigned char aesni_buf[MAX_LEN];
    unsigned char vaes_out[MAX_LEN];
    unsigned char aesni_out[MAX_LEN];
    unsigned char *vaes_in;
    unsigned char *aesni_in;
    unsigned char *vaes_dst;
    unsigned char *aesni_dst;

    if (len > MAX_LEN) {
        TEST_error("length %d exceeds %d", len, MAX_LEN);
        return 0;
    }

    memcpy(vaes_buf, in, (size_t)len);
    memcpy(aesni_buf, in, (size_t)len);
    if (inplace) {
        vaes_in = vaes_dst = vaes_buf;
        aesni_in = aesni_dst = aesni_buf;
    } else {
        vaes_in = aesni_in = (unsigned char *)in;
        vaes_dst = vaes_out;
        aesni_dst = aesni_out;
    }

    if (!crypt_path(cipher, enc, 1, key, iv, vaes_in, len, vaes_dst, split)
        || !crypt_path(cipher, enc, 0, key, iv, aesni_in, len, aesni_dst, split))
        return 0;

    if (!TEST_mem_eq(vaes_dst, len, aesni_dst, len)) {
        TEST_info("%s %s len %d inplace %d split %d",
            name, enc ? "encrypt" : "decrypt", len, inplace, split);
        return 0;
    }
    return 1;
}

static void fill_plain(unsigned char *key, int keylen, unsigned char *iv,
    unsigned char *pt, int len)
{
    int i;

    for (i = 0; i < keylen; i++)
        key[i] = (unsigned char)(0x10 + i);
    for (i = 0; i < 16; i++)
        iv[i] = (unsigned char)(0xa0 + i);
    for (i = 0; i < len; i++)
        pt[i] = (unsigned char)(i * 17 + 3);
}

static int match_lengths(const char *name, const EVP_CIPHER *(*cipher_fn)(void),
    int keylen, int enc, const int *lens, size_t nlens)
{
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char pt[MAX_LEN];
    const EVP_CIPHER *cipher = cipher_fn();
    size_t i;

    fill_plain(key, keylen, iv, pt, MAX_LEN);
    for (i = 0; i < nlens; i++) {
        if (!match(name, cipher, enc, key, iv, pt, lens[i], 0, 0))
            return 0;
    }
    return 1;
}

#if VAES256_CTR_ELIGIBLE
static const int ctr_lens[] = {
    0, 1, 15, 16, 17, 31, 32, 63, 64, 65, 80,
    127, 128, 255, 256, 511, 512, 535, 1000, 4096
};

static int test_ctr(int keylen, const EVP_CIPHER *(*cipher_fn)(void),
    const char *name)
{
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char pt[MAX_LEN];
    const EVP_CIPHER *cipher = cipher_fn();
    static const int splits[] = { 1, 10, 15, 16, 63, 64 };
    size_t i;

    if (!match_lengths(name, cipher_fn, keylen, 1, ctr_lens, OSSL_NELEM(ctr_lens))
        || !match_lengths(name, cipher_fn, keylen, 0, ctr_lens, OSSL_NELEM(ctr_lens)))
        return 0;

    fill_plain(key, keylen, iv, pt, MAX_LEN);
    for (i = 0; i < OSSL_NELEM(splits); i++) {
        if (!match(name, cipher, 1, key, iv, pt, 300, 0, splits[i])
            || !match(name, cipher, 1, key, iv, pt, 300, 1, splits[i]))
            return 0;
    }

    /*
     * Low 64 bits of the counter are all ones, so the next block carries.
     * 528 bytes leaves at least 512 bytes after that block, which resumes
     * the wide kernel. One less than all ones takes a single wide block
     * first, then the carry, then the resume.
     */
    fill_plain(key, keylen, iv, pt, MAX_LEN);
    memset(iv + 8, 0xff, 8);
    if (!match(name, cipher, 1, key, iv, pt, 96, 0, 0)
        || !match(name, cipher, 1, key, iv, pt, 528, 0, 0)
        || !match(name, cipher, 1, key, iv, pt, 535, 0, 0))
        return 0;
    iv[15] = 0xfe;
    if (!match(name, cipher, 1, key, iv, pt, 528, 0, 0))
        return 0;
    return 1;
}
#endif

#if VAES256_CBC_ELIGIBLE
static const int cbc_lens[] = {
    16, 32, 48, 240, 256, 272, 512, 528, 1024, 4096
};

static int test_cbc(int keylen, const EVP_CIPHER *(*cipher_fn)(void),
    const char *name)
{
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char pt[MAX_LEN];
    const EVP_CIPHER *cipher = cipher_fn();
    static const int splits[] = { 16, 240, 256 };

    if (!match_lengths(name, cipher_fn, keylen, 1, cbc_lens, OSSL_NELEM(cbc_lens))
        || !match_lengths(name, cipher_fn, keylen, 0, cbc_lens, OSSL_NELEM(cbc_lens)))
        return 0;

    fill_plain(key, keylen, iv, pt, MAX_LEN);
    if (!match(name, cipher, 0, key, iv, pt, 512, 1, 0)
        || !match(name, cipher, 0, key, iv, pt, 512, 1, splits[0])
        || !match(name, cipher, 0, key, iv, pt, 512, 0, splits[1])
        || !match(name, cipher, 0, key, iv, pt, 512, 0, splits[2]))
        return 0;
    return 1;
}
#endif

#if VAES256_CFB_ELIGIBLE
static const int cfb_lens[] = {
    0, 1, 7, 15, 16, 17, 31, 32, 63, 64, 100,
    255, 256, 400, 512, 1024, 4096
};

static int test_cfb(int keylen, const EVP_CIPHER *(*cipher_fn)(void),
    const char *name)
{
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char pt[MAX_LEN];
    const EVP_CIPHER *cipher = cipher_fn();
    static const int splits[] = { 1, 7, 15, 16, 17 };
    size_t i;

    if (!match_lengths(name, cipher_fn, keylen, 1, cfb_lens, OSSL_NELEM(cfb_lens))
        || !match_lengths(name, cipher_fn, keylen, 0, cfb_lens, OSSL_NELEM(cfb_lens)))
        return 0;

    fill_plain(key, keylen, iv, pt, MAX_LEN);
    for (i = 0; i < OSSL_NELEM(splits); i++) {
        if (!match(name, cipher, 1, key, iv, pt, 400, 0, splits[i])
            || !match(name, cipher, 0, key, iv, pt, 400, 0, splits[i])
            || !match(name, cipher, 1, key, iv, pt, 400, 1, splits[i])
            || !match(name, cipher, 0, key, iv, pt, 400, 1, splits[i]))
            return 0;
    }
    return 1;
}
#endif

static int test_vaes256(void)
{
    struct cap_save saved;

    if (!cpu_has_vaes256())
        return TEST_skip("AES-NI, AVX2 and VAES are required");

    cap_save(&saved);
    hide_avx512();
    if (!vaes256_selected()) {
        cap_restore(&saved);
        return 0;
    }
    cap_restore(&saved);
    TEST_note("VAES-256 path selected with AVX-512 cleared");

#if VAES256_CTR_ELIGIBLE
    if (!test_ctr(16, EVP_aes_128_ctr, "AES-128-CTR")
        || !test_ctr(24, EVP_aes_192_ctr, "AES-192-CTR")
        || !test_ctr(32, EVP_aes_256_ctr, "AES-256-CTR"))
        return 0;
#endif
#if VAES256_CBC_ELIGIBLE
    if (!test_cbc(16, EVP_aes_128_cbc, "AES-128-CBC")
        || !test_cbc(24, EVP_aes_192_cbc, "AES-192-CBC")
        || !test_cbc(32, EVP_aes_256_cbc, "AES-256-CBC"))
        return 0;
#endif
#if VAES256_CFB_ELIGIBLE
    if (!test_cfb(16, EVP_aes_128_cfb128, "AES-128-CFB")
        || !test_cfb(24, EVP_aes_192_cfb128, "AES-192-CFB")
        || !test_cfb(32, EVP_aes_256_cfb128, "AES-256-CFB"))
        return 0;
#endif
    return 1;
}

#endif /* VAES256_ELIGIBLE */

int setup_tests(void)
{
    ADD_TEST(test_vaes256);
    return 1;
}
