/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Verify ARM SME (Scalable Matrix Extension) capability detection and
 * exercise the SME-accelerated AES functions (CTR-32 and CBC decrypt)
 * against NIST SP 800-38A reference vectors.
 *
 * Test overview
 * -------------
 * 1. test_sme_capability  – calls OPENSSL_cpuid_setup(), reports the
 *    ARMV9_SME / ARMV9_SME_AES bits, and verifies that AES_SME_CAPABLE
 *    is consistent with those bits.
 *
 * 2. test_sme_ctr32        – if AES_SME_CAPABLE, calls
 *    aes_v8_sme_ctr32_encrypt_blocks directly with the NIST AES-128 CTR
 *    test vector (SP 800-38A F.5.1, 4 blocks) and checks the output.
 *
 * 3. test_sme_cbc_decrypt  – if AES_SME_CAPABLE, calls
 *    aes_v8_sme_cbc_decrypt directly with the NIST AES-128 CBC-decrypt
 *    test vector (SP 800-38A F.2.2, 4 blocks) and checks both the
 *    plaintext output and the updated IV.
 *
 * 4. test_sme_svl          – if ARMV9_SME is set, calls
 *    _armv9_sme_get_svl_bytes() to report the streaming vector length and
 *    sanity-checks that it is a power-of-two multiple of 16 bytes.
 *
 * Tests 2-4 call TEST_skip() and return success when the matching
 * hardware feature is absent, so the test suite remains green on
 * non-SME hardware.
 */

#include "testutil.h"

#if defined(__aarch64__) && defined(OPENSSL_CPUID_OBJ)

# include <string.h>
# include <openssl/aes.h>
# include "arm_arch.h"
# include "crypto/aes_platform.h"

/*
 * _armv9_sme_get_svl_bytes() is defined in crypto/arm64cpuid.pl as a
 * thin wrapper around  rdsvl x0, #1  (returns the Streaming SVE vector
 * length in bytes without entering streaming mode).
 */
uint64_t _armv9_sme_get_svl_bytes(void);

/* ------------------------------------------------------------------ */
/* NIST SP 800-38A test vectors (AES-128)                             */
/* ------------------------------------------------------------------ */

/* F.5.1  CTR-AES128.Encrypt, 4 blocks */
static const unsigned char ctr_key[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
static const unsigned char ctr_icb[] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};
static const unsigned char ctr_pt[] = {
    /* block 1 */
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    /* block 2 */
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    /* block 3 */
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    /* block 4 */
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};
static const unsigned char ctr_ct[] = {
    /* block 1 */
    0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
    0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
    /* block 2 */
    0x90, 0x49, 0x23, 0x76, 0x09, 0x52, 0x82, 0x73,
    0xd3, 0x2c, 0x5b, 0xb1, 0xac, 0xe0, 0x91, 0xd3,
    /* block 3 */
    0x26, 0x5e, 0x5a, 0xbe, 0xf9, 0x79, 0x25, 0xa1,
    0x96, 0xc5, 0x39, 0x49, 0xe3, 0x2b, 0xb0, 0x55,
    /* block 4 */
    0x98, 0x96, 0xb9, 0x0c, 0x74, 0x84, 0x77, 0x80,
    0xaf, 0x86, 0xf7, 0xc7, 0xb5, 0x2e, 0x77, 0xfb
};

/* F.2.2  CBC-AES128.Decrypt, 4 blocks */
static const unsigned char cbc_key[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
static const unsigned char cbc_iv[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const unsigned char cbc_ct[] = {
    /* block 1 */
    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
    0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
    /* block 2 */
    0x49, 0x56, 0x07, 0x47, 0xd3, 0x35, 0x5b, 0x5a,
    0x4f, 0xe9, 0x24, 0x65, 0x4d, 0x36, 0x55, 0x45,
    /* block 3 */
    0x58, 0xf5, 0x8a, 0x0e, 0x2d, 0xcf, 0x95, 0x30,
    0x6b, 0xbc, 0x21, 0x26, 0xa1, 0x6e, 0xac, 0x65,
    /* block 4 */
    0x86, 0x1d, 0xca, 0x84, 0x5a, 0xaa, 0x15, 0x74,
    0x62, 0x39, 0xa3, 0x89, 0x6b, 0x38, 0x00, 0x3b
};
static const unsigned char cbc_pt[] = {
    /* block 1 */
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    /* block 2 */
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    /* block 3 */
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    /* block 4 */
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

/* ------------------------------------------------------------------ */
/* test_sme_capability: check that ARMV9_SME / ARMV9_SME_AES flags    */
/*   are consistent with AES_SME_CAPABLE                              */
/* ------------------------------------------------------------------ */
static int test_sme_capability(void)
{
    int sme     = (OPENSSL_armcap_P & ARMV9_SME)     != 0;
    int sme_aes = (OPENSSL_armcap_P & ARMV9_SME_AES) != 0;

    TEST_info("OPENSSL_armcap_P = 0x%08x", OPENSSL_armcap_P);
    TEST_info("ARMV9_SME        : %s (bit %d)",
              sme     ? "set"   : "not set", 18);
    TEST_info("ARMV9_SME_AES    : %s (bit %d)",
              sme_aes ? "set"   : "not set", 19);
    TEST_info("AES_SME_CAPABLE  : %s", AES_SME_CAPABLE ? "yes" : "no");

    /* SME_AES requires SME – the two bits must be consistent */
    if (sme_aes && !TEST_true(sme)) {
        TEST_error("ARMV9_SME_AES set but ARMV9_SME is not – inconsistent");
        return 0;
    }

    /* AES_SME_CAPABLE must equal (SME && SME_AES) */
    if (!TEST_int_eq(AES_SME_CAPABLE ? 1 : 0, (sme && sme_aes) ? 1 : 0)) {
        TEST_error("AES_SME_CAPABLE disagrees with ARMV9_SME/ARMV9_SME_AES");
        return 0;
    }

    return 1;
}

# if __ARM_MAX_ARCH__ >= 9

/* ------------------------------------------------------------------ */
/* test_sme_ctr32: NIST SP 800-38A F.5.1 via aes_v8_sme_ctr32_*      */
/* ------------------------------------------------------------------ */
static int test_sme_ctr32(void)
{
    AES_KEY enc_key;
    unsigned char out[sizeof(ctr_pt)];
    unsigned char icb[16];

    if (!AES_SME_CAPABLE) {
        TEST_skip("FEAT_SME_AES not available – skipping CTR32 SME test");
        return 1;
    }

    if (!TEST_int_eq(AES_set_encrypt_key(ctr_key, 128, &enc_key), 0))
        return 0;

    memcpy(icb, ctr_icb, sizeof(icb));

    aes_v8_sme_ctr32_encrypt_blocks(ctr_pt, out,
                                    sizeof(ctr_pt) / 16,
                                    &enc_key, icb);

    if (!TEST_mem_eq(out, sizeof(out), ctr_ct, sizeof(ctr_ct)))
        return 0;

    TEST_info("aes_v8_sme_ctr32_encrypt_blocks: PASSED (%zu bytes, %zu blocks)",
              sizeof(ctr_pt), sizeof(ctr_pt) / 16);
    return 1;
}

/* ------------------------------------------------------------------ */
/* test_sme_cbc_decrypt: NIST SP 800-38A F.2.2 via aes_v8_sme_cbc_*  */
/* ------------------------------------------------------------------ */
static int test_sme_cbc_decrypt(void)
{
    AES_KEY dec_key;
    unsigned char out[sizeof(cbc_ct)];
    unsigned char iv[16];

    if (!AES_SME_CAPABLE) {
        TEST_skip("FEAT_SME_AES not available – skipping CBC decrypt SME test");
        return 1;
    }

    if (!TEST_int_eq(AES_set_decrypt_key(cbc_key, 128, &dec_key), 0))
        return 0;

    memcpy(iv, cbc_iv, sizeof(iv));

    aes_v8_sme_cbc_decrypt(cbc_ct, out, sizeof(cbc_ct), &dec_key, iv);

    /* Verify plaintext output */
    if (!TEST_mem_eq(out, sizeof(out), cbc_pt, sizeof(cbc_pt)))
        return 0;

    /* aes_v8_sme_cbc_decrypt must update iv to the last ciphertext block */
    if (!TEST_mem_eq(iv, 16, cbc_ct + sizeof(cbc_ct) - 16, 16))
        return 0;

    TEST_info("aes_v8_sme_cbc_decrypt: PASSED (%zu bytes, %zu blocks)",
              sizeof(cbc_ct), sizeof(cbc_ct) / 16);
    return 1;
}

/* ------------------------------------------------------------------ */
/* test_sme_svl: report & sanity-check the Streaming Vector Length    */
/* ------------------------------------------------------------------ */
static int test_sme_svl(void)
{
    uint64_t svl_bytes;

    if (!(OPENSSL_armcap_P & ARMV9_SME)) {
        TEST_skip("FEAT_SME not available – skipping SVL query");
        return 1;
    }

    svl_bytes = _armv9_sme_get_svl_bytes();

    TEST_info("Streaming Vector Length (SVL) = %u bits (%u bytes, NVEC = %u)",
              (unsigned)(svl_bytes * 8),
              (unsigned)svl_bytes,
              (unsigned)(svl_bytes / 16));

    /* SVL must be a multiple of 16 bytes (128 bits) */
    if (!TEST_true(svl_bytes >= 16 && (svl_bytes % 16) == 0))
        return 0;

    /* SVL must be a power of two */
    if (!TEST_true((svl_bytes & (svl_bytes - 1)) == 0))
        return 0;

    return 1;
}

# endif /* __ARM_MAX_ARCH__ >= 9 */

int setup_tests(void)
{
    OPENSSL_cpuid_setup();

    ADD_TEST(test_sme_capability);
# if __ARM_MAX_ARCH__ >= 9
    ADD_TEST(test_sme_ctr32);
    ADD_TEST(test_sme_cbc_decrypt);
    ADD_TEST(test_sme_svl);
# endif
    return 1;
}

#else /* !(defined(__aarch64__) && defined(OPENSSL_CPUID_OBJ)) */

int setup_tests(void)
{
    TEST_skip("ARM SME test only runs on AArch64 with OPENSSL_CPUID_OBJ");
    return 1;
}

#endif
